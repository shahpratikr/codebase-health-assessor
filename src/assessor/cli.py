import argparse
import contextlib
import json
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from assessor import audit, config, coordinator, gates, manifest, report, sandbox
from assessor.config import CORRELATION_ID
from assessor.guardrails import redact
from assessor.llm import NoCredentialsError, make_client


def _correlation_id(value: str) -> str:
    if not CORRELATION_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("must match YYYYMMDDTHHMMSSZ-<8 lowercase hex>")
    return value


def _reviewer_name(value: str) -> str:
    if not any(char.isalnum() for char in value):
        raise argparse.ArgumentTypeError("must contain a letter or digit")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assess", description="Assess the health of a client code repository.", allow_abbrev=False
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    run = commands.add_parser("run", help="assess a repository directory or .zip archive", allow_abbrev=False)
    run.add_argument("path", help="repository directory or .zip archive")
    run.add_argument("--substance", metavar="FILE", help="substance ratings file")

    decide = commands.add_parser(
        "decide", help="record a human decision on a run waiting for review", allow_abbrev=False
    )
    decide.add_argument("cid", type=_correlation_id, help="correlation ID of the run")
    decide.add_argument("--decision", required=True, choices=config.HUMAN_DECISIONS)
    decide.add_argument(
        "--reviewer", required=True, type=_reviewer_name, metavar="NAME", help="name of the person deciding"
    )
    decide.add_argument("--note", metavar="TEXT", help="reason for the decision")
    return parser


def main(argv: list[str] | None = None, *, clock: Callable[[], datetime] = audit.utc_now) -> int:
    """Return the process exit code for argv (sys.argv when None), reading times from clock.

    argparse raises SystemExit itself: 2 on a usage error, 0 after --help; any other error, such as a failed write into
    the run directory, propagates.
    """
    args = build_parser().parse_args(argv)
    return _run(args, clock) if args.command == "run" else _decide(args, clock)


def _run(args: argparse.Namespace, clock: Callable[[], datetime]) -> int:
    path = Path(args.path)
    try:
        sandbox.check_input(path)
        runs = config.runs_dir().resolve()
        if _holds(path, runs):
            raise ValueError(f"{path}: the runs directory {runs} is inside it; set ASSESSOR_RUNS_DIR elsewhere")
        manifests = manifest.load_manifests()
        ratings = Path(args.substance) if args.substance else config.SUBSTANCE_FILE
        substance = manifest.load_substance(manifests, ratings)
        client = make_client()
    except (ValueError, OSError, NoCredentialsError) as error:
        return _input_error(error)
    log = audit.AuditLog(audit.new_correlation_id(clock()), clock=clock)
    run_dir = log.path.parent
    try:
        workspace = sandbox.open_workspace(path, run_dir)
    except ValueError as error:
        # A failed extraction removes its partial workspace; the run directory it was made in must not outlive it.
        with contextlib.suppress(OSError):
            run_dir.rmdir()
        return _input_error(error)
    started_at = log.append("run_started")["ts"]
    state = coordinator.run(client, log, manifests, workspace=workspace, workspace_label=path.resolve().name)
    halt_reason = state.halt_reason or _unreported(state)
    finished_at = audit.timestamp(clock())
    opened, status = [], "halted"
    if halt_reason is None:
        opened, status = _write_report(state, substance, log, path, finished_at)
    _create(run_dir / config.SUMMARY_FILE, json.dumps(log.summary(), indent=2))
    record = {
        "correlation_id": log.correlation_id,
        "input": {"path": str(path.resolve()), "kind": "directory" if path.is_dir() else "zip"},
        "started_at": started_at,
        "finished_at": finished_at,
        "status": status,
        "gates": opened,
        "halt_reason": halt_reason,
    }
    _create(run_dir / config.RUN_FILE, json.dumps(record, indent=2))
    log.append("run_finished", status=status, halt_reason=halt_reason)
    print(f"correlation_id: {log.correlation_id}")
    print(f"status: {status}")
    print(f"open_gates: {', '.join(gate['gate'] for gate in opened) or 'none'}")
    return config.RUN_EXIT_CODES[status]


def _write_report(
    state: coordinator.RunState, substance: Mapping, log: audit.AuditLog, path: Path, generated_at: str
) -> tuple[list[dict], str]:
    """Write disposition.json and report.md and a gate_opened line per open gate; return the gates and the status."""
    draft_id = list(state.drafts)[-1]
    disposition = _redacted(state.drafts[draft_id].task["disposition"])
    verdicts = {target: state.reviews[review].output["verdict"] for target, review in state.latest_review.items()}
    newest = {
        (accepted.workflow, accepted.step): name for name, accepted in state.examinations.items() if name in verdicts
    }
    opened = gates.open_gates(
        ratings=substance["ratings"],
        disposition=disposition,
        verdicts=verdicts,
        draft_id=draft_id,
        latest=list(newest.values()),
    )
    status = "pending_human" if opened else "finalized"
    text = report.render(
        input_name=path.resolve().name,
        correlation_id=log.correlation_id,
        generated_at=generated_at,
        status=status,
        gates=opened,
        disposition=disposition,
        examinations={
            step["examination_id"]: state.examinations[step["examination_id"]].output
            for step in disposition["steps"]
        },
        verdicts=verdicts,
        draft=state.drafts[draft_id].output,
    )
    run_dir = log.path.parent
    _create(run_dir / config.DISPOSITION_FILE, json.dumps(disposition, indent=2))
    _create(run_dir / config.REPORT_FILE, text)
    for gate in opened:
        log.append("gate_opened", **gate)
    return opened, status


def _decide(args: argparse.Namespace, clock: Callable[[], datetime]) -> int:
    try:
        gates.decide(
            args.cid,
            decision=args.decision,
            reviewer=args.reviewer,
            note=None if args.note is None else redact(args.note),
            clock=clock,
        )
    except gates.DecisionRefused as error:
        print(f"assess decide: {error}", file=sys.stderr)
        return 1
    print(f"correlation_id: {args.cid}")
    print(f"decision: {args.decision}")
    print(f"status: {gates.effective_status(args.cid)}")
    return 0


def _input_error(error: Exception) -> int:
    print(f"assess run: {error}", file=sys.stderr)
    return 2


def _holds(path: Path, runs: Path) -> bool:
    """Return whether path is runs or one of its ancestors, by file identity so a case-insensitive volume agrees."""
    return any(candidate.exists() and candidate.samefile(path) for candidate in (runs, *runs.parents))


def _unreported(state: coordinator.RunState) -> str | None:
    if not state.drafts:
        return "NO_REPORT"
    return None if list(state.drafts)[-1] in state.latest_review else "REPORT_NOT_REVIEWED"


def _redacted(disposition: Mapping) -> dict:
    """Return the disposition with the coordinator's rationales and summary redacted; IDs and step names stay."""
    return {
        "steps": [{**entry, "rationale": redact(entry["rationale"])} for entry in disposition["steps"]],
        "summary": redact(disposition["summary"]),
    }


def _create(path: Path, text: str) -> None:
    # Exclusive creation keeps each file written once; backslash escapes keep a lone surrogate writable.
    with open(path, "xb") as file:
        file.write(text.encode("utf-8", "backslashreplace"))
