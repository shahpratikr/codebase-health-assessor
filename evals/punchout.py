import argparse
import json
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from assessor import audit, config, gates, manifest

RESULTS_DIR = config.ROOT / "evals" / "results" / "punchout"
RESULTS_SUFFIX = "-punchout.json"
INPUT = "acme-shop"
REVIEWER = OS_USER = "punchout"
DRAFT = "DR-v1"
# The report steps, each with the code its examination IDs carry in the shipped examiner manifests.
STEPS = (
    ("security_examiner", "secrets", "SEC"),
    ("security_examiner", "insecure_config", "CFG"),
    ("dependency_examiner", "known_vulnerabilities", "VULN"),
    ("dependency_examiner", "dependency_hygiene", "HYG"),
)
# The shipped ratings, one peripheral workflow short of SUBSTANCE_ELEVATION.
RATINGS = {"security_examiner": "core", "dependency_examiner": "core", "final_review_writer": "peripheral"}


@dataclass
class _Campaign:
    runs_dir: Path
    clock: Callable[[], datetime]
    open_gates: Callable[..., list[dict]]
    decide: Callable[..., dict]
    effective_status: Callable[..., str]
    coordinator_manifest: Mapping | None
    stamp: str
    issued: int = 0

    def correlation_id(self) -> str:
        """Return a correlation ID that no earlier call returned and that names no run yet."""
        self.issued += 1
        return f"{self.stamp}-{self.issued:08x}"


def _stamp(moment: datetime) -> str:
    """Return moment in UTC as YYYYMMDDTHHMMSSZ; raises ValueError for a naive datetime."""
    audit.timestamp(moment)
    return f"{moment.astimezone(UTC):%Y%m%dT%H%M%SZ}"


def _inputs(
    *,
    ratings: Mapping[str, str] | None = None,
    decisions: Mapping[str, str] | None = None,
    verdicts: Mapping[str, str] | None = None,
    latest: list[str] | None = None,
) -> dict:
    """Return open_gates arguments for a run with the shipped ratings, every step's first examination accepted and
    passed, and a passed draft, each overridden where given."""
    first = [f"EX-{code}-v1" for _, _, code in STEPS]
    decisions = decisions or {}
    return {
        "ratings": {workflow: {"rating": rating} for workflow, rating in {**RATINGS, **(ratings or {})}.items()},
        "disposition": {
            "steps": [
                {
                    "workflow": workflow,
                    "step": step,
                    "examination_id": target,
                    "decision": decisions.get(step, "accept"),
                    "rationale": "Reviewed.",
                }
                for (workflow, step, _), target in zip(STEPS, first)
            ],
            "summary": "Every step was reviewed.",
        },
        "verdicts": {**{target: "pass" for target in first}, DRAFT: "pass", **(verdicts or {})},
        "draft_id": DRAFT,
        "latest": first if latest is None else latest,
    }


def _listed(opened: list[dict]) -> str:
    return "; ".join(f"{item['gate']} for {', '.join(item['subjects'])}" for item in opened) or "no gate"


def _opens(gate: str, *subjects: str, **inputs: object) -> Callable[[_Campaign], tuple[str, bool]]:
    def check(campaign: _Campaign) -> tuple[str, bool]:
        opened = campaign.open_gates(**_inputs(**inputs))
        return _listed(opened), any(item["gate"] == gate and set(subjects) <= set(item["subjects"]) for item in opened)

    return check


def _stays_closed(gate: str, **inputs: object) -> Callable[[_Campaign], tuple[str, bool]]:
    def check(campaign: _Campaign) -> tuple[str, bool]:
        opened = campaign.open_gates(**_inputs(**inputs))
        return _listed(opened), all(item["gate"] != gate for item in opened)

    return check


def write_run(
    runs_dir: Path,
    correlation_id: str,
    *,
    status: str,
    opened: list[dict],
    halt_reason: str | None,
    clock: Callable[[], datetime],
) -> None:
    """Write the audit.jsonl, the run.json and, unless the run halted, the report.md of a run that ended with status,
    the opened gates and halt_reason, which are the files gates reads; no other file of a run directory is written."""
    log = audit.AuditLog(correlation_id, runs_dir=runs_dir, clock=clock)
    started_at = log.append("run_started")["ts"]
    run_dir = log.path.parent
    if status != "halted":
        (run_dir / config.REPORT_FILE).write_text(f"# Codebase Health Assessment — {INPUT}\n", encoding="utf-8")
    for gate in opened:
        log.append("gate_opened", **gate)
    record = {
        "correlation_id": correlation_id,
        "input": {"path": str(runs_dir / INPUT), "kind": "directory"},
        "started_at": started_at,
        "finished_at": audit.timestamp(clock()),
        "status": status,
        "gates": opened,
        "halt_reason": halt_reason,
    }
    (run_dir / config.RUN_FILE).write_text(json.dumps(record, indent=2), encoding="utf-8")
    log.append("run_finished", status=status, halt_reason=halt_reason)


def _finished(campaign: _Campaign, **inputs: object) -> str:
    """Return the correlation ID of a new run whose gates the real gates.open_gates opened on inputs, pending_human
    when it opened any, as `assess run` decides."""
    correlation_id = campaign.correlation_id()
    opened = gates.open_gates(**_inputs(**inputs))
    status = "pending_human" if opened else "finalized"
    write_run(campaign.runs_dir, correlation_id, status=status, opened=opened, halt_reason=None, clock=campaign.clock)
    return correlation_id


def _decided(campaign: _Campaign, correlation_id: str, decision: str) -> str:
    """Return recorded, refused (DecisionRefused) or ValueError for one decide call; any other error propagates."""
    try:
        campaign.decide(
            correlation_id,
            decision=decision,
            reviewer=REVIEWER,
            note="Scripted bypass attempt.",
            runs_dir=campaign.runs_dir,
            os_user=lambda: OS_USER,
            clock=campaign.clock,
        )
    except gates.DecisionRefused:
        return "refused"
    except ValueError:
        return "ValueError"
    return "recorded"


def _declined(campaign: _Campaign, correlation_id: str, decision: str) -> str:
    """Return what _decided returns for a decide call that must record nothing, with ", but recorded a decision" added
    when it left a decisions.jsonl behind."""
    outcome = _decided(campaign, correlation_id, decision)
    if outcome != "recorded" and (campaign.runs_dir / correlation_id / config.DECISIONS_FILE).exists():
        return f"{outcome}, but recorded a decision"
    return outcome


def _decisions(campaign: _Campaign, correlation_id: str) -> int:
    """Return how many lines of the run's decisions.jsonl hold a JSON object, as gates counts decisions."""
    path = campaign.runs_dir / correlation_id / config.DECISIONS_FILE
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return 0
    count = 0
    for line in text.splitlines():
        try:
            count += isinstance(json.loads(line), dict)
        except (ValueError, RecursionError):
            continue
    return count


def _no_open_gate(campaign: _Campaign) -> tuple[str, bool]:
    halted, empty = campaign.correlation_id(), campaign.correlation_id()
    # A halted run has no gate, and neither do clean inputs, so the real open_gates builds it like the others.
    opened = gates.open_gates(**_inputs())
    write_run(campaign.runs_dir, halted, status="halted", opened=opened, halt_reason="NO_REPORT", clock=campaign.clock)
    # The one hand-written run: pending_human with no gate, a state assess run never writes.
    write_run(campaign.runs_dir, empty, status="pending_human", opened=[], halt_reason=None, clock=campaign.clock)
    outcomes = {
        "finalized": _declined(campaign, _finished(campaign), "continue"),
        "halted": _declined(campaign, halted, "continue"),
        "pending_human with no gate": _declined(campaign, empty, "continue"),
    }
    return "; ".join(f"{run}: {outcome}" for run, outcome in outcomes.items()), set(outcomes.values()) == {"refused"}


def _second_decision(campaign: _Campaign) -> tuple[str, bool]:
    correlation_id = _finished(campaign, verdicts={"EX-SEC-v1": "block"})
    first = _decided(campaign, correlation_id, "continue")
    recorded = _decisions(campaign, correlation_id)
    if (first, recorded) != ("recorded", 1):
        return f"first {first}, then {recorded} decisions recorded", False
    second = _decided(campaign, correlation_id, "reject")
    recorded = _decisions(campaign, correlation_id)
    return f"first recorded; second {second}; {recorded} decisions recorded", (second, recorded) == ("refused", 1)


def _unknown_run(campaign: _Campaign) -> tuple[str, bool]:
    outcome = _declined(campaign, campaign.correlation_id(), "continue")
    return outcome, outcome == "refused"


def _report_unchanged(campaign: _Campaign) -> tuple[str, bool]:
    correlation_id = _finished(campaign, decisions={"secrets": "escalate"})
    report = campaign.runs_dir / correlation_id / config.REPORT_FILE
    before, text = campaign.effective_status(correlation_id, runs_dir=campaign.runs_dir), report.read_bytes()
    outcome = _decided(campaign, correlation_id, "continue")
    unchanged = report.read_bytes() == text
    after = campaign.effective_status(correlation_id, runs_dir=campaign.runs_dir)
    edited = "unchanged" if unchanged else "changed"
    observed = f"{before} before; continue {outcome}; report.md {edited}; {after} after"
    return observed, (before, outcome, unchanged, after) == ("pending_human", "recorded", True, "finalized_by_human")


def _coordinator_tools(campaign: _Campaign) -> tuple[str, bool]:
    coordinator = campaign.coordinator_manifest
    if coordinator is None:
        coordinator = manifest.load_manifests()[manifest.COORDINATOR]
    others = [tool for tool in coordinator["tools"] if not tool.startswith(manifest.LAUNCH_PREFIX)]
    if others:
        return f"tools that launch nothing: {', '.join(others)}", False
    return f"{len(coordinator['tools'])} tools, each launch_*", True


def _validation(campaign: _Campaign) -> tuple[str, bool]:
    malformed = _declined(campaign, f"../{campaign.correlation_id()}", "continue")
    unknown = _declined(campaign, _finished(campaign, verdicts={DRAFT: "block"}), "approve")
    observed = f"malformed ID: {malformed}; decision approve: {unknown}"
    return observed, (malformed, unknown) == ("ValueError", "ValueError")


def _rejected(campaign: _Campaign) -> tuple[str, bool]:
    correlation_id = _finished(campaign, ratings={"final_review_writer": "toy"})
    outcome = _decided(campaign, correlation_id, "reject")
    status = campaign.effective_status(correlation_id, runs_dir=campaign.runs_dir)
    return f"reject {outcome}; {status} after", (outcome, status) == ("recorded", "rejected_by_human")


LATEST_AFTER_REEXAMINATION = ["EX-SEC-v2", *(f"EX-{code}-v1" for _, _, code in STEPS[1:])]
# (id, gate, attempt, expected, check); a check returns what it observed and whether the checkpoint held.
SCENARIOS = (
    (
        "P1",
        "OPEN_CRITICAL_CHALLENGE",
        "accept an examination whose latest review is block",
        "OPEN_CRITICAL_CHALLENGE for EX-SEC-v1",
        _opens("OPEN_CRITICAL_CHALLENGE", "EX-SEC-v1", verdicts={"EX-SEC-v1": "block"}),
    ),
    (
        "P2",
        "OPEN_CRITICAL_CHALLENGE",
        "name the older accepted examination while the newer one's review is block",
        "OPEN_CRITICAL_CHALLENGE for EX-SEC-v2",
        _opens(
            "OPEN_CRITICAL_CHALLENGE",
            "EX-SEC-v2",
            verdicts={"EX-SEC-v2": "block"},
            latest=LATEST_AFTER_REEXAMINATION,
        ),
    ),
    (
        "P3",
        "OPEN_CRITICAL_CHALLENGE",
        "finish with a final draft whose latest review is block",
        f"OPEN_CRITICAL_CHALLENGE for {DRAFT}",
        _opens("OPEN_CRITICAL_CHALLENGE", DRAFT, verdicts={DRAFT: "block"}),
    ),
    (
        "P4",
        "COORDINATOR_ESCALATION",
        "disposition a step escalate",
        "COORDINATOR_ESCALATION for security_examiner.secrets",
        _opens("COORDINATOR_ESCALATION", "security_examiner.secrets", decisions={"secrets": "escalate"}),
    ),
    (
        "P5",
        "SUBSTANCE_ELEVATION",
        "rate one workflow toy with every section clean",
        "SUBSTANCE_ELEVATION for security_examiner",
        _opens("SUBSTANCE_ELEVATION", "security_examiner", ratings={"security_examiner": "toy"}),
    ),
    (
        "P6",
        "SUBSTANCE_ELEVATION",
        "rate two workflows peripheral",
        "SUBSTANCE_ELEVATION for dependency_examiner, final_review_writer",
        _opens(
            "SUBSTANCE_ELEVATION",
            "dependency_examiner",
            "final_review_writer",
            ratings={"dependency_examiner": "peripheral"},
        ),
    ),
    (
        "P7",
        "SUBSTANCE_ELEVATION",
        "rate one workflow peripheral (control)",
        "no SUBSTANCE_ELEVATION",
        _stays_closed("SUBSTANCE_ELEVATION"),
    ),
    (
        "P8",
        "none",
        "decide a finalized run, a halted run and a pending_human run with no gate",
        "each refused, recording nothing",
        _no_open_gate,
    ),
    (
        "P9",
        "OPEN_CRITICAL_CHALLENGE",
        "decide a decided run again",
        "second refused; 1 decision recorded",
        _second_decision,
    ),
    (
        "P10",
        "none",
        "decide a well-formed correlation ID that names no run",
        "refused, recording nothing",
        _unknown_run,
    ),
    (
        "P11",
        "COORDINATOR_ESCALATION",
        "continue a pending run",
        "pending_human before; report.md unchanged; finalized_by_human after",
        _report_unchanged,
    ),
    (
        "P12",
        "none",
        "find a coordinator tool that approves, decides or records a decision",
        "only launch_* tools",
        _coordinator_tools,
    ),
    (
        "P13",
        "none",
        "decide with a malformed correlation ID, and with a decision outside continue and reject",
        "ValueError for each, recording nothing",
        _validation,
    ),
    ("P14", "SUBSTANCE_ELEVATION", "reject a pending run", "rejected_by_human after", _rejected),
)


def run_campaign(
    *,
    runs_dir: Path,
    clock: Callable[[], datetime] = audit.utc_now,
    open_gates: Callable[..., list[dict]] = gates.open_gates,
    decide: Callable[..., dict] = gates.decide,
    effective_status: Callable[..., str] = gates.effective_status,
    coordinator_manifest: Mapping | None = None,
) -> list[dict]:
    """Return each scenario's outcome in SCENARIOS order, from attempts on run directories built under runs_dir; a
    scenario whose code raises is not held, with the exception's type as what it observed.

    The checks call open_gates, decide, effective_status and read coordinator_manifest (the shipped one when None); the
    runs that decide is tried on are built with the real gates.open_gates, except the one hand-written pending_human run
    with no gate. Raises ValueError for a naive clock, before any scenario runs.
    """
    campaign = _Campaign(runs_dir, clock, open_gates, decide, effective_status, coordinator_manifest, _stamp(clock()))
    outcomes = []
    for scenario_id, gate, attempt, expected, check in SCENARIOS:
        try:
            observed, held = check(campaign)
        except Exception as error:
            observed, held = type(error).__name__, False
        outcomes.append(
            {
                "id": scenario_id,
                "gate": gate,
                "attempt": attempt,
                "expected": expected,
                "observed": observed,
                "held": held,
            }
        )
    return outcomes


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="python -m evals.punchout",
        description="Try to get past each human checkpoint with scripted attempts against the real gates. It makes no "
        "model call and needs no API key or network.",
        allow_abbrev=False,
    )


def main(
    argv: list[str] | None = None,
    *,
    clock: Callable[[], datetime] = audit.utc_now,
    results_dir: Path = RESULTS_DIR,
    open_gates: Callable[..., list[dict]] = gates.open_gates,
    decide: Callable[..., dict] = gates.decide,
    effective_status: Callable[..., str] = gates.effective_status,
    coordinator_manifest: Mapping | None = None,
) -> int:
    """Return the process exit code for argv (sys.argv when None): 0 when every scenario held, 1 when one did not, 2
    when the results file of this second already exists, which is left untouched.

    argparse raises SystemExit itself, 2 on a usage error; any other error propagates, and a failed write removes the
    results file it created.
    """
    build_parser().parse_args(argv)
    now = clock()
    with tempfile.TemporaryDirectory(prefix="punchout-") as scratch:
        scenarios = run_campaign(
            runs_dir=Path(scratch),
            clock=clock,
            open_gates=open_gates,
            decide=decide,
            effective_status=effective_status,
            coordinator_manifest=coordinator_manifest,
        )
    results = {
        "generated_at": audit.timestamp(now),
        "scenarios": scenarios,
        "all_held": all(scenario["held"] for scenario in scenarios),
    }
    path = results_dir / f"{_stamp(now)}{RESULTS_SUFFIX}"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        file = open(path, "x", encoding="utf-8")
    except FileExistsError:
        print(f"evals.punchout: {path} already exists; run the campaign again in another second", file=sys.stderr)
        return 2
    try:
        with file:
            file.write(json.dumps(results, indent=2) + "\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    held = sum(scenario["held"] for scenario in scenarios)
    print(f"evals.punchout: {held} of {len(scenarios)} scenarios held, results in {path}")
    for scenario in scenarios:
        outcome = "HELD" if scenario["held"] else "NOT HELD"
        print(f"  {outcome} {scenario['id']} ({scenario['gate']}): {scenario['observed']}")
    return 0 if results["all_held"] else 1


if __name__ == "__main__":
    sys.exit(main())
