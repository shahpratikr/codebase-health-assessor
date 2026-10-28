import fcntl
import getpass
import hashlib
import json
import os
import pwd
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path

from assessor import config
from assessor.audit import AuditLog, timestamp, utc_now


class DecisionRefused(Exception):
    """A decision the run's state does not allow; the message says why."""


def open_gates(
    *,
    ratings: Mapping[str, Mapping],
    disposition: Mapping,
    verdicts: Mapping[str, str],
    draft_id: str,
    latest: Sequence[str],
) -> list[dict]:
    """Return the gates open at the end of a run, in config.GATES order, each as {"gate": name, "subjects": [...]}.

    verdicts maps an output's ID to its latest review's verdict, which the draft, the examinations the disposition names
    and the ones in latest, each step's newest reviewed examination, must all have (KeyError otherwise).
    """
    steps = disposition["steps"]
    by_rating = {
        rating: [workflow for workflow, entry in ratings.items() if entry["rating"] == rating]
        for rating in config.SUBSTANCE_RATINGS
    }
    elevating = by_rating["toy"] or (
        by_rating["peripheral"] if len(by_rating["peripheral"]) >= config.ELEVATING_PERIPHERAL_COUNT else []
    )
    named = [step["examination_id"] for step in steps]
    reviewed = [*named, *(target for target in latest if target not in named), draft_id]
    blocked = [target for target in reviewed if verdicts[target] == "block"]
    escalated = [f"{step['workflow']}.{step['step']}" for step in steps if step["decision"] == "escalate"]
    subjects = {
        "SUBSTANCE_ELEVATION": elevating,
        "OPEN_CRITICAL_CHALLENGE": blocked,
        "COORDINATOR_ESCALATION": escalated,
    }
    return [{"gate": gate, "subjects": subjects[gate]} for gate in config.GATES if subjects[gate]]


def _system_user() -> str:
    """Return the account name of the process's uid, the environment's user only when the uid has no account."""
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return getpass.getuser()


def decide(
    correlation_id: str,
    *,
    decision: str,
    reviewer: str,
    note: str | None = None,
    runs_dir: Path | None = None,
    os_user: Callable[[], str] = _system_user,
    clock: Callable[[], datetime] = utc_now,
) -> dict:
    """Append the decision record and a decision_recorded audit line under an exclusive lock; return the record.

    Raises ValueError for a malformed correlation ID or a decision outside config.HUMAN_DECISIONS, DecisionRefused for
    an unknown run, one with no valid run.json or open gate, or one already decided, and FileNotFoundError for a run
    with no report.md.
    """
    if decision not in config.HUMAN_DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(config.HUMAN_DECISIONS)}, not {decision!r}")
    log = AuditLog(correlation_id, runs_dir=runs_dir, clock=clock)
    run_dir = log.path.parent
    if not run_dir.is_dir():
        raise DecisionRefused(f"no run {correlation_id} under {run_dir.parent}")
    run = _read_run(run_dir)
    if run["status"] != "pending_human" or not run["gates"]:
        raise DecisionRefused(f"run {correlation_id} has no open gate, its status is {run['status']}")
    report_sha256 = hashlib.sha256((run_dir / config.REPORT_FILE).read_bytes()).hexdigest()
    gates_resolved = [gate["gate"] for gate in run["gates"]]
    user, decided_at = os_user(), timestamp(clock())
    with open(run_dir / config.DECISIONS_FILE, "a+", encoding="utf-8", errors="replace") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        file.seek(0)
        text = file.read()
        if earlier := _records(text):
            first = earlier[0]
            raise DecisionRefused(
                f"run {correlation_id} was already decided: {first['decision']} by {first['reviewer']} "
                f"at {first['decided_at']}"
            )
        record = {
            "correlation_id": correlation_id,
            "decision": decision,
            "reviewer": reviewer,
            "os_user": user,
            "note": note,
            "decided_at": decided_at,
            "gates_resolved": gates_resolved,
            "report_sha256": report_sha256,
        }
        file.write(("\n" if text and not text.endswith("\n") else "") + json.dumps(record, allow_nan=False) + "\n")
        file.flush()
        os.fsync(file.fileno())
        log.append(
            "decision_recorded",
            decision=decision,
            reviewer=reviewer,
            gates_resolved=gates_resolved,
            report_sha256=report_sha256,
        )
    return record


def effective_status(correlation_id: str, *, runs_dir: Path | None = None) -> str:
    """Return the run's status from its run.json and decisions.jsonl: the human status of its decision when a human
    decided a pending_human run, otherwise the run's own.

    Raises ValueError for a malformed correlation ID and DecisionRefused for a run with no valid run.json.
    """
    if not config.CORRELATION_ID.fullmatch(correlation_id):
        raise ValueError(f"not a correlation ID: {correlation_id!r}")
    run_dir = (config.runs_dir() if runs_dir is None else runs_dir) / correlation_id
    status = _read_run(run_dir)["status"]
    try:
        decisions = _records((run_dir / config.DECISIONS_FILE).read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        decisions = []
    if status == "pending_human" and decisions:
        return config.HUMAN_STATUSES[decisions[0]["decision"]]
    return status


def _read_run(run_dir: Path) -> dict:
    path = run_dir / config.RUN_FILE
    try:
        run = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DecisionRefused(f"run {run_dir.name} has no {config.RUN_FILE}: it did not finish") from None
    except (ValueError, RecursionError):
        run = None
    if not _is_run_record(run):
        raise DecisionRefused(f"{path} is not a run record")
    return run


def _is_run_record(run: object) -> bool:
    return (
        isinstance(run, dict)
        and run.get("status") in config.RUN_STATUSES
        and isinstance(run.get("gates"), list)
        and all(isinstance(gate, dict) and gate.get("gate") in config.GATES for gate in run["gates"])
    )


def _records(text: str) -> Sequence[dict]:
    """Return the JSON objects on the lines of decisions.jsonl text; a line that does not parse is not a decision."""
    records = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records
