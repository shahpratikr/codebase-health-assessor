import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from assessor import audit, cli, gates

CID = "20261027T101500Z-0a1b2c3d"
NOW = datetime(2026, 10, 27, 12, 0, 0, 456000, tzinfo=UTC)
REPORT = "# Codebase Health Assessment — acme-api\n"
SECRET = "sk-abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def system_account(monkeypatch):
    # The account comes from the password database, which a container with an arbitrary uid may not have.
    monkeypatch.setattr(gates.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="db-account"))


def _run(runs, status="pending_human", gate_names=("OPEN_CRITICAL_CHALLENGE", "COORDINATOR_ESCALATION")):
    run_dir = runs / CID
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text(REPORT, encoding="utf-8")
    halt_reason = "NO_REPORT" if status == "halted" else None
    record = {
        "correlation_id": CID,
        "status": status,
        "gates": [{"gate": name, "subjects": ["EX-SEC-v1"]} for name in gate_names],
        "halt_reason": halt_reason,
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    for name in ("disposition.json", "summary.json"):
        (run_dir / name).write_text("{}", encoding="utf-8")
    log = audit.AuditLog(CID, runs_dir=runs, clock=lambda: NOW)
    log.append("run_started")
    log.append("run_finished", status=status, halt_reason=halt_reason)
    return run_dir


def _argv(*extra, decision="continue", reviewer="Ana Díaz"):
    return ["decide", CID, "--decision", decision, "--reviewer", reviewer, *extra]


def _decide(*extra, **options):
    return cli.main(_argv(*extra, **options), clock=lambda: NOW)


def _snapshot(run_dir):
    return {path.name: path.read_bytes() for path in run_dir.iterdir() if path.is_file()}


def _records(run_dir):
    return [json.loads(line) for line in (run_dir / "decisions.jsonl").read_text().splitlines()]


@pytest.mark.parametrize(
    ("decision", "status"), [("continue", "finalized_by_human"), ("reject", "rejected_by_human")]
)
def test_a_decision_is_recorded_and_the_effective_status_printed(tmp_runs_dir, capsys, decision, status):
    run_dir = _run(tmp_runs_dir)
    assert _decide("--note", "Key rotated.", decision=decision) == 0
    captured = capsys.readouterr()
    assert captured.out == f"correlation_id: {CID}\ndecision: {decision}\nstatus: {status}\n"
    assert captured.err == ""
    assert _records(run_dir) == [
        {
            "correlation_id": CID,
            "decision": decision,
            "reviewer": "Ana Díaz",
            "os_user": "db-account",
            "note": "Key rotated.",
            "decided_at": "2026-10-27T12:00:00.456Z",
            "gates_resolved": ["OPEN_CRITICAL_CHALLENGE", "COORDINATOR_ESCALATION"],
            "report_sha256": hashlib.sha256(REPORT.encode()).hexdigest(),
        }
    ]


def test_the_recorded_os_user_ignores_the_user_and_logname_variables(tmp_runs_dir, monkeypatch):
    run_dir = _run(tmp_runs_dir)
    monkeypatch.setenv("USER", "someone-else")
    monkeypatch.setenv("LOGNAME", "someone-else")
    assert _decide() == 0
    assert _records(run_dir)[0]["os_user"] == "db-account"


def test_a_decision_without_a_note_records_a_null_note(tmp_runs_dir):
    run_dir = _run(tmp_runs_dir)
    assert _decide() == 0
    assert _records(run_dir)[0]["note"] is None


def test_a_secret_in_the_note_is_redacted_before_it_is_stored(tmp_runs_dir):
    run_dir = _run(tmp_runs_dir)
    assert _decide("--note", f"rotated, old key {SECRET}") == 0
    stored = (run_dir / "decisions.jsonl").read_text()
    assert SECRET not in stored
    assert "rotated, old key <redacted:sk-a" in stored


def test_a_decision_changes_only_the_decisions_file_and_appends_one_audit_line(tmp_runs_dir):
    run_dir = _run(tmp_runs_dir)
    before = _snapshot(run_dir)
    assert _decide() == 0
    after = _snapshot(run_dir)
    assert set(after) - set(before) == {"decisions.jsonl"}
    assert {name for name in before if after[name] != before[name]} == {"audit.jsonl"}
    assert after["audit.jsonl"].startswith(before["audit.jsonl"])
    appended = after["audit.jsonl"][len(before["audit.jsonl"]) :].decode().splitlines()
    assert [json.loads(line)["event"] for line in appended] == ["decision_recorded"]


def test_a_second_decision_is_refused_with_exit_1_and_changes_nothing(tmp_runs_dir, capsys):
    run_dir = _run(tmp_runs_dir)
    assert _decide() == 0
    capsys.readouterr()
    before = _snapshot(run_dir)
    assert _decide(decision="reject", reviewer="Bo") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    decided = f"run {CID} was already decided: continue by Ana Díaz at 2026-10-27T12:00:00.456Z"
    assert captured.err == f"assess decide: {decided}\n"
    assert _snapshot(run_dir) == before


def test_an_unknown_run_is_refused_with_exit_1_and_creates_nothing(tmp_runs_dir, capsys):
    assert _decide() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"assess decide: no run {CID} under {tmp_runs_dir}\n"
    assert not tmp_runs_dir.exists()


@pytest.mark.parametrize("status", ["finalized", "halted"])
def test_a_run_with_no_open_gate_is_refused_with_exit_1(tmp_runs_dir, capsys, status):
    run_dir = _run(tmp_runs_dir, status=status, gate_names=())
    before = _snapshot(run_dir)
    assert _decide() == 1
    captured = capsys.readouterr()
    assert captured.err == f"assess decide: run {CID} has no open gate, its status is {status}\n"
    assert captured.out == ""
    assert _snapshot(run_dir) == before


def test_a_unicode_reviewer_and_note_are_recorded_as_given(tmp_runs_dir):
    run_dir = _run(tmp_runs_dir)
    assert _decide("--note", "réparé ✓", reviewer="李明") == 0
    assert (_records(run_dir)[0]["reviewer"], _records(run_dir)[0]["note"]) == ("李明", "réparé ✓")
