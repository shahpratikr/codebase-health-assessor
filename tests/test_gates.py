import fcntl
import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from assessor import audit, config, gates

CID = "20261027T101500Z-0a1b2c3d"
NOW = datetime(2026, 10, 27, 12, 0, 0, 456000, tzinfo=UTC)
STEPS = [
    ("security_examiner", "secrets", "SEC"),
    ("security_examiner", "insecure_config", "CFG"),
    ("dependency_examiner", "known_vulnerabilities", "VULN"),
    ("dependency_examiner", "dependency_hygiene", "HYG"),
]
RATINGS = {
    "security_examiner": {"rating": "core", "rationale": "Billable."},
    "dependency_examiner": {"rating": "core", "rationale": "Billable."},
    "final_review_writer": {"rating": "peripheral", "rationale": "Prose only."},
}
REPORT = "# Codebase Health Assessment\n"


def _ratings(**ratings):
    rated = {workflow: ratings.get(workflow, entry["rating"]) for workflow, entry in RATINGS.items()}
    return {workflow: {**RATINGS[workflow], "rating": rating} for workflow, rating in rated.items()}


def _disposition(decisions=None, ids=None):
    decisions, ids = decisions or {}, ids or {}
    return {
        "steps": [
            {
                "workflow": workflow,
                "step": step,
                "examination_id": ids.get(step, f"EX-{code}-v1"),
                "decision": decisions.get(step, "accept"),
                "rationale": "Reviewed.",
            }
            for workflow, step, code in STEPS
        ],
        "summary": "Done.",
    }


def _verdicts(**verdicts):
    return {**{f"EX-{code}-v1": "pass" for _, _, code in STEPS}, "DR-v1": "pass", **verdicts}


def _open(**overrides):
    arguments = {
        "ratings": RATINGS,
        "disposition": _disposition(),
        "verdicts": _verdicts(),
        "draft_id": "DR-v1",
        "latest": [],
    }
    return gates.open_gates(**{**arguments, **overrides})


def _gate(gate, *subjects):
    return {"gate": gate, "subjects": list(subjects)}


def test_nothing_is_open_when_every_review_passes_and_nothing_is_escalated():
    assert _open() == []


@pytest.mark.parametrize("workflow", list(RATINGS))
def test_a_toy_workflow_opens_the_substance_elevation(workflow):
    assert _open(ratings=_ratings(**{workflow: "toy"})) == [_gate("SUBSTANCE_ELEVATION", workflow)]


def test_two_peripheral_workflows_open_the_substance_elevation():
    ratings = _ratings(dependency_examiner="peripheral")
    assert _open(ratings=ratings) == [_gate("SUBSTANCE_ELEVATION", "dependency_examiner", "final_review_writer")]


def test_three_peripheral_workflows_open_it_naming_all_three():
    ratings = _ratings(security_examiner="peripheral", dependency_examiner="peripheral")
    assert _open(ratings=ratings) == [
        _gate("SUBSTANCE_ELEVATION", "security_examiner", "dependency_examiner", "final_review_writer")
    ]


def test_one_peripheral_workflow_alone_opens_nothing():
    assert sum(entry["rating"] == "peripheral" for entry in RATINGS.values()) == 1
    assert _open(ratings=RATINGS) == []


def test_all_core_workflows_open_nothing():
    assert _open(ratings=_ratings(final_review_writer="core")) == []


def test_a_toy_workflow_names_only_the_toy_ones_even_beside_peripheral_ones():
    ratings = _ratings(security_examiner="toy", dependency_examiner="peripheral")
    assert _open(ratings=ratings) == [_gate("SUBSTANCE_ELEVATION", "security_examiner")]


def test_a_block_on_an_accepted_examination_opens_the_critical_challenge_gate_though_accepted():
    disposition = _disposition(decisions={"secrets": "accept"})
    assert _open(disposition=disposition, verdicts=_verdicts(**{"EX-SEC-v1": "block"})) == [
        _gate("OPEN_CRITICAL_CHALLENGE", "EX-SEC-v1")
    ]


@pytest.mark.parametrize("verdict", ["pass", "challenge"])
def test_a_review_that_does_not_block_opens_no_critical_challenge_gate(verdict):
    assert _open(verdicts=_verdicts(**{"EX-SEC-v1": verdict, "DR-v1": verdict})) == []


def test_a_blocked_draft_opens_the_gate_with_the_draft_after_the_examinations():
    verdicts = _verdicts(**{"EX-HYG-v1": "block", "DR-v1": "block"})
    assert _open(verdicts=verdicts) == [_gate("OPEN_CRITICAL_CHALLENGE", "EX-HYG-v1", "DR-v1")]


def test_only_the_draft_given_counts():
    verdicts = _verdicts(**{"DR-v1": "block", "DR-v2": "pass"})
    assert _open(verdicts=verdicts, draft_id="DR-v2") == []


def test_a_superseded_blocked_examination_opens_nothing_when_its_replacement_is_accepted():
    disposition = _disposition(ids={"secrets": "EX-SEC-v2"})
    verdicts = _verdicts(**{"EX-SEC-v1": "block", "EX-SEC-v2": "pass"})
    assert _open(disposition=disposition, verdicts=verdicts) == []


def test_a_blocked_replacement_opens_the_gate_for_the_replacement():
    disposition = _disposition(ids={"secrets": "EX-SEC-v2"})
    verdicts = _verdicts(**{"EX-SEC-v1": "pass", "EX-SEC-v2": "block"})
    assert _open(disposition=disposition, verdicts=verdicts) == [_gate("OPEN_CRITICAL_CHALLENGE", "EX-SEC-v2")]


def test_an_escalated_step_opens_the_escalation_gate_with_its_workflow_and_step():
    disposition = _disposition(decisions={"secrets": "escalate", "dependency_hygiene": "escalate"})
    assert _open(disposition=disposition) == [
        _gate("COORDINATOR_ESCALATION", "security_examiner.secrets", "dependency_examiner.dependency_hygiene")
    ]


def test_every_gate_can_open_at_once_and_they_come_in_the_closed_set_order():
    disposition = _disposition(decisions={"insecure_config": "escalate"})
    opened = _open(
        ratings=_ratings(security_examiner="toy"),
        disposition=disposition,
        verdicts=_verdicts(**{"EX-SEC-v1": "block"}),
    )
    assert [entry["gate"] for entry in opened] == list(config.GATES)
    assert opened == [
        _gate("SUBSTANCE_ELEVATION", "security_examiner"),
        _gate("OPEN_CRITICAL_CHALLENGE", "EX-SEC-v1"),
        _gate("COORDINATOR_ESCALATION", "security_examiner.insecure_config"),
    ]


def test_a_step_can_be_both_blocked_and_escalated():
    disposition = _disposition(decisions={"secrets": "escalate"})
    opened = _open(disposition=disposition, verdicts=_verdicts(**{"EX-SEC-v1": "block"}))
    assert [entry["gate"] for entry in opened] == ["OPEN_CRITICAL_CHALLENGE", "COORDINATOR_ESCALATION"]


@pytest.mark.parametrize("missing", ["EX-VULN-v1", "DR-v1"])
def test_an_examination_or_draft_with_no_verdict_is_an_error_not_an_open_gate(missing):
    verdicts = {target: verdict for target, verdict in _verdicts().items() if target != missing}
    with pytest.raises(KeyError, match=missing):
        _open(verdicts=verdicts)


def test_a_blocked_latest_examination_opens_the_gate_even_when_the_disposition_names_an_older_one():
    verdicts = _verdicts(**{"EX-SEC-v1": "pass", "EX-SEC-v2": "block"})
    opened = _open(verdicts=verdicts, latest=["EX-SEC-v2", "EX-CFG-v1"])
    assert opened == [_gate("OPEN_CRITICAL_CHALLENGE", "EX-SEC-v2")]


def test_a_latest_examination_that_is_also_named_counts_once_and_before_the_draft():
    verdicts = _verdicts(**{"EX-SEC-v1": "block", "EX-HYG-v1": "block", "DR-v1": "block"})
    assert _open(verdicts=verdicts, latest=["EX-HYG-v1", "EX-SEC-v1"]) == [
        _gate("OPEN_CRITICAL_CHALLENGE", "EX-SEC-v1", "EX-HYG-v1", "DR-v1")
    ]


def test_a_blocked_latest_examination_that_is_not_named_comes_after_the_named_ones_and_before_the_draft():
    verdicts = _verdicts(**{"EX-HYG-v1": "block", "EX-SEC-v2": "block", "DR-v1": "block"})
    opened = _open(verdicts=verdicts, latest=["EX-SEC-v2", "EX-CFG-v1", "EX-VULN-v1", "EX-HYG-v1"])
    assert opened == [_gate("OPEN_CRITICAL_CHALLENGE", "EX-HYG-v1", "EX-SEC-v2", "DR-v1")]


def test_a_latest_examination_with_no_verdict_is_an_error_not_an_open_gate():
    with pytest.raises(KeyError, match="EX-SEC-v2"):
        _open(latest=["EX-SEC-v2"])


def test_latest_is_required_so_that_no_caller_can_switch_the_rule_off_by_omission():
    with pytest.raises(TypeError, match="latest"):
        gates.open_gates(ratings=RATINGS, disposition=_disposition(), verdicts=_verdicts(), draft_id="DR-v1")


def test_an_older_blocked_examination_opens_nothing_once_a_newer_one_is_the_latest_and_named():
    disposition = _disposition(ids={"secrets": "EX-SEC-v2"})
    verdicts = _verdicts(**{"EX-SEC-v1": "block", "EX-SEC-v2": "pass"})
    assert _open(disposition=disposition, verdicts=verdicts, latest=["EX-SEC-v2"]) == []


def test_the_arguments_are_not_changed():
    ratings, disposition, verdicts = _ratings(security_examiner="toy"), _disposition(), _verdicts()
    before = json.dumps([ratings, disposition, verdicts])
    _open(ratings=ratings, disposition=disposition, verdicts=verdicts)
    assert json.dumps([ratings, disposition, verdicts]) == before


def _run(tmp_path, status="pending_human", gate_names=("OPEN_CRITICAL_CHALLENGE",), report=REPORT):
    run_dir = tmp_path / CID
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text(report, encoding="utf-8")
    record = {
        "correlation_id": CID,
        "status": status,
        "gates": [{"gate": name, "subjects": ["EX-SEC-v1"]} for name in gate_names],
        "halt_reason": "NO_REPORT" if status == "halted" else None,
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    for name in ("disposition.json", "summary.json"):
        (run_dir / name).write_text("{}", encoding="utf-8")
    log = audit.AuditLog(CID, runs_dir=tmp_path, clock=lambda: NOW)
    log.append("run_started")
    log.append("run_finished", status=status, halt_reason=record["halt_reason"])
    return run_dir


def _decide(tmp_path, **overrides):
    arguments = {
        "decision": "continue",
        "reviewer": "Ana Díaz",
        "note": "Key rotated.",
        "runs_dir": tmp_path,
        "os_user": lambda: "ana",
        "clock": lambda: NOW,
    }
    return gates.decide(CID, **{**arguments, **overrides})


def _snapshot(run_dir):
    return {path.name: path.read_bytes() for path in run_dir.iterdir() if path.is_file()}


def _records(run_dir):
    return [json.loads(line) for line in (run_dir / "decisions.jsonl").read_text().splitlines()]


def _audit_lines(run_dir):
    return [json.loads(line) for line in (run_dir / "audit.jsonl").read_text().splitlines()]


def test_decide_appends_one_record_with_every_field(tmp_path):
    run_dir = _run(tmp_path, gate_names=("COORDINATOR_ESCALATION", "OPEN_CRITICAL_CHALLENGE"))
    expected = {
        "correlation_id": CID,
        "decision": "continue",
        "reviewer": "Ana Díaz",
        "os_user": "ana",
        "note": "Key rotated.",
        "decided_at": "2026-10-27T12:00:00.456Z",
        "gates_resolved": ["COORDINATOR_ESCALATION", "OPEN_CRITICAL_CHALLENGE"],
        "report_sha256": hashlib.sha256(REPORT.encode()).hexdigest(),
    }
    assert _decide(tmp_path) == expected
    assert _records(run_dir) == [expected]


def test_decide_without_a_note_records_null(tmp_path):
    run_dir = _run(tmp_path)
    assert _decide(tmp_path, note=None)["note"] is None
    assert _records(run_dir)[0]["note"] is None


def test_decide_keeps_unicode_and_surrogate_escaped_text_writable(tmp_path):
    run_dir = _run(tmp_path)
    _decide(tmp_path, reviewer="李明", note="caf\udce9 ✓")
    assert _records(run_dir)[0]["reviewer"] == "李明"
    assert _records(run_dir)[0]["note"] == "caf\udce9 ✓"


def test_decide_takes_the_os_user_from_the_password_database_not_the_environment(tmp_path, monkeypatch):
    _run(tmp_path)
    monkeypatch.setenv("USER", "someone-else")
    monkeypatch.setenv("LOGNAME", "someone-else")
    asked = []

    def account(uid):
        asked.append(uid)
        return SimpleNamespace(pw_name="db-account")

    monkeypatch.setattr(gates.pwd, "getpwuid", account)
    record = gates.decide(CID, decision="reject", reviewer="Ana", runs_dir=tmp_path, clock=lambda: NOW)
    assert (record["os_user"], asked) == ("db-account", [os.getuid()])


def test_decide_falls_back_to_the_environments_user_when_the_uid_has_no_account(tmp_path, monkeypatch):
    def no_account(uid):
        raise KeyError(uid)

    _run(tmp_path)
    monkeypatch.setattr(gates.pwd, "getpwuid", no_account)
    monkeypatch.setenv("LOGNAME", "container-user")
    record = gates.decide(CID, decision="reject", reviewer="Ana", runs_dir=tmp_path, clock=lambda: NOW)
    assert record["os_user"] == "container-user"


def test_decide_appends_one_decision_recorded_audit_line_and_nothing_else_changes(tmp_path):
    run_dir = _run(tmp_path)
    before = _snapshot(run_dir)
    earlier = _audit_lines(run_dir)
    record = _decide(tmp_path)
    after = _snapshot(run_dir)
    assert {name: data for name, data in after.items() if name not in ("audit.jsonl", "decisions.jsonl")} == {
        name: data for name, data in before.items() if name != "audit.jsonl"
    }
    assert after["audit.jsonl"].startswith(before["audit.jsonl"])
    lines = _audit_lines(run_dir)
    assert lines[: len(earlier)] == earlier
    assert len(lines) == len(earlier) + 1
    assert {key: lines[-1][key] for key in ("event", "seq", "ts", "decision", "reviewer", "gates_resolved")} == {
        "event": "decision_recorded",
        "seq": len(earlier) + 1,
        "ts": record["decided_at"],
        "decision": "continue",
        "reviewer": "Ana Díaz",
        "gates_resolved": ["OPEN_CRITICAL_CHALLENGE"],
    }
    assert lines[-1]["report_sha256"] == record["report_sha256"]
    assert "note" not in lines[-1]


def test_a_second_decision_is_refused_and_writes_nothing(tmp_path):
    run_dir = _run(tmp_path)
    _decide(tmp_path)
    before = _snapshot(run_dir)
    with pytest.raises(gates.DecisionRefused, match=rf"{CID} was already decided: continue by Ana Díaz"):
        _decide(tmp_path, decision="reject", reviewer="Bo")
    assert _snapshot(run_dir) == before


def test_an_unknown_run_is_refused_and_creates_nothing(tmp_path):
    with pytest.raises(gates.DecisionRefused, match=rf"no run {CID}"):
        _decide(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_run_directory_without_a_run_record_is_refused(tmp_path):
    (tmp_path / CID).mkdir()
    with pytest.raises(gates.DecisionRefused, match="no run.json"):
        _decide(tmp_path)
    assert list((tmp_path / CID).iterdir()) == []


@pytest.mark.parametrize(
    "content",
    [
        "",
        "{",
        "[]",
        '{"status": "unknown"}',
        '"pending_human"',
        '{"status": "pending_human"}',
        '{"status": "pending_human", "gates": "OPEN_CRITICAL_CHALLENGE"}',
        '{"status": "pending_human", "gates": [{"subjects": ["EX-SEC-v1"]}]}',
        '{"status": "pending_human", "gates": [{"gate": "NOT_A_GATE", "subjects": ["x"]}]}',
        '{"status": "pending_human", "gates": ["OPEN_CRITICAL_CHALLENGE"]}',
        pytest.param("[" * 1_000_000 + "]" * 1_000_000, id="nested-too-deeply"),
    ],
)
def test_an_unreadable_run_record_is_refused(tmp_path, content):
    run_dir = _run(tmp_path)
    (run_dir / "run.json").write_text(content)
    before = _snapshot(run_dir)
    with pytest.raises(gates.DecisionRefused, match="not a run record"):
        _decide(tmp_path)
    assert _snapshot(run_dir) == before


@pytest.mark.parametrize("status", ["finalized", "halted"])
def test_a_run_with_no_open_gate_is_refused(tmp_path, status):
    run_dir = _run(tmp_path, status=status, gate_names=())
    before = _snapshot(run_dir)
    with pytest.raises(gates.DecisionRefused, match=f"has no open gate, its status is {status}"):
        _decide(tmp_path)
    assert _snapshot(run_dir) == before


def test_a_finalized_run_is_refused_even_when_its_record_lists_a_gate(tmp_path):
    run_dir = _run(tmp_path, status="finalized", gate_names=("OPEN_CRITICAL_CHALLENGE",))
    before = _snapshot(run_dir)
    with pytest.raises(gates.DecisionRefused, match="has no open gate, its status is finalized"):
        _decide(tmp_path)
    assert _snapshot(run_dir) == before


def test_a_pending_run_that_lists_no_gate_is_refused(tmp_path):
    run_dir = _run(tmp_path, gate_names=())
    before = _snapshot(run_dir)
    with pytest.raises(gates.DecisionRefused, match="has no open gate, its status is pending_human"):
        _decide(tmp_path)
    assert _snapshot(run_dir) == before


def test_a_run_without_a_report_is_an_error_and_records_nothing(tmp_path):
    run_dir = _run(tmp_path)
    (run_dir / "report.md").unlink()
    with pytest.raises(FileNotFoundError):
        _decide(tmp_path)
    assert not (run_dir / "decisions.jsonl").exists()


@pytest.mark.parametrize("cid", ["../x", "", "20261027T101500Z-0A1B2C3D", f"{CID}/.."])
def test_a_malformed_correlation_id_is_refused_before_any_path_is_built(tmp_path, cid):
    with pytest.raises(ValueError, match="correlation ID"):
        gates.decide(cid, decision="continue", reviewer="Ana", runs_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("decision", ["maybe", "Continue", "", "finalized_by_human"])
def test_a_decision_outside_the_closed_set_is_refused(tmp_path, decision):
    run_dir = _run(tmp_path)
    before = _snapshot(run_dir)
    with pytest.raises(ValueError, match="decision"):
        _decide(tmp_path, decision=decision)
    assert _snapshot(run_dir) == before


def test_the_default_runs_dir_is_the_configured_one(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(tmp_path))
    run_dir = _run(tmp_path)
    gates.decide(CID, decision="reject", reviewer="Ana", os_user=lambda: "ana", clock=lambda: NOW)
    assert len(_records(run_dir)) == 1


def test_the_decision_is_flushed_and_both_it_and_its_audit_line_fsynced_under_an_exclusive_lock(tmp_path, monkeypatch):
    run_dir = _run(tmp_path)
    probes, written = [], []
    real_fsync = gates.os.fsync

    def probing_fsync(fd):
        written.append((run_dir / "decisions.jsonl").read_text().count("\n"))
        with open(run_dir / "decisions.jsonl", "a") as other:
            try:
                fcntl.flock(other, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                probes.append("held")
            else:
                probes.append("free")
        real_fsync(fd)

    monkeypatch.setattr(gates.os, "fsync", probing_fsync)
    _decide(tmp_path)
    assert probes == ["held", "held"]
    assert written == [1, 1]


def test_the_lock_is_released_after_a_refusal(tmp_path):
    run_dir = _run(tmp_path)
    _decide(tmp_path)
    with pytest.raises(gates.DecisionRefused):
        _decide(tmp_path)
    with open(run_dir / "decisions.jsonl", "a") as other:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_a_decision_waits_for_the_lock_and_refuses_when_another_was_recorded_meanwhile(tmp_path, monkeypatch):
    run_dir = _run(tmp_path)
    path = run_dir / "decisions.jsonl"
    other = {"correlation_id": CID, "decision": "reject", "reviewer": "Bo", "decided_at": "2026-10-27T11:00:00.000Z"}
    waiting, outcome, real_flock = threading.Event(), [], fcntl.flock

    def announcing_flock(file, operation):
        waiting.set()
        real_flock(file, operation)

    def attempt():
        try:
            _decide(tmp_path)
            outcome.append("recorded")
        except gates.DecisionRefused:
            outcome.append("refused")

    with open(path, "a") as held:
        real_flock(held, fcntl.LOCK_EX)
        monkeypatch.setattr(gates.fcntl, "flock", announcing_flock)
        thread = threading.Thread(target=attempt)
        thread.start()
        assert waiting.wait(timeout=30), "decide never asked for the lock"
        held.write(json.dumps(other) + "\n")
        held.flush()
    thread.join(timeout=30)
    assert outcome == ["refused"]
    assert path.read_text().splitlines() == [json.dumps(other)]


def test_two_decide_processes_at_once_record_exactly_one(tmp_path, deadline):
    run_dir = _run(tmp_path)
    script = (
        "import signal, sys\n"
        "from pathlib import Path\n"
        "from assessor import cli\n"
        "signal.alarm(120)\n"
        "decision, ready, go, cid = sys.argv[1:]\n"
        "Path(ready).touch()\n"
        "while not Path(go).exists():\n"
        "    pass\n"
        "sys.exit(cli.main(['decide', cid, '--decision', decision, '--reviewer', 'Ana']))\n"
    )
    env = {**os.environ, "ASSESSOR_RUNS_DIR": str(tmp_path)}
    go = tmp_path / "go"
    ready = [tmp_path / f"ready-{decision}" for decision in config.HUMAN_DECISIONS]
    processes = []
    try:
        for decision, marker in zip(config.HUMAN_DECISIONS, ready):
            command = [sys.executable, "-c", script, decision, str(marker), str(go), CID]
            processes.append(
                subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            )
        with deadline(120):
            while not all(marker.exists() for marker in ready):
                assert all(process.poll() is None for process in processes), "a decide process ended early"
        go.touch()
        codes = sorted(process.wait(timeout=120) for process in processes)
    finally:
        for process in processes:
            process.kill()
            process.wait()
    assert codes == [0, 1]
    assert len(_records(run_dir)) == 1
    assert [line["event"] for line in _audit_lines(run_dir)].count("decision_recorded") == 1


def test_a_failed_audit_append_after_the_record_leaves_the_run_decided(tmp_path, monkeypatch):
    run_dir = _run(tmp_path)
    real_append = audit.AuditLog.append

    def failing_append(self, event, /, **fields):
        if event == "decision_recorded":
            raise OSError(28, "No space left on device")
        return real_append(self, event, **fields)

    monkeypatch.setattr(audit.AuditLog, "append", failing_append)
    with pytest.raises(OSError, match="No space left"):
        _decide(tmp_path)
    assert len(_records(run_dir)) == 1
    monkeypatch.setattr(audit.AuditLog, "append", real_append)
    with pytest.raises(gates.DecisionRefused, match="already decided"):
        _decide(tmp_path)


def test_a_complete_record_that_lost_its_newline_is_still_a_decision(tmp_path):
    run_dir = _run(tmp_path)
    earlier = {"correlation_id": CID, "decision": "reject", "reviewer": "Bo", "decided_at": "2026-10-27T11:00:00.000Z"}
    (run_dir / "decisions.jsonl").write_text(json.dumps(earlier))
    with pytest.raises(gates.DecisionRefused, match="already decided: reject by Bo"):
        _decide(tmp_path)
    assert gates.effective_status(CID, runs_dir=tmp_path) == "rejected_by_human"


def test_two_decisions_at_once_record_exactly_one(tmp_path):
    run_dir = _run(tmp_path)
    barrier, outcomes = threading.Barrier(2), []

    def attempt(decision):
        barrier.wait()
        try:
            _decide(tmp_path, decision=decision)
            outcomes.append(("recorded", decision))
        except gates.DecisionRefused:
            outcomes.append(("refused", decision))
        except BaseException as error:
            outcomes.append((repr(error), decision))

    threads = [threading.Thread(target=attempt, args=(decision,)) for decision in config.HUMAN_DECISIONS]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(kind for kind, _ in outcomes) == ["recorded", "refused"]
    (winner,) = [decision for kind, decision in outcomes if kind == "recorded"]
    assert [record["decision"] for record in _records(run_dir)] == [winner]
    recorded = [line for line in _audit_lines(run_dir) if line["event"] == "decision_recorded"]
    assert [line["decision"] for line in recorded] == [winner]


@pytest.mark.parametrize("line", ["[1, 2]", '"text"', "3", "null"])
def test_a_line_that_is_not_a_json_object_is_not_a_decision(tmp_path, line):
    run_dir = _run(tmp_path)
    (run_dir / "decisions.jsonl").write_text(line + "\n")
    record = _decide(tmp_path)
    assert (run_dir / "decisions.jsonl").read_text().splitlines() == [line, json.dumps(record)]
    assert gates.effective_status(CID, runs_dir=tmp_path) == "finalized_by_human"


def test_a_torn_last_decision_line_is_not_a_decision_and_the_next_record_starts_a_new_line(tmp_path):
    run_dir = _run(tmp_path)
    (run_dir / "decisions.jsonl").write_text('{"correlation_id": "torn')
    record = _decide(tmp_path)
    lines = (run_dir / "decisions.jsonl").read_text().splitlines()
    assert (len(lines), json.loads(lines[1])) == (2, record)
    assert gates.effective_status(CID, runs_dir=tmp_path) == "finalized_by_human"


def _effective(tmp_path, status, *decisions):
    gate_names = ("COORDINATOR_ESCALATION",) if status == "pending_human" else ()
    run_dir = _run(tmp_path, status=status, gate_names=gate_names)
    if decisions:
        (run_dir / "decisions.jsonl").write_text("".join(json.dumps({"decision": value}) + "\n" for value in decisions))
    return gates.effective_status(CID, runs_dir=tmp_path)


@pytest.mark.parametrize(
    ("status", "decisions", "expected"),
    [
        ("pending_human", (), "pending_human"),
        ("pending_human", ("continue",), "finalized_by_human"),
        ("pending_human", ("reject",), "rejected_by_human"),
        ("pending_human", ("reject", "continue"), "rejected_by_human"),
        ("finalized", (), "finalized"),
        ("finalized", ("reject",), "finalized"),
        ("halted", (), "halted"),
        ("halted", ("continue",), "halted"),
    ],
)
def test_effective_status_is_the_runs_own_until_a_human_decides_a_pending_run(tmp_path, status, decisions, expected):
    assert _effective(tmp_path, status, *decisions) == expected


def test_effective_status_follows_the_decide_that_just_ran(tmp_path):
    _run(tmp_path)
    assert gates.effective_status(CID, runs_dir=tmp_path) == "pending_human"
    _decide(tmp_path, decision="reject")
    assert gates.effective_status(CID, runs_dir=tmp_path) == "rejected_by_human"


def test_effective_status_refuses_a_run_with_no_run_record(tmp_path):
    with pytest.raises(gates.DecisionRefused, match="has no run.json"):
        gates.effective_status(CID, runs_dir=tmp_path)


@pytest.mark.parametrize("content", [b"[]", b"{", b"\xff\xfe", b'{"status": "pending_human", "gates": [1]}'])
def test_effective_status_refuses_a_run_record_that_is_not_one(tmp_path, content):
    run_dir = _run(tmp_path)
    (run_dir / "run.json").write_bytes(content)
    with pytest.raises(gates.DecisionRefused, match="not a run record"):
        gates.effective_status(CID, runs_dir=tmp_path)


def test_a_run_record_with_undecodable_bytes_is_refused_by_decide(tmp_path):
    run_dir = _run(tmp_path)
    (run_dir / "run.json").write_bytes(b'{"status": "pending_human", "gates": [], "x": "\xff"}')
    with pytest.raises(gates.DecisionRefused, match="not a run record"):
        _decide(tmp_path)
    assert not (run_dir / "decisions.jsonl").exists()


def test_undecodable_bytes_in_decisions_make_a_line_that_is_not_a_decision(tmp_path):
    run_dir = _run(tmp_path)
    (run_dir / "decisions.jsonl").write_bytes(b'\xff{"decision": "reject"}\n')
    assert gates.effective_status(CID, runs_dir=tmp_path) == "pending_human"
    record = _decide(tmp_path)
    assert gates.effective_status(CID, runs_dir=tmp_path) == "finalized_by_human"
    assert (run_dir / "decisions.jsonl").read_bytes().endswith(json.dumps(record).encode() + b"\n")


def test_a_clock_that_fails_leaves_the_run_untouched(tmp_path):
    run_dir = _run(tmp_path)
    before = _snapshot(run_dir)
    with pytest.raises(ValueError, match="timezone-aware"):
        _decide(tmp_path, clock=lambda: datetime(2026, 1, 1))
    assert _snapshot(run_dir) == before


def test_a_user_lookup_that_fails_leaves_the_run_untouched(tmp_path):
    def no_user():
        raise OSError("no account")

    run_dir = _run(tmp_path)
    before = _snapshot(run_dir)
    with pytest.raises(OSError, match="no account"):
        _decide(tmp_path, os_user=no_user)
    assert _snapshot(run_dir) == before


def test_effective_status_refuses_a_malformed_correlation_id(tmp_path):
    with pytest.raises(ValueError, match="correlation ID"):
        gates.effective_status("../x", runs_dir=tmp_path)
