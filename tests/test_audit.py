import builtins
import json
import os
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType

import jsonschema
import pytest

from assessor import audit, config

CID = "20261027T101500Z-0a1b2c3d"
NOW = datetime(2026, 10, 27, 10, 15, 0, 123456, tzinfo=UTC)
SCHEMA = json.loads((config.SCHEMAS_DIR / "audit_event.schema.json").read_text())

LLM_CALL = {
    "parent_step_id": None,
    "agent": "coordinator",
    "workflow": None,
    "step": None,
    "requested_model": "claude-sonnet-5-5",
    "served_model": "claude-sonnet-5-5",
    "fallback_ran": False,
    "effort": "medium",
    "input_tokens": 10,
    "output_tokens": 5,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "cost_usd": 0.00007,
    "pricing_missing": False,
    "stop_reason": "end_turn",
    "latency_ms": 250,
    "error": None,
}
TOOL_CALL = {
    "parent_step_id": f"{CID}:3",
    "agent": "security_examiner",
    "workflow": "security_examiner",
    "step": "secrets",
    "tool": "read_file",
    "allowed": True,
    "is_error": False,
}
GUARDRAIL_REJECTED = {
    "parent_step_id": f"{CID}:3",
    "agent": "security_examiner",
    "workflow": "security_examiner",
    "step": "secrets",
    "code": "SCHEMA_INVALID",
    "problems": 2,
}
DISPATCH_STARTED = {"agent": "security_examiner", "workflow": "security_examiner", "step": "secrets", "target_id": None}
DISPATCH_FINISHED = {
    "parent_step_id": f"{CID}:3",
    "agent": "security_examiner",
    "workflow": "security_examiner",
    "step": "secrets",
    "output_id": "EX-SEC-v1",
    "code": None,
}
GATE_OPENED = {"gate": "OPEN_CRITICAL_CHALLENGE", "subjects": ["EX-SEC-v1", "DR-v2"]}
RUN_FINISHED = {"status": "finalized", "halt_reason": None}
DECISION_RECORDED = {
    "decision": "continue",
    "reviewer": "Ana Díaz",
    "gates_resolved": ["COORDINATOR_ESCALATION"],
    "report_sha256": "0" * 64,
}
PAYLOADS = {
    "llm_call": LLM_CALL,
    "tool_call": TOOL_CALL,
    "guardrail_rejected": GUARDRAIL_REJECTED,
    "dispatch_started": DISPATCH_STARTED,
    "dispatch_finished": DISPATCH_FINISHED,
    "gate_opened": GATE_OPENED,
    "run_finished": RUN_FINISHED,
    "decision_recorded": DECISION_RECORDED,
}


def _log(tmp_path, clock=lambda: NOW):
    return audit.AuditLog(CID, runs_dir=tmp_path, clock=clock)


def _lines(tmp_path):
    return [json.loads(line) for line in (tmp_path / CID / "audit.jsonl").read_text().splitlines()]


def test_log_lives_at_runs_cid_audit_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(tmp_path))
    log = audit.AuditLog(CID, clock=lambda: NOW)
    log.append("run_started")
    assert log.path == tmp_path / CID / "audit.jsonl"
    assert [line["event"] for line in _lines(tmp_path)] == ["run_started"]


def test_append_writes_envelope_and_fields_and_returns_the_record(tmp_path):
    record = _log(tmp_path).append("llm_call", **LLM_CALL)
    assert record == {
        "correlation_id": CID,
        "seq": 1,
        "step_id": f"{CID}:1",
        "ts": "2026-10-27T10:15:00.123Z",
        "event": "llm_call",
        **LLM_CALL,
    }
    assert _lines(tmp_path) == [record]
    assert list(_lines(tmp_path)[0])[:5] == ["correlation_id", "seq", "step_id", "ts", "event"]


def test_seq_and_step_id_increase_per_line(tmp_path):
    log = _log(tmp_path)
    for event in ("run_started", "dispatch_started", "llm_call"):
        log.append(event, **PAYLOADS.get(event, {}))
    assert [(line["seq"], line["step_id"]) for line in _lines(tmp_path)] == [
        (1, f"{CID}:1"),
        (2, f"{CID}:2"),
        (3, f"{CID}:3"),
    ]


def test_reopened_log_appends_after_existing_lines(tmp_path):
    _log(tmp_path).append("run_started")
    _log(tmp_path).append("run_finished", **RUN_FINISHED)
    lines = _lines(tmp_path)
    assert [(line["seq"], line["event"]) for line in lines] == [(1, "run_started"), (2, "run_finished")]


def test_each_line_is_flushed_then_fsynced(tmp_path, monkeypatch):
    seen = []
    real_fsync = os.fsync

    def recording_fsync(fd):
        seen.append((tmp_path / CID / "audit.jsonl").read_text().count("\n"))
        real_fsync(fd)

    monkeypatch.setattr(audit.os, "fsync", recording_fsync)
    log = _log(tmp_path)
    log.append("run_started")
    log.append("run_finished", **RUN_FINISHED)
    assert seen == [1, 2]


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (NOW, "2026-10-27T10:15:00.123Z"),
        (
            datetime(2026, 10, 27, 15, 45, 0, 999999, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            "2026-10-27T10:15:00.999Z",
        ),
        (datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "2026-01-02T03:04:05.000Z"),
    ],
)
def test_timestamps_are_utc_iso8601(tmp_path, moment, expected):
    assert _log(tmp_path, clock=lambda: moment).append("run_started")["ts"] == expected


def test_naive_clock_is_refused(tmp_path):
    with pytest.raises(ValueError, match="timezone-aware"):
        _log(tmp_path, clock=lambda: datetime(2026, 10, 27, 10, 15)).append("run_started")
    assert not (tmp_path / CID).exists()


def test_default_clock_is_utc():
    assert audit.utc_now().utcoffset() == timedelta(0)


@pytest.mark.parametrize("event", config.AUDIT_EVENTS)
def test_every_audit_event_is_accepted(tmp_path, event):
    assert _log(tmp_path).append(event, **PAYLOADS.get(event, {}))["event"] == event


@pytest.mark.parametrize(
    ("event", "fields"),
    [
        ("llm_response", {}),
        ("LLM_CALL", LLM_CALL),
        ("llm_call", {**LLM_CALL, "messages": [{"role": "user", "content": "secret"}]}),
        ("llm_call", {**LLM_CALL, "system": "prompt"}),
        ("llm_call", {key: value for key, value in LLM_CALL.items() if key != "latency_ms"}),
        ("llm_call", {**LLM_CALL, "cost_usd": None}),
        ("llm_call", {**LLM_CALL, "pricing_missing": True}),
        ("llm_call", {**LLM_CALL, "cost_usd": -0.1}),
        ("llm_call", {**LLM_CALL, "input_tokens": -1}),
        ("llm_call", {**LLM_CALL, "input_tokens": 1.5}),
        ("llm_call", {**LLM_CALL, "fallback_ran": "no"}),
        ("llm_call", {**LLM_CALL, "parent_step_id": "../x"}),
        ("llm_call", {**LLM_CALL, "agent": ""}),
    ],
)
def test_schema_invalid_event_is_rejected_and_nothing_written(tmp_path, event, fields):
    log = _log(tmp_path)
    with pytest.raises(jsonschema.ValidationError):
        log.append(event, **fields)
    assert not (tmp_path / CID / "audit.jsonl").exists()
    assert log.append("run_started")["seq"] == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_json_number_is_rejected_and_nothing_written(tmp_path, value):
    log = _log(tmp_path)
    with pytest.raises(ValueError):
        log.append("llm_call", **{**LLM_CALL, "cost_usd": value})
    assert not (tmp_path / CID / "audit.jsonl").exists()
    assert log.append("run_started")["seq"] == 1


@pytest.mark.parametrize("event", [event for event in config.AUDIT_EVENTS if event not in PAYLOADS])
@pytest.mark.parametrize("field", ["content", "messages", "system", "headers", "allowed"])
def test_events_without_a_defined_payload_refuse_any_field(tmp_path, event, field):
    with pytest.raises(jsonschema.ValidationError):
        _log(tmp_path).append(event, **{field: "x"})
    assert not (tmp_path / CID).exists()


@pytest.mark.parametrize(
    "fields",
    [
        {**TOOL_CALL, "tool": None, "allowed": False, "is_error": True},
        {**TOOL_CALL, "workflow": None, "step": None, "parent_step_id": None},
        {**TOOL_CALL, "allowed": False, "is_error": True},
        {**TOOL_CALL, "is_error": True},
    ],
)
def test_tool_call_payload_is_accepted(tmp_path, fields):
    assert _log(tmp_path).append("tool_call", **fields)["tool"] == fields["tool"]


@pytest.mark.parametrize(
    "fields",
    [
        {**TOOL_CALL, "tool": "bash"},
        {**TOOL_CALL, "tool": "launch_security_examiner"},
        {**TOOL_CALL, "allowed": False, "is_error": False},
        {**TOOL_CALL, "tool": None},
        {**TOOL_CALL, "allowed": "no"},
        {**TOOL_CALL, "agent": "Security Examiner"},
        {**TOOL_CALL, "parent_step_id": "../x"},
        {**TOOL_CALL, "input": {"path": "config.py"}},
        {**TOOL_CALL, "content": "AKIAIOSFODNN7EXAMPLE"},
        {key: value for key, value in TOOL_CALL.items() if key != "is_error"},
    ],
)
def test_tool_call_payload_refuses_bad_or_extra_fields(tmp_path, fields):
    with pytest.raises(jsonschema.ValidationError):
        _log(tmp_path).append("tool_call", **fields)
    assert not (tmp_path / CID).exists()


@pytest.mark.parametrize("code", config.DISPATCH_ERROR_CODES)
def test_guardrail_rejected_accepts_every_dispatch_error_code(tmp_path, code):
    assert _log(tmp_path).append("guardrail_rejected", **{**GUARDRAIL_REJECTED, "code": code})["code"] == code


@pytest.mark.parametrize(
    "fields",
    [
        {**GUARDRAIL_REJECTED, "code": "NOT_A_CODE"},
        {**GUARDRAIL_REJECTED, "problems": -1},
        {**GUARDRAIL_REJECTED, "problems": 1.5},
        {**GUARDRAIL_REJECTED, "details": ["findings/0/line: 99"]},
        {**GUARDRAIL_REJECTED, "message": "examination does not match"},
        {key: value for key, value in GUARDRAIL_REJECTED.items() if key != "code"},
    ],
)
def test_guardrail_rejected_payload_refuses_bad_or_extra_fields(tmp_path, fields):
    with pytest.raises(jsonschema.ValidationError):
        _log(tmp_path).append("guardrail_rejected", **fields)
    assert not (tmp_path / CID).exists()


@pytest.mark.parametrize(
    "fields",
    [
        {**DISPATCH_STARTED, "agent": "adversarial_reviewer", "target_id": "EX-SEC-v1"},
        {**DISPATCH_STARTED, "agent": "adversarial_reviewer", "target_id": "DR-v12"},
        {**DISPATCH_STARTED, "agent": "final_review_writer", "workflow": "final_review_writer", "step": None},
    ],
)
def test_dispatch_started_payload_is_accepted(tmp_path, fields):
    assert _log(tmp_path).append("dispatch_started", **fields)["agent"] == fields["agent"]


@pytest.mark.parametrize(
    "fields",
    [
        {**DISPATCH_STARTED, "target_id": "RV-1"},
        {**DISPATCH_STARTED, "target_id": "EX-SEC-v0"},
        {**DISPATCH_STARTED, "target_id": "ex-sec-v1"},
        {**DISPATCH_STARTED, "target_id": "../x"},
        {**DISPATCH_STARTED, "agent": "Security Examiner"},
        {**DISPATCH_STARTED, "parent_step_id": None},
        {**DISPATCH_STARTED, "task": {"note": "Re-check."}},
        {key: value for key, value in DISPATCH_STARTED.items() if key != "target_id"},
    ],
)
def test_dispatch_started_payload_refuses_bad_or_extra_fields(tmp_path, fields):
    with pytest.raises(jsonschema.ValidationError):
        _log(tmp_path).append("dispatch_started", **fields)
    assert not (tmp_path / CID).exists()


@pytest.mark.parametrize(
    "fields",
    [
        {**DISPATCH_FINISHED, "output_id": "RV-12"},
        {**DISPATCH_FINISHED, "output_id": "DR-v3", "workflow": "final_review_writer", "step": None},
        {**DISPATCH_FINISHED, "output_id": None, "code": "SCHEMA_INVALID"},
    ],
)
def test_dispatch_finished_payload_is_accepted(tmp_path, fields):
    assert _log(tmp_path).append("dispatch_finished", **fields)["output_id"] == fields["output_id"]


@pytest.mark.parametrize(
    "fields",
    [
        {**DISPATCH_FINISHED, "output_id": None},
        {**DISPATCH_FINISHED, "code": "API_ERROR"},
        {**DISPATCH_FINISHED, "output_id": None, "code": "NOT_A_CODE"},
        {**DISPATCH_FINISHED, "output_id": "EX-SEC-v0"},
        {**DISPATCH_FINISHED, "output_id": "RV-1-C1"},
        {**DISPATCH_FINISHED, "parent_step_id": None},
        {**DISPATCH_FINISHED, "content": "AKIAIOSFODNN7EXAMPLE"},
        {key: value for key, value in DISPATCH_FINISHED.items() if key != "code"},
    ],
)
def test_dispatch_finished_payload_refuses_bad_or_extra_fields(tmp_path, fields):
    with pytest.raises(jsonschema.ValidationError):
        _log(tmp_path).append("dispatch_finished", **fields)
    assert not (tmp_path / CID).exists()


def test_payload_enums_match_config():
    definitions = SCHEMA["$defs"]
    assert definitions["tool_call"]["properties"]["tool"]["enum"] == [*config.SUBAGENT_TOOLS, None]
    assert definitions["guardrail_rejected"]["properties"]["code"]["enum"] == list(config.DISPATCH_ERROR_CODES)
    assert definitions["dispatch_finished"]["properties"]["code"]["enum"] == [*config.DISPATCH_ERROR_CODES, None]


def test_check_validates_without_writing(tmp_path):
    log = _log(tmp_path)
    assert log.check("llm_call", **LLM_CALL)["seq"] == 1
    with pytest.raises(jsonschema.ValidationError):
        log.check("llm_call", **{**LLM_CALL, "agent": ""})
    assert not (tmp_path / CID).exists()
    assert log.append("run_started")["seq"] == 1


def test_failed_fsync_never_reuses_a_seq(tmp_path, monkeypatch):
    real_fsync = os.fsync
    calls = []

    def failing_once(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(5, "I/O error")
        real_fsync(fd)

    monkeypatch.setattr(audit.os, "fsync", failing_once)
    log = _log(tmp_path)
    with pytest.raises(OSError):
        log.append("run_started")
    log.append("run_finished", **RUN_FINISHED)
    assert [(line["seq"], line["event"]) for line in _lines(tmp_path)] == [(1, "run_started"), (2, "run_finished")]


def test_partial_write_leaves_the_next_line_whole(tmp_path, monkeypatch):
    class TornFile:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.file.close()

        def write(self, text):
            self.file.write(text[: len(text) // 2])
            self.file.flush()
            raise OSError(28, "No space left on device")

    def open_tearing_once(path, mode="r", **kwargs):
        file = builtins.open(path, mode, **kwargs)
        if mode == "a" and not torn:
            torn.append(path)
            return TornFile(file)
        return file

    torn = []
    log = _log(tmp_path)
    log.append("run_started")
    monkeypatch.setattr(audit, "open", open_tearing_once, raising=False)
    with pytest.raises(OSError, match="No space left"):
        log.append("dispatch_started", **DISPATCH_STARTED)
    log.append("run_finished", **RUN_FINISHED)
    raw = (tmp_path / CID / "audit.jsonl").read_text().splitlines()
    assert len(raw) == 3
    assert [json.loads(raw[0])["seq"], json.loads(raw[2])["seq"]] == [1, 3]
    assert json.loads(raw[2])["event"] == "run_finished"


def test_reopened_log_starts_a_new_line_after_a_torn_one(tmp_path):
    _log(tmp_path).append("run_started")
    with open(tmp_path / CID / "audit.jsonl", "a") as log:
        log.write('{"correlation_id": "torn')
    log = _log(tmp_path)
    records = [log.append("decision_recorded", **DECISION_RECORDED), log.append("run_finished", **RUN_FINISHED)]
    raw = (tmp_path / CID / "audit.jsonl").read_text().splitlines()
    assert ([record["seq"] for record in records], len(raw)) == ([3, 4], 4)
    assert [json.loads(line) for line in raw[2:]] == records


def test_existing_empty_log_starts_at_its_first_line(tmp_path):
    (tmp_path / CID).mkdir()
    (tmp_path / CID / "audit.jsonl").write_text("")
    record = _log(tmp_path).append("run_started")
    assert (tmp_path / CID / "audit.jsonl").read_text().splitlines() == [json.dumps(record)]


def test_failed_open_raises_the_original_error_and_keeps_the_seq(tmp_path):
    log = _log(tmp_path)
    (tmp_path / CID).write_text("not a directory")
    with pytest.raises(FileExistsError):
        log.append("run_started")
    (tmp_path / CID).unlink()
    assert log.append("run_started")["seq"] == 1


def test_audit_log_prices_with_the_shipped_pricing_by_default(tmp_path):
    assert _log(tmp_path).pricing == config.load_pricing()


@pytest.mark.parametrize("pricing", [{}, {"m": {"input": 1}}])
def test_audit_log_refuses_malformed_pricing(tmp_path, pricing):
    with pytest.raises(ValueError, match="pricing"):
        audit.AuditLog(CID, runs_dir=tmp_path, pricing=pricing)


def test_audit_log_keeps_its_own_copy_of_any_pricing_mapping(tmp_path):
    prices = {"input": 1, "output": 2, "cache_write": 3, "cache_read": 4}
    inner = dict(prices)
    pricing = {"m": MappingProxyType(inner)}
    log = audit.AuditLog(CID, runs_dir=tmp_path, pricing=MappingProxyType(pricing))
    inner["input"] = 100
    pricing["n"] = {}
    assert log.pricing == {"m": prices}


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("m", {"cost_usd": 0.000013, "pricing_missing": False}),
        ("unpriced", {"cost_usd": None, "pricing_missing": True}),
    ],
)
def test_cost_prices_by_model_or_flags_it_unpriced(tmp_path, model, expected):
    log = audit.AuditLog(
        CID, runs_dir=tmp_path, pricing={"m": {"input": 1, "output": 2, "cache_write": 3, "cache_read": 4}}
    )
    tokens = {"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 2, "cache_read_input_tokens": 1}
    assert log.cost(model, tokens) == expected


def test_unpriced_llm_call_has_null_cost_and_flag(tmp_path):
    record = _log(tmp_path).append("llm_call", **{**LLM_CALL, "cost_usd": None, "pricing_missing": True})
    assert (record["cost_usd"], record["pricing_missing"]) == (None, True)


@pytest.mark.parametrize("field", ["correlation_id", "seq", "step_id", "ts", "event"])
def test_fields_cannot_override_the_envelope(tmp_path, field):
    with pytest.raises(ValueError, match=field):
        _log(tmp_path).append("run_started", **{field: "x"})
    assert not (tmp_path / CID).exists()


@pytest.mark.parametrize("cid", ["", "../x", f"{CID}/..", f"{CID}\n", CID.upper()])
def test_malformed_correlation_id_is_refused(tmp_path, cid):
    with pytest.raises(ValueError, match="correlation ID"):
        audit.AuditLog(cid, runs_dir=tmp_path)


def test_new_correlation_id_has_the_run_shape():
    first, second = audit.new_correlation_id(NOW), audit.new_correlation_id(NOW)
    assert config.CORRELATION_ID.fullmatch(first)
    assert first.startswith("20261027T101500Z-")
    assert first != second


def test_new_correlation_id_uses_utc():
    ist = datetime(2026, 10, 27, 15, 45, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert audit.new_correlation_id(ist).startswith("20261027T101500Z-")
    assert config.CORRELATION_ID.fullmatch(audit.new_correlation_id())
    with pytest.raises(ValueError, match="timezone-aware"):
        audit.new_correlation_id(datetime(2026, 10, 27))


def test_schema_patterns_and_events_match_config():
    envelope = SCHEMA["properties"]
    assert envelope["correlation_id"]["pattern"] == f"^{config.CORRELATION_ID.pattern}$"
    assert envelope["step_id"]["pattern"] == f"^{config.CORRELATION_ID.pattern}:[1-9][0-9]*$"
    assert envelope["event"]["enum"] == list(config.AUDIT_EVENTS)


def test_llm_call_accepts_a_parent_step_id_of_the_same_shape(tmp_path):
    record = _log(tmp_path).append("llm_call", **{**LLM_CALL, "parent_step_id": f"{CID}:12"})
    assert record["parent_step_id"] == f"{CID}:12"


@pytest.mark.parametrize(
    ("event", "fields"),
    [
        ("gate_opened", {**GATE_OPENED, "gate": "NOT_A_GATE"}),
        ("gate_opened", {**GATE_OPENED, "subjects": []}),
        ("gate_opened", {**GATE_OPENED, "subjects": ["has a space"]}),
        ("gate_opened", {**GATE_OPENED, "subjects": ["x" * 65]}),
        ("gate_opened", {"gate": "OPEN_CRITICAL_CHALLENGE"}),
        ("run_finished", {"status": "halted", "halt_reason": None}),
        ("run_finished", {"status": "finalized", "halt_reason": "NO_REPORT"}),
        ("run_finished", {"status": "pending_human", "halt_reason": "NO_REPORT"}),
        ("run_finished", {"status": "halted", "halt_reason": "SOMETHING_ELSE"}),
        ("run_finished", {"status": "done", "halt_reason": None}),
        ("run_finished", {"status": "halted"}),
        ("decision_recorded", {**DECISION_RECORDED, "decision": "maybe"}),
        ("decision_recorded", {**DECISION_RECORDED, "reviewer": ""}),
        ("decision_recorded", {**DECISION_RECORDED, "gates_resolved": []}),
        ("decision_recorded", {**DECISION_RECORDED, "gates_resolved": ["NOT_A_GATE"]}),
        ("decision_recorded", {**DECISION_RECORDED, "report_sha256": "ABC"}),
        ("decision_recorded", {**DECISION_RECORDED, "note": "free text never reaches the audit"}),
    ],
)
def test_run_end_payload_violations_are_rejected_and_nothing_written(tmp_path, event, fields):
    log = _log(tmp_path)
    with pytest.raises(jsonschema.ValidationError):
        log.append(event, **fields)
    assert not (tmp_path / CID / "audit.jsonl").exists()


@pytest.mark.parametrize("halt_reason", config.HALT_REASONS)
def test_run_finished_accepts_every_halt_reason_with_a_halted_status(tmp_path, halt_reason):
    record = _log(tmp_path).append("run_finished", status="halted", halt_reason=halt_reason)
    assert (record["status"], record["halt_reason"]) == ("halted", halt_reason)


@pytest.mark.parametrize("status", [status for status in config.RUN_STATUSES if status != "halted"])
def test_run_finished_accepts_a_null_halt_reason_with_any_other_status(tmp_path, status):
    assert _log(tmp_path).append("run_finished", status=status, halt_reason=None)["status"] == status


def test_run_end_payload_enums_match_config():
    defs = SCHEMA["$defs"]
    assert defs["gate_opened"]["properties"]["gate"]["enum"] == list(config.GATES)
    assert defs["run_finished"]["properties"]["status"]["enum"] == list(config.RUN_STATUSES)
    assert defs["run_finished"]["properties"]["halt_reason"]["enum"] == [*config.HALT_REASONS, None]
    assert defs["decision_recorded"]["properties"]["decision"]["enum"] == list(config.HUMAN_DECISIONS)
    assert defs["decision_recorded"]["properties"]["gates_resolved"]["items"]["enum"] == list(config.GATES)


def test_timestamp_is_utc_with_milliseconds():
    ist = datetime(2026, 10, 27, 15, 45, 1, 999999, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert audit.timestamp(NOW) == "2026-10-27T10:15:00.123Z"
    assert audit.timestamp(ist) == "2026-10-27T10:15:01.999Z"


def test_naive_timestamp_is_refused():
    with pytest.raises(ValueError, match="timezone-aware"):
        audit.timestamp(datetime(2026, 10, 27))


def _call(agent, **fields):
    return {**LLM_CALL, "agent": agent, **fields}


def _totals(**fields):
    return {
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "cost_usd": 0.0,
        "unpriced_calls": 0,
        **fields,
    }


def test_summary_totals_each_agent_and_all_calls(tmp_path):
    log = _log(tmp_path)
    log.append("run_started")
    log.append("llm_call", **_call("coordinator", cost_usd=0.1))
    log.append("llm_call", **_call("security_examiner", input_tokens=100, output_tokens=20, cost_usd=0.2))
    log.append(
        "llm_call",
        **_call("coordinator", input_tokens=7, cache_creation_input_tokens=3, cache_read_input_tokens=4, cost_usd=0.3),
    )
    log.append("dispatch_started", **DISPATCH_STARTED)
    assert log.summary() == {
        "correlation_id": CID,
        "agents": {
            "coordinator": _totals(
                llm_calls=2,
                input_tokens=17,
                output_tokens=10,
                cache_creation_input_tokens=3,
                cache_read_input_tokens=4,
                cost_usd=0.4,
            ),
            "security_examiner": _totals(llm_calls=1, input_tokens=100, output_tokens=20, cost_usd=0.2),
        },
        "total": _totals(
            llm_calls=3,
            input_tokens=117,
            output_tokens=30,
            cache_creation_input_tokens=3,
            cache_read_input_tokens=4,
            cost_usd=0.6,
        ),
    }
    assert list(log.summary()["agents"]) == ["coordinator", "security_examiner"]


def test_summary_counts_an_unpriced_call_without_adding_cost(tmp_path):
    log = _log(tmp_path)
    log.append("llm_call", **_call("coordinator", cost_usd=0.5))
    log.append("llm_call", **_call("coordinator", served_model="claude-unknown-1", cost_usd=None, pricing_missing=True))
    assert log.summary()["agents"]["coordinator"] == _totals(
        llm_calls=2, input_tokens=20, output_tokens=10, cost_usd=0.5, unpriced_calls=1
    )


def test_summary_counts_a_failed_call_as_a_call(tmp_path):
    log = _log(tmp_path)
    log.append(
        "llm_call",
        **_call(
            "coordinator",
            served_model=None,
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            stop_reason=None,
            error="APIConnectionError",
        ),
    )
    assert log.summary()["total"] == _totals(llm_calls=1)


def test_summary_of_a_log_without_lines_is_all_zero(tmp_path):
    assert _log(tmp_path).summary() == {"correlation_id": CID, "agents": {}, "total": _totals()}


def test_summary_skips_torn_and_invalid_lines_and_reads_only(tmp_path):
    log = _log(tmp_path)
    log.append("llm_call", **_call("coordinator", cost_usd=0.1))
    path = tmp_path / CID / "audit.jsonl"
    with open(path, "ab") as raw:
        raw.write(b'{"event": "llm_call"}\n[1, 2]\nnot json\n')
        raw.write(b"[" * 1_000_000 + b"]" * 1_000_000 + b'\n{"correlation_id": "torn \xe2\x82')
    before = path.read_bytes()
    assert log.summary()["total"] == _totals(llm_calls=1, input_tokens=10, output_tokens=5, cost_usd=0.1)
    assert path.read_bytes() == before
