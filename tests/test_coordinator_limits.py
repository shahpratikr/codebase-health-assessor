import json
from datetime import UTC, datetime

import anthropic
import httpx2
import pytest
from anthropic.types.beta import BetaMessage

from assessor import audit, config, coordinator, manifest, sandbox

CID = "20261027T101500Z-0a1b2c3d"
NOW = datetime(2026, 10, 27, 10, 15, tzinfo=UTC)
MANIFESTS = manifest.load_manifests()
MAX_TURNS = MANIFESTS["coordinator"]["max_turns"]
REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
EXAMINE = {"step": "secrets", "challenge_ids": [], "note": ""}
UNKNOWN_TARGET = {"target_id": "EX-SEC-v9"}
EXAMINATION = {
    "workflow": "security_examiner",
    "step": "secrets",
    "summary": "No committed credentials.",
    "findings": [],
    "limitations": [],
    "challenge_responses": [],
}


def _message(content, stop_reason="end_turn"):
    return BetaMessage.model_validate(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-5",
            "content": content,
            "stop_reason": stop_reason,
            "usage": {
                "input_tokens": 100,
                "output_tokens": 20,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        }
    )


def _launch(agent, tool_input, number=1):
    return {"type": "tool_use", "id": f"toolu_{number}", "name": f"launch_{agent}", "input": tool_input}


def _turn(*blocks):
    return _message(list(blocks), "tool_use")


def _done():
    return _message([{"type": "text", "text": "Every step is reviewed and the report is drafted."}])


def _answer(output):
    return _message([{"type": "text", "text": json.dumps(output)}])


def _read(number):
    tool_input = {"path": "app.py", "start_line": 1}
    return {"type": "tool_use", "id": f"toolu_{number}", "name": "read_file", "input": tool_input}


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(CID, runs_dir=tmp_path, clock=lambda: NOW)


def _run(client, log, tmp_path, manifests=MANIFESTS):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text("DEBUG = False\n")
    return coordinator.run(
        client, log, manifests, workspace=sandbox.Workspace(repo), workspace_label="acme-api", osv=lambda query: {}
    )


def _lines(log, event):
    return [line for line in map(json.loads, log.path.read_text().splitlines()) if line["event"] == event]


def _refused_turns(count):
    return [_turn(_launch("adversarial_reviewer", UNKNOWN_TARGET, turn)) for turn in range(1, count + 1)]


def test_coordinator_halts_at_its_turn_cap_instead_of_calling_again(fake_anthropic, log, tmp_path):
    assert MAX_TURNS == 30
    client = fake_anthropic(_refused_turns(MAX_TURNS))
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, state.turns, len(client.requests)) == ("COORDINATOR_TURN_LIMIT", MAX_TURNS, MAX_TURNS)
    assert state.halt_reason in config.HALT_REASONS


def test_launch_blocks_of_the_last_allowed_turn_are_not_dispatched(fake_anthropic, log, tmp_path):
    client = fake_anthropic([*_refused_turns(MAX_TURNS - 1), _turn(_launch("security_examiner", EXAMINE))])
    state = _run(client, log, tmp_path)
    assert state.halt_reason == "COORDINATOR_TURN_LIMIT"
    assert len(client.requests) == MAX_TURNS
    assert (state.examinations, _lines(log, "dispatch_started")) == ({}, [])


def test_end_turn_on_the_last_allowed_turn_ends_the_run_without_a_halt(fake_anthropic, log, tmp_path):
    client = fake_anthropic([*_refused_turns(MAX_TURNS - 1), _done()])
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, state.turns, len(client.requests)) == (None, MAX_TURNS, MAX_TURNS)


def test_turn_cap_comes_from_the_coordinator_manifest(fake_anthropic, log, tmp_path):
    capped = {**MANIFESTS, "coordinator": {**MANIFESTS["coordinator"], "max_turns": 2}}
    client = fake_anthropic(_refused_turns(2))
    state = _run(client, log, tmp_path, capped)
    assert (state.halt_reason, len(client.requests)) == ("COORDINATOR_TURN_LIMIT", 2)


@pytest.mark.parametrize(
    ("stop_reason", "reason"),
    [
        ("refusal", "COORDINATOR_REFUSAL"),
        ("max_tokens", "COORDINATOR_MAX_TOKENS"),
        ("model_context_window_exceeded", "COORDINATOR_MAX_TOKENS"),
        ("pause_turn", "COORDINATOR_API_ERROR"),
    ],
)
def test_coordinator_call_that_stops_without_a_usable_answer_halts_the_run(
    fake_anthropic, log, tmp_path, stop_reason, reason
):
    client = fake_anthropic([_message([{"type": "text", "text": "I will dispatch"}], stop_reason)])
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, len(client.requests)) == (reason, 1)
    assert state.halt_reason in config.HALT_REASONS


@pytest.mark.parametrize(
    "error",
    [
        anthropic.APIConnectionError(request=REQUEST),
        anthropic.InternalServerError("overloaded", response=httpx2.Response(529, request=REQUEST), body=None),
        anthropic.BadRequestError("bad", response=httpx2.Response(400, request=REQUEST), body=None),
    ],
)
def test_coordinator_call_that_raises_an_sdk_error_halts_with_api_error(fake_anthropic, log, tmp_path, error):
    client = fake_anthropic([error])
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, len(client.requests)) == ("COORDINATOR_API_ERROR", 1)
    assert state.halt_reason in config.HALT_REASONS
    assert _lines(log, "llm_call")[0]["error"] == type(error).__name__


def test_coordinator_failure_after_a_dispatch_halts_without_dispatching_again(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [_turn(_launch("security_examiner", EXAMINE)), _answer(EXAMINATION), _message([], "refusal")]
    )
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, len(client.requests)) == ("COORDINATOR_REFUSAL", 3)
    assert list(state.examinations) == ["EX-SEC-v1"]


def test_tool_use_stop_without_a_launch_block_halts_with_api_error(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_message([{"type": "text", "text": "Dispatching now."}], "tool_use")])
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, len(client.requests)) == ("COORDINATOR_API_ERROR", 1)


def test_tool_use_stop_without_a_launch_block_on_the_last_turn_halts_with_api_error(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [*_refused_turns(MAX_TURNS - 1), _message([{"type": "text", "text": "Dispatching now."}], "tool_use")]
    )
    state = _run(client, log, tmp_path)
    assert (state.halt_reason, state.turns, len(client.requests)) == ("COORDINATOR_API_ERROR", MAX_TURNS, MAX_TURNS)


@pytest.mark.parametrize(
    ("subagent", "code"),
    [
        ([_message([], "refusal")], "REFUSAL"),
        ([_message([{"type": "text", "text": "{"}], "max_tokens")], "MAX_TOKENS"),
        ([anthropic.APIConnectionError(request=REQUEST)], "API_ERROR"),
        ([_message([_read(number) for number in range(1, 14)], "tool_use")], "TOOL_LOOP_LIMIT"),
    ],
)
def test_subagent_failure_reaches_the_coordinator_as_its_dispatch_error_without_a_halt(
    fake_anthropic, log, tmp_path, subagent, code
):
    client = fake_anthropic([_turn(_launch("security_examiner", EXAMINE)), *subagent, _done()])
    state = _run(client, log, tmp_path)
    (result,) = client.requests[-1]["messages"][-1]["content"]
    error = json.loads(result["content"])["error"]
    assert (result["is_error"], error["code"], error["retryable"]) == (
        True,
        code,
        code in config.RETRYABLE_DISPATCH_ERRORS,
    )
    assert (state.halt_reason, state.examinations, len(client.requests)) == (None, {}, 3)
