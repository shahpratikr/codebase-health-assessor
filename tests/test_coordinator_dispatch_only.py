import json
from datetime import UTC, datetime

import pytest
from anthropic.types.beta import BetaMessage

from assessor import audit, config, coordinator, manifest, sandbox

CID = "20261027T101500Z-0a1b2c3d"
NOW = datetime(2026, 10, 27, 10, 15, tzinfo=UTC)
MANIFESTS = manifest.load_manifests()
LAUNCH_TOOLS = [
    "launch_security_examiner",
    "launch_dependency_examiner",
    "launch_adversarial_reviewer",
    "launch_final_review_writer",
]
DISPOSITION_SCHEMA = json.loads((config.SCHEMAS_DIR / "disposition.schema.json").read_text(encoding="utf-8"))
STRUCTURED_KEYWORDS = {"type", "properties", "required", "enum", "items", "additionalProperties"}
IDS = {"type": "array", "items": {"type": "string"}}
EXAMINE = {"step": "secrets", "challenge_ids": [], "note": ""}
EXAMINATION = {
    "workflow": "security_examiner",
    "step": "secrets",
    "summary": "No committed credentials.",
    "findings": [],
    "limitations": [],
    "challenge_responses": [],
}
REVIEW = {"target_id": "EX-SEC-v1", "verdict": "pass", "summary": "Checked app.py.", "challenges": []}
STATEMENTS = (
    "You never examine the repository, review an output or write the report yourself.",
    "They run one after another, in the order you give, and all their results come back together.",
    "Such an error comes back on every resend, whatever `retryable` says, until you fix the launch or first do what it "
    "is waiting for",
    "For an error in an agent's work, `retryable` true means the same launch can succeed if sent again, and false "
    "means it will not.",
    "Never accept an examination whose latest review blocks it",
    "When its challenges hold, whether the verdict is `challenge` or `block`, launch the writer again with their IDs",
    "once the latest draft has a review and either needs no new draft or the writer cannot be dispatched again",
    "When a draft can no longer be reviewed, launch the writer again for a new one.",
    "The writer needs, for every step, an examination that has a review: escalating a step does not remove that "
    "need.",
    "A launch past that returns `RETRY_CAP_REACHED` and will not run: do not send it again.",
)


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


def _prompt():
    return (config.ROOT / MANIFESTS["coordinator"]["prompt"]).read_text(encoding="utf-8")


def _events(log):
    return [json.loads(line)["event"] for line in log.path.read_text().splitlines()]


def _keywords(schema):
    """Return every keyword used anywhere in a JSON Schema built from properties and items."""
    found = set(schema)
    for child in [*schema.get("properties", {}).values(), *([schema["items"]] if "items" in schema else [])]:
        found |= _keywords(child)
    return found


def _names_subagent_tool(text):
    return any(f"`{tool}`" in text for tool in config.SUBAGENT_TOOLS)


def _missing_launch_tools(text):
    return [tool for tool in LAUNCH_TOOLS if f"`{tool}`" not in text]


def _missing_statements(text):
    return [statement for statement in STATEMENTS if statement not in text]


def _states_caps(text, turns, dispatches):
    phrases = (
        f"at most {turns} turns",
        f"at most {dispatches} dispatches per step",
        f"at most {dispatches} dispatches in all",
        f"reviewed at most {dispatches} times",
    )
    return all(phrase in text for phrase in phrases)


def test_coordinator_tools_are_exactly_its_four_launch_tools():
    assert [definition["name"] for definition in coordinator.tool_definitions(MANIFESTS)] == LAUNCH_TOOLS


def test_every_coordinator_request_holds_exactly_the_four_launch_tools(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_launch("security_examiner", EXAMINE)),
            _answer(EXAMINATION),
            _turn(_launch("adversarial_reviewer", {"target_id": "EX-SEC-v1"})),
            _answer(REVIEW),
            _done(),
        ]
    )
    _run(client, log, tmp_path)
    coordinator_requests = [request for request in client.requests if request["system"] == _prompt().strip()]
    assert len(coordinator_requests) == 3
    for request in coordinator_requests:
        assert request["tools"] == coordinator.tool_definitions(MANIFESTS)
        assert [tool["name"] for tool in request["tools"]] == LAUNCH_TOOLS
    for request in client.requests:
        if request not in coordinator_requests:
            assert not any(tool["name"].startswith("launch_") for tool in request.get("tools", []))


@pytest.mark.parametrize(
    "tool", ["read_file", "http_get", "bash", "launch_bash", "launch_coordinator", "security_examiner", "launch_"]
)
def test_coordinator_refuses_to_start_with_a_tool_that_launches_no_subagent(fake_anthropic, log, tmp_path, tool):
    planted = {**MANIFESTS, "coordinator": {**MANIFESTS["coordinator"], "tools": [*LAUNCH_TOOLS, tool]}}
    client = fake_anthropic([])
    with pytest.raises(ValueError, match=f"tool {tool} launches no loaded sub-agent"):
        _run(client, log, tmp_path, planted)
    assert client.requests == []
    assert not log.path.exists()


def _definitions():
    return {definition["name"]: definition for definition in coordinator.tool_definitions(MANIFESTS)}


@pytest.mark.parametrize("tool", LAUNCH_TOOLS)
def test_launch_tool_is_strict_and_requires_every_input(tool):
    definition = _definitions()[tool]
    schema = definition["input_schema"]
    assert definition["strict"] is True
    assert definition["description"].strip()
    assert (schema["type"], schema["additionalProperties"]) == ("object", False)
    assert schema["required"] == list(schema["properties"])


@pytest.mark.parametrize("agent", ["security_examiner", "dependency_examiner"])
def test_examiner_launch_takes_a_step_of_its_manifest_challenge_ids_and_a_note(agent):
    steps = [step["name"] for step in MANIFESTS[agent]["steps"]]
    assert _definitions()[f"launch_{agent}"]["input_schema"]["properties"] == {
        "step": {"type": "string", "enum": steps},
        "challenge_ids": IDS,
        "note": {"type": "string"},
    }


def test_reviewer_launch_takes_a_target_id_and_the_writer_launch_a_disposition_and_challenge_ids():
    definitions = _definitions()
    assert definitions["launch_adversarial_reviewer"]["input_schema"]["properties"] == {"target_id": {"type": "string"}}
    assert definitions["launch_final_review_writer"]["input_schema"]["properties"] == {
        "disposition": DISPOSITION_SCHEMA,
        "challenge_ids": IDS,
    }


def test_tool_definitions_are_copies_the_caller_may_change():
    first = coordinator.tool_definitions(MANIFESTS)
    first[0]["input_schema"]["properties"]["challenge_ids"]["items"]["type"] = "integer"
    first[3]["input_schema"]["properties"]["disposition"]["required"].clear()
    assert coordinator.tool_definitions(MANIFESTS)[0]["input_schema"]["properties"]["challenge_ids"] == IDS
    assert coordinator.tool_definitions(MANIFESTS)[3]["input_schema"]["properties"]["disposition"] == DISPOSITION_SCHEMA


def test_examiner_launch_step_enum_follows_the_examiner_manifest():
    examiner = {**MANIFESTS["security_examiner"], "steps": [{"name": "secrets", "code": "SEC"}]}
    (definition,) = [
        definition
        for definition in coordinator.tool_definitions({**MANIFESTS, "security_examiner": examiner})
        if definition["name"] == "launch_security_examiner"
    ]
    assert definition["input_schema"]["properties"]["step"]["enum"] == ["secrets"]


def test_launch_tool_schemas_use_only_the_structured_outputs_keywords():
    for definition in coordinator.tool_definitions(MANIFESTS):
        assert _keywords(definition["input_schema"]) <= STRUCTURED_KEYWORDS


def test_keyword_check_detects_a_planted_violation():
    items = {"type": "string", "minLength": 1}
    planted = {"type": "object", "properties": {"steps": {"type": "array", "items": items}}}
    assert _keywords(planted) - STRUCTURED_KEYWORDS == {"minLength"}


@pytest.mark.parametrize(
    "changes",
    [{}, {"model": "claude-opus-5-5", "effort": "high", "prompt": "prompts/final_review_writer.md"}],
)
def test_coordinator_request_takes_its_model_effort_and_prompt_from_the_manifest(
    fake_anthropic, log, tmp_path, changes
):
    coordinator_manifest = {**MANIFESTS["coordinator"], **changes}
    client = fake_anthropic([_done()])
    _run(client, log, tmp_path, {**MANIFESTS, "coordinator": coordinator_manifest})
    (request,) = client.requests
    assert (request["model"], request["output_config"]) == (
        coordinator_manifest["model"],
        {"effort": coordinator_manifest["effort"]},
    )
    prompt = (config.ROOT / coordinator_manifest["prompt"]).read_text(encoding="utf-8")
    assert request["system"] == prompt.strip()


def test_first_coordinator_request_holds_the_workspace_and_every_step(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_done()])
    _run(client, log, tmp_path)
    (request,) = client.requests
    (message,) = request["messages"]
    assert message["role"] == "user"
    assert json.loads(message["content"]) == {
        "workspace": "acme-api",
        "steps": [
            {"workflow": "security_examiner", "step": "secrets"},
            {"workflow": "security_examiner", "step": "insecure_config"},
            {"workflow": "dependency_examiner", "step": "known_vulnerabilities"},
            {"workflow": "dependency_examiner", "step": "dependency_hygiene"},
        ],
    }


def test_immediate_end_turn_dispatches_nothing(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_done()])
    state = _run(client, log, tmp_path)
    assert len(client.requests) == 1
    assert _events(log) == ["llm_call"]
    assert state == coordinator.RunState(turns=1)


def test_each_launch_block_is_dispatched_once_and_a_failed_dispatch_is_not_retried(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_turn(_launch("security_examiner", EXAMINE)), _answer("not an examination"), _done()])
    state = _run(client, log, tmp_path)
    assert len(client.requests) == 3
    assert _events(log).count("dispatch_started") == 1
    assert state.dispatches == {("security_examiner", "secrets"): 1}


def test_launch_block_in_an_end_turn_response_is_not_dispatched(fake_anthropic, log, tmp_path):
    response = _message(
        [{"type": "text", "text": "Done."}, _launch("security_examiner", EXAMINE)],
        "end_turn",
    )
    client = fake_anthropic([response])
    state = _run(client, log, tmp_path)
    assert len(client.requests) == 1
    assert (state.examinations, state.dispatches) == ({}, {})


def test_coordinator_prompt_names_each_launch_tool():
    assert _missing_launch_tools(_prompt()) == []


def test_launch_tool_check_detects_a_planted_violation():
    text = "Use `launch_security_examiner`, then launch_adversarial_reviewer."
    assert _missing_launch_tools(text) == LAUNCH_TOOLS[1:]


def test_coordinator_prompt_holds_its_dispatch_only_and_disposition_rules():
    assert _missing_statements(_prompt()) == []


@pytest.mark.parametrize("statement", STATEMENTS)
def test_statement_check_detects_a_planted_violation(statement):
    assert _missing_statements(_prompt().replace(statement, "")) == [statement]


def test_coordinator_prompt_names_no_subagent_tool():
    assert not _names_subagent_tool(_prompt())


def test_subagent_tool_check_detects_a_planted_violation():
    assert _names_subagent_tool("Check the cited line yourself with `read_file`.")


def test_coordinator_prompt_states_its_caps():
    coordinator_manifest = MANIFESTS["coordinator"]
    assert _states_caps(_prompt(), coordinator_manifest["max_turns"], coordinator_manifest["max_dispatches_per_step"])


@pytest.mark.parametrize(
    "text",
    [
        "You have at most 30 turns.",
        "You have at most 31 turns and at most 3 dispatches per step, at most 3 dispatches in all, reviewed at most "
        "3 times.",
        "You have at most 30 turns and at most three dispatches per step, at most 3 dispatches in all, reviewed at "
        "most 3 times.",
        "You have at most 30 turns and at most 3 dispatches per step, reviewed at most 3 times.",
        "You have at most 30 turns and at most 3 dispatches per step, at most 3 dispatches in all.",
    ],
)
def test_cap_check_detects_a_planted_violation(text):
    assert not _states_caps(text, 30, 3)
