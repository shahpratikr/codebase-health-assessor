import json
import shutil
import typing

import jsonschema
import pytest
from anthropic.types.beta.beta_output_config_param import BetaOutputConfigParam

from assessor import config, manifest

MANIFESTS = config.MANIFESTS_DIR
MANIFEST_SCHEMA = json.loads((config.SCHEMAS_DIR / "manifest.schema.json").read_text())
SUBSTANCE_SCHEMA = json.loads((config.SCHEMAS_DIR / "substance.schema.json").read_text())
SONNET = "claude-sonnet-5-5"
AGENTS = ("coordinator", "security_examiner", "dependency_examiner", "adversarial_reviewer", "final_review_writer")
SUBAGENTS = AGENTS[1:]
DROP = object()


@pytest.fixture
def manifests_dir(tmp_path):
    copy = tmp_path / "manifests"
    shutil.copytree(MANIFESTS, copy)
    return copy


def _read(directory, name):
    return json.loads((directory / f"{name}.json").read_text())


def _write(directory, name, data):
    (directory / f"{name}.json").write_text(json.dumps(data))


def _edit(directory, agent, /, **fields):
    data = _read(directory, agent)
    for field, value in fields.items():
        if value is DROP:
            del data[field]
        else:
            data[field] = value
    _write(directory, agent, data)


def _refused(directory, match):
    with pytest.raises(ValueError, match=match):
        manifest.load_manifests(directory)


def _substance(tmp_path, data):
    path = tmp_path / "substance.json"
    path.write_text(json.dumps(data))
    return manifest.load_substance(manifest.load_manifests(), path)


def _shipped_substance():
    return json.loads((MANIFESTS / "substance.json").read_text())


def test_load_manifests_returns_the_coordinator_and_every_launched_agent():
    assert list(manifest.load_manifests()) == list(AGENTS)


def test_coordinator_holds_exactly_the_four_launch_tools():
    assert manifest.load_manifests()["coordinator"]["tools"] == [
        "launch_security_examiner",
        "launch_dependency_examiner",
        "launch_adversarial_reviewer",
        "launch_final_review_writer",
    ]


@pytest.mark.parametrize(
    ("agent", "tools"),
    [
        ("security_examiner", ["list_files", "read_file"]),
        ("dependency_examiner", ["list_manifests", "read_manifest", "query_osv"]),
        ("adversarial_reviewer", ["read_file"]),
        ("final_review_writer", []),
    ],
)
def test_each_subagent_declares_exactly_its_scoped_tools(agent, tools):
    assert manifest.load_manifests()[agent]["tools"] == tools


def test_reviewer_runs_in_an_isolated_context_assigned_to_both_examiners_and_the_writer():
    reviewer = manifest.load_manifests()["adversarial_reviewer"]
    assert reviewer["role"] == "reviewer"
    assert reviewer["isolated_context"] is True
    assert reviewer["assignment"] == ["security_examiner", "dependency_examiner", "final_review_writer"]


@pytest.mark.parametrize(
    ("agent", "steps"),
    [
        ("security_examiner", [{"name": "secrets", "code": "SEC"}, {"name": "insecure_config", "code": "CFG"}]),
        (
            "dependency_examiner",
            [{"name": "known_vulnerabilities", "code": "VULN"}, {"name": "dependency_hygiene", "code": "HYG"}],
        ),
    ],
)
def test_examiners_declare_their_steps_and_codes(agent, steps):
    examiner = manifest.load_manifests()[agent]
    assert examiner["role"] == "examiner"
    assert examiner["steps"] == steps


def test_subagent_tool_calls_are_capped_at_12_and_the_coordinator_at_30_turns_and_3_dispatches():
    manifests = manifest.load_manifests()
    assert {agent: manifests[agent]["max_tool_calls"] for agent in SUBAGENTS} == dict.fromkeys(SUBAGENTS, 12)
    assert manifests["coordinator"]["max_turns"] == 30
    assert manifests["coordinator"]["max_dispatches_per_step"] == 3


@pytest.mark.parametrize(
    ("agent", "effort"),
    [
        ("coordinator", "medium"),
        ("security_examiner", "medium"),
        ("dependency_examiner", "medium"),
        ("adversarial_reviewer", "high"),
        ("final_review_writer", "low"),
    ],
)
def test_every_agent_runs_on_sonnet_5_5_at_its_effort(agent, effort):
    loaded = manifest.load_manifests()[agent]
    assert (loaded["model"], loaded["effort"]) == (SONNET, effort)


@pytest.mark.parametrize(
    ("agent", "schema"),
    [
        ("security_examiner", "schemas/examination.schema.json"),
        ("dependency_examiner", "schemas/examination.schema.json"),
        ("adversarial_reviewer", "schemas/review.schema.json"),
        ("final_review_writer", "schemas/writer_output.schema.json"),
    ],
)
def test_subagents_name_their_output_contract_schema(agent, schema):
    assert manifest.load_manifests()[agent]["output_schema"] == schema


@pytest.mark.parametrize(
    ("agent", "skills"),
    [
        ("security_examiner", ["skills/secrets_and_config_checklist.md"]),
        ("dependency_examiner", ["skills/dependency_risk_checklist.md"]),
        ("adversarial_reviewer", []),
        ("final_review_writer", []),
    ],
)
def test_each_agent_names_its_own_prompt_and_skills(agent, skills):
    loaded = manifest.load_manifests()[agent]
    assert loaded["prompt"] == f"prompts/{agent}.md"
    assert loaded["skills"] == skills


def test_coordinator_names_its_own_prompt():
    assert manifest.load_manifests()["coordinator"]["prompt"] == "prompts/coordinator.md"


def test_shipped_substance_rates_both_examiners_core_and_the_writer_peripheral_with_rationales():
    ratings = manifest.load_substance(manifest.load_manifests())["ratings"]
    assert {agent: rating["rating"] for agent, rating in ratings.items()} == {
        "security_examiner": "core",
        "dependency_examiner": "core",
        "final_review_writer": "peripheral",
    }
    assert all(rating["rationale"].strip() for rating in ratings.values())


def test_shipped_substance_lists_the_reviewer_as_not_rated_with_a_reason():
    not_rated = manifest.load_substance(manifest.load_manifests())["not_rated"]
    assert list(not_rated) == ["adversarial_reviewer"]
    assert not_rated["adversarial_reviewer"]["reason"].strip()


def test_load_substance_reads_another_ratings_file(tmp_path):
    toy = _shipped_substance()
    toy["ratings"]["dependency_examiner"] = {"rating": "toy", "rationale": "Demo of the elevation gate."}
    assert _substance(tmp_path, toy) == toy


@pytest.mark.parametrize(
    "tool",
    [
        "read_file",
        "http_get",
        "bash",
        "list_files",
        "security_examiner",
        "adversarial_reviewer",
        "dispatch_security_examiner",
        "Launch_security_examiner",
        "launch_",
        "launch_Security_examiner",
    ],
)
def test_coordinator_tool_that_is_not_a_launch_tool_is_refused(manifests_dir, tool):
    _edit(manifests_dir, "coordinator", tools=[*_read(manifests_dir, "coordinator")["tools"], tool])
    _refused(manifests_dir, rf"coordinator\.json: '{tool}' does not match '\^launch_")


@pytest.mark.parametrize("tool", ["launch_ghost", "launch_security_examiner\n"])
def test_launch_tool_without_a_subagent_manifest_is_refused(manifests_dir, tool):
    _edit(manifests_dir, "coordinator", tools=[*_read(manifests_dir, "coordinator")["tools"], tool])
    _refused(manifests_dir, rf"(?s)coordinator\.json: tool {tool} maps to no sub-agent manifest")


def test_launch_tool_whose_manifest_is_missing_is_refused(manifests_dir):
    (manifests_dir / "final_review_writer.json").unlink()
    _refused(manifests_dir, "tool launch_final_review_writer maps to no sub-agent manifest")


@pytest.mark.parametrize("tool", ["launch_../coordinator", "launch_x/y", "launch_x.y"])
def test_launch_tool_with_path_characters_is_refused(manifests_dir, tool):
    _edit(manifests_dir, "coordinator", tools=[*_read(manifests_dir, "coordinator")["tools"], tool])
    _refused(manifests_dir, r"coordinator\.json: '.*' does not match '\^launch_")


def test_launch_tool_cannot_start_the_coordinator(manifests_dir):
    _edit(manifests_dir, "coordinator", tools=[*_read(manifests_dir, "coordinator")["tools"], "launch_coordinator"])
    _refused(manifests_dir, "launch_coordinator must launch a sub-agent")


def test_launch_tool_cannot_load_the_substance_file_as_a_manifest(manifests_dir):
    _edit(manifests_dir, "coordinator", tools=[*_read(manifests_dir, "coordinator")["tools"], "launch_substance"])
    _refused(manifests_dir, "substance.json")


def test_repeated_launch_tool_is_refused(manifests_dir):
    tools = _read(manifests_dir, "coordinator")["tools"]
    _edit(manifests_dir, "coordinator", tools=[*tools, tools[0]])
    _refused(manifests_dir, "coordinator.json")


def test_coordinator_file_must_hold_the_coordinator_role(manifests_dir):
    _write(manifests_dir, "coordinator", {**_read(manifests_dir, "security_examiner"), "name": "coordinator"})
    _refused(manifests_dir, r"coordinator\.json: role must be coordinator")


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("field", ["temperature", "top_p", "top_k", "thinking", "tool_choice", "max_tokens"])
def test_undeclared_field_is_refused(manifests_dir, agent, field):
    _edit(manifests_dir, agent, **{field: None})
    _refused(manifests_dir, f"{agent}.json: .*{field}")


@pytest.mark.parametrize(
    ("agent", "field"),
    [
        *[(agent, field) for agent in AGENTS for field in ("name", "role", "model", "effort", "prompt", "tools")],
        ("coordinator", "max_turns"),
        ("coordinator", "max_dispatches_per_step"),
        *[(agent, field) for agent in SUBAGENTS for field in ("skills", "max_tool_calls", "output_schema")],
        ("security_examiner", "steps"),
        ("dependency_examiner", "steps"),
        ("adversarial_reviewer", "isolated_context"),
        ("adversarial_reviewer", "assignment"),
    ],
)
def test_missing_required_field_is_refused(manifests_dir, agent, field):
    _edit(manifests_dir, agent, **{field: DROP})
    _refused(manifests_dir, f"{agent}.json")


@pytest.mark.parametrize("agent", AGENTS)
def test_missing_role_is_reported_as_the_missing_field(manifests_dir, agent):
    _edit(manifests_dir, agent, role=DROP)
    _refused(manifests_dir, f"{agent}.json: 'role' is a required property")


@pytest.mark.parametrize(
    ("agent", "field", "value"),
    [
        ("coordinator", "max_tool_calls", 12),
        ("coordinator", "skills", []),
        ("coordinator", "output_schema", "schemas/review.schema.json"),
        ("security_examiner", "assignment", ["final_review_writer"]),
        ("security_examiner", "isolated_context", True),
        ("security_examiner", "max_turns", 30),
        ("adversarial_reviewer", "steps", [{"name": "review", "code": "REV"}]),
        ("final_review_writer", "steps", [{"name": "report", "code": "REP"}]),
        ("final_review_writer", "isolated_context", True),
        ("final_review_writer", "assignment", ["security_examiner"]),
    ],
)
def test_field_of_another_role_is_refused(manifests_dir, agent, field, value):
    _edit(manifests_dir, agent, **{field: value})
    _refused(manifests_dir, f"{agent}.json")


@pytest.mark.parametrize("tool", ["bash", "http_get", "write_file", "launch_security_examiner", "READ_FILE"])
@pytest.mark.parametrize("agent", ["security_examiner", "dependency_examiner", "adversarial_reviewer"])
def test_subagent_tool_outside_the_known_set_is_refused(manifests_dir, agent, tool):
    _edit(manifests_dir, agent, tools=[*_read(manifests_dir, agent)["tools"], tool])
    _refused(manifests_dir, f"{agent}.json")


@pytest.mark.parametrize("tool", ["read_file", "list_files"])
def test_writer_with_any_tool_is_refused(manifests_dir, tool):
    _edit(manifests_dir, "final_review_writer", tools=[tool])
    _refused(manifests_dir, "final_review_writer.json")


@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_reviewer_isolated_context_must_be_true(manifests_dir, value):
    _edit(manifests_dir, "adversarial_reviewer", isolated_context=value)
    _refused(manifests_dir, "adversarial_reviewer.json")


@pytest.mark.parametrize(
    ("agent", "field", "value"),
    [
        ("coordinator", "effort", "extreme"),
        ("coordinator", "effort", "MEDIUM"),
        ("coordinator", "role", "boss"),
        ("coordinator", "model", ""),
        ("coordinator", "model", "Claude Sonnet"),
        ("coordinator", "max_turns", 0),
        ("coordinator", "max_turns", -1),
        ("coordinator", "max_turns", True),
        ("coordinator", "max_turns", "30"),
        ("coordinator", "max_dispatches_per_step", 0),
        ("coordinator", "prompt", "../prompts/coordinator.md"),
        ("coordinator", "prompt", "prompts/coordinator.txt"),
        ("coordinator", "prompt", "/etc/passwd"),
        ("coordinator", "prompt", "prompts/coordinator.md\n"),
        ("security_examiner", "skills", ["skills/secrets_and_config_checklist.md\n"]),
        ("security_examiner", "output_schema", "schemas/examination.schema.json\n"),
        ("coordinator", "tools", "launch_security_examiner"),
        ("security_examiner", "max_tool_calls", 0),
        ("security_examiner", "max_tool_calls", None),
        ("security_examiner", "skills", ["skills/../secrets_and_config_checklist.md"]),
        ("security_examiner", "skills", ["prompts/security_examiner.md"]),
        ("security_examiner", "skills", ["skills/a.md", "skills/a.md"]),
        ("security_examiner", "output_schema", "schemas/examination.json"),
        ("security_examiner", "output_schema", "../schemas/examination.schema.json"),
        ("security_examiner", "steps", []),
        ("security_examiner", "steps", [{"name": "secrets"}]),
        ("security_examiner", "steps", [{"name": "secrets", "code": "SEC", "title": "Secrets"}]),
        ("security_examiner", "steps", [{"name": "Secrets", "code": "SEC"}]),
        ("security_examiner", "steps", [{"name": "sécrets", "code": "SEC"}]),
        ("security_examiner", "steps", [{"name": "secrets\n", "code": "SEC"}]),
        ("security_examiner", "steps", [{"name": "secrets", "code": "sec"}]),
        ("security_examiner", "steps", [{"name": "secrets", "code": "S"}]),
        ("security_examiner", "steps", [{"name": "secrets", "code": "SEC\n"}]),
        (
            "adversarial_reviewer",
            "assignment",
            ["security_examiner", "dependency_examiner", "final_review_writer", "security_examiner"],
        ),
        ("security_examiner", "name", "Security_examiner"),
    ],
)
def test_invalid_value_is_refused(manifests_dir, agent, field, value):
    _edit(manifests_dir, agent, **{field: value})
    _refused(manifests_dir, f"{agent}.json")


@pytest.mark.parametrize("number", ["12.0", "1.2e1", "1e1", "NaN", "Infinity", "-Infinity"])
def test_decimal_or_non_finite_number_is_refused(manifests_dir, number):
    path = manifests_dir / "security_examiner.json"
    path.write_text(path.read_text().replace('"max_tool_calls": 12', f'"max_tool_calls": {number}'))
    assert number in path.read_text()
    _refused(manifests_dir, f"security_examiner.json: .*{number}")


def test_repeated_json_key_is_refused(manifests_dir):
    path = manifests_dir / "security_examiner.json"
    path.write_text(path.read_text().replace('"tools":', '"tools": ["read_file"], "tools":'))
    _refused(manifests_dir, "security_examiner.json: duplicate key tools")


@pytest.mark.parametrize("text", ['{"name": ', "[]", "", "\xff"])
def test_malformed_manifest_file_is_refused(manifests_dir, text):
    (manifests_dir / "dependency_examiner.json").write_text(text, encoding="latin-1")
    _refused(manifests_dir, "dependency_examiner.json")


@pytest.mark.parametrize("depth", [100_000, 1_000_000])
def test_deeply_nested_manifest_is_refused_as_a_value_error(manifests_dir, depth):
    (manifests_dir / "security_examiner.json").write_text("[" * depth + "]" * depth)
    _refused(manifests_dir, r"security_examiner\.json: nested too deeply")


def test_directory_in_place_of_a_subagent_manifest_raises_its_os_error(manifests_dir):
    (manifests_dir / "security_examiner.json").unlink()
    (manifests_dir / "security_examiner.json").mkdir()
    with pytest.raises(IsADirectoryError, match="security_examiner.json"):
        manifest.load_manifests(manifests_dir)


def test_unreadable_pricing_file_raises_its_os_error(manifests_dir, monkeypatch):
    def refuse(path, *args, **kwargs):
        raise PermissionError(f"Permission denied: '{path}'")

    monkeypatch.setattr(config, "open", refuse, raising=False)
    with pytest.raises(PermissionError, match="pricing.json"):
        manifest.load_manifests(manifests_dir)


def test_unreadable_subagent_manifest_raises_its_os_error(manifests_dir, monkeypatch):
    read_text = manifest.Path.read_text

    def refuse_examiner(path, *args, **kwargs):
        if path.name == "security_examiner.json":
            raise PermissionError(f"Permission denied: '{path}'")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(manifest.Path, "read_text", refuse_examiner)
    with pytest.raises(PermissionError, match="security_examiner.json"):
        manifest.load_manifests(manifests_dir)


def test_missing_coordinator_manifest_raises_its_os_error(manifests_dir):
    (manifests_dir / "coordinator.json").unlink()
    with pytest.raises(FileNotFoundError, match="coordinator.json"):
        manifest.load_manifests(manifests_dir)


@pytest.mark.parametrize(("name", "error"), [("absent.json", FileNotFoundError), ("folder", IsADirectoryError)])
def test_unreadable_substance_path_raises_its_os_error(tmp_path, name, error):
    (tmp_path / "folder").mkdir()
    with pytest.raises(error, match=name):
        manifest.load_substance(manifest.load_manifests(), tmp_path / name)


def test_manifest_name_must_match_its_file(manifests_dir):
    _edit(manifests_dir, "security_examiner", name="dependency_examiner")
    _refused(manifests_dir, r"security_examiner\.json: name 'dependency_examiner' must match")


@pytest.mark.parametrize(
    "assignment",
    [
        [],
        ["security_examiner", "dependency_examiner"],
        ["security_examiner", "final_review_writer"],
        ["security_examiner", "dependency_examiner", "final_review_writer", "adversarial_reviewer"],
        ["security_examiner", "dependency_examiner", "final_review_writer", "coordinator"],
        ["security_examiner", "dependency_examiner", "final_review_writer", "ghost"],
    ],
)
def test_reviewer_assignment_must_be_exactly_the_examiners_and_the_writer(manifests_dir, assignment):
    _edit(manifests_dir, "adversarial_reviewer", assignment=assignment)
    _refused(manifests_dir, r"adversarial_reviewer\.json: assignment must be exactly")


def _launch_copy(directory, source, name):
    _write(directory, name, {**_read(directory, source), "name": name})
    _edit(directory, "coordinator", tools=[*_read(directory, "coordinator")["tools"], f"launch_{name}"])


@pytest.mark.parametrize(
    ("source", "name"), [("adversarial_reviewer", "second_reviewer"), ("final_review_writer", "second_writer")]
)
def test_second_reviewer_or_writer_is_refused(manifests_dir, source, name):
    _launch_copy(manifests_dir, source, name)
    _refused(manifests_dir, r"coordinator\.json: launch_ tools must start")


@pytest.mark.parametrize("dropped", ["launch_adversarial_reviewer", "launch_final_review_writer"])
def test_coordinator_without_a_reviewer_or_writer_is_refused(manifests_dir, dropped):
    tools = [tool for tool in _read(manifests_dir, "coordinator")["tools"] if tool != dropped]
    _edit(manifests_dir, "coordinator", tools=tools)
    _refused(manifests_dir, r"coordinator\.json: launch_ tools must start")


def test_coordinator_without_an_examiner_is_refused(manifests_dir):
    _edit(manifests_dir, "coordinator", tools=["launch_adversarial_reviewer", "launch_final_review_writer"])
    _edit(manifests_dir, "adversarial_reviewer", assignment=["final_review_writer"])
    _refused(manifests_dir, r"coordinator\.json: launch_ tools must start")


def test_step_code_used_by_another_examiner_is_refused(manifests_dir):
    steps = _read(manifests_dir, "dependency_examiner")["steps"]
    _edit(manifests_dir, "dependency_examiner", steps=[steps[0], {**steps[1], "code": "SEC"}])
    _refused(manifests_dir, r"dependency_examiner\.json: step code SEC is already used by security_examiner\.secrets")


def test_step_code_repeated_within_an_examiner_is_refused(manifests_dir):
    steps = [{"name": "secrets", "code": "SEC"}, {"name": "insecure_config", "code": "SEC"}]
    _edit(manifests_dir, "security_examiner", steps=steps)
    _refused(manifests_dir, r"security_examiner\.json: step code SEC is already used by security_examiner\.secrets")


def test_step_name_repeated_within_an_examiner_is_refused(manifests_dir):
    steps = [{"name": "secrets", "code": "SEC"}, {"name": "secrets", "code": "CFG"}]
    _edit(manifests_dir, "security_examiner", steps=steps)
    _refused(manifests_dir, r"security_examiner\.json: step secrets is declared twice")


def test_unpriced_model_is_refused(manifests_dir):
    _edit(manifests_dir, "final_review_writer", model="claude-sonnet-9")
    _refused(manifests_dir, r"final_review_writer\.json: model claude-sonnet-9 has no price")


def test_models_are_checked_against_the_given_pricing(manifests_dir):
    opus_only = {"claude-opus-5-5": {"input": 4.0, "output": 20.0, "cache_write": 5.0, "cache_read": 0.2}}
    with pytest.raises(ValueError, match=r"coordinator\.json: model claude-sonnet-5-5 has no price"):
        manifest.load_manifests(manifests_dir, pricing=opus_only)


@pytest.mark.parametrize("pricing", [{}, {"claude-sonnet-5-5": {"input": 2.0}}])
def test_malformed_given_pricing_is_refused(manifests_dir, pricing):
    with pytest.raises(ValueError, match="^pricing: pricing"):
        manifest.load_manifests(manifests_dir, pricing=pricing)


@pytest.mark.parametrize("rating", ["essential", "Core", "", None])
def test_substance_rating_outside_the_closed_set_is_refused(tmp_path, rating):
    data = _shipped_substance()
    data["ratings"]["security_examiner"]["rating"] = rating
    with pytest.raises(ValueError, match="substance.json"):
        _substance(tmp_path, data)


@pytest.mark.parametrize(
    ("section", "agent", "field", "value"),
    [
        ("ratings", "security_examiner", "rationale", DROP),
        ("ratings", "security_examiner", "rationale", " \n\t"),
        ("ratings", "security_examiner", "rationale", 7),
        ("ratings", "final_review_writer", "rating", DROP),
        ("not_rated", "adversarial_reviewer", "reason", DROP),
        ("not_rated", "adversarial_reviewer", "reason", ""),
        ("ratings", "security_examiner", "weight", 2),
        ("not_rated", "adversarial_reviewer", "rating", "toy"),
    ],
)
def test_substance_entry_without_its_reason_or_with_extra_fields_is_refused(tmp_path, section, agent, field, value):
    data = _shipped_substance()
    if value is DROP:
        del data[section][agent][field]
    else:
        data[section][agent][field] = value
    with pytest.raises(ValueError, match="substance.json"):
        _substance(tmp_path, data)


@pytest.mark.parametrize("change", ["drop ratings", "drop not_rated", "extra notes", "ratings list"])
def test_substance_with_the_wrong_top_level_shape_is_refused(tmp_path, change):
    data = _shipped_substance()
    if change == "drop ratings":
        del data["ratings"]
    elif change == "drop not_rated":
        del data["not_rated"]
    elif change == "extra notes":
        data["notes"] = "x"
    else:
        data["ratings"] = list(data["ratings"].values())
    with pytest.raises(ValueError, match="substance.json"):
        _substance(tmp_path, data)


def _reason(text="Reason."):
    return {"reason": text}


def _rating(rating="core"):
    return {"rating": rating, "rationale": "Rationale."}


@pytest.mark.parametrize(
    ("ratings", "not_rated", "match"),
    [
        (
            {"security_examiner": _rating(), "dependency_examiner": _rating()},
            {"adversarial_reviewer": _reason()},
            "ratings must cover exactly",
        ),
        (
            {
                "security_examiner": _rating(),
                "dependency_examiner": _rating(),
                "final_review_writer": _rating(),
                "adversarial_reviewer": _rating(),
            },
            {},
            "ratings must cover exactly",
        ),
        (
            {"security_examiner": _rating(), "dependency_examiner": _rating()},
            {"adversarial_reviewer": _reason(), "final_review_writer": _reason()},
            "ratings must cover exactly",
        ),
        (
            {
                "security_examiner": _rating(),
                "dependency_examiner": _rating(),
                "final_review_writer": _rating(),
                "coordinator": _rating(),
            },
            {"adversarial_reviewer": _reason()},
            "ratings must cover exactly",
        ),
        (
            {"security_examiner": _rating(), "dependency_examiner": _rating(), "final_review_writer": _rating()},
            {},
            "not_rated must list exactly adversarial_reviewer",
        ),
        (
            {"security_examiner": _rating(), "dependency_examiner": _rating(), "final_review_writer": _rating()},
            {"adversarial_reviewer": _reason(), "ghost": _reason()},
            "not_rated must list exactly adversarial_reviewer",
        ),
    ],
)
def test_substance_must_rate_exactly_the_workflows_and_list_only_the_reviewer_as_not_rated(
    tmp_path, ratings, not_rated, match
):
    with pytest.raises(ValueError, match=rf"substance\.json: {match}"):
        _substance(tmp_path, {"ratings": ratings, "not_rated": not_rated})


def test_substance_with_a_repeated_key_is_refused(tmp_path):
    path = tmp_path / "substance.json"
    text = (MANIFESTS / "substance.json").read_text()
    repeated = '"ratings": {"security_examiner": {"rating": "toy", "rationale": "x"},'
    path.write_text(text.replace('"ratings": {', repeated, 1))
    with pytest.raises(ValueError, match="duplicate key security_examiner"):
        manifest.load_substance(manifest.load_manifests(), path)


def test_schema_closed_sets_match_config():
    assert MANIFEST_SCHEMA["properties"]["role"]["enum"] == list(config.AGENT_ROLES)
    assert [branch["if"]["properties"]["role"]["const"] for branch in MANIFEST_SCHEMA["allOf"]] == list(
        config.AGENT_ROLES
    )
    assert MANIFEST_SCHEMA["properties"]["effort"]["enum"] == list(config.EFFORTS)
    assert MANIFEST_SCHEMA["$defs"]["subagent_tools"]["items"]["enum"] == list(config.SUBAGENT_TOOLS)
    rating = SUBSTANCE_SCHEMA["properties"]["ratings"]["additionalProperties"]["properties"]["rating"]
    assert rating["enum"] == list(config.SUBSTANCE_RATINGS)


@pytest.mark.parametrize("schema", [MANIFEST_SCHEMA, SUBSTANCE_SCHEMA])
def test_schemas_are_valid_draft_2020_12(schema):
    jsonschema.Draft202012Validator.check_schema(schema)


def test_effort_levels_are_the_installed_sdk_literal():
    effort = typing.get_type_hints(BetaOutputConfigParam)["effort"]
    literal = next(arg for arg in typing.get_args(effort) if typing.get_origin(arg) is typing.Literal)
    assert config.EFFORTS == typing.get_args(literal)
