import json
import os

import pytest

from assessor import config, manifest, sandbox, tools
from assessor.tools import deps, files

MANIFESTS = manifest.load_manifests()
SUBAGENTS = [name for name, agent in MANIFESTS.items() if agent["role"] != "coordinator"]
STRICT_KEYWORDS = {"type", "properties", "required", "enum", "items", "additionalProperties"}
VALID_INPUTS = {
    "list_files": {"directory": "."},
    "read_file": {"path": "app.py", "start_line": 1},
    "list_manifests": {},
    "read_manifest": {"path": "requirements.txt", "start_line": 1},
    "query_osv": {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"},
}
HANDLERS = [(files, "list_files"), (files, "read_file"), (deps, "list_manifests"), (deps, "read_manifest"),
            (deps, "query_osv")]


def _workspace(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    (repo / "requirements.txt").write_text("requests==2.19.0\n")
    return sandbox.Workspace(repo)


def _osv(calls):
    def send(query):
        calls.append(query)
        return {}

    return send


@pytest.fixture
def ran(monkeypatch):
    calls = []
    for module, name in HANDLERS:
        monkeypatch.setattr(module, name, lambda *args, name=name: calls.append(name) or {})
    return calls


def _outside_strict_subset(schema, where="schema"):
    """List each keyword, object without additionalProperties: false, or optional property outside the strict subset."""
    found = [f"{where}: {keyword}" for keyword in schema if keyword not in STRICT_KEYWORDS]
    if schema.get("type") == "object":
        if schema.get("additionalProperties") is not False:
            found.append(f"{where}: additionalProperties")
        if sorted(schema.get("required", [])) != sorted(schema.get("properties", {})):
            found.append(f"{where}: required")
    for name, child in schema.get("properties", {}).items():
        found += _outside_strict_subset(child, f"{where}.{name}")
    if "items" in schema:
        found += _outside_strict_subset(schema["items"], f"{where}[]")
    return found


def test_registry_covers_exactly_the_subagent_tools():
    assert tuple(tools.INPUT_SCHEMAS) == config.SUBAGENT_TOOLS


def test_input_schemas_stay_inside_the_strict_subset():
    assert {name: _outside_strict_subset(schema) for name, schema in tools.INPUT_SCHEMAS.items()} == dict.fromkeys(
        config.SUBAGENT_TOOLS, []
    )


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ({"type": "integer", "minimum": 1}, ["schema: minimum"]),
        ({"type": "object", "properties": {}}, ["schema: additionalProperties"]),
        (
            {"type": "object", "properties": {"a": {"type": "string"}}, "required": [], "additionalProperties": False},
            ["schema: required"],
        ),
        (
            {
                "type": "object",
                "properties": {"a": {"type": "array", "items": {"type": "string", "maxLength": 9}}},
                "required": ["a"],
                "additionalProperties": False,
            },
            ["schema.a[]: maxLength"],
        ),
    ],
)
def test_strict_subset_check_detects_a_planted_violation(planted, expected):
    assert _outside_strict_subset(planted) == expected


def test_query_osv_input_has_no_url_or_host_field():
    assert sorted(tools.INPUT_SCHEMAS["query_osv"]["properties"]) == ["ecosystem", "name", "version"]
    assert tools.INPUT_SCHEMAS["query_osv"]["properties"]["ecosystem"]["enum"] == list(config.OSV_ECOSYSTEMS)


@pytest.mark.parametrize(
    ("agent", "tool"), [(agent, tool) for agent in SUBAGENTS for tool in MANIFESTS[agent]["tools"]]
)
def test_every_tool_a_shipped_manifest_declares_runs(tmp_path, agent, tool):
    result = tools.execute(MANIFESTS[agent], tool, VALID_INPUTS[tool], workspace=_workspace(tmp_path), osv=_osv([]))
    assert (result.allowed, result.is_error) == (True, False), result.content
    assert isinstance(json.loads(result.content), dict)


@pytest.mark.parametrize(
    ("agent", "tool"),
    [
        ("adversarial_reviewer", "list_files"),
        ("adversarial_reviewer", "query_osv"),
        ("final_review_writer", "read_file"),
        ("final_review_writer", "list_files"),
        ("security_examiner", "query_osv"),
        ("security_examiner", "read_manifest"),
        ("security_examiner", "list_manifests"),
        ("dependency_examiner", "read_file"),
        ("dependency_examiner", "list_files"),
        ("coordinator", "read_file"),
        ("coordinator", "launch_security_examiner"),
        ("security_examiner", "bash"),
        ("security_examiner", "http_get"),
        ("security_examiner", "Read_File"),
        ("security_examiner", "read_file "),
    ],
)
def test_a_tool_the_manifest_does_not_declare_is_refused_unrun(tmp_path, ran, agent, tool):
    result = tools.execute(MANIFESTS[agent], tool, VALID_INPUTS.get(tool, {}), workspace=_workspace(tmp_path))
    assert result == tools.ToolResult(f"{tool}: not a tool of {agent}", is_error=True, allowed=False)
    assert ran == []


def test_a_declared_name_outside_the_registry_is_refused_unrun(tmp_path, ran):
    rogue, workspace = {"name": "rogue", "tools": ["bash", "read_file"]}, _workspace(tmp_path)
    result = tools.execute(rogue, "bash", {"command": "ls"}, workspace=workspace)
    assert result == tools.ToolResult("bash: not a tool of rogue", is_error=True, allowed=False)
    assert ran == []
    assert tools.execute(rogue, "read_file", VALID_INPUTS["read_file"], workspace=workspace).allowed
    assert ran == ["read_file"]


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("read_file", {"path": "app.py"}),
        ("read_file", {"path": "app.py", "start_line": 1, "encoding": "latin-1"}),
        ("read_file", {"path": 7, "start_line": 1}),
        ("read_file", {"path": "app.py", "start_line": "1"}),
        ("read_file", {"path": "app.py", "start_line": True}),
        ("read_file", None),
        ("read_file", ["app.py", 1]),
        ("list_files", {}),
        ("list_manifests", {"directory": "."}),
        ("query_osv", {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0", "url": "https://evil.test"}),
        ("query_osv", {"ecosystem": "Go", "name": "x", "version": "1"}),
        ("query_osv", {"ecosystem": "pypi", "name": "requests", "version": "2.19.0"}),
    ],
)
def test_input_outside_the_tool_schema_is_an_error_result_and_runs_nothing(tmp_path, ran, tool, tool_input):
    agent = {"name": "tester", "tools": list(config.SUBAGENT_TOOLS)}
    result = tools.execute(agent, tool, tool_input, workspace=_workspace(tmp_path))
    assert (result.allowed, result.is_error) == (True, True)
    assert result.content.startswith(f"{tool}: invalid input: ")
    assert ran == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable files")
def test_an_os_error_is_an_error_result_without_the_absolute_path(tmp_path):
    workspace = _workspace(tmp_path)
    (workspace.root / "app.py").chmod(0)
    try:
        result = tools.execute(
            MANIFESTS["security_examiner"], "read_file", VALID_INPUTS["read_file"], workspace=workspace
        )
    finally:
        (workspace.root / "app.py").chmod(0o644)
    assert result == tools.ToolResult("read_file: Permission denied", is_error=True, allowed=True)


@pytest.mark.parametrize(
    ("agent", "tool", "tool_input", "escaped"),
    [
        ("dependency_examiner", "read_manifest", {"path": "\ud800", "start_line": 1}, "\\ud800"),
        ("dependency_examiner", "read_manifest", {"path": "x\udcff/package.json", "start_line": 1}, "\\udcff"),
        ("security_examiner", "read_file", {"path": "\udce9.env", "start_line": 1}, "\\udce9"),
        ("security_examiner", "\ud800", {}, "\\ud800"),
    ],
)
def test_error_text_that_echoes_agent_input_is_always_valid_utf8(tmp_path, agent, tool, tool_input, escaped):
    result = tools.execute(MANIFESTS[agent], tool, tool_input, workspace=_workspace(tmp_path))
    assert result.is_error
    assert escaped in result.content.encode("utf-8").decode("utf-8")


def test_a_tool_refusal_is_an_error_result(tmp_path):
    result = tools.execute(
        MANIFESTS["security_examiner"], "read_file", {"path": "../x", "start_line": 1}, workspace=_workspace(tmp_path)
    )
    assert result == tools.ToolResult("read_file: ../x: outside the workspace", is_error=True, allowed=True)


def test_query_osv_uses_the_configured_transport_when_none_is_given(tmp_path, monkeypatch):
    replay = tmp_path / "replay.json"
    replay.write_text(json.dumps({"PyPI/requests@2.19.0": {"vulns": [{"id": "GHSA-test-0001"}]}}))
    monkeypatch.setenv("ASSESSOR_OSV_REPLAY", str(replay))
    examiner = MANIFESTS["dependency_examiner"]
    result = tools.execute(examiner, "query_osv", VALID_INPUTS["query_osv"], workspace=_workspace(tmp_path))
    assert [vuln["id"] for vuln in json.loads(result.content)["vulns"]] == ["GHSA-test-0001"]


@pytest.mark.parametrize(("text", "error"), [("{not json", ValueError), ("[]", ValueError), (None, FileNotFoundError)])
def test_a_broken_replay_file_raises_instead_of_reaching_the_agent(tmp_path, monkeypatch, text, error):
    replay = tmp_path / "replay.json"
    if text is not None:
        replay.write_text(text)
    monkeypatch.setenv("ASSESSOR_OSV_REPLAY", str(replay))
    with pytest.raises(error):
        tools.execute(
            MANIFESTS["dependency_examiner"], "query_osv", VALID_INPUTS["query_osv"], workspace=_workspace(tmp_path)
        )
