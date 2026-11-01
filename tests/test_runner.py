import json
import re
from datetime import UTC, datetime
from pathlib import Path

import anthropic
import httpx2
import pytest
from anthropic.types.beta import BetaMessage

from assessor import audit, config, manifest, sandbox, tools
from assessor.agents import runner
from assessor.guardrails import DispatchError, ExaminationContext, ReviewContext, WriterContext, redact
from assessor.tools import files

CID = "20261027T101500Z-0a1b2c3d"
PARENT = f"{CID}:3"
NOW = datetime(2026, 10, 27, 10, 15, tzinfo=UTC)
MANIFESTS = manifest.load_manifests()
SUBAGENTS = [name for name, agent in MANIFESTS.items() if agent["role"] != "coordinator"]
EXAMINER_STEPS = [
    (name, step["name"]) for name, agent in MANIFESTS.items() if agent["role"] == "examiner" for step in agent["steps"]
]
SECRET = "AKIAIOSFODNN7EXAMPLE"
LENS_HEADINGS = ["Challenge", "Catch", "Detect", "Block"]
# 40 base64 characters mixing cases and digits: the shape redact() masks as an AWS secret access key.
TOKEN_LIKE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd"
READ = {"path": "config.py", "start_line": 1}
REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
SECRETS_FINDING = {
    "title": "AWS access key committed in source",
    "severity": "critical",
    "category": "secret",
    "file": "config.py",
    "line": 2,
    "evidence": f'AWS_ACCESS_KEY_ID = "{SECRET}"',
    "recommendation": "Rotate the key and read it from the environment.",
    "advisory_ids": [],
}
HYGIENE_FINDING = {
    "title": "Unpinned dependency",
    "severity": "low",
    "category": "pinning",
    "file": "requirements.txt",
    "line": 1,
    "evidence": "requests>=2",
    "recommendation": "Pin an exact version and commit a lockfile.",
    "advisory_ids": [],
}
CHALLENGES = [
    {
        "id": "RV-1-C1",
        "finding_id": "SEC-1",
        "lens": "challenge",
        "severity": "major",
        "claim": "The key on line 2 is AWS's documented example, not a live key.",
        "evidence_checked": [{"file": "config.py", "line": 2}],
        "rationale": "A documented example key grants no access.",
    }
]


def _examination(workflow="security_examiner", step="secrets", findings=(SECRETS_FINDING,)):
    return {
        "workflow": workflow,
        "step": step,
        "summary": "Checked the repository.",
        "findings": list(findings),
        "limitations": [],
        "challenge_responses": [],
    }


OUTPUTS = {
    "security_examiner": _examination(),
    "dependency_examiner": _examination("dependency_examiner", "dependency_hygiene", [HYGIENE_FINDING]),
    "adversarial_reviewer": {"target_id": "EX-SEC-v1", "verdict": "pass", "summary": "Checked.", "challenges": []},
    "final_review_writer": {
        "executive_summary": "One committed key needs rotating [SEC-1].",
        "sections": [{"key": "security_examiner.secrets", "prose": "Rotate the key on line 2 [SEC-1]."}],
    },
}
LABELS = {
    "security_examiner": ("security_examiner", "secrets"),
    "dependency_examiner": ("dependency_examiner", "dependency_hygiene"),
    "adversarial_reviewer": ("security_examiner", "secrets"),
    "final_review_writer": ("final_review_writer", None),
}


def _workspace(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text(f'DEBUG = False\nAWS_ACCESS_KEY_ID = "{SECRET}"\n')
    (repo / "requirements.txt").write_text("requests>=2\n")
    return sandbox.Workspace(repo)


def _context(agent, workspace):
    match agent:
        case "security_examiner":
            return ExaminationContext("security_examiner", "secrets", "SEC", workspace)
        case "dependency_examiner":
            return ExaminationContext("dependency_examiner", "dependency_hygiene", "HYG", workspace)
        case "adversarial_reviewer":
            return ReviewContext("EX-SEC-v1", ["SEC-1"])
        case "final_review_writer":
            return WriterContext([("security_examiner", "secrets")], ["SEC-1"])


def _osv(queries):
    def send(query):
        queries.append(query)
        return {"vulns": [{"id": "GHSA-test-0001"}]}

    return send


def _run(client, log, workspace, agent="security_examiner", agent_manifest=None, ctx=None, **overrides):
    workflow, step = LABELS[agent]
    options = {"workflow": workflow, "step": step, "parent_step_id": PARENT, "osv": _osv([]), **overrides}
    return runner.run_subagent(
        client,
        log,
        MANIFESTS[agent] if agent_manifest is None else agent_manifest,
        {"note": "Examine the step."},
        _context(agent, workspace) if ctx is None else ctx,
        workspace=workspace,
        **options,
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


def _answer(output):
    return _message([{"type": "text", "text": json.dumps(output)}])


def _tool_use(name, tool_input, number=1):
    return {"type": "tool_use", "id": f"toolu_{number}", "name": name, "input": tool_input}


def _calls(*blocks):
    return _message(list(blocks), "tool_use")


def _result(content, is_error=False, number=1):
    return {"type": "tool_result", "tool_use_id": f"toolu_{number}", "content": content, "is_error": is_error}


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(CID, runs_dir=tmp_path, clock=lambda: NOW)


def _lines(log, event=None):
    lines = [json.loads(line) for line in log.path.read_text().splitlines()]
    return [line for line in lines if event is None or line["event"] == event]


def _payloads(log, event):
    return [{key: value for key, value in line.items() if key not in audit.ENVELOPE} for line in _lines(log, event)]


def _labels(agent):
    workflow, step = LABELS[agent]
    return {"parent_step_id": PARENT, "agent": agent, "workflow": workflow, "step": step}


def _read(path):
    return (config.ROOT / path).read_text(encoding="utf-8")


def _missing_files(agent_manifest):
    named = [agent_manifest["prompt"], *agent_manifest["skills"], agent_manifest["output_schema"]]
    return [path for path in named if not (config.ROOT / path).is_file()]


def _contract(agent_manifest):
    return Path(agent_manifest["output_schema"]).name.removesuffix(".schema.json")


@pytest.mark.parametrize("agent", SUBAGENTS)
def test_every_file_a_subagent_manifest_names_exists(agent):
    assert _missing_files(MANIFESTS[agent]) == []


def test_missing_file_check_detects_a_planted_violation():
    planted = {
        **MANIFESTS["security_examiner"],
        "prompt": "prompts/nobody.md",
        "skills": ["skills/secrets_and_config_checklist.md", "skills/nothing.md"],
        "output_schema": "schemas/none.schema.json",
    }
    assert _missing_files(planted) == ["prompts/nobody.md", "skills/nothing.md", "schemas/none.schema.json"]


@pytest.mark.parametrize("agent", SUBAGENTS)
def test_every_subagent_output_schema_names_a_guardrail_contract(agent):
    assert _contract(MANIFESTS[agent]) in config.CONTRACTS


def test_contract_check_detects_a_planted_violation():
    planted = {**MANIFESTS["security_examiner"], "output_schema": "schemas/dispatch_error.schema.json"}
    assert _contract(planted) not in config.CONTRACTS


def _unrated(section):
    return [severity for severity in config.FINDING_SEVERITIES if not re.search(rf"\b{severity}\b", section)]


def _lens_headings(text):
    headings = [line.removeprefix("## ").strip() for line in text.splitlines() if line.startswith("## ")]
    return [heading for heading in headings if heading in LENS_HEADINGS]


def _states_cap(text, cap):
    return f"at most {cap} tool calls" in text


@pytest.mark.parametrize(("agent", "step"), EXAMINER_STEPS)
def test_every_examiner_step_has_a_checklist_section_that_rates_every_severity(agent, step):
    section = runner.checklist_section(MANIFESTS[agent], step)
    assert section.strip()
    assert _unrated(section) == []


def test_severity_check_detects_a_planted_violation():
    assert _unrated("Rate a leaked key critical, and a test key highly sensitive.") == ["high", "medium", "low"]


PAIR_NAME = "the AWS documentation example key pair"
PAIR_BULLET = (
    f"- {PAIR_NAME}, whose access key ID ends in `EXAMPLE`, or either half of it alone: report it as a cloud key "
    "like any other, rated critical; the medium rule for examples below does not lower it"
)
PAIR_EXCEPTION = f"({PAIR_NAME} is not one: see What counts)"
PAIR_RULES = (
    f"What counts:\n{PAIR_BULLET}\n"
    f"What does not count, so do not report it:\n- an obvious placeholder: `xxx` {PAIR_EXCEPTION}\n"
)


def _example_pair_problems(section):
    counts, _, rest = section.partition("What does not count")
    placeholder = [line for line in rest.splitlines() if line.startswith("- an obvious placeholder")]
    problems = []
    counted = [line for line in counts.splitlines() if line.startswith(f"- {PAIR_NAME}")]
    wording = ("either half of it alone", "report it as a cloud key", "rated critical", "does not lower it")
    if not any(all(phrase in line for phrase in wording) for line in counted):
        problems.append("not counted as a critical cloud key")
    if not any(line.endswith(PAIR_EXCEPTION) for line in placeholder):
        problems.append("not excepted from the placeholder bullet")
    if SECRET in section or "EXAMPLEKEY" in section:
        problems.append("holds a literal example value")
    return problems


def test_secrets_section_counts_the_aws_example_pair_as_a_critical_cloud_key_not_a_placeholder():
    assert _example_pair_problems(runner.checklist_section(MANIFESTS["security_examiner"], "secrets")) == []
    assert _example_pair_problems(PAIR_RULES) == []


@pytest.mark.parametrize(
    "planted",
    [
        PAIR_RULES.replace(f"What counts:\n{PAIR_BULLET}\n", "What counts:\n").replace(
            "do not report it:\n", f"do not report it:\n{PAIR_BULLET}\n"
        ),
        PAIR_RULES.replace("report it as a cloud key like any other, rated critical", "ignore it"),
        PAIR_RULES.replace(", rated critical", ""),
        PAIR_RULES.replace("; the medium rule for examples below does not lower it", ""),
        PAIR_RULES.replace(", or either half of it alone", ""),
        PAIR_RULES.replace(f"What counts:\n{PAIR_BULLET}\n", f"{PAIR_BULLET[2:]}\nWhat counts:\n"),
        PAIR_RULES.replace("see What counts)", "see What counts), so skip it"),
        PAIR_RULES + f"- {SECRET}\n",
        "",
    ],
    ids=[
        "bullet moved",
        "instruction reversed",
        "rating dropped",
        "override dropped",
        "halves dropped",
        "not a list item",
        "exception softened",
        "literal written",
        "empty",
    ],
)
def test_example_pair_check_detects_a_planted_violation(planted):
    assert _example_pair_problems(planted)


def test_reviewer_prompt_is_organised_under_challenge_catch_detect_and_block():
    assert _lens_headings(_read(MANIFESTS["adversarial_reviewer"]["prompt"])) == LENS_HEADINGS


@pytest.mark.parametrize(
    "text",
    [
        "## Catch\n## Challenge\n## Detect\n## Block\n",
        "## Challenge\n## Catch\n## Detect\n",
        "### Challenge\n## Catch\n## Detect\n## Block\n",
        "## Challenge\n## Catch\n## Detect\n## Block\n## Block\n",
    ],
)
def test_lens_heading_check_detects_a_planted_violation(text):
    assert _lens_headings(text) != LENS_HEADINGS


@pytest.mark.parametrize("agent", [agent for agent in SUBAGENTS if MANIFESTS[agent]["tools"]])
def test_prompts_of_agents_with_tools_state_their_tool_call_cap(agent):
    assert _states_cap(_read(MANIFESTS[agent]["prompt"]), MANIFESTS[agent]["max_tool_calls"])


@pytest.mark.parametrize("text", ["You can make at most twelve tool calls.", "You can make at most 13 tool calls."])
def test_tool_call_cap_check_detects_a_planted_violation(text):
    assert not _states_cap(text, 12)


@pytest.mark.parametrize("agent", SUBAGENTS)
def test_request_is_built_only_from_the_manifest(fake_anthropic, log, tmp_path, agent):
    client = fake_anthropic([_answer(OUTPUTS[agent])])
    _run(client, log, _workspace(tmp_path), agent)
    agent_manifest, (request,) = MANIFESTS[agent], client.requests
    schema = json.loads(_read(agent_manifest["output_schema"]))
    parts = [_read(agent_manifest["prompt"]), *(_read(skill) for skill in agent_manifest["skills"])]
    assert request["model"] == agent_manifest["model"]
    assert request["output_config"] == {
        "effort": agent_manifest["effort"],
        "format": {"type": "json_schema", "schema": schema},
    }
    assert request["system"] == "\n\n".join(part.strip() for part in parts)
    assert (request["betas"], request["fallbacks"]) == ([config.FALLBACK_BETA], config.FALLBACKS)
    if agent_manifest["tools"]:
        assert request["tools"] == [tools.definition(name) for name in agent_manifest["tools"]]
    else:
        assert "tools" not in request


def test_each_subagent_request_holds_only_its_scoped_tools(fake_anthropic, log, tmp_path):
    workspace, named = _workspace(tmp_path), {}
    for agent in SUBAGENTS:
        client = fake_anthropic([_answer(OUTPUTS[agent])])
        _run(client, log, workspace, agent)
        named[agent] = [tool["name"] for tool in client.requests[0].get("tools", [])]
    assert named == {
        "security_examiner": ["list_files", "read_file"],
        "dependency_examiner": ["list_manifests", "read_manifest", "query_osv"],
        "adversarial_reviewer": ["read_file"],
        "final_review_writer": [],
    }


def test_task_is_the_first_and_only_message_of_a_fresh_conversation(fake_anthropic, log, tmp_path):
    task = runner.examiner_task(
        MANIFESTS["security_examiner"], "secrets", workspace_label="acme-api", challenges=CHALLENGES, note="Re-check."
    )
    client, workspace = fake_anthropic([_answer(OUTPUTS["security_examiner"])]), _workspace(tmp_path)
    runner.run_subagent(
        client,
        log,
        MANIFESTS["security_examiner"],
        task,
        _context("security_examiner", workspace),
        workspace=workspace,
        workflow="security_examiner",
        step="secrets",
        parent_step_id=PARENT,
    )
    (message,) = client.requests[0]["messages"]
    assert message["role"] == "user"
    assert json.loads(message["content"]) == task


def test_examiner_task_holds_the_step_its_checklist_section_the_challenges_verbatim_and_the_note():
    examiner = MANIFESTS["security_examiner"]
    task = runner.examiner_task(
        examiner, "insecure_config", workspace_label="acme-api", challenges=CHALLENGES, note="Answer RV-1-C1."
    )
    assert task == {
        "workflow": "security_examiner",
        "step": "insecure_config",
        "workspace": "acme-api",
        "checklist": runner.checklist_section(examiner, "insecure_config"),
        "challenges": CHALLENGES,
        "note": "Answer RV-1-C1.",
    }


def test_first_examination_has_no_challenges():
    task = runner.examiner_task(
        MANIFESTS["dependency_examiner"], "known_vulnerabilities", workspace_label="acme-api", challenges=[], note=""
    )
    assert (task["challenges"], task["note"]) == ([], "")


def test_task_builders_keep_their_own_copy_of_the_challenges():
    challenges = json.loads(json.dumps(CHALLENGES))
    examiner = runner.examiner_task(
        MANIFESTS["security_examiner"], "secrets", workspace_label="acme-api", challenges=challenges, note=""
    )
    writer = runner.writer_task({"steps": [], "summary": ""}, {}, {}, challenges)
    challenges[0]["claim"] = "changed"
    challenges.append({})
    assert examiner["challenges"] == writer["challenges"] == CHALLENGES


@pytest.mark.parametrize("step", ["licences", "secret", "known_vulnerabilities", ""])
def test_examiner_task_refuses_a_step_its_manifest_does_not_declare(step):
    with pytest.raises(ValueError, match=f"security_examiner: '{step}' is not one of its steps"):
        runner.examiner_task(MANIFESTS["security_examiner"], step, workspace_label="acme-api", challenges=[], note="")


def test_examiner_task_refuses_an_undeclared_step_even_when_a_skill_covers_it(tmp_path, monkeypatch):
    examiner = _planted_skills(tmp_path, monkeypatch, "## secrets\n- keys\n\n## licences\n- GPL\n")
    with pytest.raises(ValueError, match="'licences' is not one of its steps"):
        runner.examiner_task(examiner, "licences", workspace_label="acme-api", challenges=[], note="")


def test_writer_task_holds_only_the_disposition_examinations_reviews_and_challenges():
    disposition = {"steps": [], "summary": "All accepted."}
    examinations, reviews = {"EX-SEC-v1": OUTPUTS["security_examiner"]}, {"RV-1": OUTPUTS["adversarial_reviewer"]}
    assert runner.writer_task(disposition, examinations, reviews, CHALLENGES) == {
        "disposition": disposition,
        "examinations": examinations,
        "reviews": reviews,
        "challenges": CHALLENGES,
    }


def _planted_skills(tmp_path, monkeypatch, *texts):
    (tmp_path / "skills").mkdir()
    for number, text in enumerate(texts):
        (tmp_path / "skills" / f"checks{number}.md").write_text(text)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    return {**MANIFESTS["security_examiner"], "skills": [f"skills/checks{number}.md" for number in range(len(texts))]}


def test_checklist_section_is_the_text_under_the_step_heading(tmp_path, monkeypatch):
    examiner = _planted_skills(
        tmp_path,
        monkeypatch,
        "# Checks\n\nIntro.\n\n## secrets\n\n- keys\n- tokens\n\n### Severity\n\n- high\n\n"
        "## insecure_config\n\n- debug\n",
    )
    assert runner.checklist_section(examiner, "secrets") == "- keys\n- tokens\n\n### Severity\n\n- high"
    assert runner.checklist_section(examiner, "insecure_config") == "- debug"


def test_checklist_section_may_come_from_any_of_the_skills(tmp_path, monkeypatch):
    examiner = _planted_skills(tmp_path, monkeypatch, "## insecure_config\n- debug\n", "## secrets\n- keys\n")
    assert runner.checklist_section(examiner, "secrets") == "- keys"


@pytest.mark.parametrize(
    "texts",
    [
        ("# Checks\n\n## insecure_config\n\n- debug\n",),
        ("## secrets\n- a\n\n## secrets\n- b\n",),
        ("## secrets\n- a\n", "## secrets\n- b\n"),
        ("## secretsx\n- a\n",),
        ("### secrets\n- a\n",),
        ("##secrets\n- a\n",),
    ],
)
def test_a_step_without_exactly_one_checklist_section_is_refused(tmp_path, monkeypatch, texts):
    with pytest.raises(ValueError, match="secrets"):
        runner.checklist_section(_planted_skills(tmp_path, monkeypatch, *texts), "secrets")


def test_accepted_examination_is_numbered_and_redacted(fake_anthropic, log, tmp_path):
    result = _run(fake_anthropic([_answer(OUTPUTS["security_examiner"])]), log, _workspace(tmp_path))
    assert result == {
        **OUTPUTS["security_examiner"],
        "findings": [{"id": "SEC-1", **SECRETS_FINDING, "evidence": 'AWS_ACCESS_KEY_ID = "<redacted:AKIA…>"'}],
    }


@pytest.mark.parametrize("agent", ["adversarial_reviewer", "final_review_writer"])
def test_accepted_review_or_draft_comes_back_as_written(fake_anthropic, log, tmp_path, agent):
    assert _run(fake_anthropic([_answer(OUTPUTS[agent])]), log, _workspace(tmp_path), agent) == OUTPUTS[agent]


def test_answer_after_thinking_and_across_text_blocks_is_read_as_one(fake_anthropic, log, tmp_path):
    text = json.dumps(OUTPUTS["adversarial_reviewer"])
    content = [
        {"type": "thinking", "thinking": "", "signature": "sig"},
        {"type": "text", "text": text[:20]},
        {"type": "text", "text": text[20:]},
    ]
    result = _run(fake_anthropic([_message(content)]), log, _workspace(tmp_path), "adversarial_reviewer")
    assert result == OUTPUTS["adversarial_reviewer"]


def test_declared_tool_runs_in_the_workspace_and_its_result_goes_back(fake_anthropic, log, tmp_path):
    workspace = _workspace(tmp_path)
    client = fake_anthropic([_calls(_tool_use("read_file", READ)), _answer(OUTPUTS["security_examiner"])])
    _run(client, log, workspace)
    expected = tools.execute(MANIFESTS["security_examiner"], "read_file", READ, workspace=workspace)
    assert client.requests[1]["messages"][-1] == {"role": "user", "content": [_result(expected.content)]}
    assert [line["event"] for line in _lines(log)] == ["llm_call", "tool_call", "llm_call"]
    assert _payloads(log, "tool_call") == [
        {**_labels("security_examiner"), "tool": "read_file", "allowed": True, "is_error": False}
    ]


def test_tool_call_line_holds_no_tool_input_or_output(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_calls(_tool_use("read_file", READ)), _answer(OUTPUTS["adversarial_reviewer"])])
    _run(client, log, _workspace(tmp_path), "adversarial_reviewer")
    text = log.path.read_text()
    assert "config.py" not in text and SECRET not in text and "DEBUG" not in text


def test_undeclared_tool_is_refused_unrun_with_an_error_result_and_an_audit_line(
    fake_anthropic, log, tmp_path, monkeypatch
):
    ran = []
    monkeypatch.setattr(files, "list_files", lambda *args: ran.append(args) or {})
    client = fake_anthropic(
        [_calls(_tool_use("list_files", {"directory": "."})), _answer(OUTPUTS["adversarial_reviewer"])]
    )
    _run(client, log, _workspace(tmp_path), "adversarial_reviewer")
    assert client.requests[1]["messages"][-1]["content"] == [
        _result("list_files: not a tool of adversarial_reviewer", is_error=True)
    ]
    assert ran == []
    assert _payloads(log, "tool_call") == [
        {**_labels("adversarial_reviewer"), "tool": "list_files", "allowed": False, "is_error": True}
    ]


@pytest.mark.parametrize("name", ["bash", "launch_security_examiner", "Read_File", "x" * 300])
def test_a_tool_outside_the_known_set_is_refused_and_audited_without_its_name(fake_anthropic, log, tmp_path, name):
    client = fake_anthropic([_calls(_tool_use(name, {})), _answer(OUTPUTS["security_examiner"])])
    _run(client, log, _workspace(tmp_path))
    assert client.requests[1]["messages"][-1]["content"] == [
        _result(f"{name}: not a tool of security_examiner", is_error=True)
    ]
    assert _payloads(log, "tool_call") == [
        {**_labels("security_examiner"), "tool": None, "allowed": False, "is_error": True}
    ]


@pytest.mark.parametrize(
    ("tool_input", "content"),
    [
        ({"path": "missing.py", "start_line": 1}, "read_file: missing.py: "),
        ({"path": "../config.py", "start_line": 1}, "read_file: ../config.py: outside the workspace"),
        ({"path": "config.py"}, "read_file: invalid input: "),
    ],
)
def test_a_failing_tool_call_is_an_error_result_that_stays_allowed(fake_anthropic, log, tmp_path, tool_input, content):
    client = fake_anthropic([_calls(_tool_use("read_file", tool_input)), _answer(OUTPUTS["security_examiner"])])
    _run(client, log, _workspace(tmp_path))
    (result,) = client.requests[1]["messages"][-1]["content"]
    assert result["is_error"] is True and result["content"].startswith(content)
    assert _payloads(log, "tool_call") == [
        {**_labels("security_examiner"), "tool": "read_file", "allowed": True, "is_error": True}
    ]


def test_parallel_tool_calls_return_every_result_in_one_message_in_order(fake_anthropic, log, tmp_path):
    workspace = _workspace(tmp_path)
    turn = _calls(_tool_use("list_files", {"directory": "."}, 1), _tool_use("read_file", READ, 2))
    client = fake_anthropic([turn, _answer(OUTPUTS["security_examiner"])])
    _run(client, log, workspace)
    examiner = MANIFESTS["security_examiner"]
    listed = tools.execute(examiner, "list_files", {"directory": "."}, workspace=workspace)
    read = tools.execute(examiner, "read_file", READ, workspace=workspace)
    assert client.requests[1]["messages"][1:] == [
        {"role": "assistant", "content": turn.content},
        {"role": "user", "content": [_result(listed.content, False, 1), _result(read.content, False, 2)]},
    ]
    assert [line["event"] for line in _lines(log)] == ["llm_call", "tool_call", "tool_call", "llm_call"]


def test_each_assistant_turn_goes_back_unchanged_and_earlier_messages_never_change(fake_anthropic, log, tmp_path):
    first = _calls(
        {"type": "thinking", "thinking": "", "signature": "sig-1"},
        {"type": "text", "text": "Reading the config."},
        _tool_use("read_file", READ, 1),
    )
    second = _calls(
        {"type": "thinking", "thinking": "", "signature": "sig-2"}, _tool_use("list_files", {"directory": ""}, 2)
    )
    client = fake_anthropic([first, second, _answer(OUTPUTS["security_examiner"])])
    _run(client, log, _workspace(tmp_path))
    _, after_first, after_second = (request["messages"] for request in client.requests)
    assert after_first[1] == {"role": "assistant", "content": first.content}
    assert after_second[: len(after_first)] == after_first
    assert after_second[len(after_first)] == {"role": "assistant", "content": second.content}
    assert len(after_second) == 5


def test_a_fallback_served_turn_goes_back_with_its_fallback_block(fake_anthropic, log, tmp_path):
    fallback = {
        "type": "fallback",
        "from": {"model": "claude-sonnet-5-5"},
        "to": {"model": "claude-sonnet-5"},
        "trigger": {"type": "refusal", "category": "cyber"},
    }
    turn = _calls(fallback, _tool_use("read_file", READ))
    client = fake_anthropic([turn, _answer(OUTPUTS["security_examiner"])])
    _run(client, log, _workspace(tmp_path))
    assert client.requests[1]["messages"][1] == {"role": "assistant", "content": turn.content}


def test_query_osv_goes_through_the_given_transport(fake_anthropic, log, tmp_path):
    queries, package = [], {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}
    client = fake_anthropic([_calls(_tool_use("query_osv", package)), _answer(OUTPUTS["dependency_examiner"])])
    _run(client, log, _workspace(tmp_path), "dependency_examiner", osv=_osv(queries))
    assert queries == [{"package": {"ecosystem": "PyPI", "name": "requests"}, "version": "2.19.0"}]
    (result,) = client.requests[1]["messages"][-1]["content"]
    assert [vuln["id"] for vuln in json.loads(result["content"])["vulns"]] == ["GHSA-test-0001"]


def test_twelve_tool_calls_then_an_answer_are_accepted(fake_anthropic, log, tmp_path):
    script = [_calls(_tool_use("read_file", READ, number)) for number in range(1, 13)]
    client = fake_anthropic([*script, _answer(OUTPUTS["security_examiner"])])
    assert _run(client, log, _workspace(tmp_path))["findings"][0]["id"] == "SEC-1"
    assert len(_lines(log, "tool_call")) == 12
    assert _lines(log, "guardrail_rejected") == []


def _assert_tool_loop_limit(raised, log, executed):
    assert (raised.value.code, raised.value.retryable) == ("TOOL_LOOP_LIMIT", True)
    assert "12" in raised.value.message
    assert len(_lines(log, "tool_call")) == executed
    assert _payloads(log, "guardrail_rejected") == [
        {**_labels("security_examiner"), "code": "TOOL_LOOP_LIMIT", "problems": len(raised.value.details)}
    ]


def test_the_thirteenth_tool_call_stops_the_invocation_unrun(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_calls(_tool_use("read_file", READ, number)) for number in range(1, 14)])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    assert len(client.requests) == 13
    _assert_tool_loop_limit(raised, log, executed=12)


def test_tool_calls_in_one_turn_count_toward_the_cap(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_calls(*(_tool_use("read_file", READ, number) for number in range(1, 14)))])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    assert len(client.requests) == 1
    _assert_tool_loop_limit(raised, log, executed=12)


def test_refused_tool_calls_count_toward_the_cap(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_calls(_tool_use("bash", {}, number)) for number in range(1, 14)])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    _assert_tool_loop_limit(raised, log, executed=12)
    assert {line["allowed"] for line in _lines(log, "tool_call")} == {False}


def test_tool_call_cap_comes_from_the_manifest(fake_anthropic, log, tmp_path):
    capped = {**MANIFESTS["security_examiner"], "max_tool_calls": 1}
    client = fake_anthropic([_calls(_tool_use("read_file", READ, 1)), _calls(_tool_use("read_file", READ, 2))])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path), agent_manifest=capped)
    assert raised.value.code == "TOOL_LOOP_LIMIT"
    assert len(client.requests) == 2
    assert len(_lines(log, "tool_call")) == 1


@pytest.mark.parametrize(
    ("stop_reason", "code", "retryable"),
    [
        ("refusal", "REFUSAL", False),
        ("max_tokens", "MAX_TOKENS", True),
        ("model_context_window_exceeded", "MAX_TOKENS", True),
        ("pause_turn", "API_ERROR", True),
    ],
)
def test_a_call_that_ends_without_an_answer_becomes_its_dispatch_error(
    fake_anthropic, log, tmp_path, stop_reason, code, retryable
):
    client = fake_anthropic([_message([{"type": "text", "text": "{"}], stop_reason)])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    assert (raised.value.code, raised.value.retryable) == (code, retryable)
    assert [line["event"] for line in _lines(log)] == ["llm_call"]


def test_an_sdk_error_after_its_retries_becomes_api_error(fake_anthropic, log, tmp_path):
    client = fake_anthropic([anthropic.APIConnectionError(request=REQUEST)])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    assert (raised.value.code, raised.value.retryable) == ("API_ERROR", True)
    assert _lines(log, "llm_call")[0]["error"] == "APIConnectionError"


def test_a_refusal_after_tool_calls_ends_the_invocation(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_calls(_tool_use("read_file", READ)), _message([], "refusal")])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    assert raised.value.code == "REFUSAL"
    assert [line["event"] for line in _lines(log)] == ["llm_call", "tool_call", "llm_call"]


@pytest.mark.parametrize(
    "content",
    [
        [{"type": "text", "text": "Here is the examination you asked for."}],
        [{"type": "text", "text": ""}],
        [{"type": "thinking", "thinking": "", "signature": "sig"}],
        [],
        [{"type": "text", "text": "[" * 1_000_000 + "]" * 1_000_000}],
    ],
)
def test_an_answer_that_is_not_json_is_schema_invalid(fake_anthropic, log, tmp_path, content):
    with pytest.raises(DispatchError) as raised:
        _run(fake_anthropic([_message(content)]), log, _workspace(tmp_path))
    assert raised.value.code == "SCHEMA_INVALID"
    assert raised.value.message.startswith("security_examiner: ")
    assert _payloads(log, "guardrail_rejected") == [
        {**_labels("security_examiner"), "code": "SCHEMA_INVALID", "problems": len(raised.value.details)}
    ]


CHALLENGE = {
    "finding_id": "SEC-1",
    "lens": "challenge",
    "severity": "major",
    "claim": "The key is AWS's documented example.",
    "evidence_checked": [{"file": "config.py", "line": 2}],
    "rationale": "Line 2 holds the documented example key.",
}


@pytest.mark.parametrize(
    ("agent", "output", "code"),
    [
        (
            "security_examiner",
            {key: value for key, value in OUTPUTS["security_examiner"].items() if key != "limitations"},
            "SCHEMA_INVALID",
        ),
        ("security_examiner", _examination(step="insecure_config"), "SCHEMA_INVALID"),
        ("security_examiner", _examination(findings=[{**SECRETS_FINDING, "line": 99}]), "EVIDENCE_INVALID"),
        ("security_examiner", _examination(findings=[{**SECRETS_FINDING, "file": "nope.env"}]), "EVIDENCE_INVALID"),
        ("adversarial_reviewer", {**OUTPUTS["adversarial_reviewer"], "challenges": [CHALLENGE]}, "SCHEMA_INVALID"),
        (
            "adversarial_reviewer",
            {
                **OUTPUTS["adversarial_reviewer"],
                "verdict": "challenge",
                "challenges": [{**CHALLENGE, "finding_id": "SEC-7"}],
            },
            "EVIDENCE_INVALID",
        ),
        ("final_review_writer", {**OUTPUTS["final_review_writer"], "sections": []}, "SCHEMA_INVALID"),
        (
            "final_review_writer",
            {**OUTPUTS["final_review_writer"], "executive_summary": "Rotate the key [SEC-9]."},
            "EVIDENCE_INVALID",
        ),
    ],
)
def test_an_answer_that_fails_its_guardrail_is_rejected_and_audited(
    fake_anthropic, log, tmp_path, agent, output, code
):
    with pytest.raises(DispatchError) as raised:
        _run(fake_anthropic([_answer(output)]), log, _workspace(tmp_path), agent)
    assert raised.value.code == code
    problems = len(raised.value.details)
    assert _payloads(log, "guardrail_rejected") == [{**_labels(agent), "code": code, "problems": problems}]
    assert _payloads(log, "guardrail_rejected")[0]["problems"] >= 1


def test_references_validate_checked_come_back_unmasked_while_their_text_is_masked(fake_anthropic, log, tmp_path):
    workspace, path = _workspace(tmp_path), "src/main/java/com/acme/aws/S3UploadServi.java"
    assert redact(path) != path and redact(TOKEN_LIKE) != TOKEN_LIKE
    (workspace.root / path).parent.mkdir(parents=True)
    (workspace.root / path).write_text(f'class S3UploadServi {{ String key = "{SECRET}"; }}\n')
    finding = {**SECRETS_FINDING, "file": path, "line": 1, "title": f"Key {path}", "evidence": f"key = {SECRET}"}
    output = {**_examination(findings=[finding]), "workflow": TOKEN_LIKE, "step": TOKEN_LIKE}
    ctx = ExaminationContext(TOKEN_LIKE, TOKEN_LIKE, "SEC", workspace)
    result = _run(fake_anthropic([_answer(output)]), log, workspace, ctx=ctx)
    (accepted,) = result["findings"]
    assert (result["workflow"], result["step"], accepted["file"]) == (TOKEN_LIKE, TOKEN_LIKE, path)
    assert accepted["title"] == "Key <redacted:src/…>.java"
    assert accepted["evidence"] == "key = <redacted:AKIA…>"


def test_review_and_draft_references_come_back_unmasked(fake_anthropic, log, tmp_path):
    workspace, target_id = _workspace(tmp_path), f"EX-{TOKEN_LIKE}"
    challenge = {**CHALLENGE, "finding_id": TOKEN_LIKE, "claim": f"{TOKEN_LIKE} is wrong."}
    review = {"target_id": target_id, "verdict": "challenge", "summary": "Checked.", "challenges": [challenge]}
    ctx = ReviewContext(target_id, [TOKEN_LIKE])
    result = _run(fake_anthropic([_answer(review)]), log, workspace, "adversarial_reviewer", ctx=ctx)
    (accepted,) = result["challenges"]
    assert (result["target_id"], accepted["finding_id"]) == (target_id, TOKEN_LIKE)
    assert accepted["claim"] == "<redacted:AbCd…> is wrong."
    key = f"security_examiner.{TOKEN_LIKE}"
    draft = {"executive_summary": "One finding [SEC-1].", "sections": [{"key": key, "prose": "Rotate it [SEC-1]."}]}
    ctx = WriterContext([("security_examiner", TOKEN_LIKE)], ["SEC-1"])
    result = _run(fake_anthropic([_answer(draft)]), log, workspace, "final_review_writer", ctx=ctx)
    assert result["sections"][0]["key"] == key


@pytest.mark.parametrize(
    ("path", "masked"),
    [
        (f"{SECRET}/../config.py", "<redacted:AKIA…>/../config.py"),
        (f"./{SECRET}/../config.py", "./<redacted:AKIA…>/../config.py"),
        (f"{SECRET}//../config.py", "<redacted:AKIA…>//../config.py"),
        (f"{SECRET}/.././config.py", "<redacted:AKIA…>/.././config.py"),
    ],
)
def test_a_file_path_that_is_not_in_plain_form_is_masked(fake_anthropic, log, tmp_path, path, masked):
    output = _examination(findings=[{**SECRETS_FINDING, "file": path}])
    result = _run(fake_anthropic([_answer(output)]), log, _workspace(tmp_path))
    assert result["findings"][0]["file"] == masked


@pytest.mark.parametrize(
    ("path", "returned"),
    [
        (f"keys/{SECRET}.txt", f"keys/{SECRET}.txt"),
        (f"./keys/{SECRET}.txt", f"./keys/{SECRET}.txt"),
        (f"keys//{SECRET}.txt", f"keys//{SECRET}.txt"),
        (f"keys/./{SECRET}.txt", f"keys/./{SECRET}.txt"),
        ("./src/main/java/com/acme/aws/S3UploadServ.java", "./src/main/java/com/acme/aws/S3UploadServ.java"),
        (f"keys/{SECRET}..bak", f"keys/{SECRET}..bak"),
        (f"keys/../keys/{SECRET}.txt", "keys/../keys/<redacted:AKIA…>.txt"),
    ],
)
def test_a_file_named_like_a_key_is_kept_unless_a_dotdot_segment_could_hide_text(
    fake_anthropic, log, tmp_path, path, returned
):
    workspace = _workspace(tmp_path)
    for real in (f"keys/{SECRET}.txt", f"keys/{SECRET}..bak", "src/main/java/com/acme/aws/S3UploadServ.java"):
        (workspace.root / real).parent.mkdir(parents=True, exist_ok=True)
        (workspace.root / real).write_text("rotate me\n")
    output = _examination(findings=[{**SECRETS_FINDING, "file": path, "line": 1}])
    assert _run(fake_anthropic([_answer(output)]), log, workspace)["findings"][0]["file"] == returned


@pytest.mark.parametrize("path", [f"nope/./{SECRET}.txt", f"{SECRET}//config.py", f"{SECRET}/./config.py"])
def test_a_segment_that_names_nothing_fails_validation_unless_a_dotdot_follows(fake_anthropic, log, tmp_path, path):
    output = _examination(findings=[{**SECRETS_FINDING, "file": path, "line": 1}])
    with pytest.raises(DispatchError) as raised:
        _run(fake_anthropic([_answer(output)]), log, _workspace(tmp_path))
    assert raised.value.code == "EVIDENCE_INVALID"


def test_a_reviewer_evidence_file_is_still_masked(fake_anthropic, log, tmp_path):
    evidence = [{"file": f"{TOKEN_LIKE}.env", "line": 1}]
    review = {
        **OUTPUTS["adversarial_reviewer"],
        "verdict": "challenge",
        "challenges": [{**CHALLENGE, "evidence_checked": evidence}],
    }
    result = _run(fake_anthropic([_answer(review)]), log, _workspace(tmp_path), "adversarial_reviewer")
    assert result["challenges"][0]["evidence_checked"] == [{"file": "<redacted:AbCd…>.env", "line": 1}]


def test_a_tool_use_stop_that_calls_no_tool_is_an_api_error(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_message([{"type": "text", "text": "Let me look."}], "tool_use")])
    with pytest.raises(DispatchError) as raised:
        _run(client, log, _workspace(tmp_path))
    assert (raised.value.code, raised.value.retryable) == ("API_ERROR", True)
    assert len(client.requests) == 1
    rejected = {**_labels("security_examiner"), "code": "API_ERROR", "problems": 0}
    assert _payloads(log, "guardrail_rejected") == [rejected]


def test_a_context_of_the_wrong_contract_raises_type_error(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_answer(OUTPUTS["security_examiner"])])
    with pytest.raises(TypeError, match="ExaminationContext"):
        _run(client, log, _workspace(tmp_path), ctx=ReviewContext("EX-SEC-v1", []))


def test_an_output_schema_that_names_no_contract_raises_value_error(fake_anthropic, log, tmp_path):
    examiner = {**MANIFESTS["security_examiner"], "output_schema": "schemas/dispatch_error.schema.json"}
    client = fake_anthropic([_answer(OUTPUTS["security_examiner"])])
    with pytest.raises(ValueError, match="not a contract: dispatch_error"):
        _run(client, log, _workspace(tmp_path), agent_manifest=examiner)


def test_a_broken_replay_file_raises_and_writes_no_tool_line(fake_anthropic, log, tmp_path, monkeypatch):
    replay = tmp_path / "replay.json"
    replay.write_text("{not json")
    monkeypatch.setenv("ASSESSOR_OSV_REPLAY", str(replay))
    package = {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}
    client = fake_anthropic([_calls(_tool_use("query_osv", package))])
    with pytest.raises(ValueError, match="replay.json"):
        _run(client, log, _workspace(tmp_path), "dependency_examiner", osv=None)
    assert _lines(log, "tool_call") == []


@pytest.mark.parametrize("field", ["prompt", "skills", "output_schema"])
def test_a_missing_agent_file_raises_before_any_call(fake_anthropic, log, tmp_path, field):
    missing = {
        "prompt": "prompts/nobody.md",
        "skills": ["skills/nothing.md"],
        "output_schema": "schemas/no.schema.json",
    }
    client, examiner = fake_anthropic([]), {**MANIFESTS["security_examiner"], field: missing[field]}
    with pytest.raises(FileNotFoundError):
        _run(client, log, _workspace(tmp_path), agent_manifest=examiner)
    assert client.requests == []


def test_a_failed_audit_write_stops_the_invocation_before_the_tool_result_is_sent(
    fake_anthropic, log, tmp_path, monkeypatch
):
    def fail_on_the_tool_line(descriptor, real=audit.os.fsync):
        if '"tool_call"' in log.path.read_text().splitlines()[-1]:
            raise OSError("disk full")
        real(descriptor)

    monkeypatch.setattr(audit.os, "fsync", fail_on_the_tool_line)
    client = fake_anthropic([_calls(_tool_use("read_file", READ))])
    with pytest.raises(OSError, match="disk full"):
        _run(client, log, _workspace(tmp_path))
    assert len(client.requests) == 1


def test_a_rejected_answer_keeps_secrets_out_of_the_error_and_the_audit(fake_anthropic, log, tmp_path):
    output = _examination(findings=[{**SECRETS_FINDING, "line": SECRET}])
    with pytest.raises(DispatchError) as raised:
        _run(fake_anthropic([_answer(output)]), log, _workspace(tmp_path))
    assert SECRET not in json.dumps(raised.value.to_result())
    assert SECRET not in log.path.read_text()


def test_every_line_carries_the_dispatch_labels(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_calls(_tool_use("read_file", READ)), _answer(OUTPUTS["adversarial_reviewer"])])
    _run(client, log, _workspace(tmp_path), "adversarial_reviewer")
    labels = _labels("adversarial_reviewer")
    assert [{key: line[key] for key in labels} for line in _lines(log)] == [labels] * 3
