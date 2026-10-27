import copy
import json
import os

import jsonschema
import pytest

from assessor import config, guardrails, manifest, sandbox

SCHEMAS = {name: json.loads((config.SCHEMAS_DIR / f"{name}.schema.json").read_text()) for name in config.CONTRACTS}
DISPATCH_ERROR_SCHEMA = json.loads((config.SCHEMAS_DIR / "dispatch_error.schema.json").read_text())
STRICT_KEYWORDS = {"type", "properties", "required", "enum", "items", "additionalProperties"}
STEPS = [
    ("security_examiner", "secrets"),
    ("security_examiner", "insecure_config"),
    ("dependency_examiner", "known_vulnerabilities"),
    ("dependency_examiner", "dependency_hygiene"),
]
KEYS = [f"{workflow}.{step}" for workflow, step in STEPS]
EXAMINATIONS = {"EX-SEC-v1": STEPS[0], "EX-CFG-v1": STEPS[1], "EX-VULN-v1": STEPS[2], "EX-HYG-v1": STEPS[3]}
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


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


def _workspace(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "config.py").write_text("DEBUG = True\nAWS_KEY = 'x'\nCORS = '*'\n")
    (repo / "src" / "app.py").write_text("print('hi')\n")
    (repo / "requirements.txt").write_text("requests==2.19.0\n")
    (repo / "empty.txt").write_text("")
    (repo / "logo.png").write_bytes(b"\x89PNG\x00\x00")
    (repo / "big.txt").write_text("x" * (config.READ_MAX_BYTES + 1))
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n")
    (tmp_path / "outside.py").write_text("SECRET = 1\n")
    (repo / "link.py").symlink_to(tmp_path / "outside.py")
    return sandbox.Workspace(repo)


def _finding(**changes):
    return {
        "title": "Debug mode on",
        "severity": "high",
        "category": "debug",
        "file": "config.py",
        "line": 1,
        "evidence": "DEBUG = True",
        "recommendation": "Turn debug off in production.",
        "advisory_ids": [],
        **changes,
    }


def _examination(*findings, **changes):
    return {
        "workflow": "security_examiner",
        "step": "insecure_config",
        "summary": "One unsafe setting.",
        "findings": list(findings),
        "limitations": [],
        "challenge_responses": [],
        **changes,
    }


def _exam_ctx(tmp_path, workflow="security_examiner", step="insecure_config", code="CFG"):
    return guardrails.ExaminationContext(workflow=workflow, step=step, code=code, workspace=_workspace(tmp_path))


def _challenge(**changes):
    return {
        "finding_id": "CFG-1",
        "lens": "challenge",
        "severity": "major",
        "claim": "The severity is understated.",
        "evidence_checked": [{"file": "config.py", "line": 1}],
        "rationale": "Debug mode exposes a console.",
        **changes,
    }


def _review(*challenges, verdict=None, **changes):
    if verdict is None:
        verdict = "pass" if not challenges else "challenge"
    review = {"target_id": "EX-CFG-v1", "verdict": verdict, "summary": "Checked.", "challenges": list(challenges)}
    return {**review, **changes}


def _review_ctx(target_id="EX-CFG-v1", finding_ids=("CFG-1", "CFG-2")):
    return guardrails.ReviewContext(target_id=target_id, finding_ids=frozenset(finding_ids))


def _writer(sections=None, summary="Two of four steps fail [SEC-1]."):
    if sections is None:
        sections = [{"key": key, "prose": f"Prose for {key}."} for key in KEYS]
    return {"executive_summary": summary, "sections": sections}


def _writer_ctx(input_ids=("SEC-1", "CFG-1", "VULN-1", "RV-1", "RV-1-C1", "EX-SEC-v1")):
    return guardrails.WriterContext(steps=STEPS, input_ids=frozenset(input_ids))


def _entry(workflow, step, examination_id, decision="accept"):
    entry = {"workflow": workflow, "step": step, "examination_id": examination_id, "decision": decision}
    return {**entry, "rationale": "ok"}


def _disposition(entries=None):
    if entries is None:
        entries = [_entry(*steps, examination_id) for examination_id, steps in EXAMINATIONS.items()]
    return {"steps": entries, "summary": "All steps reviewed."}


def _disposition_ctx(examinations=None, reviewed=tuple(EXAMINATIONS)):
    return guardrails.DispositionContext(
        steps=STEPS, examinations=EXAMINATIONS if examinations is None else examinations, reviewed=frozenset(reviewed)
    )


def _rejected(contract, output, ctx):
    with pytest.raises(guardrails.DispatchError) as caught:
        guardrails.validate(contract, output, ctx)
    return caught.value


def test_dispatch_error_codes_are_the_closed_set():
    assert config.DISPATCH_ERROR_CODES == (
        "SCHEMA_INVALID",
        "EVIDENCE_INVALID",
        "PRECONDITION_FAILED",
        "UNKNOWN_TARGET",
        "RETRY_CAP_REACHED",
        "TOOL_LOOP_LIMIT",
        *config.LLM_ERROR_CODES,
    )
    assert config.RETRYABLE_DISPATCH_ERRORS == (
        "SCHEMA_INVALID",
        "EVIDENCE_INVALID",
        "TOOL_LOOP_LIMIT",
        "MAX_TOKENS",
        "API_ERROR",
    )


@pytest.mark.parametrize("code", config.DISPATCH_ERROR_CODES)
def test_every_dispatch_error_result_matches_its_schema(code):
    result = guardrails.DispatchError(code, "failed", ["a detail"]).to_result()
    jsonschema.Draft202012Validator(DISPATCH_ERROR_SCHEMA).validate(result)
    assert result == {
        "error": {
            "code": code,
            "message": "failed",
            "retryable": code in config.RETRYABLE_DISPATCH_ERRORS,
            "details": ["a detail"],
        }
    }


@pytest.mark.parametrize(
    "error",
    [
        {"code": "SCHEMA_INVALID", "message": "m", "retryable": False, "details": []},
        {"code": "REFUSAL", "message": "m", "retryable": True, "details": []},
        {"code": "SCHEMA_INVALID", "message": "m", "retryable": True},
        {"code": "SCHEMA_INVALID", "message": "m", "retryable": True, "details": [], "output": {}},
        {"code": "BROKEN", "message": "m", "retryable": True, "details": []},
    ],
)
def test_dispatch_error_schema_detects_a_planted_violation(error):
    assert not jsonschema.Draft202012Validator(DISPATCH_ERROR_SCHEMA).is_valid({"error": error})


def test_dispatch_error_schema_lists_the_closed_sets():
    error = DISPATCH_ERROR_SCHEMA["properties"]["error"]
    assert error["properties"]["code"]["enum"] == list(config.DISPATCH_ERROR_CODES)
    assert error["if"]["properties"]["code"]["enum"] == list(config.RETRYABLE_DISPATCH_ERRORS)


def test_an_unknown_dispatch_error_code_is_refused():
    with pytest.raises(ValueError, match="not a dispatch error code: BROKEN"):
        guardrails.DispatchError("BROKEN", "m")


def test_dispatch_error_details_are_capped():
    error = guardrails.DispatchError("SCHEMA_INVALID", "m", [f"problem {n}" for n in range(50)])
    shown = config.DISPATCH_ERROR_MAX_DETAILS - 1
    assert len(error.details) == config.DISPATCH_ERROR_MAX_DETAILS
    assert error.details[:shown] == [f"problem {n}" for n in range(shown)]
    assert error.details[-1] == f"{50 - shown} more not shown"


def test_dispatch_error_details_at_the_cap_are_all_shown():
    details = [f"problem {n}" for n in range(config.DISPATCH_ERROR_MAX_DETAILS)]
    assert guardrails.DispatchError("SCHEMA_INVALID", "m", details).details == details


def test_dispatch_error_text_is_cut_to_the_cap():
    cap = config.DISPATCH_ERROR_TEXT_MAX_CHARS
    error = guardrails.DispatchError("SCHEMA_INVALID", "m" * (cap + 5), ["d" * cap, "e" * (cap + 1)])
    assert error.message == "m" * (cap - 1) + "…"
    assert error.details == ["d" * cap, "e" * (cap - 1) + "…"]


def test_dispatch_error_text_never_carries_a_secret_or_a_lone_surrogate():
    error = guardrails.DispatchError("EVIDENCE_INVALID", f"key {AWS_KEY}", [f"file {AWS_KEY}.py", "bad \ud800 name"])
    text = json.dumps(error.to_result(), ensure_ascii=False)
    assert AWS_KEY not in text
    assert "<redacted:AKIA…>" in error.message
    assert error.details[1] == "bad \\ud800 name"
    text.encode("utf-8")


def test_dispatch_error_str_names_the_code_and_message():
    assert str(guardrails.DispatchError("UNKNOWN_TARGET", "no such examination")) == (
        "UNKNOWN_TARGET: no such examination"
    )


def test_contracts_are_the_planned_closed_set():
    assert config.CONTRACTS == ("examination", "review", "writer_output", "disposition")


@pytest.mark.parametrize("contract", config.CONTRACTS)
def test_output_schemas_stay_inside_the_strict_subset(contract):
    assert _outside_strict_subset(SCHEMAS[contract]) == []


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ({"type": "string", "minLength": 1}, ["schema: minLength"]),
        ({"type": "object", "properties": {}}, ["schema: additionalProperties"]),
        (
            {"type": "object", "properties": {"a": {"type": "string"}}, "required": [], "additionalProperties": False},
            ["schema: required"],
        ),
        ({"type": "array", "items": {"type": "integer", "minimum": 1}}, ["schema[]: minimum"]),
    ],
)
def test_strict_subset_check_detects_a_planted_violation(planted, expected):
    assert _outside_strict_subset(planted) == expected


@pytest.mark.parametrize("schema", [*SCHEMAS.values(), DISPATCH_ERROR_SCHEMA])
def test_schemas_are_valid_draft_2020_12(schema):
    jsonschema.Draft202012Validator.check_schema(schema)


def test_schema_closed_sets_match_config():
    finding = SCHEMAS["examination"]["properties"]["findings"]["items"]["properties"]
    response = SCHEMAS["examination"]["properties"]["challenge_responses"]["items"]["properties"]
    challenge = SCHEMAS["review"]["properties"]["challenges"]["items"]["properties"]
    step = SCHEMAS["disposition"]["properties"]["steps"]["items"]["properties"]
    assert finding["severity"]["enum"] == list(config.FINDING_SEVERITIES)
    assert response["response"]["enum"] == list(config.CHALLENGE_RESPONSES)
    assert SCHEMAS["review"]["properties"]["verdict"]["enum"] == list(config.REVIEW_VERDICTS)
    assert challenge["lens"]["enum"] == list(config.LENSES)
    assert challenge["severity"]["enum"] == list(config.CHALLENGE_SEVERITIES)
    assert step["decision"]["enum"] == list(config.DISPOSITION_DECISIONS)


def test_value_closed_sets_are_the_planned_ones():
    assert config.FINDING_SEVERITIES == ("critical", "high", "medium", "low")
    assert config.REVIEW_VERDICTS == ("pass", "challenge", "block")
    assert config.LENSES == ("challenge", "catch", "detect")
    assert config.CHALLENGE_SEVERITIES == ("critical", "major", "minor")
    assert config.CHALLENGE_RESPONSES == ("upheld", "rejected")
    assert config.DISPOSITION_DECISIONS == ("accept", "escalate")


def test_guardrail_settings_are_the_documented_ones():
    assert config.ADVISORY_STEP == "known_vulnerabilities"
    assert (config.DISPATCH_ERROR_MAX_DETAILS, config.DISPATCH_ERROR_TEXT_MAX_CHARS) == (20, 300)
    assert config.REDACT_KEEP_CHARS == 4


def test_every_shipped_output_schema_is_a_contract():
    for agent in manifest.load_manifests().values():
        if "output_schema" in agent:
            path = config.ROOT / agent["output_schema"]
            assert path.is_file()
            assert path.name.removesuffix(".schema.json") in config.CONTRACTS


def test_advisory_step_is_a_shipped_examiner_step():
    steps = [step["name"] for agent in manifest.load_manifests().values() for step in agent.get("steps", [])]
    assert config.ADVISORY_STEP in steps


@pytest.mark.parametrize("contract", config.CONTRACTS)
def test_every_contract_has_its_own_context(contract):
    with pytest.raises(TypeError, match=f"^{contract} needs a [A-Za-z]+Context, not object$"):
        guardrails.validate(contract, {}, object())


def _valid_outputs():
    finding = _finding(advisory_ids=["GHSA-x"])
    response = {"challenge_id": "RV-1-C1", "response": "upheld", "rationale": "ok"}
    return {
        "examination": _examination(finding, limitations=["none"], challenge_responses=[response]),
        "review": _review(_challenge()),
        "writer_output": _writer(),
        "disposition": _disposition(),
    }


def _leaves(schema, value, path=()):
    """Yield (path, value with that leaf replaced by a value of the wrong JSON type) for each leaf of schema."""
    wrong = {"string": 1, "integer": "1", "array": "x", "object": []}
    if path:
        yield path, wrong[schema["type"]]
    if schema["type"] == "object":
        for name, child in schema["properties"].items():
            yield from _leaves(child, value[name], (*path, name))
    elif schema["type"] == "array":
        yield from _leaves(schema["items"], value[0], (*path, 0))


def _replaced(value, path, new):
    value = copy.deepcopy(value)
    target = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = new
    return value


@pytest.mark.parametrize(
    ("contract", "path", "wrong"),
    [
        (contract, path, wrong)
        for contract, output in _valid_outputs().items()
        for path, wrong in _leaves(SCHEMAS[contract], output)
    ],
)
def test_every_field_of_the_wrong_type_is_schema_invalid(tmp_path, contract, path, wrong):
    ctx = {
        "examination": _exam_ctx(tmp_path),
        "review": _review_ctx(),
        "writer_output": _writer_ctx(),
        "disposition": _disposition_ctx(),
    }[contract]
    error = _rejected(contract, _replaced(_valid_outputs()[contract], path, wrong), ctx)
    where = "/".join(str(part) for part in path)
    assert error.code == "SCHEMA_INVALID"
    assert any(detail.startswith(f"{where}: ") for detail in error.details), error.details


def test_an_unknown_contract_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not a contract: report"):
        guardrails.validate("report", {}, _exam_ctx(tmp_path))


def test_a_context_for_another_contract_is_refused():
    with pytest.raises(TypeError, match="review needs a ReviewContext, not WriterContext"):
        guardrails.validate("review", _review(), _writer_ctx())


def test_a_valid_examination_is_accepted_with_finding_ids(tmp_path):
    output = _examination(_finding(), _finding(file="config.py", line=3, severity="medium"))
    accepted = guardrails.validate("examination", output, _exam_ctx(tmp_path))
    assert accepted == {**output, "findings": [{"id": "CFG-1", **_finding()}, {"id": "CFG-2", **output["findings"][1]}]}


def test_findings_get_unique_ids_in_step_order_even_when_identical(tmp_path):
    output = _examination(*[_finding()] * 3)
    accepted = guardrails.validate("examination", output, _exam_ctx(tmp_path))
    assert [finding["id"] for finding in accepted["findings"]] == ["CFG-1", "CFG-2", "CFG-3"]


def test_an_examination_with_no_findings_is_accepted(tmp_path):
    output = _examination(limitations=["No manifest found."])
    assert guardrails.validate("examination", output, _exam_ctx(tmp_path)) == output


def test_validate_leaves_its_input_unchanged(tmp_path):
    output = _examination(_finding())
    before = copy.deepcopy(output)
    accepted = guardrails.validate("examination", output, _exam_ctx(tmp_path))
    assert output == before
    accepted["findings"][0]["advisory_ids"].append("X")
    assert output == before


@pytest.mark.parametrize(
    ("contract", "output", "where"),
    [
        ("examination", [], "the top level: [] is not of type 'object'"),
        ("examination", {**_examination(), "status": "PASS"}, "the top level: Additional properties are not"),
        (
            "examination",
            {k: v for k, v in _examination().items() if k != "limitations"},
            "the top level: 'limitations' is a required",
        ),
        ("examination", _examination(_finding(severity="severe")), "findings/0/severity: 'severe' is not one of"),
        ("examination", _examination(_finding(line="1")), "findings/0/line: '1' is not of type 'integer'"),
        ("examination", _examination(_finding(line=1.0)), "findings/0/line: 1.0 is not of type 'integer'"),
        ("examination", _examination(_finding(line=True)), "findings/0/line: True is not of type 'integer'"),
        ("examination", _examination(_finding(id="CFG-9")), "findings/0: Additional properties are not allowed"),
        ("examination", _examination(_finding(advisory_ids=[1])), "findings/0/advisory_ids/0: 1 is not of type"),
        (
            "examination",
            _examination(challenge_responses=[{"challenge_id": "RV-1-C1", "response": "ignored", "rationale": ""}]),
            "challenge_responses/0/response: 'ignored' is not one of",
        ),
        ("review", _review(verdict="approve"), "verdict: 'approve' is not one of"),
        ("review", _review(_challenge(lens="nitpick")), "challenges/0/lens: 'nitpick' is not one of"),
        ("review", _review(_challenge(severity="high")), "challenges/0/severity: 'high' is not one of"),
        ("review", _review(_challenge(evidence_checked=[{"file": "a"}])), "challenges/0/evidence_checked/0: 'line'"),
        ("review", {**_review(), "challenges": None}, "challenges: None is not of type 'array'"),
        ("writer_output", {"sections": []}, "the top level: 'executive_summary' is a required property"),
        ("writer_output", _writer([{"key": KEYS[0], "prose": 1}]), "sections/0/prose: 1 is not of type 'string'"),
        ("disposition", _disposition([_entry(*STEPS[0], "EX-SEC-v1", "approve")]), "steps/0/decision: 'approve'"),
        ("disposition", {"steps": []}, "the top level: 'summary' is a required property"),
    ],
)
def test_output_outside_its_schema_is_schema_invalid(tmp_path, contract, output, where):
    ctx = {
        "examination": _exam_ctx(tmp_path),
        "review": _review_ctx(),
        "writer_output": _writer_ctx(),
        "disposition": _disposition_ctx(),
    }[contract]
    error = _rejected(contract, output, ctx)
    assert (error.code, error.retryable) == ("SCHEMA_INVALID", True)
    assert error.message == f"{contract} does not match schemas/{contract}.schema.json"
    assert any(detail.startswith(where) for detail in error.details), error.details


def test_every_schema_problem_is_listed(tmp_path):
    output = _examination(_finding(severity="severe", line="1"))
    error = _rejected("examination", output, _exam_ctx(tmp_path))
    assert sorted(detail.split(":")[0] for detail in error.details) == ["findings/0/line", "findings/0/severity"]


def test_deeply_nested_output_is_schema_invalid(tmp_path):
    nested = []
    for _ in range(100_000):
        nested = [nested]
    error = _rejected("examination", _examination(limitations=nested), _exam_ctx(tmp_path))
    assert (error.code, error.details) == ("SCHEMA_INVALID", ["the top level: nested too deeply"])


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"workflow": "dependency_examiner"}, "step: dependency_examiner.insecure_config is not the dispatched "),
        ({"step": "secrets"}, "step: security_examiner.secrets is not the dispatched "),
    ],
)
def test_an_examination_for_another_step_is_schema_invalid(tmp_path, changes, detail):
    error = _rejected("examination", _examination(**changes), _exam_ctx(tmp_path))
    assert error.code == "SCHEMA_INVALID"
    assert error.message == "examination does not fit its dispatch or leaves required text empty"
    assert error.details == [detail + "security_examiner.insecure_config"]


def test_advisory_ids_outside_the_advisory_step_are_schema_invalid(tmp_path):
    output = _examination(_finding(), _finding(advisory_ids=["GHSA-x"]))
    error = _rejected("examination", output, _exam_ctx(tmp_path))
    assert error.code == "SCHEMA_INVALID"
    assert error.details == [f"findings/1/advisory_ids: only {config.ADVISORY_STEP} findings cite advisories"]


def test_advisory_ids_on_the_advisory_step_are_accepted(tmp_path):
    ctx = _exam_ctx(tmp_path, workflow="dependency_examiner", step="known_vulnerabilities", code="VULN")
    finding = _finding(file="requirements.txt", line=1, advisory_ids=["GHSA-x", "PYSEC-2018-28"])
    output = _examination(finding, workflow="dependency_examiner", step="known_vulnerabilities")
    accepted = guardrails.validate("examination", output, ctx)
    assert accepted["findings"] == [{"id": "VULN-1", **finding}]


@pytest.mark.parametrize("line", [1, 3])
def test_a_line_inside_the_file_is_accepted(tmp_path, line):
    assert guardrails.validate("examination", _examination(_finding(line=line)), _exam_ctx(tmp_path))


@pytest.mark.parametrize("line", [0, -1, 4, 10**30])
def test_a_line_outside_the_file_is_evidence_invalid(tmp_path, line):
    error = _rejected("examination", _examination(_finding(), _finding(line=line)), _exam_ctx(tmp_path))
    assert (error.code, error.retryable) == ("EVIDENCE_INVALID", True)
    assert error.message == "examination cites a file or line the workspace does not have"
    assert error.details == [f"findings/1/line: {line} is not a line of config.py (3 lines)"]


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("missing.py", "missing.py: not a file"),
        ("src", "src: not a file"),
        ("", ".: not a file"),
        ("empty.txt", None),
        ("logo.png", "logo.png: binary file"),
        ("big.txt", f"big.txt: larger than the {config.READ_MAX_BYTES}-byte read limit"),
        ("../outside.py", "../outside.py: outside the workspace"),
        ("link.py", "link.py: outside the workspace"),
        ("/etc/passwd", "/etc/passwd: absolute paths are refused"),
        (".git/config", ".git/config: files under .git are not read"),
    ],
)
def test_a_file_the_workspace_cannot_show_is_evidence_invalid(tmp_path, path, reason):
    error = _rejected("examination", _examination(_finding(file=path)), _exam_ctx(tmp_path))
    assert error.code == "EVIDENCE_INVALID"
    if reason is None:
        assert error.details == [f"findings/0/line: 1 is not a line of {path} (0 lines)"]
    else:
        assert len(error.details) == 1
        assert error.details[0].startswith(f"findings/0/file: {reason}")
    assert str(tmp_path) not in error.details[0]


def test_files_in_subdirectories_are_cited_by_relative_path(tmp_path):
    output = _examination(_finding(file="src/app.py", line=1))
    assert guardrails.validate("examination", output, _exam_ctx(tmp_path))["findings"][0]["id"] == "CFG-1"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable files")
def test_an_unreadable_file_is_evidence_invalid_without_the_absolute_path(tmp_path):
    ctx = _exam_ctx(tmp_path)
    (ctx.workspace.root / "config.py").chmod(0)
    try:
        error = _rejected("examination", _examination(_finding()), ctx)
    finally:
        (ctx.workspace.root / "config.py").chmod(0o644)
    assert (error.code, error.details) == ("EVIDENCE_INVALID", ["findings/0/file: config.py: Permission denied"])


def test_each_bad_finding_is_listed_and_each_file_is_read_once(tmp_path, monkeypatch):
    ctx = _exam_ctx(tmp_path)
    reads = []
    real = sandbox.Workspace.read_lines
    monkeypatch.setattr(sandbox.Workspace, "read_lines", lambda self, path: reads.append(path) or real(self, path))
    output = _examination(_finding(line=9), _finding(file="nope.py"), _finding(line=2), _finding(line=0))
    error = _rejected("examination", output, ctx)
    assert [detail.split(":")[0] for detail in error.details] == [
        "findings/0/line",
        "findings/1/file",
        "findings/3/line",
    ]
    assert sorted(reads) == ["config.py", "nope.py"]


def test_schema_problems_are_reported_before_semantic_ones(tmp_path):
    output = _examination(_finding(file="nope.py"), _finding(severity="severe"), step="secrets")
    error = _rejected("examination", output, _exam_ctx(tmp_path))
    assert error.code == "SCHEMA_INVALID"
    assert [detail.split(":")[0] for detail in error.details] == ["findings/1/severity"]


def test_dispatch_problems_are_reported_before_evidence_ones(tmp_path):
    error = _rejected("examination", _examination(_finding(file="nope.py"), step="secrets"), _exam_ctx(tmp_path))
    assert error.code == "SCHEMA_INVALID"


@pytest.mark.parametrize(
    "challenges",
    [
        [],
        [_challenge(severity="minor")],
        [_challenge(severity="major"), _challenge(severity="minor", lens="catch", finding_id="")],
        [_challenge(severity="critical")],
        [_challenge(severity="minor"), _challenge(severity="critical", lens="detect")],
    ],
)
@pytest.mark.parametrize("verdict", config.REVIEW_VERDICTS)
def test_verdict_must_match_its_challenges(challenges, verdict):
    severities = [challenge["severity"] for challenge in challenges]
    expected = "pass" if not challenges else "block" if "critical" in severities else "challenge"
    review = _review(*challenges, verdict=verdict)
    if verdict == expected:
        assert guardrails.validate("review", review, _review_ctx()) == review
        return
    error = _rejected("review", review, _review_ctx())
    assert (error.code, error.message) == ("SCHEMA_INVALID", "review does not fit its target or its challenges")
    critical = severities.count("critical")
    assert error.details == [
        f"verdict: {verdict} does not match {len(challenges)} challenge(s), {critical} critical; it must be {expected}"
    ]


@pytest.mark.parametrize("field", ["title", "evidence", "recommendation"])
@pytest.mark.parametrize("blank", ["", " \n\t"])
def test_a_finding_with_empty_required_text_is_schema_invalid(tmp_path, field, blank):
    error = _rejected("examination", _examination(_finding(), _finding(**{field: blank})), _exam_ctx(tmp_path))
    assert (error.code, error.details) == ("SCHEMA_INVALID", [f"findings/1/{field}: empty"])


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"claim": ""}, "challenges/0/claim: empty"),
        ({"rationale": "  "}, "challenges/0/rationale: empty"),
        ({"evidence_checked": []}, "challenges/0/evidence_checked: empty; cite at least one file and line"),
        ({"evidence_checked": [{"file": "a", "line": 0}]}, "challenges/0/evidence_checked/0/line: 0 is not a line"),
        (
            {"evidence_checked": [{"file": "a", "line": 1}, {"file": "b", "line": -7}]},
            "challenges/0/evidence_checked/1/line: -7 is not a line",
        ),
        ({"evidence_checked": [{"file": " ", "line": 1}]}, "challenges/0/evidence_checked/0/file: empty"),
    ],
)
def test_a_challenge_without_its_claim_rationale_or_evidence_is_schema_invalid(changes, detail):
    error = _rejected("review", _review(_challenge(**changes)), _review_ctx())
    assert (error.code, error.message) == ("SCHEMA_INVALID", "review does not fit its target or its challenges")
    assert error.details == [detail]


def test_a_review_of_another_target_is_schema_invalid():
    error = _rejected("review", _review(target_id="EX-SEC-v1"), _review_ctx())
    assert (error.code, error.details) == ("SCHEMA_INVALID", ["target_id: EX-SEC-v1 is not the dispatched EX-CFG-v1"])


def test_a_challenge_on_a_finding_the_target_lacks_is_evidence_invalid():
    review = _review(_challenge(), _challenge(finding_id="CFG-9"), _challenge(finding_id=""))
    error = _rejected("review", review, _review_ctx())
    assert (error.code, error.message) == ("EVIDENCE_INVALID", "review challenges a finding its target does not have")
    assert error.details == ["challenges/1/finding_id: CFG-9 is not a finding of EX-CFG-v1"]


def test_a_review_of_a_target_without_findings_takes_only_unattached_challenges():
    ctx = _review_ctx(target_id="DR-v1", finding_ids=())
    review = _review(_challenge(finding_id="", lens="detect"), target_id="DR-v1")
    assert guardrails.validate("review", review, ctx) == review
    assert _rejected("review", _review(_challenge(), target_id="DR-v1"), ctx).code == "EVIDENCE_INVALID"


def test_a_valid_writer_output_is_accepted():
    output = _writer()
    assert guardrails.validate("writer_output", output, _writer_ctx()) == output


def test_sections_may_come_in_any_order():
    output = _writer(list(reversed(_writer()["sections"])))
    assert guardrails.validate("writer_output", output, _writer_ctx()) == output


@pytest.mark.parametrize(
    ("sections", "details"),
    [
        (_writer()["sections"][1:], [f"sections: {KEYS[0]} is missing"]),
        (
            [*_writer()["sections"], {"key": KEYS[2], "prose": "Again."}],
            [f"sections: {KEYS[2]} appears 2 times"],
        ),
        (
            [*_writer()["sections"], {"key": "security_examiner.licensing", "prose": "New."}],
            ["sections: security_examiner.licensing is not a step of this run"],
        ),
        ([], [f"sections: {key} is missing" for key in KEYS]),
    ],
)
def test_a_missing_duplicate_or_extra_section_is_schema_invalid(sections, details):
    error = _rejected("writer_output", _writer(sections), _writer_ctx())
    assert (error.code, error.message) == ("SCHEMA_INVALID", "writer output does not have one prose section per step")
    assert error.details == details


@pytest.mark.parametrize("prose", ["", "   ", "\n\t\n"])
def test_empty_prose_is_schema_invalid(prose):
    sections = _writer()["sections"]
    sections[2]["prose"] = prose
    error = _rejected("writer_output", _writer(sections), _writer_ctx())
    assert (error.code, error.details) == ("SCHEMA_INVALID", ["sections/2/prose: empty"])
    assert error.message == "writer output has empty prose or a line that renders as a heading"


def test_an_empty_executive_summary_is_schema_invalid():
    error = _rejected("writer_output", _writer(summary=" \n"), _writer_ctx())
    assert (error.code, error.details) == ("SCHEMA_INVALID", ["executive_summary: empty"])


@pytest.mark.parametrize(
    ("prose", "line"),
    [
        ("# Title", 1),
        ("Fine.\n## Sub", 2),
        ("Fine.\n   # Indented", 2),
        ("a\r\n#x", 2),
        ("a\r# x", 2),
        ("a\n\n#", 3),
        ("Title\n=====", 2),
        ("Title\n---", 2),
        ("> # Quoted heading", 1),
        ("- # Listed heading", 1),
        ("1. # Numbered heading", 1),
        ("<h2>Raw</h2>", 1),
        ("Text <H1 class='x'>Big</H1>", 1),
        ("<h1\nTitle\n</h1>", 1),
        ("> Title\n> ===", 2),
    ],
)
def test_a_prose_line_that_renders_as_a_heading_is_schema_invalid(prose, line):
    sections = _writer()["sections"]
    sections[1]["prose"] = prose
    error = _rejected("writer_output", _writer(sections), _writer_ctx())
    assert error.code == "SCHEMA_INVALID"
    assert error.details == [f"sections/1/prose: line {line} renders as a heading"]


def test_a_heading_line_in_the_executive_summary_is_schema_invalid():
    error = _rejected("writer_output", _writer(summary="Intro.\n# Verdict"), _writer_ctx())
    assert error.details == ["executive_summary: line 2 renders as a heading"]


@pytest.mark.parametrize(
    "prose",
    ["Issue #4 and C# code are fine; see [SEC-1].", "-1 is negative.\na - b = c\n* * *", "Use <hr> or <header>."],
)
def test_lines_that_render_as_no_heading_are_accepted(prose):
    sections = _writer()["sections"]
    sections[0]["prose"] = prose
    assert guardrails.validate("writer_output", _writer(sections), _writer_ctx())


@pytest.mark.parametrize(
    ("prose", "unknown"),
    [
        ("New issue [SEC-9].", ["SEC-9"]),
        ("Both [SEC-1, SEC-2] matter.", ["SEC-2"]),
        ("See [see CFG-1 and HYG-3].", ["HYG-3"]),
        ("Twice [SEC-7] and [SEC-7].", ["SEC-7"]),
        ("Advisory [CVE-2018-18074].", ["CVE-2018-18074"]),
        ("Review [RV-2-C1].", ["RV-2-C1"]),
        ("Link [SEC-8](#sec).", ["SEC-8"]),
        ("Split [SEC-1,\nVULN-4].", ["VULN-4"]),
        ("Glued [xSEC-9] and [SEC-8_draft].", ["xSEC-9", "SEC-8"]),
        ("Lower case [sec-9] and [Sec-10].", ["sec-9", "Sec-10"]),
        ("Leading hyphen [-SEC-99].", ["SEC-99"]),
        ("Suffixed [SEC-98-new] and [SEC-1-draft].", ["SEC-98"]),
    ],
)
def test_a_cited_id_not_in_the_input_is_evidence_invalid(prose, unknown):
    sections = _writer()["sections"]
    sections[3]["prose"] = prose
    error = _rejected("writer_output", _writer(sections), _writer_ctx())
    assert (error.code, error.message) == ("EVIDENCE_INVALID", "writer output cites an ID its input does not have")
    assert error.details == [f"sections/3/prose: cites {name}, which is not in the input" for name in unknown]


def test_a_cited_id_in_the_executive_summary_is_checked():
    error = _rejected("writer_output", _writer(summary="Overall [VULN-2]."), _writer_ctx())
    assert error.details == ["executive_summary: cites VULN-2, which is not in the input"]


@pytest.mark.parametrize(
    "prose",
    [
        "Known [SEC-1], [CFG-1] and [VULN-1].",
        "Review [RV-1] raised [RV-1-C1] on [EX-SEC-v1].",
        "Brackets without IDs [optional], [x-ray], [read-only], [A-Z], [1], [] are prose.",
        "A token not led by a letter [1a-2] is no citation.",
        "Bare SEC-9 and UTF-8 are not citations.",
    ],
)
def test_known_ids_and_non_citations_are_accepted(prose):
    sections = _writer()["sections"]
    sections[0]["prose"] = prose
    assert guardrails.validate("writer_output", _writer(sections), _writer_ctx())


def test_a_long_hyphenated_token_is_scanned_in_linear_time(deadline):
    sections = _writer()["sections"]
    sections[0]["prose"] = "[" + "a-" * 30_000 + "a]"
    with deadline(10):
        assert guardrails.validate("writer_output", _writer(sections), _writer_ctx())


def test_section_problems_are_reported_before_unknown_citations():
    sections = _writer()["sections"][1:]
    sections[0]["prose"] = "New [SEC-9]."
    assert _rejected("writer_output", _writer(sections), _writer_ctx()).code == "SCHEMA_INVALID"


def test_a_valid_disposition_is_accepted():
    output = _disposition()
    assert guardrails.validate("disposition", output, _disposition_ctx()) == output


@pytest.mark.parametrize(
    ("entries", "details"),
    [
        (_disposition()["steps"][:3], ["steps: dependency_examiner.dependency_hygiene is missing"]),
        (
            [*_disposition()["steps"], _entry(*STEPS[0], "EX-SEC-v1", "escalate")],
            ["steps: security_examiner.secrets appears 2 times"],
        ),
        (
            [*_disposition()["steps"], _entry("security_examiner", "licensing", "EX-SEC-v1")],
            ["steps: security_examiner.licensing is not a step of this run"],
        ),
    ],
)
def test_a_disposition_must_cover_each_step_exactly_once(entries, details):
    error = _rejected("disposition", _disposition(entries), _disposition_ctx())
    assert (error.code, error.message) == ("SCHEMA_INVALID", "disposition does not cover each step exactly once")
    assert error.details == details


@pytest.mark.parametrize(("examination_id", "index"), [("EX-SEC-v9", 0), ("EX-CFG-v1", 0), ("", 0)])
def test_a_disposition_naming_no_examination_of_its_step_is_unknown_target(examination_id, index):
    entries = _disposition()["steps"]
    entries[index]["examination_id"] = examination_id
    error = _rejected("disposition", _disposition(entries), _disposition_ctx())
    assert (error.code, error.retryable) == ("UNKNOWN_TARGET", False)
    assert error.message == "disposition names an examination that is not of its step"
    assert error.details == [
        f"steps/{index}/examination_id: {examination_id} is not an examination of security_examiner.secrets"
    ]


def test_examination_steps_given_as_lists_still_match():
    ctx = _disposition_ctx(examinations={key: list(value) for key, value in EXAMINATIONS.items()})
    assert guardrails.validate("disposition", _disposition(), ctx)


def test_a_disposition_of_an_unreviewed_examination_is_precondition_failed():
    ctx = _disposition_ctx(reviewed=["EX-SEC-v1", "EX-VULN-v1"])
    error = _rejected("disposition", _disposition(), ctx)
    assert (error.code, error.retryable) == ("PRECONDITION_FAILED", False)
    assert error.message == "disposition names an examination that has no review"
    assert error.details == [
        "steps/1/examination_id: EX-CFG-v1 has no review",
        "steps/3/examination_id: EX-HYG-v1 has no review",
    ]


def test_disposition_problems_are_reported_coverage_then_target_then_review():
    entries = _disposition()["steps"]
    entries[0]["examination_id"] = "EX-SEC-v9"
    ctx = _disposition_ctx(reviewed=())
    assert _rejected("disposition", _disposition(entries), ctx).code == "UNKNOWN_TARGET"
    assert _rejected("disposition", _disposition(entries[1:]), ctx).code == "SCHEMA_INVALID"


def test_secrets_echoed_into_error_details_are_redacted(tmp_path):
    output = _examination(_finding(file=f"keys/{AWS_KEY}.txt"))
    error = _rejected("examination", output, _exam_ctx(tmp_path))
    assert AWS_KEY not in json.dumps(error.to_result())
    assert error.details == ["findings/0/file: keys/<redacted:AKIA…>.txt: not a file"]
