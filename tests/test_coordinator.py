import json
from datetime import UTC, datetime

import jsonschema
import pytest
from anthropic.types.beta import BetaMessage

from assessor import audit, config, coordinator, manifest, sandbox
from assessor.agents import runner

CID = "20261027T101500Z-0a1b2c3d"
NOW = datetime(2026, 10, 27, 10, 15, tzinfo=UTC)
MANIFESTS = manifest.load_manifests()
CAP = MANIFESTS["coordinator"]["max_dispatches_per_step"]
DISPATCH_ERROR = json.loads((config.SCHEMAS_DIR / "dispatch_error.schema.json").read_text(encoding="utf-8"))
SECRET = "AKIAIOSFODNN7EXAMPLE"
CANARY = "CANARY-5e1d07"
STEPS = [
    ("security_examiner", "secrets"),
    ("security_examiner", "insecure_config"),
    ("dependency_examiner", "known_vulnerabilities"),
    ("dependency_examiner", "dependency_hygiene"),
]
CODES = {"secrets": "SEC", "insecure_config": "CFG", "known_vulnerabilities": "VULN", "dependency_hygiene": "HYG"}
WORKFLOWS = {step: workflow for workflow, step in STEPS}
FINDINGS = {
    "secrets": [
        {
            "title": "AWS access key committed in source",
            "severity": "critical",
            "category": "aws-key",
            "file": "config.py",
            "line": 2,
            "evidence": 'AWS_ACCESS_KEY_ID = "AKIA..."',
            "recommendation": "Rotate the key and read it from the environment.",
            "advisory_ids": [],
        }
    ],
    "insecure_config": [],
    "known_vulnerabilities": [
        {
            "title": "requests 2.19.0 has a known advisory",
            "severity": "high",
            "category": "known-vulnerability",
            "file": "requirements.txt",
            "line": 2,
            "evidence": "requests==2.19.0",
            "recommendation": "Upgrade requests to 2.20.0 or later.",
            "advisory_ids": ["GHSA-x84v-xcm2-53pg"],
        }
    ],
    "dependency_hygiene": [
        {
            "title": "flask is not pinned",
            "severity": "low",
            "category": "unpinned",
            "file": "requirements.txt",
            "line": 1,
            "evidence": "flask>=2",
            "recommendation": "Pin an exact version and commit a lockfile.",
            "advisory_ids": [],
        }
    ],
}
CHALLENGE = {
    "finding_id": "SEC-1",
    "lens": "challenge",
    "severity": "critical",
    "claim": "Line 2 holds the key, but the finding misreads which variable it is assigned to.",
    "evidence_checked": [{"file": "config.py", "line": 2}],
    "rationale": "The line assigns AWS_ACCESS_KEY_ID, as read.",
}
MISSED = {
    "finding_id": "",
    "lens": "catch",
    "severity": "major",
    "claim": "The debug flag on line 1 was not considered.",
    "evidence_checked": [{"file": "config.py", "line": 1}],
    "rationale": "Line 1 sets DEBUG.",
}
DRAFT_CHALLENGE = {
    "finding_id": "",
    "lens": "catch",
    "severity": "major",
    "claim": "The summary leaves out the vulnerable requests version.",
    "evidence_checked": [{"file": "requirements.txt", "line": 2}],
    "rationale": "Line 2 pins requests 2.19.0.",
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
    return _message([{"type": "text", "text": output if isinstance(output, str) else json.dumps(output)}])


def _examine(step, challenge_ids=(), note="", number=1):
    return _launch(WORKFLOWS[step], {"step": step, "challenge_ids": list(challenge_ids), "note": note}, number)


def _review_of(target_id, number=1):
    return _launch("adversarial_reviewer", {"target_id": target_id}, number)


def _write(disposition, challenge_ids=()):
    return _launch("final_review_writer", {"disposition": disposition, "challenge_ids": list(challenge_ids)})


def _examination(step, findings=None, responses=()):
    return {
        "workflow": WORKFLOWS[step],
        "step": step,
        "summary": f"Examined the {step} step.",
        "findings": FINDINGS[step] if findings is None else findings,
        "limitations": [],
        "challenge_responses": list(responses),
    }


def _review(target_id, *challenges):
    verdict = (
        "block"
        if any(challenge["severity"] == "critical" for challenge in challenges)
        else "challenge"
        if challenges
        else "pass"
    )
    summary = "Checked the cited lines."
    return {"target_id": target_id, "verdict": verdict, "summary": summary, "challenges": list(challenges)}


def _disposition(**examination_ids):
    return {
        "steps": [
            {
                "workflow": workflow,
                "step": step,
                "examination_id": examination_ids.get(step, f"EX-{CODES[step]}-v1"),
                "decision": "accept",
                "rationale": "The review found nothing to fix.",
            }
            for workflow, step in STEPS
        ],
        "summary": "Every step is accepted.",
    }


def _draft(summary="One committed key needs rotating [SEC-1]."):
    return {
        "executive_summary": summary,
        "sections": [
            {"key": f"{workflow}.{step}", "prose": f"The {step} step was examined."} for workflow, step in STEPS
        ],
    }


def _reviewed():
    """Return the script that examines the four steps in one turn and reviews each examination in the next."""
    return [
        _turn(*[_examine(step, number=number) for number, (_, step) in enumerate(STEPS, 1)]),
        *[_answer(_examination(step)) for _, step in STEPS],
        _turn(*[_review_of(f"EX-{CODES[step]}-v1", number) for number, (_, step) in enumerate(STEPS, 1)]),
        *[_answer(_review(f"EX-{CODES[step]}-v1")) for _, step in STEPS],
    ]


def _drafted():
    return [*_reviewed(), _turn(_write(_disposition())), _answer(_draft())]


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(CID, runs_dir=tmp_path, clock=lambda: NOW)


def _workspace(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "config.py").write_text(f'DEBUG = True\nAWS_ACCESS_KEY_ID = "{SECRET}"\n')
    (repo / "requirements.txt").write_text("flask>=2\nrequests==2.19.0\n")
    return sandbox.Workspace(repo)


def _run(client, log, tmp_path, manifests=MANIFESTS, osv=lambda query: {}):
    return coordinator.run(
        client, log, manifests, workspace=_workspace(tmp_path), workspace_label="acme-api", osv=osv
    )


def _coordinator_requests(client):
    return [
        request
        for request in client.requests
        if any(tool["name"].startswith("launch_") for tool in request.get("tools", []))
    ]


def _blocks(request):
    """Return the tool_result blocks of the request's last message."""
    return request["messages"][-1]["content"]


def _results(client):
    """Return every launch result the coordinator received, in order, parsed."""
    return [json.loads(block["content"]) for request in _coordinator_requests(client)[1:] for block in _blocks(request)]


def _codes(client):
    return [result.get("error", {}).get("code") for result in _results(client)]


def _task(request):
    (message,) = request["messages"]
    return json.loads(message["content"])


def _subagent_requests(client, agent):
    prompt = (config.ROOT / MANIFESTS[agent]["prompt"]).read_text(encoding="utf-8").strip()
    return [request for request in client.requests if request["system"].startswith(prompt)]


def _lines(log, event=None):
    lines = [json.loads(line) for line in log.path.read_text().splitlines()]
    return [line for line in lines if event is None or line["event"] == event]


def _payload(line):
    return {key: value for key, value in line.items() if key not in audit.ENVELOPE}


def _dump(value):
    return json.dumps(value, default=lambda block: block.to_dict())


def test_examiner_launch_runs_only_that_step_in_a_fresh_conversation(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_turn(_examine("secrets", note="First pass.")), _answer(_examination("secrets")), _done()])
    _run(client, log, tmp_path)
    (request,) = _subagent_requests(client, "security_examiner")
    assert _task(request) == runner.examiner_task(
        MANIFESTS["security_examiner"], "secrets", workspace_label="acme-api", challenges=[], note="First pass."
    )
    assert [tool["name"] for tool in request["tools"]] == MANIFESTS["security_examiner"]["tools"]


def test_examination_result_is_the_compact_accepted_examination(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_turn(_examine("secrets")), _answer(_examination("secrets")), _done()])
    state = _run(client, log, tmp_path)
    (block,) = _blocks(client.requests[-1])
    assert (block["tool_use_id"], block["is_error"]) == ("toolu_1", False)
    finding = FINDINGS["secrets"][0]
    assert json.loads(block["content"]) == {
        "examination_id": "EX-SEC-v1",
        "step": "secrets",
        "version": 1,
        "status": "FAIL",
        "findings": [{"id": "SEC-1", **{key: finding[key] for key in ("severity", "title", "file", "line")}}],
    }
    accepted = state.examinations["EX-SEC-v1"]
    assert (accepted.workflow, accepted.step, accepted.output["findings"][0]["id"]) == (
        "security_examiner",
        "secrets",
        "SEC-1",
    )


@pytest.mark.parametrize(
    ("severities", "status"),
    [
        ([], "PASS"),
        (["low", "medium"], "PASS"),
        (["high"], "FAIL"),
        (["critical"], "FAIL"),
        (["low", "critical"], "FAIL"),
    ],
)
def test_section_status_fails_only_on_a_critical_or_high_finding(severities, status):
    assert coordinator.section_status([{"severity": severity} for severity in severities]) == status
    assert status in config.SECTION_STATUSES


def test_review_result_carries_the_review_and_challenge_ids_the_harness_assigned(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_review_of("EX-SEC-v1", 1), _review_of("EX-SEC-v1", 2)),
            _answer(_review("EX-SEC-v1", CHALLENGE, MISSED)),
            _answer(_review("EX-SEC-v1")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert _results(client)[1:] == [
        {
            "review_id": "RV-1",
            "target_id": "EX-SEC-v1",
            "verdict": "block",
            "challenges": [{"id": "RV-1-C1", **CHALLENGE}, {"id": "RV-1-C2", **MISSED}],
        },
        {"review_id": "RV-2", "target_id": "EX-SEC-v1", "verdict": "pass", "challenges": []},
    ]
    assert state.latest_review == {"EX-SEC-v1": "RV-2"}
    assert state.reviews["RV-1"].output["challenges"][1] == {"id": "RV-1-C2", **MISSED}
    assert (state.reviews["RV-1"].workflow, state.reviews["RV-1"].step) == ("security_examiner", "secrets")


def test_review_task_holds_the_target_and_the_task_it_was_produced_from(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets", note="First pass.")),
            _answer(_examination("secrets")),
            _turn(_review_of("EX-SEC-v1")),
            _answer(_review("EX-SEC-v1")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    (examiner,) = _subagent_requests(client, "security_examiner")
    (reviewer,) = _subagent_requests(client, "adversarial_reviewer")
    examination = state.examinations["EX-SEC-v1"].output
    assert _task(reviewer) == runner.review_task("EX-SEC-v1", examination, _task(examiner))
    assert [tool["name"] for tool in reviewer["tools"]] == ["read_file"]


def _challenged(*then):
    return [
        _turn(_examine("secrets")),
        _answer(_examination("secrets")),
        _turn(_review_of("EX-SEC-v1")),
        _answer(_review("EX-SEC-v1", CHALLENGE, MISSED)),
        *then,
    ]


def test_redispatch_carries_the_resolved_challenges_verbatim_and_the_note(fake_anthropic, log, tmp_path):
    responses = [{"challenge_id": "RV-1-C2", "response": "upheld", "rationale": "Line 1 sets DEBUG."}]
    client = fake_anthropic(
        _challenged(
            _turn(_examine("secrets", ["RV-1-C2", "RV-1-C1"], "Answer both challenges.")),
            _answer(_examination("secrets", responses=responses)),
            _done(),
        )
    )
    state = _run(client, log, tmp_path)
    first, second = _subagent_requests(client, "security_examiner")
    assert len(second["messages"]) == 1
    task = _task(second)
    assert task["challenges"] == [{"id": "RV-1-C2", **MISSED}, {"id": "RV-1-C1", **CHALLENGE}]
    assert task["note"] == "Answer both challenges."
    assert {key: value for key, value in task.items() if key not in ("challenges", "note")} == {
        key: value for key, value in _task(first).items() if key not in ("challenges", "note")
    }
    assert (_results(client)[-1]["examination_id"], _results(client)[-1]["version"]) == ("EX-SEC-v2", 2)
    assert state.examinations["EX-SEC-v2"].output["challenge_responses"] == responses


def test_repeated_challenge_ids_are_passed_once(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        _challenged(_turn(_examine("secrets", ["RV-1-C1", "RV-1-C1"])), _answer(_examination("secrets")), _done())
    )
    _run(client, log, tmp_path)
    assert _task(_subagent_requests(client, "security_examiner")[1])["challenges"] == [{"id": "RV-1-C1", **CHALLENGE}]


@pytest.mark.parametrize("challenge_id", ["RV-9-C1", "RV-1-C3", "rv-1-c1", "RV-1", "EX-SEC-v1", ""])
def test_unknown_challenge_id_is_refused_with_unknown_target_and_nothing_dispatched(
    fake_anthropic, log, tmp_path, challenge_id
):
    client = fake_anthropic(_challenged(_turn(_examine("secrets", ["RV-1-C1", challenge_id])), _done()))
    _run(client, log, tmp_path)
    error = _results(client)[-1]["error"]
    assert (error["code"], error["retryable"]) == ("UNKNOWN_TARGET", False)
    assert len(error["details"]) == 1
    assert len(_subagent_requests(client, "security_examiner")) == 1


def test_challenge_to_another_steps_examination_is_refused_with_unknown_target(fake_anthropic, log, tmp_path):
    client = fake_anthropic(_challenged(_turn(_examine("insecure_config", ["RV-1-C2"])), _done()))
    state = _run(client, log, tmp_path)
    assert _codes(client)[-1] == "UNKNOWN_TARGET"
    assert ("security_examiner", "insecure_config") not in state.dispatches


@pytest.mark.parametrize(
    ("agent", "tool_input"),
    [
        ("security_examiner", {"step": "licences", "challenge_ids": [], "note": ""}),
        ("security_examiner", {"step": "known_vulnerabilities", "challenge_ids": [], "note": ""}),
        ("dependency_examiner", {"step": "secrets", "challenge_ids": [], "note": ""}),
        ("security_examiner", {"step": "secrets", "challenge_ids": []}),
        ("security_examiner", {"step": "secrets", "challenge_ids": "RV-1-C1", "note": ""}),
        ("security_examiner", {"step": "secrets", "challenge_ids": [], "note": "", "model": "claude-opus-5-5"}),
        ("adversarial_reviewer", {"target_id": 7}),
        ("adversarial_reviewer", {}),
        ("final_review_writer", {"disposition": {"steps": [], "summary": ""}}),
        ("final_review_writer", {"disposition": {"steps": [], "summary": "", "status": "PASS"}, "challenge_ids": []}),
    ],
)
def test_launch_input_outside_its_schema_is_refused_with_schema_invalid(
    fake_anthropic, log, tmp_path, agent, tool_input
):
    client = fake_anthropic([_turn(_launch(agent, tool_input)), _done()])
    state = _run(client, log, tmp_path)
    assert _codes(client) == ["SCHEMA_INVALID"]
    assert _results(client)[0]["error"]["details"]
    assert (len(client.requests), state.dispatches) == (2, {})


@pytest.mark.parametrize(
    "launch",
    [
        _launch("security_examiner", {"step": "licences", "challenge_ids": [], "note": ""}),
        _write({"steps": [], "summary": "Nothing examined."}),
    ],
)
def test_launch_refused_on_its_own_input_is_refused_again_when_resent_unchanged(fake_anthropic, log, tmp_path, launch):
    client = fake_anthropic([_turn(launch), _turn(launch), _done()])
    state = _run(client, log, tmp_path)
    assert [(result["error"]["code"], result["error"]["retryable"]) for result in _results(client)] == [
        ("SCHEMA_INVALID", True)
    ] * 2
    assert state.dispatches == {}


def test_refused_review_succeeds_unchanged_once_its_target_is_accepted(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_review_of("EX-SEC-v1")),
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_review_of("EX-SEC-v1")),
            _answer(_review("EX-SEC-v1")),
            _done(),
        ]
    )
    _run(client, log, tmp_path)
    assert _codes(client) == ["UNKNOWN_TARGET", None, None]
    assert _results(client)[-1]["review_id"] == "RV-1"


@pytest.mark.parametrize("name", ["read_file", "launch_coordinator", "launch_security_examiner "])
def test_tool_name_outside_the_launch_tools_is_refused_with_schema_invalid(fake_anthropic, log, tmp_path, name):
    block = {"type": "tool_use", "id": "toolu_1", "name": name, "input": {"step": "secrets"}}
    client = fake_anthropic([_turn(block), _done()])
    _run(client, log, tmp_path)
    assert _codes(client) == ["SCHEMA_INVALID"]
    assert len(client.requests) == 2


def test_examination_versions_count_only_accepted_examinations_of_their_step(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets")),
            _answer("not an examination"),
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_examine("insecure_config")),
            _answer(_examination("insecure_config")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    examination_ids = [result.get("examination_id") for result in _results(client)]
    assert examination_ids == [None, "EX-SEC-v1", "EX-SEC-v2", "EX-CFG-v1"]
    assert list(state.examinations) == ["EX-SEC-v1", "EX-SEC-v2", "EX-CFG-v1"]


@pytest.mark.parametrize(
    ("output", "code"),
    [
        (f"Here is the examination: {CANARY}", "SCHEMA_INVALID"),
        (
            {
                **_examination("secrets"),
                "summary": CANARY,
                "findings": [{**FINDINGS["secrets"][0], "severity": "urgent"}],
            },
            "SCHEMA_INVALID",
        ),
        (
            {**_examination("secrets"), "summary": CANARY, "findings": [{**FINDINGS["secrets"][0], "line": 99}]},
            "EVIDENCE_INVALID",
        ),
    ],
)
def test_rejected_output_reaches_the_coordinator_only_as_its_dispatch_error(
    fake_anthropic, log, tmp_path, output, code
):
    client = fake_anthropic([_turn(_examine("secrets")), _answer(output), _done()])
    state = _run(client, log, tmp_path)
    (block,) = _blocks(client.requests[-1])
    result = json.loads(block["content"])
    jsonschema.validate(result, DISPATCH_ERROR)
    assert (block["is_error"], result["error"]["code"]) == (True, code)
    assert CANARY not in _dump(client.requests[-1])
    assert state.examinations == {}


def test_rejected_output_is_never_stored(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets"), _review_of("EX-SEC-v1", 2)),
            _answer({**_examination("secrets"), "findings": [{**FINDINGS["secrets"][0], "line": 99}]}),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert (state.examinations, state.reviews, state.drafts) == ({}, {}, {})
    assert [path.name for path in (tmp_path / CID).rglob("*.json")] == []


def test_accepted_outputs_are_written_once_under_their_harness_ids(fake_anthropic, log, tmp_path):
    client = fake_anthropic([*_drafted(), _turn(_review_of("DR-v1")), _answer(_review("DR-v1")), _done()])
    state = _run(client, log, tmp_path)
    run_dir = tmp_path / CID
    written = sorted(str(path.relative_to(run_dir)) for path in run_dir.rglob("*.json"))
    assert written == sorted(
        [
            *(f"examinations/{examination_id}.json" for examination_id in state.examinations),
            *(f"reviews/{review_id}.json" for review_id in state.reviews),
            "drafts/DR-v1.json",
        ]
    )
    assert len(state.examinations) == 4 and len(state.reviews) == 5
    for kind, outputs in (("examinations", state.examinations), ("reviews", state.reviews), ("drafts", state.drafts)):
        for output_id, accepted in outputs.items():
            assert json.loads((run_dir / kind / f"{output_id}.json").read_text()) == accepted.output


def test_existing_output_file_is_never_overwritten(fake_anthropic, log, tmp_path):
    (tmp_path / CID / "examinations").mkdir(parents=True)
    (tmp_path / CID / "examinations" / "EX-SEC-v1.json").write_text("{}")
    client = fake_anthropic([_turn(_examine("secrets")), _answer(_examination("secrets"))])
    with pytest.raises(FileExistsError):
        _run(client, log, tmp_path)
    assert (tmp_path / CID / "examinations" / "EX-SEC-v1.json").read_text() == "{}"


def test_no_seeded_secret_reaches_the_coordinator_or_the_run_directory(fake_anthropic, log, tmp_path):
    leaky = {
        **FINDINGS["secrets"][0],
        "title": f"Key {SECRET} committed",
        "evidence": f'AWS_ACCESS_KEY_ID = "{SECRET}"',
    }
    client = fake_anthropic(
        [
            _turn(_examine("secrets")),
            _answer(_examination("secrets", [leaky])),
            _turn(_review_of("EX-SEC-v1")),
            _answer(_review("EX-SEC-v1")),
            _done(),
        ]
    )
    _run(client, log, tmp_path)
    assert SECRET not in _dump(client.requests[-1])
    assert all(SECRET not in path.read_text() for path in (tmp_path / CID).rglob("*") if path.is_file())


@pytest.mark.parametrize("target_id", ["EX-SEC-v9", "EX-CFG-v1", "DR-v1", "RV-1", "ex-sec-v1", ""])
def test_review_of_an_unknown_target_is_refused_with_unknown_target(fake_anthropic, log, tmp_path, target_id):
    client = fake_anthropic(_challenged(_turn(_review_of(target_id)), _done()))
    _run(client, log, tmp_path)
    assert _codes(client)[-1] == "UNKNOWN_TARGET"
    assert len(_subagent_requests(client, "adversarial_reviewer")) == 1


def test_draft_review_holds_the_moderated_context_and_no_finding_ids(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            *_drafted(),
            _turn(_review_of("DR-v1", 1), _review_of("DR-v1", 2)),
            _answer(_review("DR-v1", {**DRAFT_CHALLENGE, "finding_id": "SEC-1"})),
            _answer(_review("DR-v1", DRAFT_CHALLENGE)),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    (writer,) = _subagent_requests(client, "final_review_writer")
    draft_review = _subagent_requests(client, "adversarial_reviewer")[-1]
    assert _task(draft_review) == runner.review_task("DR-v1", state.drafts["DR-v1"].output, _task(writer))
    assert _codes(client)[-2:] == ["EVIDENCE_INVALID", None]
    assert _results(client)[-1]["challenges"] == [{"id": "RV-5-C1", **DRAFT_CHALLENGE}]
    assert state.latest_review["DR-v1"] == "RV-5"
    for accepted in (state.drafts["DR-v1"], state.reviews["RV-5"]):
        assert (accepted.workflow, accepted.step) == ("final_review_writer", None)


def test_writer_with_an_unreviewed_examination_is_refused_with_precondition_failed(fake_anthropic, log, tmp_path):
    unreviewed = _reviewed()[:-1]
    unreviewed[5] = _turn(
        *[_review_of(f"EX-{CODES[step]}-v1", number) for number, (_, step) in enumerate(STEPS[:3], 1)]
    )
    client = fake_anthropic([*unreviewed, _turn(_write(_disposition())), _done()])
    state = _run(client, log, tmp_path)
    error = _results(client)[-1]["error"]
    assert (error["code"], error["retryable"]) == ("PRECONDITION_FAILED", False)
    assert "EX-HYG-v1" in error["details"][0]
    assert _subagent_requests(client, "final_review_writer") == []
    assert ("final_review_writer", None) not in state.dispatches


def test_writer_refused_for_an_unreviewed_examination_succeeds_unchanged_once_it_is_reviewed(
    fake_anthropic, log, tmp_path
):
    unreviewed = _reviewed()[:-1]
    unreviewed[5] = _turn(
        *[_review_of(f"EX-{CODES[step]}-v1", number) for number, (_, step) in enumerate(STEPS[:3], 1)]
    )
    client = fake_anthropic(
        [
            *unreviewed,
            _turn(_write(_disposition())),
            _turn(_review_of("EX-HYG-v1")),
            _answer(_review("EX-HYG-v1")),
            _turn(_write(_disposition())),
            _answer(_draft()),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert _codes(client)[-3:] == ["PRECONDITION_FAILED", None, None]
    assert list(state.drafts) == ["DR-v1"]


@pytest.mark.parametrize(
    ("disposition", "code"),
    [
        ({**_disposition(), "steps": _disposition()["steps"][:3]}, "SCHEMA_INVALID"),
        ({**_disposition(), "steps": [*_disposition()["steps"], _disposition()["steps"][0]]}, "SCHEMA_INVALID"),
        (_disposition(secrets="EX-SEC-v9"), "UNKNOWN_TARGET"),
        (_disposition(secrets="EX-CFG-v1"), "UNKNOWN_TARGET"),
        (_disposition(secrets="DR-v1"), "UNKNOWN_TARGET"),
        (
            {
                **_disposition(),
                "steps": [{**_disposition()["steps"][0], "decision": "approve"}, *_disposition()["steps"][1:]],
            },
            "SCHEMA_INVALID",
        ),
    ],
)
def test_writer_disposition_that_breaks_its_contract_is_refused(fake_anthropic, log, tmp_path, disposition, code):
    client = fake_anthropic([*_reviewed(), _turn(_write(disposition)), _done()])
    _run(client, log, tmp_path)
    assert _codes(client)[-1] == code
    assert _subagent_requests(client, "final_review_writer") == []


def test_writer_input_holds_only_the_named_examinations_and_their_latest_reviews(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            *_reviewed(),
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_review_of("EX-SEC-v2", 1), _review_of("EX-SEC-v2", 2)),
            _answer(_review("EX-SEC-v2", MISSED)),
            _answer(_review("EX-SEC-v2")),
            _turn(_write(_disposition(secrets="EX-SEC-v2"))),
            _answer(_draft()),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    (writer,) = _subagent_requests(client, "final_review_writer")
    task = _task(writer)
    assert list(task["examinations"]) == ["EX-SEC-v2", "EX-CFG-v1", "EX-VULN-v1", "EX-HYG-v1"]
    assert list(task["reviews"]) == ["RV-6", "RV-2", "RV-3", "RV-4"]
    assert task["examinations"]["EX-SEC-v2"] == state.examinations["EX-SEC-v2"].output
    assert task["reviews"]["RV-6"] == state.reviews["RV-6"].output
    assert task["challenges"] == []
    assert _results(client)[-1] == {"draft_id": "DR-v1", "sections": 4}


def test_writer_gets_the_coordinators_disposition_unchanged(fake_anthropic, log, tmp_path):
    disposition = _disposition()
    disposition["steps"][3] = {**disposition["steps"][3], "decision": "escalate", "rationale": "A human should decide."}
    client = fake_anthropic([*_reviewed(), _turn(_write(disposition)), _answer(_draft()), _done()])
    state = _run(client, log, tmp_path)
    (writer,) = _subagent_requests(client, "final_review_writer")
    assert _task(writer)["disposition"] == disposition
    assert state.drafts["DR-v1"].task["disposition"] == disposition


@pytest.mark.parametrize(
    ("cited", "accepted"),
    [
        ("[SEC-1]", True),
        ("[HYG-1]", True),
        ("[EX-SEC-v1]", True),
        ("[RV-1]", True),
        ("[RV-1-C1]", True),
        ("[SEC-2]", False),
        ("[EX-SEC-v2]", False),
        ("[RV-9]", False),
        ("[GHSA-x84v-xcm2-53pg]", False),
        ("[CWE-798]", False),
    ],
)
def test_writer_may_cite_any_harness_id_in_its_input_and_no_other(fake_anthropic, log, tmp_path, cited, accepted):
    script = _reviewed()
    script[6] = _answer(_review("EX-SEC-v1", {**MISSED, "severity": "minor"}))
    client = fake_anthropic([*script, _turn(_write(_disposition())), _answer(_draft(f"See {cited}.")), _done()])
    _run(client, log, tmp_path)
    assert _codes(client)[-1] == (None if accepted else "EVIDENCE_INVALID")


def test_redraft_carries_the_draft_challenges_verbatim(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            *_drafted(),
            _turn(_review_of("DR-v1")),
            _answer(_review("DR-v1", DRAFT_CHALLENGE)),
            _turn(_write(_disposition(), ["RV-5-C1"])),
            _answer(_draft("Rotate the key [SEC-1] and upgrade requests, as asked in [RV-5-C1].")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    second = _subagent_requests(client, "final_review_writer")[1]
    assert _task(second)["challenges"] == [{"id": "RV-5-C1", **DRAFT_CHALLENGE}]
    assert _results(client)[-1] == {"draft_id": "DR-v2", "sections": 4}
    assert list(state.drafts) == ["DR-v1", "DR-v2"]


def test_writer_challenge_ids_must_name_challenges_to_a_draft(fake_anthropic, log, tmp_path):
    script = _reviewed()
    script[6] = _answer(_review("EX-SEC-v1", {**MISSED, "severity": "minor"}))
    client = fake_anthropic([*script, _turn(_write(_disposition(), ["RV-1-C1"])), _done()])
    _run(client, log, tmp_path)
    assert _codes(client)[-1] == "UNKNOWN_TARGET"
    assert _subagent_requests(client, "final_review_writer") == []


def test_fourth_dispatch_for_a_step_is_refused_with_retry_cap_reached(fake_anthropic, log, tmp_path):
    assert CAP == 3
    client = fake_anthropic(
        [
            _turn(_examine("secrets")),
            _answer("not an examination"),
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_examine("secrets")),
            _answer(_examination("secrets")),
            _turn(_examine("secrets"), _examine("insecure_config", number=2)),
            _answer(_examination("insecure_config")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert _codes(client) == ["SCHEMA_INVALID", None, None, "RETRY_CAP_REACHED", None]
    assert _results(client)[3]["error"]["retryable"] is False
    assert len(_subagent_requests(client, "security_examiner")) == 4
    assert state.dispatches == {("security_examiner", "secrets"): 3, ("security_examiner", "insecure_config"): 1}


def test_dispatch_cap_comes_from_the_coordinator_manifest(fake_anthropic, log, tmp_path):
    capped = {**MANIFESTS, "coordinator": {**MANIFESTS["coordinator"], "max_dispatches_per_step": 2}}
    accepted = [item for _ in range(2) for item in (_turn(_examine("secrets")), _answer(_examination("secrets")))]
    client = fake_anthropic([*accepted, _turn(_examine("secrets")), _done()])
    state = _run(client, log, tmp_path, capped)
    assert _codes(client) == [None, None, "RETRY_CAP_REACHED"]
    assert state.dispatches == {("security_examiner", "secrets"): 2}


def test_refused_launches_do_not_count_toward_the_cap(fake_anthropic, log, tmp_path):
    refused = [_turn(_examine("secrets", ["RV-9-C1"])) for _ in range(CAP)]
    accepted = [item for _ in range(CAP) for item in (_turn(_examine("secrets")), _answer(_examination("secrets")))]
    client = fake_anthropic([*refused, *accepted, _done()])
    state = _run(client, log, tmp_path)
    assert _codes(client) == ["UNKNOWN_TARGET"] * CAP + [None] * CAP
    assert state.dispatches == {("security_examiner", "secrets"): CAP}


def test_fourth_writer_dispatch_is_refused_with_retry_cap_reached(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            *_reviewed(),
            _turn(_write(_disposition())),
            _answer("not a draft"),
            _turn(_write(_disposition())),
            _answer(_draft()),
            _turn(_write(_disposition())),
            _answer(_draft()),
            _turn(_write(_disposition())),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert _codes(client)[-4:] == ["SCHEMA_INVALID", None, None, "RETRY_CAP_REACHED"]
    assert list(state.drafts) == ["DR-v1", "DR-v2"]
    assert state.dispatches[("final_review_writer", None)] == CAP


def test_fourth_review_of_one_target_is_refused_with_retry_cap_reached(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets"), _examine("insecure_config", number=2)),
            _answer(_examination("secrets")),
            _answer(_examination("insecure_config")),
            _turn(_review_of("EX-SEC-v1")),
            _answer("not a review"),
            _turn(_review_of("EX-SEC-v1")),
            _answer(_review("EX-SEC-v1")),
            _turn(_review_of("EX-SEC-v1")),
            _answer(_review("EX-SEC-v1")),
            _turn(_review_of("EX-SEC-v1"), _review_of("EX-CFG-v1", 2)),
            _answer(_review("EX-CFG-v1")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert _codes(client)[2:] == ["SCHEMA_INVALID", None, None, "RETRY_CAP_REACHED", None]
    assert state.dispatches[("adversarial_reviewer", "EX-SEC-v1")] == CAP
    assert list(state.reviews) == ["RV-1", "RV-2", "RV-3"]


def test_launch_blocks_of_one_turn_run_in_order_and_answer_in_one_message(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets"), _review_of("EX-SEC-v9", 2), _examine("dependency_hygiene", number=3)),
            _answer(_examination("secrets")),
            _answer(_examination("dependency_hygiene")),
            _done(),
        ]
    )
    _run(client, log, tmp_path)
    message = client.requests[-1]["messages"][-1]
    assert message["role"] == "user"
    assert [(block["type"], block["tool_use_id"], block["is_error"]) for block in message["content"]] == [
        ("tool_result", "toolu_1", False),
        ("tool_result", "toolu_2", True),
        ("tool_result", "toolu_3", False),
    ]
    assert [_task(request)["step"] for request in client.requests[1:3]] == ["secrets", "dependency_hygiene"]


def test_launch_can_name_an_output_accepted_earlier_in_the_same_turn(fake_anthropic, log, tmp_path):
    client = fake_anthropic(
        [
            _turn(_examine("secrets"), _review_of("EX-SEC-v1", 2)),
            _answer(_examination("secrets")),
            _answer(_review("EX-SEC-v1")),
            _done(),
        ]
    )
    state = _run(client, log, tmp_path)
    assert _codes(client) == [None, None]
    assert state.latest_review == {"EX-SEC-v1": "RV-1"}


def test_dependency_examiner_queries_osv_through_the_transport_the_run_was_given(fake_anthropic, log, tmp_path):
    queries = []

    def transport(query):
        queries.append(query)
        return {"vulns": []}

    tool_input = {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}
    query = {"type": "tool_use", "id": "toolu_9", "name": "query_osv", "input": tool_input}
    client = fake_anthropic(
        [
            _turn(_examine("known_vulnerabilities")),
            _message([query], "tool_use"),
            _answer(_examination("known_vulnerabilities", [])),
            _done(),
        ]
    )
    _run(client, log, tmp_path, osv=transport)
    assert queries == [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"}]
    assert _codes(client) == [None]


def test_error_other_than_a_dispatch_error_propagates_and_leaves_the_dispatch_unfinished(
    fake_anthropic, log, tmp_path, monkeypatch
):
    def unreadable(*args, **kwargs):
        raise OSError("skills unreadable")

    monkeypatch.setattr(runner, "run_subagent", unreadable)
    client = fake_anthropic([_turn(_examine("secrets"))])
    with pytest.raises(OSError, match="skills unreadable"):
        _run(client, log, tmp_path)
    assert [line["event"] for line in _lines(log)] == ["llm_call", "dispatch_started"]


def test_accepted_output_holding_a_lone_surrogate_is_stored_and_passed_on_escaped(fake_anthropic, log, tmp_path):
    summary = "Examined the step \ud800 once."
    client = fake_anthropic(
        [
            _turn(_examine("secrets")),
            _answer({**_examination("secrets"), "summary": summary}),
            _turn(_review_of("EX-SEC-v1")),
            _answer(_review("EX-SEC-v1")),
            _done(),
        ]
    )
    _run(client, log, tmp_path)
    stored = (tmp_path / CID / "examinations" / "EX-SEC-v1.json").read_text(encoding="utf-8")
    assert "\\ud800" in stored
    assert json.loads(stored)["summary"] == summary
    assert _task(_subagent_requests(client, "adversarial_reviewer")[0])["target"]["summary"] == summary


def test_coordinator_messages_are_append_only(fake_anthropic, log, tmp_path):
    thinking = _message(
        [
            {"type": "thinking", "thinking": "Start with secrets.", "signature": "sig"},
            {"type": "text", "text": "Examining secrets first."},
            _examine("secrets"),
        ],
        "tool_use",
    )
    review = _turn(_review_of("EX-SEC-v1"))
    client = fake_anthropic(
        [thinking, _answer(_examination("secrets")), review, _answer(_review("EX-SEC-v1")), _done()]
    )
    _run(client, log, tmp_path)
    first, second, third = _coordinator_requests(client)
    for earlier, later in ((first, second), (second, third)):
        assert later["messages"][: len(earlier["messages"])] == earlier["messages"]
        assert len(later["messages"]) == len(earlier["messages"]) + 2
    assert second["messages"][1] == {"role": "assistant", "content": thinking.content}
    assert third["messages"][3] == {"role": "assistant", "content": review.content}


def test_subagent_lines_point_to_their_dispatch_started_line(fake_anthropic, log, tmp_path):
    read = {"type": "tool_use", "id": "toolu_9", "name": "read_file", "input": {"path": "config.py", "start_line": 1}}
    client = fake_anthropic(
        [_turn(_examine("secrets")), _message([read], "tool_use"), _answer(_examination("secrets")), _done()]
    )
    _run(client, log, tmp_path)
    lines = _lines(log)
    assert [line["event"] for line in lines] == [
        "llm_call",
        "dispatch_started",
        "llm_call",
        "tool_call",
        "llm_call",
        "dispatch_finished",
        "llm_call",
    ]
    started = lines[1]
    labels = {"agent": "security_examiner", "workflow": "security_examiner", "step": "secrets"}
    assert _payload(started) == {**labels, "target_id": None}
    assert [line["parent_step_id"] for line in lines[2:6]] == [started["step_id"]] * 4
    assert [{key: line[key] for key in labels} for line in lines[2:5]] == [labels] * 3
    finished = {"parent_step_id": started["step_id"], **labels, "output_id": "EX-SEC-v1", "code": None}
    assert _payload(lines[5]) == finished
    for line in (lines[0], lines[6]):
        labels = (line["agent"], line["workflow"], line["step"], line["parent_step_id"])
        assert labels == ("coordinator", None, None, None)


def test_failed_dispatch_finishes_with_its_code_and_no_output_id(fake_anthropic, log, tmp_path):
    client = fake_anthropic([_turn(_examine("secrets")), _answer("not an examination"), _done()])
    _run(client, log, tmp_path)
    events = ("dispatch_started", "guardrail_rejected", "dispatch_finished")
    (started,), (rejected,), (finished,) = (_lines(log, event) for event in events)
    assert rejected["parent_step_id"] == started["step_id"]
    assert (finished["parent_step_id"], finished["output_id"], finished["code"]) == (
        started["step_id"],
        None,
        "SCHEMA_INVALID",
    )


def test_review_dispatch_lines_name_the_target_and_its_step(fake_anthropic, log, tmp_path):
    client = fake_anthropic(_challenged(_done()))
    _run(client, log, tmp_path)
    started, finished = _lines(log, "dispatch_started")[1], _lines(log, "dispatch_finished")[1]
    labels = {"agent": "adversarial_reviewer", "workflow": "security_examiner", "step": "secrets"}
    assert _payload(started) == {**labels, "target_id": "EX-SEC-v1"}
    assert _payload(finished) == {"parent_step_id": started["step_id"], **labels, "output_id": "RV-1", "code": None}


@pytest.mark.parametrize(
    ("script", "labels", "code"),
    [
        ([_turn(_review_of("EX-SEC-v9"))], (None, None), "UNKNOWN_TARGET"),
        (
            [_turn(_launch("security_examiner", {"step": "licences", "challenge_ids": [], "note": ""}))],
            ("security_examiner", None),
            "SCHEMA_INVALID",
        ),
        ([_turn(_launch("adversarial_reviewer", {"target": "EX-SEC-v1"}))], (None, None), "SCHEMA_INVALID"),
        (
            [_turn(_launch("final_review_writer", {"challenge_ids": []}))],
            ("final_review_writer", None),
            "SCHEMA_INVALID",
        ),
        ([_turn(_examine("secrets", ["RV-9-C1"]))], ("security_examiner", "secrets"), "UNKNOWN_TARGET"),
        ([_turn(_write(_disposition()))], ("final_review_writer", None), "UNKNOWN_TARGET"),
        ([_turn({"type": "tool_use", "id": "toolu_1", "name": "bash", "input": {}})], (None, None), "SCHEMA_INVALID"),
    ],
)
def test_refused_launch_writes_a_coordinator_guardrail_rejected_line_and_no_dispatch(
    fake_anthropic, log, tmp_path, script, labels, code
):
    client = fake_anthropic([*script, _done()])
    _run(client, log, tmp_path)
    (rejected,) = _lines(log, "guardrail_rejected")
    problems = len(_results(client)[0]["error"]["details"])
    assert _payload(rejected) == {
        "parent_step_id": None,
        "agent": "coordinator",
        "workflow": labels[0],
        "step": labels[1],
        "code": code,
        "problems": problems,
    }
    assert _lines(log, "dispatch_started") == []
