import copy
import json
import os

import pytest

from assessor import manifest
from assessor.agents import runner
from assessor.guardrails import DispatchError, ExaminationContext, ReviewContext, WriterContext
from assessor.sandbox import Workspace
from evals import scripted_dispatcher as scripted

MANIFESTS = manifest.load_manifests()
SECURITY = MANIFESTS["security_examiner"]
REVIEWER = MANIFESTS["adversarial_reviewer"]
WRITER = MANIFESTS["final_review_writer"]
STEPS = [
    ("security_examiner", "secrets"),
    ("security_examiner", "insecure_config"),
    ("dependency_examiner", "known_vulnerabilities"),
    ("dependency_examiner", "dependency_hygiene"),
]
APP = "import os\n\nSECRET_KEY = os.environ['SECRET_KEY']\nDEBUG = False\n"


def _finding(line=3, severity="critical", file="app.py"):
    return {
        "title": "A finding",
        "severity": severity,
        "category": "secret",
        "file": file,
        "line": line,
        "evidence": "The line.",
        "recommendation": "Fix it.",
        "advisory_ids": [],
    }


def _body(findings=()):
    return {"summary": "Examined.", "findings": list(findings), "limitations": [], "challenge_responses": []}


def _challenge(finding_id="SEC-1", severity="critical"):
    return {
        "finding_id": finding_id,
        "lens": "challenge",
        "severity": severity,
        "claim": "The claim.",
        "evidence_checked": [{"file": "app.py", "line": 3}],
        "rationale": "The reason.",
    }


def _review(verdict="pass", challenges=()):
    return {"verdict": verdict, "summary": "Reviewed.", "challenges": list(challenges)}


def _draft(prose="Nothing to report."):
    return {
        "executive_summary": "Summary.",
        "sections": [{"key": f"{workflow}.{step}", "prose": prose} for workflow, step in STEPS],
    }


def _attempt(output, refused=None):
    return {"output": output} if refused is None else {"output": output, "refused": refused}


def _answer(agent, step, *attempts):
    answer = {"agent": agent, "attempts": list(attempts)}
    if step is not None:
        answer["step"] = step
    return answer


def _script(*answers, files=None):
    return {
        "id": "K9",
        "description": "A script.",
        "workspace": "acme-shop",
        "files": {"app.py": APP} if files is None else files,
        "answers": list(answers),
        "criteria": ["review_coverage"],
    }


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    return Workspace(tmp_path)


def _examine(dispatcher, workspace, step="secrets", agent=SECURITY):
    ctx = ExaminationContext(agent["name"], step, "SEC", workspace)
    labels = {"workflow": agent["name"], "step": step, "parent_step_id": None}
    return dispatcher(None, None, agent, {}, ctx, workspace=workspace, **labels)


def _review_of(dispatcher, workspace, target_id="EX-SEC-v1", step="secrets", finding_ids=("SEC-1",)):
    labels = ("security_examiner", step) if target_id.startswith("EX-") else ("final_review_writer", None)
    return dispatcher(
        None, None, REVIEWER, {}, ReviewContext(target_id, list(finding_ids)),
        workspace=workspace, workflow=labels[0], step=labels[1], parent_step_id=None,
    )


def _write(dispatcher, workspace, ids=()):
    return dispatcher(
        None, None, WRITER, {}, WriterContext(STEPS, set(ids)),
        workspace=workspace, workflow="final_review_writer", step=None, parent_step_id=None,
    )


def test_an_examiner_call_returns_the_scripted_body_with_its_dispatch_labels_and_assigned_finding_ids(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(_answer("security_examiner", "secrets", _attempt(_body([_finding(), _finding(4, "low")]))))
    )
    result = _examine(dispatcher, workspace)
    assert (result["workflow"], result["step"], result["summary"]) == ("security_examiner", "secrets", "Examined.")
    assert [(item["id"], item["line"]) for item in result["findings"]] == [("SEC-1", 3), ("SEC-2", 4)]


def test_the_nth_call_of_a_key_gets_its_nth_attempt_and_the_last_attempt_repeats(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(_answer("security_examiner", "secrets", _attempt(_body([_finding()])), _attempt(_body())))
    )
    counts = [len(_examine(dispatcher, workspace)["findings"]) for _ in range(4)]
    assert counts == [1, 0, 0, 0]


def test_each_agent_and_step_counts_its_own_attempts(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(
            _answer("security_examiner", "secrets", _attempt(_body([_finding()])), _attempt(_body())),
            _answer("security_examiner", "insecure_config", _attempt(_body([_finding(line=4)])), _attempt(_body())),
        )
    )
    first = _examine(dispatcher, workspace, "secrets")
    other = _examine(dispatcher, workspace, "insecure_config")
    second = _examine(dispatcher, workspace, "secrets")
    assert (len(first["findings"]), len(other["findings"]), len(second["findings"])) == (1, 1, 0)


def test_a_reviewer_and_an_examiner_of_one_step_count_apart(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(
            _answer("security_examiner", "secrets", _attempt(_body([_finding()])), _attempt(_body())),
            _answer("adversarial_reviewer", "secrets", _attempt(_review("block", [_challenge()])), _attempt(_review())),
        )
    )
    verdicts = [_review_of(dispatcher, workspace)["verdict"], _examine(dispatcher, workspace)["findings"] != []]
    assert verdicts == ["block", True]


def test_a_step_the_script_does_not_list_reports_no_findings(workspace):
    result = _examine(scripted.ScriptedDispatcher(_script()), workspace)
    assert (result["findings"], result["limitations"], result["challenge_responses"]) == ([], [], [])


def test_a_review_the_script_does_not_list_passes_the_dispatched_target(workspace):
    result = _review_of(scripted.ScriptedDispatcher(_script()), workspace, "EX-SEC-v2")
    assert (result["target_id"], result["verdict"], result["challenges"]) == ("EX-SEC-v2", "pass", [])


def test_a_draft_the_script_does_not_list_has_one_section_per_step_of_the_run(workspace):
    result = _write(scripted.ScriptedDispatcher(_script()), workspace)
    assert [section["key"] for section in result["sections"]] == [f"{w}.{s}" for w, s in STEPS]
    assert all(section["prose"].strip() for section in result["sections"]) and result["executive_summary"].strip()


def test_a_scripted_answer_is_redacted_as_a_sub_agents_answer_is(workspace):
    leaky = _finding()
    leaky["evidence"] = 'password = "hunter2hunter2"'
    dispatcher = scripted.ScriptedDispatcher(_script(_answer("security_examiner", "secrets", _attempt(_body([leaky])))))
    result = _examine(dispatcher, workspace)
    assert "hunter2hunter2" not in json.dumps(result)
    assert result["findings"][0]["evidence"].startswith("password = \"<redacted:")
    assert (result["findings"][0]["file"], result["findings"][0]["id"]) == ("app.py", "SEC-1")


def test_a_scripted_review_is_labelled_with_the_target_that_was_dispatched(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(
            _answer("security_examiner", "secrets", _attempt(_body([_finding()]))),
            _answer("adversarial_reviewer", "secrets", _attempt(_review("block", [_challenge()]))),
        )
    )
    assert _review_of(dispatcher, workspace, "EX-SEC-v3")["target_id"] == "EX-SEC-v3"


def test_the_reviews_of_drafts_have_a_key_of_their_own(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(
            _answer("adversarial_reviewer", None, _attempt(_review("block", [_challenge("")]))),
            _answer("adversarial_reviewer", "secrets", _attempt(_review())),
        )
    )
    assert _review_of(dispatcher, workspace, "DR-v1", finding_ids=())["verdict"] == "block"
    assert _review_of(dispatcher, workspace, "EX-SEC-v1")["verdict"] == "pass"


def test_a_scripted_draft_is_returned_as_written(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(_answer("final_review_writer", None, _attempt(_draft("Two lines of prose."))))
    )
    assert _write(dispatcher, workspace)["sections"][0]["prose"] == "Two lines of prose."


def test_an_attempt_the_guardrails_refuse_raises_their_error_for_the_coordinator(workspace):
    broken = {key: value for key, value in _body().items() if key != "summary"}
    dispatcher = scripted.ScriptedDispatcher(
        _script(_answer("security_examiner", "secrets", _attempt(broken, "SCHEMA_INVALID"), _attempt(_body())))
    )
    with pytest.raises(DispatchError) as raised:
        _examine(dispatcher, workspace)
    assert (raised.value.code, raised.value.retryable) == ("SCHEMA_INVALID", True)
    assert "summary" in " ".join(raised.value.details)
    assert _examine(dispatcher, workspace)["findings"] == []


def test_an_attempt_that_cites_a_line_the_workspace_lacks_raises_the_evidence_error(workspace):
    dispatcher = scripted.ScriptedDispatcher(
        _script(_answer("security_examiner", "secrets", _attempt(_body([_finding(line=99)]), "EVIDENCE_INVALID")))
    )
    with pytest.raises(DispatchError) as raised:
        _examine(dispatcher, workspace)
    assert raised.value.code == "EVIDENCE_INVALID"


def test_calls_are_recorded_in_order_by_agent_and_step(workspace):
    dispatcher = scripted.ScriptedDispatcher(_script())
    _examine(dispatcher, workspace, "insecure_config")
    _review_of(dispatcher, workspace, "EX-CFG-v1", "insecure_config")
    _review_of(dispatcher, workspace, "DR-v1")
    _write(dispatcher, workspace)
    assert dispatcher.calls == [
        ("security_examiner", "insecure_config"),
        ("adversarial_reviewer", "insecure_config"),
        ("adversarial_reviewer", None),
        ("final_review_writer", None),
    ]


class _Boom(Exception):
    pass


class _Untouchable:
    def __getattr__(self, name):
        raise AssertionError(f"the scripted dispatcher touched {name}")


def test_the_dispatcher_calls_no_model_and_writes_no_audit_line(workspace):
    dispatcher = scripted.ScriptedDispatcher(_script())
    ctx = ExaminationContext("security_examiner", "secrets", "SEC", workspace)
    result = dispatcher(
        _Untouchable(), _Untouchable(), SECURITY, {}, ctx,
        workspace=workspace, workflow="security_examiner", step="secrets", parent_step_id="x:1",
    )
    assert result["findings"] == []


def test_a_returned_answer_is_a_copy_so_a_caller_cannot_change_the_script(workspace):
    script = _script(_answer("security_examiner", "secrets", _attempt(_body([_finding()]))))
    before = copy.deepcopy(script)
    dispatcher = scripted.ScriptedDispatcher(script)
    first = _examine(dispatcher, workspace)
    first["findings"].clear()
    first["summary"] = "changed"
    again = _examine(dispatcher, workspace)
    assert (again["summary"], len(again["findings"])) == ("Examined.", 1)
    assert script == before


def test_a_script_changed_after_the_dispatcher_was_built_does_not_change_its_answers(workspace):
    script = _script(_answer("security_examiner", "secrets", _attempt(_body([_finding()]))))
    dispatcher = scripted.ScriptedDispatcher(script)
    script["answers"][0]["attempts"][0]["output"]["findings"].clear()
    script["answers"].clear()
    assert len(_examine(dispatcher, workspace)["findings"]) == 1


def test_two_dispatchers_of_one_script_count_their_own_attempts(workspace):
    script = _script(_answer("security_examiner", "secrets", _attempt(_body([_finding()])), _attempt(_body())))
    first, second = scripted.ScriptedDispatcher(script), scripted.ScriptedDispatcher(script)
    _examine(first, workspace)
    assert len(_examine(second, workspace)["findings"]) == 1


def test_the_replacement_is_what_runner_calls_inside_the_block_and_the_original_after_it():
    original = runner.run_subagent
    with scripted.replacing_subagents("a stand-in"):
        assert runner.run_subagent == "a stand-in"
    assert runner.run_subagent is original


def test_the_original_run_subagent_comes_back_after_an_error_in_the_block():
    original = runner.run_subagent
    with pytest.raises(_Boom):
        with scripted.replacing_subagents("a stand-in"):
            raise _Boom
    assert runner.run_subagent is original


def test_a_workspace_of_files_holds_them_at_their_paths_and_is_removed_afterwards():
    with scripted.workspace_of({"app.py": APP, "deploy/ci.yml": "on: push\n"}) as workspace:
        root = workspace.root
        assert workspace.read_lines("app.py")[2] == "SECRET_KEY = os.environ['SECRET_KEY']"
        assert workspace.read_lines("deploy/ci.yml") == ["on: push"]
    assert not root.exists()


def test_a_workspace_of_no_files_is_an_empty_directory():
    with scripted.workspace_of({}) as workspace:
        assert list(workspace.root.iterdir()) == []


def test_the_workspace_is_removed_even_when_the_block_fails():
    root = None
    with pytest.raises(_Boom):
        with scripted.workspace_of({"app.py": APP}) as workspace:
            root = workspace.root
            raise _Boom
    assert root is not None and not root.exists()


@pytest.fixture
def scratch(monkeypatch, tmp_path):
    """Point the temporary directory at an empty folder, so that what a block leaves behind can be listed."""
    folder = tmp_path / "scratch"
    folder.mkdir()
    monkeypatch.setenv("TMPDIR", str(folder))
    monkeypatch.setattr("tempfile.tempdir", None)
    return folder


@pytest.mark.parametrize("name", ["../escape.py", "/etc/passwd", "a/../../escape.py", "node_modules/x.js"])
def test_a_file_name_that_leaves_the_workspace_or_is_not_read_is_refused_and_nothing_is_left(name, scratch):
    with pytest.raises(ValueError, match="files: "):
        with scripted.workspace_of({name: "x"}):
            pass
    assert os.listdir(scratch) == []
    assert not (scratch.parent / "escape.py").exists()


@pytest.mark.parametrize(
    ("files", "pattern"),
    [
        pytest.param({"a": "x\n", "a/b": "y\n"}, r"^files: a/b: ", id="a-file-and-a-directory-of-one-name"),
        pytest.param({"a/b": "y\n", "a": "x\n"}, r"^files: a: ", id="a-directory-and-a-file-of-one-name"),
        pytest.param(
            {"A.py": "1\n", "a.py": "2\n"},
            r"^files: a\.py and A\.py name the same file, letter case or Unicode form ignored",
            id="names-that-differ-in-letter-case-only",
        ),
        pytest.param(
            {"a.py": "1\n", "./a.py": "2\n"},
            r"^files: \./a\.py and a\.py name the same file",
            id="one-file-spelled-two-ways",
        ),
        pytest.param(
            {"caf\u00e9.py": "1\n", "cafe\u0301.py": "2\n"},
            r"^files: .* name the same file, letter case or Unicode form ignored",
            id="names-that-differ-in-unicode-form-only",
        ),
        pytest.param({"a.py": "x\ud800y"}, r"^files: a\.py: ", id="text-that-cannot-be-encoded"),
    ],
)
def test_file_names_that_cannot_all_be_written_are_refused_naming_files_and_leave_nothing(files, pattern, scratch):
    with pytest.raises(ValueError, match=pattern):
        with scripted.workspace_of(files):
            pass
    assert os.listdir(scratch) == []


def _valid():
    return _script(
        _answer("security_examiner", "secrets", _attempt(_body([_finding()])), _attempt(_body())),
        _answer("adversarial_reviewer", "secrets", _attempt(_review("block", [_challenge()])), _attempt(_review())),
        _answer("adversarial_reviewer", None, _attempt(_review("block", [_challenge("")])), _attempt(_review())),
        _answer("final_review_writer", None, _attempt(_draft())),
    )


def test_a_script_whose_answers_the_guardrails_accept_passes_the_check():
    scripted.check_script(_valid(), MANIFESTS)


def test_a_script_with_no_answers_passes_the_check():
    scripted.check_script(_script(files={}), MANIFESTS)


def _set(path, value):
    def mutate(script):
        node = script
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value

    return mutate


def _remove(*path):
    def mutate(script):
        node = script
        for part in path[:-1]:
            node = node[part]
        del node[path[-1]]

    return mutate


def _second_review_repeats_the_first(script):
    attempts = script["answers"][1]["attempts"]
    attempts[1] = copy.deepcopy(attempts[0])


BROKEN_SCRIPTS = [
    pytest.param(_set(["answers", 0, "agent"], "ghost"), "ghost", id="unknown-agent"),
    pytest.param(_set(["answers", 0, "agent"], "dependency_examiner"), "secrets", id="step-of-another-examiner"),
    pytest.param(_set(["answers", 0, "step"], "nonsense"), "nonsense", id="unknown-examiner-step"),
    pytest.param(_remove("answers", 0, "step"), "step", id="examiner-without-step"),
    pytest.param(_set(["answers", 1, "step"], "nonsense"), "nonsense", id="review-of-unknown-step"),
    pytest.param(_set(["answers", 3, "step"], "secrets"), "final_review_writer", id="writer-with-a-step"),
    pytest.param(_set(["answers", 0, "agent"], "adversarial_reviewer"), "twice", id="review-key-listed-twice"),
    pytest.param(
        lambda script: script["answers"].append(copy.deepcopy(script["answers"][0])), "twice", id="duplicate-key"
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "findings", 0, "line"], 99),
        "answers/0/attempts/0: EVIDENCE_INVALID",
        id="line-the-workspace-lacks",
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "findings", 0, "file"], "missing.py"),
        "EVIDENCE_INVALID",
        id="file-the-workspace-lacks",
    ),
    pytest.param(
        _remove("answers", 0, "attempts", 1, "output", "summary"),
        "answers/0/attempts/1: SCHEMA_INVALID",
        id="no-summary",
    ),
    pytest.param(
        _set(["answers", 1, "attempts", 0, "output", "verdict"], "pass"),
        "verdict",
        id="verdict-the-challenges-contradict",
    ),
    pytest.param(
        _set(["answers", 1, "attempts", 0, "output", "challenges", 0, "finding_id"], "SEC-9"),
        "EVIDENCE_INVALID",
        id="challenge-of-a-finding-no-examination-has",
    ),
    pytest.param(
        _set(["answers", 2, "attempts", 0, "output", "challenges", 0, "finding_id"], "SEC-1"),
        "EVIDENCE_INVALID",
        id="draft-challenge-naming-a-finding",
    ),
    pytest.param(
        _set(["answers", 3, "attempts", 0, "output", "sections", 0, "prose"], "See [SEC-1]."),
        "EVIDENCE_INVALID",
        id="draft-citing-an-id",
    ),
    pytest.param(
        lambda script: script["answers"][3]["attempts"][0]["output"]["sections"].pop(),
        "SCHEMA_INVALID",
        id="draft-missing-a-section",
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "refused"], "SCHEMA_INVALID"),
        "answers/0/attempts/0: the guardrails accepted",
        id="marked-refused-but-accepted",
    ),
    pytest.param(
        lambda script: (
            script["answers"][0]["attempts"][1]["output"].pop("summary"),
            script["answers"][0]["attempts"][1].update(refused="EVIDENCE_INVALID"),
        ),
        "SCHEMA_INVALID",
        id="marked-with-another-code-than-the-guardrails-gave",
    ),
    pytest.param(
        _set(["answers", 3, "attempts", 0, "refused"], "EVIDENCE_INVALID"),
        "answers/3/attempts/0: a writer's attempt cannot be marked EVIDENCE_INVALID",
        id="writer-marked-evidence-invalid",
    ),
    pytest.param(
        lambda script: script["answers"][3]["attempts"][0].update(
            refused="EVIDENCE_INVALID", output=_draft("See [SEC-1] for the key.")
        ),
        "answers/3/attempts/0: a writer's attempt cannot be marked EVIDENCE_INVALID",
        id="writer-citing-an-id-marked-evidence-invalid",
    ),
    pytest.param(_set(["files"], {"../x.py": "text"}), "files: ../x.py", id="file-outside-the-workspace"),
    pytest.param(_set(["files"], {"A.py": "1\n", "a.py": "2\n"}), "files: ", id="files-that-collide-in-letter-case"),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "step"], "insecure_config"),
        "answers/0/attempts/0: output states step",
        id="examination-stating-its-step",
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "workflow"], "security_examiner"),
        "answers/0/attempts/0: output states workflow",
        id="examination-stating-its-workflow",
    ),
    pytest.param(
        _set(["answers", 1, "attempts", 0, "output", "target_id"], "EX-SEC-v1"),
        "answers/1/attempts/0: output states target_id",
        id="review-stating-its-target",
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "findings"], None),
        "answers/0/attempts/0: SCHEMA_INVALID",
        id="findings-null",
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "findings"], 5),
        "answers/0/attempts/0: SCHEMA_INVALID",
        id="findings-an-integer",
    ),
    pytest.param(
        _set(["answers", 0, "attempts", 0, "output", "findings"], 2.5),
        "answers/0/attempts/0: SCHEMA_INVALID",
        id="findings-a-float",
    ),
    pytest.param(
        _set(["answers", 1, "attempts", 0, "output", "findings"], 5),
        "answers/1/attempts/0: SCHEMA_INVALID",
        id="review-with-a-findings-field",
    ),
    pytest.param(
        _second_review_repeats_the_first,
        "answers/1/attempts/1: EVIDENCE_INVALID",
        id="review-citing-a-finding-the-examination-it-pairs-with-lacks",
    ),
    pytest.param(
        lambda script: script["answers"][1]["attempts"].pop(1),
        "answers/1/attempts/0: EVIDENCE_INVALID",
        id="repeated-review-citing-a-finding-a-later-examination-lacks",
    ),
    pytest.param(
        lambda script: script["answers"].pop(0),
        "answers/0/attempts/0: EVIDENCE_INVALID",
        id="review-citing-a-finding-of-an-unscripted-examiner",
    ),
]


@pytest.mark.parametrize(("mutate", "fragment"), BROKEN_SCRIPTS)
def test_a_script_that_breaks_a_rule_is_refused_with_the_attempt_it_names(mutate, fragment):
    script = _valid()
    mutate(script)
    with pytest.raises(ValueError, match=fragment.replace("[", r"\[").replace("]", r"\]")):
        scripted.check_script(script, MANIFESTS)


def test_a_repeated_review_is_checked_against_every_examination_it_will_serve():
    script = _valid()
    script["answers"][0]["attempts"][1] = _attempt(_body([_finding(line=4)]))
    script["answers"][1]["attempts"].pop(1)
    scripted.check_script(script, MANIFESTS)


def test_a_refused_review_attempt_is_retried_on_the_examination_it_failed_to_review():
    script = _valid()
    refused = _attempt(_review("block", []), "SCHEMA_INVALID")
    script["answers"][1]["attempts"] = [refused, _attempt(_review("block", [_challenge()])), _attempt(_review())]
    scripted.check_script(script, MANIFESTS)


def test_a_review_retried_after_a_refusal_is_checked_against_the_examination_it_retries():
    script = _valid()
    script["answers"][0]["attempts"] = [_attempt(_body()), _attempt(_body([_finding()]))]
    refused = _attempt(_review("block", []), "SCHEMA_INVALID")
    script["answers"][1]["attempts"] = [refused, _attempt(_review("block", [_challenge()]))]
    with pytest.raises(ValueError, match="answers/1/attempts/1: EVIDENCE_INVALID"):
        scripted.check_script(script, MANIFESTS)


def test_a_review_that_is_refused_every_time_never_moves_on_to_a_later_examination():
    script = _valid()
    script["answers"][0]["attempts"] = [_attempt(_body([_finding()])), _attempt(_body([_finding(), _finding(4)]))]
    script["answers"][1]["attempts"] = [_attempt(_review("block", [_challenge("SEC-2")]), "EVIDENCE_INVALID")]
    scripted.check_script(script, MANIFESTS)


def test_a_refused_examination_attempt_is_no_examination_so_reviews_pair_with_the_accepted_ones():
    script = _valid()
    script["answers"][0]["attempts"].insert(0, _attempt({}, "SCHEMA_INVALID"))
    scripted.check_script(script, MANIFESTS)
    script["answers"][0]["attempts"].insert(1, _attempt(_body()))
    with pytest.raises(ValueError, match="answers/1/attempts/0: EVIDENCE_INVALID"):
        scripted.check_script(script, MANIFESTS)


def test_a_later_review_attempt_is_checked_against_the_examination_an_unscripted_examiner_gives():
    script = _valid()
    script["answers"].pop(0)
    script["answers"][0]["attempts"] = [_attempt(_review()), _attempt(_review("block", [_challenge()]))]
    with pytest.raises(ValueError, match="answers/0/attempts/1: EVIDENCE_INVALID"):
        scripted.check_script(script, MANIFESTS)


def test_a_review_past_the_last_examination_an_examiner_will_give_is_never_asked_for():
    script = _valid()
    script["answers"][0]["attempts"] = [_attempt(_body()), _attempt({}, "SCHEMA_INVALID")]
    script["answers"][1]["attempts"] = [_attempt(_review()), _attempt(_review("block", [_challenge()]))]
    scripted.check_script(script, MANIFESTS)


def test_a_writer_attempt_marked_schema_invalid_is_checked_like_any_other():
    script = _valid()
    refused = _attempt({"executive_summary": "x", "sections": []}, "SCHEMA_INVALID")
    script["answers"][3]["attempts"] = [refused, _attempt(_draft())]
    scripted.check_script(script, MANIFESTS)


def test_a_review_of_a_step_whose_examiner_never_gets_an_attempt_accepted_is_never_asked_for():
    script = _valid()
    script["answers"][0]["attempts"] = [_attempt({}, "SCHEMA_INVALID")]
    scripted.check_script(script, MANIFESTS)


def test_an_attempt_marked_refused_that_the_guardrails_refuse_with_that_code_passes_the_check():
    script = _valid()
    script["answers"][0]["attempts"].insert(0, _attempt({}, "SCHEMA_INVALID"))
    scripted.check_script(script, MANIFESTS)


def test_the_check_reads_every_attempt_not_only_the_first():
    script = _valid()
    script["answers"][0]["attempts"][1]["output"]["findings"] = [_finding(line=99)]
    with pytest.raises(ValueError, match="answers/0/attempts/1"):
        scripted.check_script(script, MANIFESTS)


def test_the_check_leaves_no_workspace_directory_behind(scratch):
    broken = _valid()
    broken["answers"][0]["attempts"][0]["output"]["findings"][0]["line"] = 99
    scripted.check_script(_valid(), MANIFESTS)
    with pytest.raises(ValueError):
        scripted.check_script(broken, MANIFESTS)
    assert os.listdir(scratch) == []
