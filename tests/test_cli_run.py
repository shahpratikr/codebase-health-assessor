import hashlib
import itertools
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from anthropic.types.beta import BetaMessage

from assessor import cli, config
from assessor.llm import NoCredentialsError

NOW = datetime(2026, 10, 27, 10, 15, tzinfo=UTC)
SECRET = "AKIAIOSFODNN7EXAMPLE"
STEPS = [
    ("security_examiner", "secrets"),
    ("security_examiner", "insecure_config"),
    ("dependency_examiner", "known_vulnerabilities"),
    ("dependency_examiner", "dependency_hygiene"),
]
CODES = {"secrets": "SEC", "insecure_config": "CFG", "known_vulnerabilities": "VULN", "dependency_hygiene": "HYG"}
WORKFLOWS = {step: workflow for workflow, step in STEPS}
SECRET_FINDING = {
    "title": "AWS access key committed in source",
    "severity": "critical",
    "category": "aws-key",
    "file": "config.py",
    "line": 2,
    "evidence": f'AWS_ACCESS_KEY_ID = "{SECRET}"',
    "recommendation": "Rotate the key and read it from the environment.",
    "advisory_ids": [],
}
CRITICAL_CHALLENGE = {
    "finding_id": "SEC-1",
    "lens": "challenge",
    "severity": "critical",
    "claim": "Line 2 holds the key, but the finding misreads which variable it is assigned to.",
    "evidence_checked": [{"file": "config.py", "line": 2}],
    "rationale": "The line assigns AWS_ACCESS_KEY_ID, as read.",
}
CRITICAL_DRAFT_CHALLENGE = {
    "finding_id": "",
    "lens": "catch",
    "severity": "critical",
    "claim": "The summary leaves out the committed key.",
    "evidence_checked": [{"file": "config.py", "line": 2}],
    "rationale": "Line 2 holds the key.",
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


def _examine(step, number):
    return _launch(WORKFLOWS[step], {"step": step, "challenge_ids": [], "note": ""}, number)


def _review_of(target_id, number=1):
    return _launch("adversarial_reviewer", {"target_id": target_id}, number)


def _examination(step, findings, summary=None):
    return {
        "workflow": WORKFLOWS[step],
        "step": step,
        "summary": summary or f"Examined the {step} step.",
        "findings": findings,
        "limitations": [],
        "challenge_responses": [],
    }


def _review(target_id, *challenges):
    critical = any(challenge["severity"] == "critical" for challenge in challenges)
    verdict = "block" if critical else "challenge" if challenges else "pass"
    return {"target_id": target_id, "verdict": verdict, "summary": "Checked.", "challenges": list(challenges)}


def _disposition(decisions=None, rationale="The review found nothing to fix.", summary="Every step is accepted."):
    decisions = decisions or {}
    return {
        "steps": [
            {
                "workflow": workflow,
                "step": step,
                "examination_id": f"EX-{CODES[step]}-v1",
                "decision": decisions.get(step, "accept"),
                "rationale": rationale,
            }
            for workflow, step in STEPS
        ],
        "summary": summary,
    }


def _draft(prose=None):
    prose = prose or {}
    return {
        "executive_summary": "The assessment is complete.",
        "sections": [
            {"key": f"{workflow}.{step}", "prose": prose.get(step, f"The {step} step was examined.")}
            for workflow, step in STEPS
        ],
    }


def _examined(findings=None, summary=None):
    findings = findings or {}
    return [
        _turn(*[_examine(step, number) for number, (_, step) in enumerate(STEPS, 1)]),
        *[_answer(_examination(step, findings.get(step, []), summary)) for _, step in STEPS],
    ]


def _reviewed(challenges=None):
    challenges = challenges or {}
    ids = {step: f"EX-{CODES[step]}-v1" for _, step in STEPS}
    return [
        _turn(*[_review_of(ids[step], number) for number, (_, step) in enumerate(STEPS, 1)]),
        *[_answer(_review(ids[step], *challenges.get(step, []))) for _, step in STEPS],
    ]


def _drafted(disposition=None, draft=None, draft_challenges=()):
    return [
        _turn(_launch("final_review_writer", {"disposition": disposition or _disposition(), "challenge_ids": []})),
        _answer(draft or _draft()),
        _turn(_review_of("DR-v1")),
        _answer(_review("DR-v1", *draft_challenges)),
    ]


def _clean():
    return [*_examined(), *_reviewed(), *_drafted(), _done()]


def _repo(tmp_path):
    repo = tmp_path / "acme-api"
    repo.mkdir(exist_ok=True)
    (repo / "config.py").write_text(f'DEBUG = True\nAWS_ACCESS_KEY_ID = "{SECRET}"\n')
    (repo / "requirements.txt").write_text("flask>=2\nrequests==2.19.0\n")
    return repo


def _zipped(tmp_path):
    archive = tmp_path / "acme-api.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zipped:
        for path in sorted(_repo(tmp_path).iterdir()):
            zipped.write(path, path.name)
    return archive


@pytest.fixture
def assess(fake_anthropic, monkeypatch, tmp_path):
    """Return a function that runs `assess run` on a source with scripted model responses; it returns the exit code
    and the fake client."""

    def run(script, *extra, source=None, clock=lambda: NOW):
        client = fake_anthropic(script)
        monkeypatch.setattr(cli, "make_client", lambda: client)
        code = cli.main(["run", str(source or _repo(tmp_path)), *extra], clock=clock)
        return code, client

    return run


def _only_run(runs):
    (run_dir,) = runs.iterdir()
    return run_dir


def _json(path):
    return json.loads(path.read_text())


def _audit(run_dir):
    return [json.loads(line) for line in (run_dir / "audit.jsonl").read_text().splitlines()]


def _headings(run_dir):
    return [line for line in (run_dir / "report.md").read_text().splitlines() if line.startswith("#")]


def _no_run_created(runs):
    return not runs.exists() or not any(runs.iterdir())


def _substance(tmp_path, **ratings):
    substance = _json(config.SUBSTANCE_FILE)
    for workflow, rating in ratings.items():
        substance["ratings"][workflow]["rating"] = rating
    path = tmp_path / "substance.json"
    path.write_text(json.dumps(substance))
    return str(path)


def test_a_repository_with_no_findings_is_finalized_with_every_section_pass(
    assess, tmp_path, tmp_runs_dir, capsys
):
    code, client = assess(_clean())
    run_dir = _only_run(tmp_runs_dir)
    assert code == 0
    assert client.script == []
    captured = capsys.readouterr()
    assert captured.out == f"correlation_id: {run_dir.name}\nstatus: finalized\nopen_gates: none\n"
    assert captured.err == ""
    assert sorted(path.name for path in run_dir.iterdir()) == [
        "audit.jsonl",
        "disposition.json",
        "drafts",
        "examinations",
        "report.md",
        "reviews",
        "run.json",
        "summary.json",
    ]
    assert _json(run_dir / "run.json") == {
        "correlation_id": run_dir.name,
        "input": {"path": str((tmp_path / "acme-api").resolve()), "kind": "directory"},
        "started_at": "2026-10-27T10:15:00.000Z",
        "finished_at": "2026-10-27T10:15:00.000Z",
        "status": "finalized",
        "gates": [],
        "halt_reason": None,
    }
    assert _json(run_dir / "disposition.json") == _disposition()
    assert _headings(run_dir) == [
        "# Codebase Health Assessment — acme-api",
        "## Executive summary",
        "## Secrets exposure — PASS",
        "## Insecure configuration — PASS",
        "## Known vulnerable dependencies — PASS",
        "## Dependency hygiene — PASS",
        "## Review trail",
    ]
    assert "Human review" not in (run_dir / "report.md").read_text()
    assert not (run_dir / "decisions.jsonl").exists()


def test_the_audit_opens_with_run_started_and_closes_with_run_finished(assess, tmp_runs_dir):
    assess(_clean())
    lines = _audit(_only_run(tmp_runs_dir))
    assert (lines[0]["event"], lines[-1]["event"]) == ("run_started", "run_finished")
    assert (lines[-1]["status"], lines[-1]["halt_reason"]) == ("finalized", None)
    assert [line["seq"] for line in lines] == list(range(1, len(lines) + 1))
    assert "gate_opened" not in {line["event"] for line in lines}


def test_the_summary_totals_equal_the_sums_of_the_audit_lines(assess, tmp_runs_dir):
    assess(_clean())
    run_dir = _only_run(tmp_runs_dir)
    calls = [line for line in _audit(run_dir) if line["event"] == "llm_call"]
    summary = _json(run_dir / "summary.json")
    assert summary["correlation_id"] == run_dir.name
    assert set(summary["agents"]) == {
        "coordinator",
        "security_examiner",
        "dependency_examiner",
        "adversarial_reviewer",
        "final_review_writer",
    }
    assert {agent: totals["llm_calls"] for agent, totals in summary["agents"].items()} == {
        "coordinator": 5,
        "security_examiner": 2,
        "dependency_examiner": 2,
        "adversarial_reviewer": 5,
        "final_review_writer": 1,
    }
    for agent, totals in [*summary["agents"].items(), ("", summary["total"])]:
        mine = [call for call in calls if agent in ("", call["agent"])]
        assert totals["llm_calls"] == len(mine)
        for field in config.TOKEN_FIELDS:
            assert totals[field] == sum(call[field] for call in mine)
        assert totals["cost_usd"] == pytest.approx(sum(call["cost_usd"] for call in mine), abs=1e-9)
        assert totals["unpriced_calls"] == 0
    assert summary["total"]["llm_calls"] == 15
    assert summary["total"]["input_tokens"] == 1500


def test_the_run_files_carry_the_clock_time_of_the_run_not_of_the_writes(assess, tmp_runs_dir):
    ticks = itertools.count()
    assess(_clean(), clock=lambda: NOW + timedelta(seconds=next(ticks)))
    run_dir = _only_run(tmp_runs_dir)
    run = _json(run_dir / "run.json")
    assert run["started_at"] < run["finished_at"]
    assert f"- Generated at: {run['finished_at']}\n" in (run_dir / "report.md").read_text()
    assert _audit(run_dir)[0]["ts"] == run["started_at"]


def test_the_coordinator_is_told_the_name_of_the_repository(assess):
    _, client = assess(_clean())
    assert json.loads(client.requests[0]["messages"][0]["content"])["workspace"] == "acme-api"


def test_a_zip_is_extracted_into_the_run_directory_and_assessed(assess, tmp_path, tmp_runs_dir):
    archive = _zipped(tmp_path)
    code, client = assess(_clean(), source=archive)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 0
    assert (run_dir / "workspace" / "config.py").read_text() == (tmp_path / "acme-api" / "config.py").read_text()
    assert _json(run_dir / "run.json")["input"] == {"path": str(archive.resolve()), "kind": "zip"}
    assert json.loads(client.requests[0]["messages"][0]["content"])["workspace"] == "acme-api.zip"
    assert _headings(run_dir)[0] == "# Codebase Health Assessment — acme-api.zip"


def test_a_toy_workflow_holds_the_run_for_a_human(assess, tmp_path, tmp_runs_dir, capsys):
    ratings = _substance(tmp_path, final_review_writer="toy")
    code, _ = assess(_clean(), "--substance", ratings)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 3
    assert capsys.readouterr().out == (
        f"correlation_id: {run_dir.name}\nstatus: pending_human\nopen_gates: SUBSTANCE_ELEVATION\n"
    )
    gates = [{"gate": "SUBSTANCE_ELEVATION", "subjects": ["final_review_writer"]}]
    run = _json(run_dir / "run.json")
    assert (run["status"], run["gates"], run["halt_reason"]) == ("pending_human", gates, None)
    lines = _audit(run_dir)
    assert [(line["gate"], line["subjects"]) for line in lines if line["event"] == "gate_opened"] == [
        ("SUBSTANCE_ELEVATION", ["final_review_writer"])
    ]
    assert lines[-1]["event"] == "run_finished" and lines[-1]["status"] == "pending_human"
    report = (run_dir / "report.md").read_text()
    assert "- Status at generation: pending_human\n- Open gates: SUBSTANCE_ELEVATION\n" in report
    assert _headings(run_dir)[-1] == "## Human review"


def test_two_peripheral_workflows_hold_the_run_and_one_does_not(assess, tmp_path, tmp_runs_dir):
    ratings = _substance(tmp_path, dependency_examiner="peripheral")
    code, _ = assess(_clean(), "--substance", ratings)
    assert code == 3
    assert _json(_only_run(tmp_runs_dir) / "run.json")["gates"] == [
        {"gate": "SUBSTANCE_ELEVATION", "subjects": ["dependency_examiner", "final_review_writer"]}
    ]


@pytest.mark.parametrize("content", ["", "{", "[]", '{"ratings": {}, "not_rated": {}}'])
def test_a_substance_file_the_loader_refuses_exits_2_before_any_request_or_run(
    fake_anthropic, monkeypatch, tmp_path, tmp_runs_dir, capsys, content
):
    client = fake_anthropic([])
    monkeypatch.setattr(cli, "make_client", lambda: client)
    ratings = tmp_path / "ratings.json"
    ratings.write_text(content)
    assert cli.main(["run", str(_repo(tmp_path)), "--substance", str(ratings)], clock=lambda: NOW) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"assess run: {ratings}")
    assert client.requests == []
    assert _no_run_created(tmp_runs_dir)


def test_a_substance_file_that_does_not_exist_exits_2(assess, tmp_path, tmp_runs_dir, capsys):
    code, client = assess([], "--substance", str(tmp_path / "missing.json"))
    assert code == 2
    assert "No such file or directory" in capsys.readouterr().err
    assert (client.requests, _no_run_created(tmp_runs_dir)) == ([], True)


def test_a_block_on_an_accepted_examination_holds_the_run_though_the_coordinator_accepted(
    assess, tmp_runs_dir, capsys
):
    script = [
        *_examined({"secrets": [SECRET_FINDING]}),
        *_reviewed({"secrets": [CRITICAL_CHALLENGE]}),
        *_drafted(),
        _done(),
    ]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 3
    assert capsys.readouterr().out.endswith("status: pending_human\nopen_gates: OPEN_CRITICAL_CHALLENGE\n")
    assert _json(run_dir / "run.json")["gates"] == [{"gate": "OPEN_CRITICAL_CHALLENGE", "subjects": ["EX-SEC-v1"]}]
    assert "## Secrets exposure — FAIL" in _headings(run_dir)
    assert "## Insecure configuration — PASS" in _headings(run_dir)


def test_every_open_gate_is_audited_in_the_closed_set_order_and_printed(assess, tmp_path, tmp_runs_dir, capsys):
    ratings = _substance(tmp_path, final_review_writer="toy")
    script = [*_examined(), *_reviewed(), *_drafted(_disposition({"insecure_config": "escalate"})), _done()]
    code, _ = assess(script, "--substance", ratings)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 3
    assert capsys.readouterr().out.endswith("open_gates: SUBSTANCE_ELEVATION, COORDINATOR_ESCALATION\n")
    opened = [line for line in _audit(run_dir) if line["event"] == "gate_opened"]
    assert [(line["gate"], line["subjects"]) for line in opened] == [
        ("SUBSTANCE_ELEVATION", ["final_review_writer"]),
        ("COORDINATOR_ESCALATION", ["security_examiner.insecure_config"]),
    ]
    assert [gate["gate"] for gate in _json(run_dir / "run.json")["gates"]] == [line["gate"] for line in opened]


def test_a_blocked_newer_examination_holds_the_run_though_the_disposition_names_the_older_one(
    assess, tmp_runs_dir, capsys
):
    debug_finding = {
        **SECRET_FINDING,
        "title": "Debug flag left on",
        "category": "debug",
        "line": 1,
        "evidence": "DEBUG = True",
    }
    debug_challenge = {
        **CRITICAL_CHALLENGE,
        "finding_id": "CFG-1",
        "evidence_checked": [{"file": "config.py", "line": 1}],
    }
    again = [
        _launch("security_examiner", {"step": step, "challenge_ids": [], "note": "again"}, number)
        for number, step in enumerate(["insecure_config", "secrets"], 1)
    ]
    script = [
        *_examined(),
        *_reviewed(),
        _turn(*again),
        _answer(_examination("insecure_config", [debug_finding])),
        _answer(_examination("secrets", [])),
        _turn(_review_of("EX-CFG-v2", 1), _review_of("EX-SEC-v2", 2)),
        _answer(_review("EX-CFG-v2", debug_challenge)),
        _answer(_review("EX-SEC-v2")),
        *_drafted(),
        _done(),
    ]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 3
    assert capsys.readouterr().out.endswith("open_gates: OPEN_CRITICAL_CHALLENGE\n")
    assert _json(run_dir / "run.json")["gates"] == [{"gate": "OPEN_CRITICAL_CHALLENGE", "subjects": ["EX-CFG-v2"]}]
    assert "## Insecure configuration — PASS" in _headings(run_dir)
    assert "Subjects: EX-CFG-v2." in (run_dir / "report.md").read_text()


def test_an_unreviewed_newest_examination_does_not_hide_the_block_on_the_one_before_it(assess, tmp_runs_dir):
    again = _launch("security_examiner", {"step": "secrets", "challenge_ids": [], "note": "again"})
    script = [
        *_examined(),
        *_reviewed(),
        _turn(again),
        _answer(_examination("secrets", [SECRET_FINDING])),
        _turn(_review_of("EX-SEC-v2")),
        _answer(_review("EX-SEC-v2", CRITICAL_CHALLENGE)),
        _turn(again),
        _answer(_examination("secrets", [])),
        *_drafted(),
        _done(),
    ]
    code, _ = assess(script)
    assert code == 3
    assert _json(_only_run(tmp_runs_dir) / "run.json")["gates"] == [
        {"gate": "OPEN_CRITICAL_CHALLENGE", "subjects": ["EX-SEC-v2"]}
    ]


def test_a_blocked_draft_holds_the_run(assess, tmp_runs_dir):
    script = [*_examined(), *_reviewed(), *_drafted(draft_challenges=[CRITICAL_DRAFT_CHALLENGE]), _done()]
    code, _ = assess(script)
    assert code == 3
    assert _json(_only_run(tmp_runs_dir) / "run.json")["gates"] == [
        {"gate": "OPEN_CRITICAL_CHALLENGE", "subjects": ["DR-v1"]}
    ]


def test_only_the_latest_draft_counts_when_the_first_was_blocked_and_the_second_passes(assess, tmp_runs_dir):
    redraft = [
        _turn(_launch("final_review_writer", {"disposition": _disposition(), "challenge_ids": ["RV-5-C1"]})),
        _answer(_draft()),
        _turn(_review_of("DR-v2")),
        _answer(_review("DR-v2")),
    ]
    script = [
        *_examined(),
        *_reviewed(),
        *_drafted(draft_challenges=[CRITICAL_DRAFT_CHALLENGE]),
        *redraft,
        _done(),
    ]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 0
    assert _json(run_dir / "run.json")["gates"] == []
    assert sorted(path.name for path in (run_dir / "drafts").iterdir()) == ["DR-v1.json", "DR-v2.json"]


def test_an_escalated_step_holds_the_run_and_shows_in_the_review_trail(assess, tmp_runs_dir, capsys):
    script = [*_examined(), *_reviewed(), *_drafted(_disposition({"insecure_config": "escalate"})), _done()]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 3
    assert capsys.readouterr().out.endswith("open_gates: COORDINATOR_ESCALATION\n")
    assert _json(run_dir / "run.json")["gates"] == [
        {"gate": "COORDINATOR_ESCALATION", "subjects": ["security_examiner.insecure_config"]}
    ]
    assert "| Insecure configuration | EX-CFG-v1 | pass | escalate |" in (run_dir / "report.md").read_text()


def test_a_run_ending_with_no_draft_halts_with_no_report_and_writes_no_report(assess, tmp_runs_dir, capsys):
    code, client = assess([_done()])
    run_dir = _only_run(tmp_runs_dir)
    assert code == 1
    assert capsys.readouterr().out == f"correlation_id: {run_dir.name}\nstatus: halted\nopen_gates: none\n"
    assert sorted(path.name for path in run_dir.iterdir()) == ["audit.jsonl", "run.json", "summary.json"]
    run = _json(run_dir / "run.json")
    assert (run["status"], run["gates"], run["halt_reason"]) == ("halted", [], "NO_REPORT")
    assert _audit(run_dir)[-1]["status"] == "halted" and _audit(run_dir)[-1]["halt_reason"] == "NO_REPORT"
    assert _json(run_dir / "summary.json")["total"]["llm_calls"] == len(client.requests) == 1


def test_a_run_whose_latest_draft_has_no_review_halts_with_report_not_reviewed(assess, tmp_runs_dir):
    script = [*_examined(), *_reviewed(), *_drafted()[:2], _done()]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 1
    assert _json(run_dir / "run.json")["halt_reason"] == "REPORT_NOT_REVIEWED"
    assert not (run_dir / "report.md").exists() and not (run_dir / "disposition.json").exists()
    assert (run_dir / "drafts" / "DR-v1.json").exists()


def test_a_redraft_without_a_review_halts_though_the_first_draft_was_reviewed(assess, tmp_runs_dir):
    rewrite = _launch("final_review_writer", {"disposition": _disposition(), "challenge_ids": []})
    redraft = [_turn(rewrite), _answer(_draft())]
    code, _ = assess([*_examined(), *_reviewed(), *_drafted(), *redraft, _done()])
    assert code == 1
    assert _json(_only_run(tmp_runs_dir) / "run.json")["halt_reason"] == "REPORT_NOT_REVIEWED"


def test_a_coordinator_halt_decides_the_reason_even_when_a_reviewed_draft_exists(assess, tmp_runs_dir):
    refusal = _message([{"type": "text", "text": "I cannot continue."}], "refusal")
    code, _ = assess([*_examined(), *_reviewed(), *_drafted(), refusal])
    run_dir = _only_run(tmp_runs_dir)
    assert code == 1
    assert _json(run_dir / "run.json")["halt_reason"] == "COORDINATOR_REFUSAL"
    assert not (run_dir / "report.md").exists()
    assert _audit(run_dir)[-1]["halt_reason"] == "COORDINATOR_REFUSAL"


@pytest.mark.parametrize(
    ("stop_reason", "halt_reason"), [("refusal", "COORDINATOR_REFUSAL"), ("max_tokens", "COORDINATOR_MAX_TOKENS")]
)
def test_a_coordinator_halt_before_any_draft_keeps_its_own_halt_reason(
    assess, tmp_runs_dir, stop_reason, halt_reason
):
    stopped = _message([{"type": "text", "text": "I cannot continue."}], stop_reason)
    code, _ = assess([stopped])
    assert code == 1
    assert _json(_only_run(tmp_runs_dir) / "run.json")["halt_reason"] == halt_reason


def test_a_halted_run_opens_no_gate_whatever_its_ratings_say(assess, tmp_path, tmp_runs_dir, capsys):
    code, _ = assess([_done()], "--substance", _substance(tmp_path, security_examiner="toy"))
    run_dir = _only_run(tmp_runs_dir)
    assert code == 1
    assert capsys.readouterr().out == f"correlation_id: {run_dir.name}\nstatus: halted\nopen_gates: none\n"
    assert _json(run_dir / "run.json")["gates"] == []
    assert "gate_opened" not in {line["event"] for line in _audit(run_dir)}


def test_a_missing_path_exits_2_without_asking_for_credentials_or_creating_a_run(
    monkeypatch, tmp_path, tmp_runs_dir, capsys
):
    def refuse():
        raise AssertionError("credentials were requested")

    monkeypatch.setattr(cli, "make_client", refuse)
    assert cli.main(["run", str(tmp_path / "nowhere")], clock=lambda: NOW) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"assess run: {tmp_path / 'nowhere'}: does not exist\n"
    assert _no_run_created(tmp_runs_dir)


def test_a_file_that_is_not_a_zip_exits_2_and_creates_no_run(assess, tmp_path, tmp_runs_dir, capsys):
    notes = tmp_path / "notes.txt"
    notes.write_text("not an archive")
    code, client = assess([], source=notes)
    assert code == 2
    assert capsys.readouterr().err == f"assess run: {notes}: not a zip archive\n"
    assert (client.requests, _no_run_created(tmp_runs_dir)) == ([], True)


def test_a_zip_with_an_escaping_entry_exits_2_and_creates_no_run(assess, tmp_path, tmp_runs_dir, capsys):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../outside.txt", "x")
    code, _ = assess([], source=archive)
    assert code == 2
    assert "entry ../outside.txt escapes the workspace" in capsys.readouterr().err
    assert _no_run_created(tmp_runs_dir)


@pytest.mark.parametrize(("cap", "limit"), [("ZIP_MAX_ENTRIES", 1), ("ZIP_MAX_BYTES", 3)])
def test_a_zip_over_a_cap_exits_2_and_creates_no_run(
    assess, monkeypatch, tmp_path, tmp_runs_dir, capsys, cap, limit
):
    monkeypatch.setattr(config, cap, limit)
    code, _ = assess([], source=_zipped(tmp_path))
    assert code == 2
    assert "is over the" in capsys.readouterr().err
    assert _no_run_created(tmp_runs_dir)


def test_a_zip_that_fails_while_extracting_exits_2_and_leaves_no_run_directory(
    assess, tmp_path, tmp_runs_dir, capsys
):
    archive = _zipped(tmp_path)
    archive.write_bytes(archive.read_bytes().replace(b"flask>=2", b"flask>=3"))
    code, client = assess([], source=archive)
    assert code == 2
    assert "could not extract requirements.txt" in capsys.readouterr().err
    assert (client.requests, _no_run_created(tmp_runs_dir)) == ([], True)


def test_missing_credentials_exit_2_with_a_message_and_no_run(monkeypatch, tmp_path, tmp_runs_dir, capsys):
    def refuse():
        raise NoCredentialsError("no Anthropic credentials: set ANTHROPIC_API_KEY")

    monkeypatch.setattr(cli, "make_client", refuse)
    assert cli.main(["run", str(_repo(tmp_path))], clock=lambda: NOW) == 2
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "assess run: no Anthropic credentials: set ANTHROPIC_API_KEY\n")
    assert _no_run_created(tmp_runs_dir)


def test_no_seeded_secret_is_left_under_the_runs_directory(assess, tmp_runs_dir):
    leaky = {"secrets": [SECRET_FINDING]}
    challenge = {**CRITICAL_CHALLENGE, "claim": f"The key {SECRET} on line 2 is real.", "severity": "major"}
    draft = _draft({"secrets": f"The committed key {SECRET} needs rotating."})
    disposition = _disposition(rationale=f"Accepted: {SECRET} is the only key.", summary=f"Rotate {SECRET}.")
    script = [
        *_examined(leaky, summary=f"Found {SECRET}."),
        *_reviewed({"secrets": [challenge]}),
        *_drafted(disposition, draft),
        _done(),
    ]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 0
    stored = {path: path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}
    assert stored
    assert [path for path, data in stored.items() if SECRET.encode() in data] == []
    assert any(b"<redacted:AKIA" in data for data in stored.values())
    assert "&lt;redacted:" in (run_dir / "report.md").read_text()
    redacted = _json(run_dir / "disposition.json")
    assert "<redacted:" in redacted["summary"]
    assert all("<redacted:" in step["rationale"] for step in redacted["steps"])


def test_a_zip_run_leaves_the_clients_own_files_as_the_only_place_a_secret_is_stored(assess, tmp_path, tmp_runs_dir):
    findings = {"secrets": [SECRET_FINDING]}
    script = [*_examined(findings), *_reviewed(), *_drafted(_disposition(rationale=f"Accepted: {SECRET}")), _done()]
    code, _ = assess(script, source=_zipped(tmp_path))
    run_dir = _only_run(tmp_runs_dir)
    assert code == 0
    holders = {path.relative_to(run_dir).parts[0] for path in run_dir.rglob("*") if path.is_file()
               and SECRET.encode() in path.read_bytes()}
    assert holders == {"workspace"}


def test_html_in_the_writers_prose_never_reaches_the_report_unescaped(assess, tmp_runs_dir):
    draft = _draft({"secrets": "<!--\nnot a comment <details> <https://evil.example/x>"})
    code, _ = assess([*_examined(), *_reviewed(), *_drafted(draft=draft), _done()])
    report = (_only_run(tmp_runs_dir) / "report.md").read_text()
    assert code == 0
    assert "<" not in report
    assert "&lt;!--" in report


def test_the_runs_directory_check_sees_through_a_symlink_to_the_input(assess, monkeypatch, tmp_path, capsys):
    repo = _repo(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(repo)
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(repo / "runs"))
    code, client = assess([], source=link)
    assert code == 2
    assert "is inside it" in capsys.readouterr().err
    assert client.requests == []


def test_holds_compares_file_identity_so_a_symlink_to_an_ancestor_of_the_runs_directory_counts(tmp_path):
    repo = _repo(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(repo)
    other = tmp_path / "other"
    other.mkdir()
    assert cli._holds(link, repo / "runs") is True
    assert cli._holds(repo, repo / "runs") is True
    assert cli._holds(other, repo / "runs") is False


def test_the_runs_directory_check_ignores_letter_case_on_a_case_insensitive_volume(
    assess, monkeypatch, tmp_path, capsys
):
    repo = _repo(tmp_path)
    shouted = tmp_path / "ACME-API"
    if not shouted.exists():
        pytest.skip("the volume is case-sensitive")
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(repo / "runs"))
    code, client = assess([], source=shouted)
    assert code == 2
    assert "is inside it" in capsys.readouterr().err
    assert client.requests == []


def test_a_runs_directory_inside_the_input_directory_exits_2_and_creates_nothing(
    assess, monkeypatch, tmp_path, capsys
):
    repo = _repo(tmp_path)
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(repo / "runs"))
    code, client = assess([], source=repo)
    assert code == 2
    assert f"the runs directory {(repo / 'runs').resolve()} is inside it" in capsys.readouterr().err
    assert (client.requests, (repo / "runs").exists()) == ([], False)


def test_the_default_runs_directory_is_refused_when_the_current_directory_is_the_input(
    assess, monkeypatch, tmp_path, capsys
):
    repo = _repo(tmp_path)
    monkeypatch.delenv("ASSESSOR_RUNS_DIR")
    monkeypatch.chdir(repo)
    code, client = assess([], source=".")
    assert code == 2
    assert "is inside it" in capsys.readouterr().err
    assert (client.requests, (repo / "runs").exists()) == ([], False)


def test_a_lone_surrogate_in_the_writers_prose_or_the_rationale_is_written_escaped(assess, tmp_runs_dir):
    draft = _draft({"secrets": "caf\udc80 exposed"})
    script = [*_examined(), *_reviewed(), *_drafted(_disposition(rationale="r\udc80"), draft), _done()]
    code, _ = assess(script)
    run_dir = _only_run(tmp_runs_dir)
    assert code == 0
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "caf\\udc80 exposed" in report
    assert "| r\\udc80 |" in report
    assert _json(run_dir / "disposition.json")["steps"][0]["rationale"] == "r\udc80"


def test_a_run_file_that_already_exists_is_never_overwritten(assess, monkeypatch, tmp_runs_dir):
    cid = "20261027T101500Z-0a1b2c3d"
    monkeypatch.setattr(cli.audit, "new_correlation_id", lambda now: cid)
    (tmp_runs_dir / cid).mkdir(parents=True)
    (tmp_runs_dir / cid / "run.json").write_text("keep")
    with pytest.raises(FileExistsError):
        assess(_clean())
    assert (tmp_runs_dir / cid / "run.json").read_text() == "keep"


def test_deciding_a_held_run_leaves_its_report_and_run_record_as_written(assess, tmp_path, tmp_runs_dir, capsys):
    assess(_clean(), "--substance", _substance(tmp_path, security_examiner="toy"))
    run_dir = _only_run(tmp_runs_dir)
    capsys.readouterr()
    names = ("report.md", "run.json", "disposition.json", "summary.json")
    written = {name: (run_dir / name).read_bytes() for name in names}
    argv = ["decide", run_dir.name, "--decision", "continue", "--reviewer", "Ana Díaz", "--note", "Reviewed."]
    assert cli.main(argv, clock=lambda: NOW) == 0
    shown = f"correlation_id: {run_dir.name}\ndecision: continue\nstatus: finalized_by_human\n"
    assert capsys.readouterr().out == shown
    assert {name: (run_dir / name).read_bytes() for name in written} == written
    (record,) = [json.loads(line) for line in (run_dir / "decisions.jsonl").read_text().splitlines()]
    assert record["report_sha256"] == hashlib.sha256(written["report.md"]).hexdigest()
    assert record["gates_resolved"] == ["SUBSTANCE_ELEVATION"]
    assert _audit(run_dir)[-1]["event"] == "decision_recorded"


def test_a_halted_run_cannot_be_decided(assess, tmp_runs_dir, capsys):
    assess([_done()])
    run_dir = _only_run(tmp_runs_dir)
    capsys.readouterr()
    argv = ["decide", run_dir.name, "--decision", "continue", "--reviewer", "Ana"]
    assert cli.main(argv, clock=lambda: NOW) == 1
    assert capsys.readouterr().err == f"assess decide: run {run_dir.name} has no open gate, its status is halted\n"
    assert not (run_dir / "decisions.jsonl").exists()
