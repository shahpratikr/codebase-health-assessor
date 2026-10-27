import json
from datetime import UTC, datetime

import pytest
from anthropic.types.beta import BetaMessage

from assessor import audit, manifest, sandbox
from assessor.agents import runner
from assessor.guardrails import ExaminationContext, ReviewContext, WriterContext

CID = "20261027T101500Z-0a1b2c3d"
PARENT = f"{CID}:3"
NOW = datetime(2026, 10, 27, 10, 15, tzinfo=UTC)
MANIFESTS = manifest.load_manifests()
CANARY = "CANARY-7f3a91"
FINDING = {
    "title": "Debug mode on",
    "severity": "high",
    "category": "debug",
    "file": "app.py",
    "line": 1,
    "evidence": "DEBUG = True",
    "recommendation": "Turn debug mode off outside development.",
    "advisory_ids": [],
}
EXAMINATION = {
    "workflow": "security_examiner",
    "step": "insecure_config",
    "summary": "Debug mode is on.",
    "findings": [FINDING],
    "limitations": [],
    "challenge_responses": [],
}
REVIEW = {"target_id": "EX-CFG-v1", "verdict": "pass", "summary": "Line 1 holds it.", "challenges": []}
DISPOSITION = {
    "steps": [
        {
            "workflow": "security_examiner",
            "step": "insecure_config",
            "examination_id": "EX-CFG-v1",
            "decision": "accept",
            "rationale": "The review passed.",
        }
    ],
    "summary": "Accepted.",
}
DRAFT = {
    "executive_summary": "Debug mode is on [CFG-1].",
    "sections": [{"key": "security_examiner.insecure_config", "prose": "Turn it off [CFG-1]."}],
}
DRAFT_REVIEW = {"target_id": "DR-v1", "verdict": "pass", "summary": "Faithful.", "challenges": []}


def _workspace(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("DEBUG = True\n")
    (repo / "notes.txt").write_text(f"internal note {CANARY}\n")
    return sandbox.Workspace(repo)


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


def _read(path, number=1):
    block = {"type": "tool_use", "id": f"toolu_{number}", "name": "read_file", "input": {"path": path, "start_line": 1}}
    return _message([block], "tool_use")


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(CID, runs_dir=tmp_path, clock=lambda: NOW)


def _dump(value):
    return json.dumps(value, default=lambda block: block.to_dict())


def _examine(client, log, workspace, note="First pass."):
    task = runner.examiner_task(
        MANIFESTS["security_examiner"], "insecure_config", workspace_label="acme-api", challenges=[], note=note
    )
    examination = runner.run_subagent(
        client,
        log,
        MANIFESTS["security_examiner"],
        task,
        ExaminationContext("security_examiner", "insecure_config", "CFG", workspace),
        workspace=workspace,
        workflow="security_examiner",
        step="insecure_config",
        parent_step_id=PARENT,
    )
    return task, examination


def _review(client, log, workspace, task):
    finding_ids = [finding["id"] for finding in task["target"].get("findings", [])]
    return runner.run_subagent(
        client,
        log,
        MANIFESTS["adversarial_reviewer"],
        task,
        ReviewContext(task["target_id"], finding_ids),
        workspace=workspace,
        workflow="security_examiner",
        step="insecure_config",
        parent_step_id=PARENT,
    )


def test_reviewer_request_never_holds_the_examiner_conversation(fake_anthropic, log, tmp_path):
    workspace = _workspace(tmp_path)
    working = _message(
        [
            {"type": "thinking", "thinking": f"weighing {CANARY}", "signature": "sig"},
            {"type": "text", "text": f"Checking {CANARY} first."},
            {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "notes.txt", "start_line": 1}},
        ],
        "tool_use",
    )
    examiner = fake_anthropic([working, _answer(EXAMINATION)])
    examiner_task, examination = _examine(examiner, log, workspace)
    assert CANARY in _dump(examiner.requests[1]["messages"])
    reviewer = fake_anthropic([_read("app.py"), _answer(REVIEW)])
    task = runner.review_task("EX-CFG-v1", examination, examiner_task)
    assert _review(reviewer, log, workspace, task) == REVIEW
    assert all(CANARY not in _dump(request) for request in reviewer.requests)
    (message,) = reviewer.requests[0]["messages"]
    assert message["role"] == "user"
    assert json.loads(message["content"]) == task


def test_review_task_holds_only_the_target_and_the_task_it_was_built_from(fake_anthropic, log, tmp_path):
    examiner_task, examination = _examine(fake_anthropic([_answer(EXAMINATION)]), log, _workspace(tmp_path))
    assert runner.review_task("EX-CFG-v1", examination, examiner_task) == {
        "target_id": "EX-CFG-v1",
        "target": examination,
        "input_context": examiner_task,
    }


def test_report_review_holds_the_draft_and_the_moderated_context_it_was_written_from(fake_anthropic, log, tmp_path):
    workspace = _workspace(tmp_path)
    examination = {**EXAMINATION, "findings": [{"id": "CFG-1", **FINDING}]}
    writer_task = runner.writer_task(DISPOSITION, {"EX-CFG-v1": examination}, {"RV-1": REVIEW}, [])
    writer = fake_anthropic([_answer(DRAFT)])
    draft = runner.run_subagent(
        writer,
        log,
        MANIFESTS["final_review_writer"],
        writer_task,
        WriterContext([("security_examiner", "insecure_config")], ["CFG-1"]),
        workspace=workspace,
        workflow="final_review_writer",
        step=None,
        parent_step_id=PARENT,
    )
    task = runner.review_task("DR-v1", draft, writer_task)
    reviewer = fake_anthropic([_answer(DRAFT_REVIEW)])
    _review(reviewer, log, workspace, task)
    (message,) = reviewer.requests[0]["messages"]
    assert json.loads(message["content"]) == {
        "target_id": "DR-v1",
        "target": DRAFT,
        "input_context": {
            "disposition": DISPOSITION,
            "examinations": {"EX-CFG-v1": examination},
            "reviews": {"RV-1": REVIEW},
            "challenges": [],
        },
    }


def test_each_invocation_starts_a_new_message_list(fake_anthropic, log, tmp_path):
    workspace = _workspace(tmp_path)
    client = fake_anthropic([_read("app.py"), _answer(EXAMINATION), _answer(EXAMINATION)])
    _examine(client, log, workspace, note="First pass.")
    second_task, _ = _examine(client, log, workspace, note="Second pass.")
    first, after_tool, second = (request["messages"] for request in client.requests)
    assert len(first) == 1 and len(after_tool) == 3
    assert [json.loads(message["content"]) for message in second] == [second_task]


def test_review_task_keeps_its_own_copy_of_the_target_and_context():
    target, context = json.loads(json.dumps(EXAMINATION)), {"note": "First pass."}
    task = runner.review_task("EX-CFG-v1", target, context)
    target["findings"].clear()
    context["note"] = "changed"
    assert task == {"target_id": "EX-CFG-v1", "target": EXAMINATION, "input_context": {"note": "First pass."}}
