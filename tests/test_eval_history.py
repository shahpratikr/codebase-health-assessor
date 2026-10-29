import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime

import jsonschema
import pytest
from anthropic.types.beta import BetaMessage

from assessor import config, manifest
from evals import run

NOW = datetime(2026, 10, 29, 9, 30, tzinfo=UTC)
MANIFESTS = manifest.load_manifests()
MARKER = "agent-written-text-marker"
SONNET = "claude-sonnet-5-5"
SCHEMA = json.loads((config.SCHEMAS_DIR / "eval_history.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)
SHIPPED = run.EVALS_DIR / run.RESULTS_DIR / run.HISTORY_FILE
KEYS = [
    "agent",
    "generated_at",
    "runs",
    "model",
    "effort",
    "prompt_sha256",
    "skills_sha256",
    "judge_prompt_sha256",
    "all_passed",
    "summary",
    "total_cost_usd",
    "note",
]
SUMMARY_KEYS = ["criterion", "comparison", "threshold", "per_run_mean", "passed_all_runs"]
LINE = {
    "agent": "security_examiner",
    "generated_at": "2026-10-29T09:30:00.000Z",
    "runs": 3,
    "model": SONNET,
    "effort": "medium",
    "prompt_sha256": "a" * 64,
    "skills_sha256": "b" * 64,
    "judge_prompt_sha256": None,
    "all_passed": False,
    "summary": [
        {
            "criterion": "seeded_recall",
            "comparison": "at_least",
            "threshold": 0.8,
            "per_run_mean": [1.0, 0.75, 0.833333],
            "passed_all_runs": False,
        }
    ],
    "total_cost_usd": 0.0123,
    "note": "first | try \\ again",
}
LONG_SECRET = "sk-ant-api03-" + "a" * 60
# Every character other than "\n" that str.splitlines() splits on.
SEPARATORS = ["\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdefghijklmnop\n-----END PRIVATE KEY-----"


def _message(content, stop_reason="end_turn", model=SONNET):
    return BetaMessage.model_validate(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": model,
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


def _answer(output, model=SONNET):
    return _message([{"type": "text", "text": json.dumps(output)}], model=model)


def _finding(file, line, severity):
    return {
        "title": f"{MARKER} title",
        "severity": severity,
        "category": "secret",
        "file": file,
        "line": line,
        "evidence": f"{MARKER} evidence",
        "recommendation": f"{MARKER} fix",
        "advisory_ids": [],
    }


def _examination(step, findings):
    return {
        "workflow": "security_examiner",
        "step": step,
        "summary": f"Examined {step}.",
        "findings": findings,
        "limitations": [],
        "challenge_responses": [],
    }


def _oracle(broken=()):
    """Return the script of a security examiner that reports exactly the seeded issues of the shipped set; a (case,
    step) in broken answers with text that is not JSON, and its case's later steps are never asked."""
    script = []
    for case in run.load_eval_set("security_examiner", MANIFESTS, run.EVALS_DIR).cases:
        for step in case["steps"]:
            if (case["id"], step) in broken:
                script.append(_message([{"type": "text", "text": "not json"}]))
                break
            seeded = [item for item in case["expected"] if item["step"] == step]
            findings = [_finding(item["file"], item["line"], item["severity"]) for item in seeded]
            script.append(_answer(_examination(step, findings)))
    return script


def _shipped_copy(tmp_path, agents=("security_examiner",)):
    root = tmp_path / "evals"
    for agent in agents:
        shutil.copytree(run.EVALS_DIR / agent, root / agent)
    return root


def _history_path(root):
    return root / run.RESULTS_DIR / run.HISTORY_FILE


def _history(root):
    return [json.loads(line) for line in _history_path(root).read_text(encoding="utf-8").splitlines()]


def _results(root, agent="security_examiner"):
    return json.loads((root / run.RESULTS_DIR / f"{agent}.json").read_text(encoding="utf-8"))


def _criteria(root, agent):
    return json.loads((root / agent / "criteria.json").read_text(encoding="utf-8"))["criteria"]


@pytest.fixture
def evaluate(fake_anthropic, monkeypatch, tmp_path):
    """Return a function that runs the security examiner's shipped set once with scripted responses and the extra
    arguments; it returns the exit code and the evals directory."""

    def go(script, *extra, root=None):
        root = root or _shipped_copy(tmp_path)
        client = fake_anthropic(script)
        monkeypatch.setattr(run, "make_client", lambda: client)
        code = run.main(["--agent", "security_examiner", "--runs", "1", *extra], clock=lambda: NOW, evals_dir=root)
        return code, root

    return go


def _failing(monkeypatch, tmp_path, crash=None):
    """Replace each agent's executor with one that ends every case run in API_ERROR without a model call, or raises
    for the agent named crash; return a copy of every shipped eval set."""

    def stand_in(agent):
        def execute(client, log, agent_manifest, case):
            if agent == crash:
                raise RuntimeError("boom")
            return {}, "API_ERROR"

        return execute

    for agent in list(run.AGENTS):
        monkeypatch.setitem(run.AGENTS, agent, stand_in(agent))
    monkeypatch.setattr(run, "make_client", lambda: object())
    return _shipped_copy(tmp_path, tuple(run.AGENTS))


def test_an_execution_appends_one_line_holding_the_agents_results_and_the_eval_sets_comparisons(evaluate):
    code, root = evaluate(_oracle())
    assert code == 0
    results = _results(root)
    comparisons = {criterion["name"]: criterion["comparison"] for criterion in _criteria(root, "security_examiner")}
    (line,) = _history(root)
    assert list(line) == KEYS
    assert line == {
        "agent": "security_examiner",
        "generated_at": results["generated_at"],
        "runs": 1,
        "model": results["model"],
        "effort": results["effort"],
        "prompt_sha256": results["prompt_sha256"],
        "skills_sha256": results["skills_sha256"],
        "judge_prompt_sha256": None,
        "all_passed": True,
        "summary": [
            {
                "criterion": item["criterion"],
                "comparison": comparisons[item["criterion"]],
                "threshold": item["threshold"],
                "per_run_mean": item["per_run_mean"],
                "passed_all_runs": item["passed_all_runs"],
            }
            for item in results["summary"]
        ],
        "total_cost_usd": results["total_cost_usd"],
        "note": "",
    }
    assert all(list(item) == SUMMARY_KEYS for item in line["summary"])
    VALIDATOR.validate(line)


def test_a_line_matches_its_schema_and_takes_an_at_most_comparison_from_the_eval_set(monkeypatch, tmp_path):
    root = _failing(monkeypatch, tmp_path)
    argv = ["--agent", "adversarial_reviewer", "--runs", "2", "--note", "tuned the reviewer"]
    assert run.main(argv, clock=lambda: NOW, evals_dir=root) == 1
    (line,) = _history(root)
    VALIDATOR.validate(line)
    criteria = _criteria(root, "adversarial_reviewer")
    assert [(item["criterion"], item["comparison"], item["threshold"]) for item in line["summary"]] == [
        (criterion["name"], criterion["comparison"], criterion["threshold"]) for criterion in criteria
    ]
    assert "at_most" in {item["comparison"] for item in line["summary"]}
    assert all(len(item["per_run_mean"]) == 2 for item in line["summary"])
    assert (line["runs"], line["note"], line["generated_at"]) == (2, "tuned the reviewer", "2026-10-29T09:30:00.000Z")


def test_all_appends_a_line_for_every_agent_in_registry_order_failing_executions_included(monkeypatch, tmp_path):
    root = _failing(monkeypatch, tmp_path)
    assert run.main(["--agent", "all", "--runs", "1", "--note", "baseline"], clock=lambda: NOW, evals_dir=root) == 1
    lines = _history(root)
    assert [line["agent"] for line in lines] == list(run.AGENTS)
    assert all(line["all_passed"] is False and line["note"] == "baseline" for line in lines)
    assert all(not item["passed_all_runs"] for line in lines for item in line["summary"])
    tone = hashlib.sha256((config.ROOT / run.JUDGES[run.WRITER]["prompt"]).read_bytes()).hexdigest()
    assert {line["agent"]: line["judge_prompt_sha256"] for line in lines} == {
        agent: tone if agent == run.WRITER else None for agent in run.AGENTS
    }
    for line in lines:
        VALIDATOR.validate(line)


def test_a_crash_in_a_later_agent_keeps_the_lines_of_the_agents_that_finished(monkeypatch, tmp_path):
    third = list(run.AGENTS)[2]
    root = _failing(monkeypatch, tmp_path, crash=third)
    with pytest.raises(RuntimeError, match="boom"):
        run.main(["--agent", "all", "--runs", "1"], clock=lambda: NOW, evals_dir=root)
    assert [line["agent"] for line in _history(root)] == list(run.AGENTS)[:2]
    assert not (root / run.RESULTS_DIR / f"{third}.json").exists()


def test_a_run_with_a_temporary_evals_dir_leaves_the_shipped_history_untouched(evaluate):
    before = SHIPPED.read_bytes() if SHIPPED.exists() else None
    code, root = evaluate(_oracle())
    assert (code, len(_history(root))) == (0, 1)
    assert (SHIPPED.read_bytes() if SHIPPED.exists() else None) == before


def test_a_second_execution_keeps_the_earlier_lines_byte_for_byte(evaluate):
    _, root = evaluate(_oracle(), "--note", "first")
    earlier = _history_path(root).read_bytes()
    code, _ = evaluate(_oracle(broken={("S1", "secrets")}), "--note", "second", root=root)
    assert code == 1
    text = _history_path(root).read_bytes()
    assert text.startswith(earlier)
    assert [(line["note"], line["all_passed"]) for line in _history(root)] == [("first", True), ("second", False)]


def test_an_execution_in_which_a_criterion_missed_is_appended_with_all_passed_false(evaluate):
    code, root = evaluate(_oracle(broken={("S1", "secrets")}))
    assert code == 1
    (line,) = _history(root)
    summary = {item["criterion"]: item for item in line["summary"]}
    assert line["all_passed"] is False
    assert (summary["seeded_recall"]["per_run_mean"], summary["seeded_recall"]["passed_all_runs"]) == ([0.75], False)
    assert summary["clean_precision"]["passed_all_runs"] is True


def test_a_call_served_by_an_unpriced_model_gives_a_null_cost_that_the_schema_accepts(evaluate):
    script = _oracle()
    script[0] = _answer(_examination("secrets", [_finding("config.py", 4, "critical")]), model="claude-unpriced-9")
    _, root = evaluate(script)
    (line,) = _history(root)
    assert line["total_cost_usd"] is None
    VALIDATOR.validate(line)


def test_a_line_holds_none_of_the_text_the_agent_wrote(evaluate):
    _, root = evaluate(_oracle())
    text = _history_path(root).read_text(encoding="utf-8")
    assert MARKER not in text
    assert "Examined" not in text


def test_a_note_leaves_the_printed_output_as_it_was(evaluate, capsys):
    _, root = evaluate(_oracle())
    without = capsys.readouterr().out
    evaluate(_oracle(), "--note", "a note", root=root)
    assert capsys.readouterr().out == without


def test_no_line_is_appended_when_an_eval_set_fails_to_load(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "make_client", lambda: object())
    root = _shipped_copy(tmp_path)
    (root / "security_examiner" / "criteria.json").write_text("{}")
    assert run.main(["--agent", "security_examiner", "--runs", "1", "--note", "x"], evals_dir=root) == 2
    assert not (root / run.RESULTS_DIR).exists()


@pytest.mark.parametrize("failure", ["schema", "append"])
def test_a_failed_append_propagates_and_leaves_the_results_file_as_written(
    evaluate, monkeypatch, tmp_path, capsys, failure
):
    root = _shipped_copy(tmp_path)
    if failure == "schema":
        build = run.history_line
        monkeypatch.setattr(run, "history_line", lambda *args: {**build(*args), "text": MARKER})
        expected = jsonschema.ValidationError
    else:

        def refuse(*args, **kwargs):
            raise OSError("disk is full")

        monkeypatch.setattr(run, "open", refuse, raising=False)
        expected = OSError
    with pytest.raises(expected):
        evaluate(_oracle(), root=root)
    results = _results(root)
    assert (results["agent"], len(results["cases"])) == ("security_examiner", 5)
    assert not _history_path(root).exists()
    assert capsys.readouterr().out == ""


def test_the_line_is_written_whole_flushed_and_then_fsynced(monkeypatch, tmp_path):
    path = tmp_path / "results" / run.HISTORY_FILE
    seen = []
    real_fsync = os.fsync

    def recording_fsync(fd):
        seen.append(path.read_bytes())
        real_fsync(fd)

    monkeypatch.setattr(run.os, "fsync", recording_fsync)
    run.append_history(LINE, path)
    assert seen == [path.read_bytes()]
    assert seen[0].endswith(b"\n")
    assert json.loads(seen[0]) == LINE


@pytest.mark.parametrize(
    "existing",
    [None, b"", b'{"agent": "earlier"}\n', b'{"agent": "torn', b'{"agent": "earlier"}\n{"agent": "torn'],
    ids=["no-file", "empty-file", "whole-line", "torn-only-line", "torn-last-line"],
)
def test_an_append_starts_on_a_line_of_its_own_and_never_rewrites_what_is_there(tmp_path, existing):
    path = tmp_path / run.HISTORY_FILE
    if existing is not None:
        path.write_bytes(existing)
    run.append_history(LINE, path)
    kept = existing or b""
    kept += b"\n" if kept and not kept.endswith(b"\n") else b""
    text = path.read_bytes()
    assert text.startswith(kept)
    assert text[len(kept) :].count(b"\n") == 1 and text.endswith(b"\n")
    assert json.loads(text[len(kept) :]) == LINE


def _without(key):
    return {name: value for name, value in LINE.items() if name != key}


def _summary(**changes):
    return {**LINE, "summary": [{**LINE["summary"][0], **changes}]}


@pytest.mark.parametrize(
    "line",
    [
        {**LINE, "text": MARKER},
        _without("note"),
        _without("judge_prompt_sha256"),
        {**LINE, "agent": ""},
        {**LINE, "generated_at": "2026-10-29"},
        {**LINE, "runs": 0},
        {**LINE, "effort": "extreme"},
        {**LINE, "prompt_sha256": "abc"},
        {**LINE, "prompt_sha256": "a" * 64 + "\n"},
        {**LINE, "agent": "security_examiner\n"},
        {**LINE, "skills_sha256": "B" * 64},
        {**LINE, "judge_prompt_sha256": "a" * 63},
        {**LINE, "all_passed": "yes"},
        {**LINE, "summary": []},
        _summary(comparison="exactly"),
        _summary(per_run_mean=[]),
        _summary(case_id="S1"),
        {**LINE, "total_cost_usd": -0.5},
        {**LINE, "total_cost_usd": "0.1"},
        {**LINE, "note": "a\nb"},
        {**LINE, "note": "trailing newline\n"},
        {**LINE, "note": "a\u2028b"},
        *[{**LINE, "note": f"a{separator}b"} for separator in SEPARATORS],
        {**LINE, "model": SONNET + "\n"},
        {**LINE, "generated_at": LINE["generated_at"] + "\n"},
        {**LINE, "skills_sha256": "b" * 64 + "\n"},
        {**LINE, "judge_prompt_sha256": "c" * 64 + "\n"},
        _summary(criterion="seeded_recall\n"),
        {**LINE, "note": "x" * (run.NOTE_MAX_CHARS + 1)},
        {**LINE, "note": None},
    ],
    ids=[
        "extra-key",
        "no-note",
        "no-judge-hash",
        "empty-agent",
        "date-only",
        "zero-runs",
        "unknown-effort",
        "short-hash",
        "hash-with-trailing-newline",
        "agent-with-trailing-newline",
        "uppercase-hash",
        "short-judge-hash",
        "text-boolean",
        "no-criteria",
        "unknown-comparison",
        "no-run-means",
        "extra-summary-key",
        "negative-cost",
        "text-cost",
        "newline-note",
        "trailing-newline-note",
        "separator-note",
        *[f"note-with-U+{ord(separator):04X}" for separator in SEPARATORS],
        "model-with-trailing-newline",
        "date-with-trailing-newline",
        "skills-hash-with-trailing-newline",
        "judge-hash-with-trailing-newline",
        "criterion-with-trailing-newline",
        "long-note",
        "null-note",
    ],
)
def test_a_line_that_breaks_the_schema_raises_and_writes_nothing(tmp_path, line):
    path = tmp_path / run.HISTORY_FILE
    path.write_bytes(b'{"agent": "earlier"}\n')
    with pytest.raises(jsonschema.ValidationError):
        run.append_history(line, path)
    assert path.read_bytes() == b'{"agent": "earlier"}\n'


def test_a_value_json_cannot_hold_raises_and_writes_nothing(tmp_path):
    path = tmp_path / run.HISTORY_FILE
    with pytest.raises(ValueError):
        run.append_history(_summary(per_run_mean=[float("nan")]), path)
    assert not path.exists()


def test_the_valid_sample_line_passes_the_schema():
    VALIDATOR.validate(LINE)
    VALIDATOR.validate({**LINE, "judge_prompt_sha256": "c" * 64, "total_cost_usd": None, "note": ""})


def test_the_schema_repeats_the_config_sets_and_the_runners_note_limit():
    properties = SCHEMA["properties"]
    assert properties["effort"]["enum"] == list(config.EFFORTS)
    assert properties["summary"]["items"]["properties"]["comparison"]["enum"] == list(config.COMPARISONS)
    assert properties["note"]["maxLength"] == run.NOTE_MAX_CHARS == 500
    assert SCHEMA["required"] == KEYS
    assert properties["summary"]["items"]["required"] == SUMMARY_KEYS


@pytest.mark.parametrize(
    ("note", "stored"),
    [
        ("x" * 500, "x" * 500),
        ("a | b \\ c", "a | b \\ c"),
        ("naïve note 🙂", "naïve note 🙂"),
        ("rotated password=hunter2 today", "rotated password=<redacted:hun…> today"),
        ("x" * 470 + " " + LONG_SECRET, "x" * 470 + " <redacted:sk-a…>"),
        ("", ""),
    ],
    ids=["500-characters", "pipe-and-backslash", "unicode", "redacted", "long-secret-shrinks-under-the-limit", "empty"],
)
def test_a_note_is_stored_redacted_and_otherwise_as_typed(evaluate, note, stored):
    code, root = evaluate(_oracle(), "--note", note)
    assert code == 0
    assert _history(root)[0]["note"] == stored


@pytest.mark.parametrize(
    "note",
    [
        "x" * 501,
        "x" * 487 + " password=abc",
        "a\nb",
        "trailing newline\n",
        "a\rb",
        "a\r\nb",
        "a\x0bb",
        "a\x0cb",
        "a\x1cb",
        "a\x1db",
        "a\x1eb",
        "a\x85b",
        "a\u2028b",
        "a\u2029b",
        "a\udcffb",
        PEM,
        'rotated password="""line1\nline2\nline3"""',
        'password="abcdefghij\nklmnop"',
        "AKIAIOSFODNN7EXAMPLE\nrotated",
    ],
    ids=[
        "501-characters",
        "short-secret-grows-past-the-limit",
        "newline",
        "trailing-newline",
        "carriage-return",
        "crlf",
        "vertical-tab",
        "form-feed",
        "file-separator",
        "group-separator",
        "record-separator",
        "next-line",
        "line-separator",
        "paragraph-separator",
        "lone-surrogate",
        "pem-block-that-redaction-collapses-to-one-line",
        "triple-quoted-secret-that-redaction-collapses-to-one-line",
        "quoted-secret-with-a-line-break-inside",
        "secret-in-the-first-line",
    ],
)
def test_a_long_multi_line_or_unencodable_note_is_a_usage_error_before_any_model_call(
    monkeypatch, tmp_path, capsys, note
):
    def refuse():
        raise AssertionError("credentials were looked at")

    monkeypatch.setattr(run, "make_client", refuse)
    root = _shipped_copy(tmp_path)
    with pytest.raises(SystemExit) as raised:
        run.main(["--agent", "security_examiner", "--runs", "1", "--note", note], evals_dir=root)
    assert raised.value.code == 2
    assert "--note" in capsys.readouterr().err
    assert not (root / run.RESULTS_DIR).exists()


@pytest.mark.parametrize("note", ["x" * 487 + " password=hunter2", "password=hunter2\nsecond line"])
def test_a_refused_note_is_not_echoed_in_the_usage_error(monkeypatch, tmp_path, capsys, note):
    monkeypatch.setattr(run, "make_client", lambda: object())
    with pytest.raises(SystemExit):
        run.main(["--agent", "security_examiner", "--runs", "1", "--note", note], evals_dir=_shipped_copy(tmp_path))
    err = capsys.readouterr().err
    assert "hunter2" not in err and "second line" not in err


def test_without_a_note_the_parser_gives_an_empty_one():
    assert run.build_parser().parse_args(["--agent", "all", "--runs", "1"]).note == ""


def test_a_note_that_looks_like_an_option_is_taken_with_an_equals_sign_and_the_help_says_so(capsys):
    argv = ["--agent", "all", "--runs", "1"]
    assert run.build_parser().parse_args([*argv, "--note=-x"]).note == "-x"
    assert run.build_parser().parse_args([*argv, "--note", "-fix the prompt"]).note == "-fix the prompt"
    with pytest.raises(SystemExit) as raised:
        run.build_parser().parse_args([*argv, "--note", "-x"])
    assert raised.value.code == 2
    assert "--note=TEXT" in " ".join(run.build_parser().format_help().split())


def test_the_separators_the_schema_tests_use_are_every_character_but_newline_that_splitlines_splits_on():
    characters = [chr(code) for code in range(sys.maxunicode + 1) if chr(code) != "\n"]
    assert sorted(SEPARATORS) == [c for c in characters if len(f"a{c}b".splitlines()) > 1]
