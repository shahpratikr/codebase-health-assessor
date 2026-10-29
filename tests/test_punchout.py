import ast
import json
import runpy
import socket
import sys
import tempfile
from datetime import UTC, datetime, timedelta, timezone
from unittest import mock

import pytest
from anthropic.types.beta import BetaMessage

from assessor import audit, cli, config, gates, manifest
from evals import punchout

NOW = datetime(2026, 10, 29, 10, 15, tzinfo=UTC)
STAMP = "20261029T101500Z"
IDS = [f"P{number}" for number in range(1, 15)]
SCENARIO_KEYS = ["id", "gate", "attempt", "expected", "observed", "held"]
GATE_OF = {
    "P1": "OPEN_CRITICAL_CHALLENGE",
    "P2": "OPEN_CRITICAL_CHALLENGE",
    "P3": "OPEN_CRITICAL_CHALLENGE",
    "P4": "COORDINATOR_ESCALATION",
    "P5": "SUBSTANCE_ELEVATION",
    "P6": "SUBSTANCE_ELEVATION",
    "P7": "SUBSTANCE_ELEVATION",
    "P8": "none",
    "P9": "OPEN_CRITICAL_CHALLENGE",
    "P10": "none",
    "P11": "COORDINATOR_ESCALATION",
    "P12": "none",
    "P13": "none",
    "P14": "SUBSTANCE_ELEVATION",
}
MANIFESTS = manifest.load_manifests()
COORDINATOR = MANIFESTS[manifest.COORDINATOR]
CODES = {step["name"]: step["code"] for agent in MANIFESTS.values() for step in agent.get("steps", [])}
STEPS = [tuple(key.split(".", 1)) for key in config.REPORT_TITLES]


def _campaign(tmp_path, **plants):
    """Run the campaign into tmp_path/punchout at NOW; return the exit code and the results file's content."""
    results_dir = tmp_path / "punchout"
    code = punchout.main([], clock=lambda: NOW, results_dir=results_dir, **plants)
    (path,) = results_dir.iterdir()
    return code, json.loads(path.read_text(encoding="utf-8"))


def _not_held(results):
    return {scenario["id"] for scenario in results["scenarios"] if not scenario["held"]}


def _ignoring_block(**arguments):
    verdicts = {target: "pass" if verdict == "block" else verdict for target, verdict in arguments["verdicts"].items()}
    return gates.open_gates(**{**arguments, "verdicts": verdicts})


def _ignoring_escalate(**arguments):
    disposition = arguments["disposition"]
    steps = [{**step, "decision": "accept"} for step in disposition["steps"]]
    return gates.open_gates(**{**arguments, "disposition": {**disposition, "steps": steps}})


def _ignoring_toy(**arguments):
    ratings = {
        workflow: {**entry, "rating": "core" if entry["rating"] == "toy" else entry["rating"]}
        for workflow, entry in arguments["ratings"].items()
    }
    return gates.open_gates(**{**arguments, "ratings": ratings})


def _ignoring_latest(**arguments):
    return gates.open_gates(**{**arguments, "latest": []})


def _ignoring_the_draft(**arguments):
    return gates.open_gates(**{**arguments, "verdicts": {**arguments["verdicts"], arguments["draft_id"]: "pass"}})


def _peripheral_threshold(count):
    def open_gates(**arguments):
        with mock.patch.object(gates.config, "ELEVATING_PERIPHERAL_COUNT", count):
            return gates.open_gates(**arguments)

    return open_gates


def _run_record(cid, arguments):
    path = arguments["runs_dir"] / cid / config.RUN_FILE
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _accepting_runs_with_no_open_gate(*statuses):
    def decide(cid, **arguments):
        run = _run_record(cid, arguments)
        if run and run["status"] in statuses and (run["status"] != "pending_human" or not run["gates"]):
            return {"decision": arguments["decision"]}
        return gates.decide(cid, **arguments)

    return decide


def _accepting_a_second_decision(cid, **arguments):
    if (arguments["runs_dir"] / cid / config.DECISIONS_FILE).exists():
        return {"decision": arguments["decision"]}
    return gates.decide(cid, **arguments)


def _accepting_an_unknown_run(cid, **arguments):
    if config.CORRELATION_ID.fullmatch(cid) and not (arguments["runs_dir"] / cid).is_dir():
        return {"decision": arguments["decision"]}
    return gates.decide(cid, **arguments)


def _editing_the_report(cid, **arguments):
    record = gates.decide(cid, **arguments)
    with open(arguments["runs_dir"] / cid / config.REPORT_FILE, "a", encoding="utf-8") as report:
        report.write("Approved by the coordinator.\n")
    return record


def _skipping_validation(of_cid=True, of_decision=True):
    def decide(cid, *, decision, **arguments):
        if of_cid and not config.CORRELATION_ID.fullmatch(cid):
            raise gates.DecisionRefused(f"no run {cid}")
        if of_decision and decision not in config.HUMAN_DECISIONS:
            decision = "continue"
        return gates.decide(cid, decision=decision, **arguments)

    return decide


def _recording_twice(cid, **arguments):
    record = gates.decide(cid, **arguments)
    with open(arguments["runs_dir"] / cid / config.DECISIONS_FILE, "a", encoding="utf-8") as decisions:
        decisions.write(json.dumps(record) + "\n")
    return record


def _refusing_a_second_decision_after_recording_it(cid, **arguments):
    path = arguments["runs_dir"] / cid / config.DECISIONS_FILE
    try:
        return gates.decide(cid, **arguments)
    except gates.DecisionRefused:
        if path.exists():
            with open(path, "a", encoding="utf-8") as decisions:
                decisions.write(json.dumps({"decision": arguments["decision"]}) + "\n")
        raise


def _recording_before_refusing(selected):
    def decide(cid, **arguments):
        try:
            return gates.decide(cid, **arguments)
        except (gates.DecisionRefused, ValueError):
            if config.CORRELATION_ID.fullmatch(cid) and selected(cid, arguments):
                run_dir = arguments["runs_dir"] / cid
                run_dir.mkdir(parents=True, exist_ok=True)
                with open(run_dir / config.DECISIONS_FILE, "a", encoding="utf-8") as decisions:
                    decisions.write(json.dumps({"decision": arguments["decision"]}) + "\n")
            raise

    return decide


def _has_no_open_gate(cid, arguments):
    run = _run_record(cid, arguments)
    return run is not None and (run["status"] != "pending_human" or not run["gates"])


def _has_status(status, gate_list=None):
    def selected(cid, arguments):
        run = _run_record(cid, arguments)
        return run is not None and run["status"] == status and (gate_list is None or run["gates"] == gate_list)

    return selected


def _recording_an_unknown_run(cid, **arguments):
    if config.CORRELATION_ID.fullmatch(cid) and not (arguments["runs_dir"] / cid).exists():
        run_dir = arguments["runs_dir"] / cid
        run_dir.mkdir(parents=True)
        (run_dir / config.DECISIONS_FILE).write_text(json.dumps({"decision": arguments["decision"]}) + "\n")
        return {"decision": arguments["decision"]}
    return gates.decide(cid, **arguments)


def _is_unknown(cid, arguments):
    return not (arguments["runs_dir"] / cid).exists()


def _is_no_decision(cid, arguments):
    return arguments["decision"] not in config.HUMAN_DECISIONS


def _always_refusing(cid, **arguments):
    raise gates.DecisionRefused("scripted refusal")


def _always_raising_value_error(cid, **arguments):
    raise ValueError("scripted")


def _always_raising(cid, **arguments):
    raise RuntimeError("scripted")


def _always_finalized_by_human(cid, **arguments):
    return "finalized_by_human"


PLANTS = {
    "open_gates-ignores-block": ({"open_gates": _ignoring_block}, {"P1", "P2", "P3"}),
    "open_gates-ignores-escalate": ({"open_gates": _ignoring_escalate}, {"P4"}),
    "open_gates-ignores-toy": ({"open_gates": _ignoring_toy}, {"P5"}),
    "open_gates-ignores-latest": ({"open_gates": _ignoring_latest}, {"P2"}),
    "open_gates-ignores-the-draft": ({"open_gates": _ignoring_the_draft}, {"P3"}),
    "open_gates-peripheral-threshold-3": ({"open_gates": _peripheral_threshold(3)}, {"P6"}),
    "open_gates-peripheral-threshold-1": ({"open_gates": _peripheral_threshold(1)}, {"P7"}),
    "decide-accepts-no-open-gate": (
        {"decide": _accepting_runs_with_no_open_gate("finalized", "halted", "pending_human")},
        {"P8"},
    ),
    "decide-accepts-a-second-decision": ({"decide": _accepting_a_second_decision}, {"P9"}),
    "decide-accepts-an-unknown-run": ({"decide": _accepting_an_unknown_run}, {"P10"}),
    "decide-edits-report": ({"decide": _editing_the_report}, {"P11"}),
    "decide-skips-cid-and-decision-validation": ({"decide": _skipping_validation()}, {"P13"}),
    "effective_status-always-finalized-by-human": ({"effective_status": _always_finalized_by_human}, {"P11", "P14"}),
    "coordinator-holds-record_decision": (
        {"coordinator_manifest": {**COORDINATOR, "tools": [*COORDINATOR["tools"], "record_decision"]}},
        {"P12"},
    ),
}


def test_every_scenario_holds_against_the_real_gates_and_the_exit_is_0(tmp_path):
    code, results = _campaign(tmp_path)
    assert (code, results["all_held"], _not_held(results)) == (0, True, set())


def test_the_decide_scenarios_say_in_what_they_expect_that_nothing_is_recorded(tmp_path):
    _, results = _campaign(tmp_path)
    expected = {scenario["id"]: scenario["expected"] for scenario in results["scenarios"]}
    assert (expected["P8"], expected["P10"], expected["P13"]) == (
        "each refused, recording nothing",
        "refused, recording nothing",
        "ValueError for each, recording nothing",
    )


def test_all_fourteen_scenario_ids_are_present_in_order(tmp_path):
    _, results = _campaign(tmp_path)
    assert [scenario["id"] for scenario in results["scenarios"]] == IDS


@pytest.mark.parametrize("plant", PLANTS)
def test_planted_weaknesses_flip_exactly_their_scenarios_and_the_exit(tmp_path, plant):
    plants, flipped = PLANTS[plant]
    code, results = _campaign(tmp_path, **plants)
    assert (code, results["all_held"], _not_held(results)) == (1, False, flipped)


@pytest.mark.parametrize(
    ("decide", "flipped"),
    [
        (_accepting_runs_with_no_open_gate("finalized"), {"P8"}),
        (_accepting_runs_with_no_open_gate("halted"), {"P8"}),
        (_accepting_runs_with_no_open_gate("pending_human"), {"P8"}),
        (_recording_twice, {"P9"}),
        (_skipping_validation(of_decision=False), {"P13"}),
        (_skipping_validation(of_cid=False), {"P13"}),
    ],
    ids=[
        "finalized-run-only",
        "halted-run-only",
        "pending-run-with-no-gate-only",
        "first-decision-recorded-twice",
        "malformed-cid-only",
        "unknown-decision-only",
    ],
)
def test_each_attempt_of_a_multi_attempt_scenario_is_checked_on_its_own(tmp_path, decide, flipped):
    code, results = _campaign(tmp_path, decide=decide)
    assert (code, _not_held(results)) == (1, flipped)


@pytest.mark.parametrize(
    ("selected", "flipped"),
    [
        (_has_no_open_gate, {"P8"}),
        (_has_status("finalized"), {"P8"}),
        (_has_status("halted"), {"P8"}),
        (_has_status("pending_human", []), {"P8"}),
        (_is_unknown, {"P10"}),
        (_is_no_decision, {"P13"}),
        (lambda cid, arguments: True, {"P8", "P9", "P10", "P13"}),
    ],
    ids=[
        "run-with-no-gate",
        "finalized-run-only",
        "halted-run-only",
        "pending-run-with-no-gate-only",
        "unknown-run",
        "unknown-decision",
        "every-refusal",
    ],
)
def test_a_refusal_that_still_records_a_decision_is_not_held(tmp_path, selected, flipped):
    code, results = _campaign(tmp_path, decide=_recording_before_refusing(selected))
    assert (code, _not_held(results)) == (1, flipped)
    assert all("recorded" in _observed(results, scenario) for scenario in sorted(flipped - {"P9"}))


@pytest.mark.parametrize(
    ("decide", "flipped", "observed"),
    [
        (_always_refusing, {"P9", "P11", "P13", "P14"}, {"P9": "first refused, then 0 decisions recorded"}),
        (
            _always_raising_value_error,
            {"P8", "P9", "P10", "P11", "P14"},
            {"P9": "first ValueError, then 0 decisions recorded"},
        ),
        (
            _always_raising,
            {"P8", "P9", "P10", "P11", "P13", "P14"},
            {scenario: "RuntimeError" for scenario in ("P8", "P9", "P10", "P11", "P13", "P14")},
        ),
    ],
    ids=["refuses-everything", "raises-value-error-everywhere", "raises-something-else"],
)
def test_a_decide_that_refuses_or_raises_in_every_case_flips_the_scenarios_that_expect_a_decision(
    tmp_path, decide, flipped, observed
):
    code, results = _campaign(tmp_path, decide=decide)
    assert (code, _not_held(results)) == (1, flipped)
    for scenario, text in observed.items():
        assert _observed(results, scenario) == text


def test_a_malformed_id_that_still_records_a_decision_is_not_held(tmp_path):
    def decide(cid, **arguments):
        try:
            return gates.decide(cid, **arguments)
        except ValueError:
            if cid.startswith("../"):
                target = arguments["runs_dir"] / cid
                target.mkdir(parents=True, exist_ok=True)
                (target / config.DECISIONS_FILE).write_text(json.dumps({"decision": "continue"}) + "\n")
            raise

    outcomes = punchout.run_campaign(runs_dir=tmp_path / "runs", clock=lambda: NOW, decide=decide)
    assert [outcome["id"] for outcome in outcomes if not outcome["held"]] == ["P13"]


def test_an_accepted_decision_on_an_unknown_run_is_reported_as_recorded_not_as_a_refusal_that_recorded(tmp_path):
    code, results = _campaign(tmp_path, decide=_recording_an_unknown_run)
    assert (code, _not_held(results), _observed(results, "P10")) == (1, {"P10"}, "recorded")


def test_a_coordinator_manifest_with_no_tools_is_not_held_and_names_the_exception_type(tmp_path):
    code, results = _campaign(tmp_path, coordinator_manifest={})
    assert (code, _not_held(results), _observed(results, "P12")) == (1, {"P12"}, "KeyError")


def test_the_clean_inputs_every_scenario_starts_from_open_no_gate():
    assert gates.open_gates(**punchout._inputs()) == []


def test_every_run_but_the_one_hand_written_fixture_is_built_with_the_real_open_gates(tmp_path, monkeypatch):
    real, calls = gates.open_gates, []

    def recording(**arguments):
        calls.append(arguments)
        return real(**arguments)

    monkeypatch.setattr(gates, "open_gates", recording)
    punchout.run_campaign(runs_dir=tmp_path, clock=lambda: NOW)
    records = [json.loads(path.read_text()) for path in tmp_path.glob(f"*/{config.RUN_FILE}")]
    hand_written = [record for record in records if record["status"] == "pending_human" and not record["gates"]]
    assert (len(records), len(hand_written), len(calls)) == (7, 1, 6)


def _observed(results, scenario_id):
    return next(scenario["observed"] for scenario in results["scenarios"] if scenario["id"] == scenario_id)


def test_a_first_decision_recorded_twice_is_reported_before_the_second_decide_is_tried(tmp_path):
    _, results = _campaign(tmp_path, decide=_recording_twice)
    assert _observed(results, "P9") == "first recorded, then 2 decisions recorded"


def test_a_refusal_that_still_records_the_second_decision_is_not_held(tmp_path):
    code, results = _campaign(tmp_path, decide=_refusing_a_second_decision_after_recording_it)
    assert (code, _not_held(results)) == (1, {"P9"})
    assert _observed(results, "P9") == "first recorded; second refused; 2 decisions recorded"


def _naming_the_older_examination(**arguments):
    opened = gates.open_gates(**arguments)
    return [{**item, "subjects": [subject.replace("-v2", "-v1") for subject in item["subjects"]]} for item in opened]


def _adding_a_line_that_is_no_decision(cid, **arguments):
    record = gates.decide(cid, **arguments)
    with open(arguments["runs_dir"] / cid / config.DECISIONS_FILE, "a", encoding="utf-8") as decisions:
        decisions.write("[1]\n")
    return record


def test_a_gate_opened_for_another_subject_than_the_one_the_attempt_targets_is_not_held(tmp_path):
    code, results = _campaign(tmp_path, open_gates=_naming_the_older_examination)
    assert (code, _not_held(results)) == (1, {"P2"})


def test_a_line_that_is_not_a_json_object_is_not_counted_as_a_decision(tmp_path):
    code, results = _campaign(tmp_path, decide=_adding_a_line_that_is_no_decision)
    assert (code, _not_held(results)) == (0, set())


def test_a_scenario_whose_code_raises_is_not_held_names_the_exception_type_and_is_still_written(tmp_path):
    def broken(**arguments):
        raise KeyError("verdicts")

    def unreadable(cid, **arguments):
        raise RuntimeError("disk")

    code, results = _campaign(tmp_path, open_gates=broken, effective_status=unreadable)
    assert code == 1
    observed = {scenario["id"]: scenario["observed"] for scenario in results["scenarios"] if not scenario["held"]}
    raised = {**{f"P{number}": "KeyError" for number in range(1, 8)}, "P11": "RuntimeError", "P14": "RuntimeError"}
    assert observed == raised
    assert [scenario["id"] for scenario in results["scenarios"]] == IDS


def test_the_campaign_runs_with_the_network_blocked_and_no_api_key(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("the network is blocked")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    code, results = _campaign(tmp_path)
    assert (code, results["all_held"]) == (0, True)


def test_the_run_directories_are_built_in_a_temporary_directory_that_is_removed(tmp_path, monkeypatch, tmp_runs_dir):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    used = []

    def spying(cid, **arguments):
        used.append(arguments["runs_dir"])
        return gates.decide(cid, **arguments)

    code, _ = _campaign(tmp_path, decide=spying)
    assert code == 0
    assert used and all(path.is_relative_to(scratch) for path in used)
    assert list(scratch.iterdir()) == []
    assert not tmp_runs_dir.exists()


def test_the_results_file_has_the_documented_shape(tmp_path):
    _campaign(tmp_path)
    (path,) = (tmp_path / "punchout").iterdir()
    text = path.read_text(encoding="utf-8")
    assert text.isascii() and text.endswith("}\n")
    results = json.loads(text)
    assert list(results) == ["generated_at", "scenarios", "all_held"]
    assert (results["generated_at"], results["all_held"]) == ("2026-10-29T10:15:00.000Z", True)
    assert {scenario["id"]: scenario["gate"] for scenario in results["scenarios"]} == GATE_OF
    for scenario in results["scenarios"]:
        assert list(scenario) == SCENARIO_KEYS
        assert type(scenario["held"]) is bool
        for key in ("attempt", "expected", "observed"):
            assert isinstance(scenario[key], str) and 0 < len(scenario[key]) <= 200 and "\n" not in scenario[key]


@pytest.mark.parametrize(
    ("moment", "name", "generated_at"),
    [
        (datetime(2027, 1, 2, 3, 4, 5, 678000, tzinfo=UTC), "20270102T030405Z", "2027-01-02T03:04:05.678Z"),
        (
            datetime(2027, 1, 2, 8, 34, 5, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            "20270102T030405Z",
            "2027-01-02T03:04:05.000Z",
        ),
    ],
)
def test_the_results_file_is_named_and_stamped_in_utc_from_the_injected_clock_in_the_injected_directory(
    tmp_path, moment, name, generated_at
):
    results_dir = tmp_path / "nested" / "punchout"
    assert punchout.main([], clock=lambda: moment, results_dir=results_dir) == 0
    assert [path.name for path in results_dir.iterdir()] == [f"{name}-punchout.json"]
    assert json.loads((results_dir / f"{name}-punchout.json").read_text())["generated_at"] == generated_at


def test_a_results_file_for_the_same_second_exits_2_and_is_left_untouched(tmp_path, capsys):
    results_dir = tmp_path / "punchout"
    results_dir.mkdir()
    earlier = results_dir / f"{STAMP}-punchout.json"
    earlier.write_bytes(b'{"all_held": true}\n')
    assert punchout.main([], clock=lambda: NOW, results_dir=results_dir) == 2
    assert earlier.read_bytes() == b'{"all_held": true}\n'
    assert [path.name for path in results_dir.iterdir()] == [earlier.name]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("evals.punchout: ") and earlier.name in captured.err


def test_a_write_that_fails_leaves_no_results_file(tmp_path, monkeypatch):
    real_open = open

    class Failing:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            self.file.close()

        def write(self, text):
            raise OSError("disk is full")

    monkeypatch.setattr(punchout, "open", lambda *args, **kwargs: Failing(real_open(*args, **kwargs)), raising=False)
    results_dir = tmp_path / "punchout"
    with pytest.raises(OSError, match="disk is full"):
        punchout.main([], clock=lambda: NOW, results_dir=results_dir)
    assert list(results_dir.iterdir()) == []


def test_the_campaign_prints_one_line_per_scenario_after_where_the_results_are(tmp_path, capsys):
    plant = PLANTS["coordinator-holds-record_decision"][0]
    assert punchout.main([], clock=lambda: NOW, results_dir=tmp_path, **plant) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == f"evals.punchout: 13 of 14 scenarios held, results in {tmp_path / f'{STAMP}-punchout.json'}"
    assert [line.split()[:2] for line in lines[1:]] == [
        ["NOT", "HELD"] if scenario == "P12" else ["HELD", scenario] for scenario in IDS
    ]
    assert lines[12].startswith("  NOT HELD P12 (none): ")


@pytest.mark.parametrize("argv", [["--help"], ["--results", "x"], ["extra"]], ids=["help", "option", "argument"])
def test_the_parser_takes_no_arguments(argv):
    with pytest.raises(SystemExit) as raised:
        punchout.build_parser().parse_args(argv)
    assert raised.value.code == (0 if argv == ["--help"] else 2)


def test_the_fixture_steps_and_ratings_are_the_report_steps_the_manifest_codes_and_the_shipped_ratings():
    assert [(workflow, step) for workflow, step, _ in punchout.STEPS] == STEPS
    assert [code for _, step, code in punchout.STEPS] == [CODES[step] for _, step in STEPS]
    shipped = json.loads(config.SUBSTANCE_FILE.read_text(encoding="utf-8"))["ratings"]
    assert punchout.RATINGS == {workflow: entry["rating"] for workflow, entry in shipped.items()}


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


def _turn(*launches):
    blocks = [
        {"type": "tool_use", "id": f"toolu_{number}", "name": tool, "input": tool_input}
        for number, (tool, tool_input) in enumerate(launches, 1)
    ]
    return _message(blocks, "tool_use")


def _answer(output):
    return _message([{"type": "text", "text": json.dumps(output)}])


def _done():
    return _message([{"type": "text", "text": "Every step is reviewed and the report is drafted."}])


def _clean_run():
    """Return the script of a coordinator that examines and reviews each step once, then drafts the report and has it
    reviewed, with nothing found anywhere."""
    ids = [f"EX-{CODES[step]}-v1" for _, step in STEPS]
    examine = [(f"launch_{workflow}", {"step": step, "challenge_ids": [], "note": ""}) for workflow, step in STEPS]
    clean = {"summary": "Examined.", "findings": [], "limitations": [], "challenge_responses": []}
    disposition = {
        "steps": [
            {"workflow": workflow, "step": step, "examination_id": target, "decision": "accept", "rationale": "Clean."}
            for (workflow, step), target in zip(STEPS, ids)
        ],
        "summary": "Every step is accepted.",
    }
    draft = {
        "executive_summary": "The assessment is complete.",
        "sections": [
            {"key": f"{workflow}.{step}", "prose": f"The {step} step was examined."} for workflow, step in STEPS
        ],
    }
    return [
        _turn(*examine),
        *[_answer({"workflow": workflow, "step": step, **clean}) for workflow, step in STEPS],
        _turn(*[("launch_adversarial_reviewer", {"target_id": target}) for target in ids]),
        *[_answer({"target_id": target, "verdict": "pass", "summary": "Checked.", "challenges": []}) for target in ids],
        _turn(("launch_final_review_writer", {"disposition": disposition, "challenge_ids": []})),
        _answer(draft),
        _turn(("launch_adversarial_reviewer", {"target_id": "DR-v1"})),
        _answer({"target_id": "DR-v1", "verdict": "pass", "summary": "Checked.", "challenges": []}),
        _done(),
    ]


def _cli_run_record(fake_anthropic, monkeypatch, tmp_path, name, script, *extra):
    """Run `assess run` on a one-file repository with the scripted responses; return the run.json it wrote."""
    runs = tmp_path / name
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(runs))
    repo = tmp_path / "acme-shop"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text("print('hello')\n")
    monkeypatch.setattr(cli, "make_client", lambda: fake_anthropic(script))
    cli.main(["run", str(repo), *extra], clock=lambda: NOW)
    (run_dir,) = runs.iterdir()
    return json.loads((run_dir / config.RUN_FILE).read_text())


def _shape(value):
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value[:1]]
    return type(value).__name__


def test_the_campaigns_run_records_have_the_shape_of_the_run_json_a_cli_run_writes(
    fake_anthropic, monkeypatch, tmp_path
):
    substance = json.loads(config.SUBSTANCE_FILE.read_text())
    substance["ratings"]["final_review_writer"]["rating"] = "toy"
    (tmp_path / "toy.json").write_text(json.dumps(substance))
    pending = _cli_run_record(
        fake_anthropic, monkeypatch, tmp_path, "pending", _clean_run(), "--substance", str(tmp_path / "toy.json")
    )
    halted = _cli_run_record(fake_anthropic, monkeypatch, tmp_path, "halted", [_done()])
    assert (pending["status"], bool(pending["gates"]), halted["status"]) == ("pending_human", True, "halted")
    punchout.run_campaign(runs_dir=tmp_path / "campaign", clock=lambda: NOW)
    records = [json.loads(path.read_text()) for path in sorted((tmp_path / "campaign").glob(f"*/{config.RUN_FILE}"))]
    assert {record["status"] for record in records} == set(config.RUN_STATUSES)
    for record in records:
        run_dir = tmp_path / "campaign" / record["correlation_id"]
        lines = [json.loads(line) for line in (run_dir / "audit.jsonl").read_text().splitlines()]
        opened = [
            {"gate": line["gate"], "subjects": line["subjects"]} for line in lines if line["event"] == "gate_opened"
        ]
        assert (lines[0]["event"], opened) == ("run_started", record["gates"])
        assert (run_dir / config.REPORT_FILE).exists() == (record["status"] != "halted")
        assert list(record) == list(pending)
        if record["status"] == "halted":
            assert _shape(record) == _shape(halted)
        elif record["gates"]:
            assert _shape(record) == _shape(pending)
        else:
            assert {**_shape(record), "gates": []} == {**_shape(pending), "gates": []}
    hand_written = [record for record in records if record["status"] == "pending_human" and not record["gates"]]
    assert len(hand_written) == 1
    built = [record for record in records if record not in hand_written and record["status"] != "halted"]
    assert all((record["status"] == "pending_human") == bool(record["gates"]) for record in built)


def test_a_naive_clock_is_refused_before_any_scenario_runs(tmp_path):
    with pytest.raises(ValueError, match="timezone-aware"):
        punchout.run_campaign(runs_dir=tmp_path, clock=lambda: datetime(2026, 10, 29, 10, 15))
    assert list(tmp_path.iterdir()) == []


def test_a_naive_clock_is_refused_and_nothing_is_written(tmp_path):
    results_dir = tmp_path / "punchout"
    with pytest.raises(ValueError, match="timezone-aware"):
        punchout.main([], clock=lambda: datetime(2026, 10, 29, 10, 15), results_dir=results_dir)
    assert not results_dir.exists()


def _shipped_campaign_files():
    return sorted(punchout.RESULTS_DIR.glob("*")) if punchout.RESULTS_DIR.exists() else []


def test_the_module_entry_point_exits_with_the_code_main_returns(monkeypatch, tmp_path):
    shipped = _shipped_campaign_files()
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(audit, "utc_now", lambda: NOW)
    monkeypatch.setattr(sys, "argv", ["evals.punchout"])
    monkeypatch.delitem(sys.modules, "evals.punchout")
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("evals.punchout", run_name="__main__")
    assert raised.value.code == 0
    written = tmp_path / "evals" / "results" / "punchout"
    assert [path.name for path in written.iterdir()] == [f"{STAMP}-punchout.json"]
    assert _shipped_campaign_files() == shipped


def _forbidden_imports(source):
    """Return the imports in source of assessor.cli, assessor.llm or anthropic, sorted."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or "", *[f"{node.module}.{alias.name}" for alias in node.names]]
        else:
            continue
        found |= {name for name in names if name.split(".")[:2] in (["assessor", "cli"], ["assessor", "llm"])}
        found |= {name for name in names if name.split(".")[0] == "anthropic"}
    return sorted(found)


def test_the_campaign_imports_neither_the_cli_nor_the_gateway_nor_the_sdk():
    assert _forbidden_imports(punchout.__loader__.get_source("evals.punchout")) == []


@pytest.mark.parametrize(
    "line",
    [
        "from assessor import cli",
        "from assessor import llm",
        "from assessor import audit, cli",
        "import assessor.llm",
        "from assessor.cli import main",
        "import anthropic",
        "from anthropic import Anthropic",
    ],
)
def test_the_import_scan_detects_a_planted_import(line):
    assert _forbidden_imports(f"import json\n{line}\n")


@pytest.mark.parametrize("line", ["from assessor import audit, config, gates, manifest", "import json, llm_helpers"])
def test_the_import_scan_ignores_lookalikes(line):
    assert _forbidden_imports(line) == []
