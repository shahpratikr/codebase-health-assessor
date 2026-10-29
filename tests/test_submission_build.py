import hashlib
import json
import os
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

import jsonschema
import pytest
import yaml

from assessor import audit, config, manifest
from evals import run as evals_run
from submission import build, rules, validate

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

ROOT = config.ROOT
GOLDEN = ROOT / "tests" / "fixtures" / "iterations_golden.md"
TIME = (2026, 10, 29, 8, 44, 18)
COMMIT = b"1ddb21b81068df4d6e06fea32d374afa4cbc8831"
FINALIZED = "examples/sample-runs/finalized/20261029T101500Z-0a1b2c3d"
ELEVATED = "examples/sample-runs/elevated/20261029T102000Z-1b2c3d4e"
CAMPAIGN = "evals/results/punchout/20261029T103000Z-punchout.json"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
# The evidence that the eval runs and the recorded sample runs commit: stubs replace it, so the tests hold before
# those runs and after them.
EVIDENCE = (
    "git_log.txt",
    "evals/results/*.json",
    rules.HISTORY,
    "evals/results/punchout/",
    "examples/sample-runs/finalized/",
    "examples/sample-runs/elevated/",
)
FIELDS = {
    "manifest": [
        "schema_version",
        "submission",
        "coordinator",
        "agents",
        "workflows",
        "punch_outs",
        "adversarial_review",
        "version_control",
        "not_judged",
    ],
    "submission": ["title", "stage"],
    "coordinator": ["entry_point", "prompt_file", "dispatch"],
    "agents": ["name", "role", "workflows", "allowed_tools", "reviews", "isolated_context"],
    "workflows": ["name", "sub_agent_entry_point", "steps", "artifacts"],
    "steps": ["name", "prompt_file", "eval_files", "log_files"],
    "artifacts": ["log", "success_rate"],
    "punch_outs": ["name", "evidence"],
    "adversarial_review": ["reviewer_agent", "evidence"],
    "version_control": ["evidence"],
    "not_judged": ["path", "reason"],
}


def _line(agent, generated_at, prompt, skills, summary, cost, note, judge=None):
    return {
        "agent": agent,
        "generated_at": generated_at,
        "runs": 3,
        "model": "claude-sonnet-5-5",
        "effort": "medium",
        "prompt_sha256": prompt * 64,
        "skills_sha256": skills,
        "judge_prompt_sha256": judge,
        "all_passed": all(item[4] for item in summary),
        "summary": [
            dict(zip(["criterion", "comparison", "threshold", "per_run_mean", "passed_all_runs"], item))
            for item in summary
        ],
        "total_cost_usd": cost,
        "note": note,
    }


BASELINE = _line(
    "security_examiner",
    "2026-10-20T09:00:00.000Z",
    "1",
    "a" * 64,
    [
        ("seeded_recall", "at_least", 0.8, [1.0, 0.75, 0.833333], False),
        ("clean_precision", "at_least", 1.0, [1.0, 1.0, 1.0], True),
    ],
    0.0123,
    "baseline",
)
# Interleaved agents, an identical duplicate line, an at_most criterion, a null cost, an empty note, integer means, a
# criterion only the first or the last line has, a judge hash and a note holding | and \.
HISTORY = [
    BASELINE,
    _line(
        "coordinator",
        "2026-10-21T10:00:00.000Z",
        "c",
        EMPTY_SHA256,
        [
            ("review_coverage", "at_least", 1.0, [1.0, 1.0, 1.0], True),
            ("no_unneeded_redispatch", "at_least", 0.8, [0.916667, 1.0, 1.0], True),
            ("escalation_correct", "at_least", 0.8, [1.0, 0.5, 1.0], False),
        ],
        None,
        "",
    ),
    BASELINE,
    _line(
        "dependency_examiner",
        "2026-10-21T11:00:00.000Z",
        "3",
        "b" * 64,
        [
            ("vuln_recall", "at_least", 0.8, [0.666667, 0.666667, 1.0], False),
            ("hygiene_recall", "at_least", 0.8, [1.0, 1.0, 1.0], True),
        ],
        0.25,
        "first run",
    ),
    _line(
        "adversarial_reviewer",
        "2026-10-21T12:00:00.000Z",
        "4",
        EMPTY_SHA256,
        [
            ("defect_catch_rate", "at_least", 0.8, [1.0, 1.0, 1.0], True),
            ("false_challenge_rate", "at_most", 0.2, [0.0, 0.0, 0.5], False),
        ],
        0,
        "a|b",
    ),
    _line(
        "final_review_writer",
        "2026-10-21T13:00:00.000Z",
        "5",
        EMPTY_SHA256,
        [("tone_score", "at_least", 4.0, [4.2, 4.4, 4.0], True)],
        0.1,
        "Tone judge pinned",
        judge="6" * 64,
    ),
    _line(
        "security_examiner",
        "2026-10-22T09:30:00.000Z",
        "2",
        "a" * 64,
        [
            ("seeded_recall", "at_least", 0.8, [0.9, 0.9, 0.9], True),
            ("injection_resistance", "at_least", 1.0, [1, 1, 1], True),
        ],
        1.5,
        "Tightened the | rule and C:\\temp",
    ),
    _line(
        "dependency_examiner",
        "2026-10-23T08:00:00.000Z",
        "3",
        "b" * 64,
        [
            ("vuln_recall", "at_least", 0.8, [1.0, 1.0, 1.0], True),
            ("hygiene_recall", "at_least", 0.8, [1.0, 0.8, 1.0], True),
        ],
        0.3,
        "Recorded OSV again",
    ),
]


def _history(lines=HISTORY):
    return "".join(json.dumps(line) + "\n" for line in lines).encode()


def _run(directory, *, decided):
    files = {
        f"{directory}/audit.jsonl": b'{"event": "run_started"}\n',
        f"{directory}/run.json": b"{}\n",
        f"{directory}/summary.json": b"{}\n",
        f"{directory}/disposition.json": b"{}\n",
        f"{directory}/report.md": b"# Report\n",
        f"{directory}/examinations/EX-SEC-v1.json": b"{}\n",
        f"{directory}/examinations/EX-CFG-v1.json": b"{}\n",
        f"{directory}/reviews/RV-1.json": b"{}\n",
        f"{directory}/reviews/RV-2.json": b"{}\n",
        f"{directory}/drafts/DR-v1.json": b"{}\n",
    }
    if decided:
        files[f"{directory}/decisions.jsonl"] = b"{}\n"
    return files


STUBS = {
    "git_log.txt": b"commit 1ddb21b\n",
    **{f"{rules.RESULTS}/{agent}.json": b"{}\n" for agent in rules.AGENTS},
    rules.HISTORY: _history(),
    CAMPAIGN: json.dumps({"generated_at": "2026-10-29T10:30:00.000Z", "scenarios": [], "all_held": True}).encode(),
    **_run(FINALIZED, decided=False),
    **_run(ELEVATED, decided=True),
}


def _git(*args, check=True):
    # Inherited GIT_DIR or GIT_WORK_TREE would point these calls at another repository.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(["git", *args], env=env, capture_output=True, timeout=60, check=check)


@pytest.fixture(scope="module")
def tree():
    """Return {path: bytes} of what the package line would archive from this checkout, untracked files that git does
    not ignore included, with stubs in place of the evidence that manual runs commit."""
    if _git("-C", str(ROOT), "rev-parse", "--is-inside-work-tree", check=False).returncode != 0:
        pytest.skip("needs a git work tree")
    listed = _git("-C", str(ROOT), "ls-files", "-z", "-co", "--exclude-standard").stdout.decode().split("\0")
    names = sorted({name for name in listed if name and (ROOT / name).is_file()})
    files = {name: (ROOT / name).read_bytes() for name in names}
    return {**{name: data for name, data in files.items() if not _is_evidence(name)}, **STUBS}


def _is_evidence(name):
    return any(rules.matches(pattern, name) for pattern in EVIDENCE)


def _zip(path, files, *, directories=True, extra_directories=(), attributes=None, times=None):
    """Write files to path as git archive lays them out: one time on every entry, the commit as the archive comment and,
    unless directories is false, an entry for each parent directory before its first file.

    attributes maps a name to the (external_attr, comment) of its entry, and times to its date_time.
    """
    with zipfile.ZipFile(path, "w") as archive:
        written = set()
        for name in sorted([*files, *extra_directories]):
            parents = name.rstrip("/").split("/")[:-1]
            for directory in ["/".join(parents[:depth]) + "/" for depth in range(1, len(parents) + 1)] + [name]:
                if directory.endswith("/") and directory not in written and (directories or directory == name):
                    written.add(directory)
                    info = zipfile.ZipInfo(directory, TIME)
                    info.external_attr = 0x10
                    archive.writestr(info, b"")
            if name in files:
                info = zipfile.ZipInfo(name, (times or {}).get(name, TIME))
                info.compress_type = zipfile.ZIP_DEFLATED
                if attributes and name in attributes:
                    info.external_attr, info.comment = attributes[name]
                archive.writestr(info, files[name])
        archive.comment = COMMIT
    return path


def _build(tmp_path, files, **options):
    path = _zip(tmp_path / "submission.zip", files, **options)
    return build.main([str(path)]), path


def _entries(path):
    with zipfile.ZipFile(path) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}


def _manifest(path):
    return yaml.safe_load(_entries(path)[rules.MANIFEST])


def _built(tmp_path, files):
    code, path = _build(tmp_path, files)
    assert code == 0
    return _manifest(path)


def _problems(capsys):
    lines = capsys.readouterr().err.splitlines()
    assert all(line.startswith("submission.build: ") for line in lines)
    return [line.removeprefix("submission.build: ") for line in lines]


def _refused(tmp_path, files, capsys):
    code, path = _build(tmp_path, files)
    assert code == 1
    return _problems(capsys)


def _json(files, name):
    return json.loads(files[name])


def _with(files, name, data):
    return {**files, name: json.dumps(data).encode()}


def _without(files, *names):
    return {name: data for name, data in files.items() if name not in names}


def _evals(agent, case, extras=(), file="case.json"):
    cases = [f"evals/{agent}/cases/{case}{number}/{file}" for number in range(1, 6)]
    return [f"evals/{agent}/criteria.json", *cases, "evals/run.py", "evals/scoring.py", *extras]


LOGS = ["docs/iterations.md", rules.HISTORY, f"{FINALIZED}/audit.jsonl", f"{ELEVATED}/audit.jsonl"]
CAMPAIGN_EVIDENCE = ["evals/punchout.py", CAMPAIGN]
REVIEWS = [f"{run}/reviews/RV-{number}.json" for run in (FINALIZED, ELEVATED) for number in (1, 2)]


def _workflow(name, agent, steps, eval_files, entry_point=True):
    workflow = {"name": name}
    if entry_point:
        workflow["sub_agent_entry_point"] = "src/assessor/agents/runner.py"
    workflow["steps"] = [
        {"name": step, "prompt_file": f"prompts/{agent}.md", "eval_files": eval_files, "log_files": LOGS}
        for step in steps
    ]
    workflow["artifacts"] = {"log": "docs/iterations.md", "success_rate": f"evals/results/{agent}.json"}
    return workflow


def test_the_built_zip_passes_the_validator_and_the_build_says_what_it_added(tmp_path, tree, capsys):
    code, path = _build(tmp_path, tree)
    assert code == 0
    assert capsys.readouterr().out == f"submission.build: added docs/iterations.md and manifest.yaml to {path}\n"
    assert validate.main([str(path)]) == 0


def test_manifest_yaml_holds_only_the_intake_field_names_in_their_order(tmp_path, tree):
    code, path = _build(tmp_path, tree)
    text = _entries(path)[rules.MANIFEST].decode()
    data = yaml.safe_load(text)
    assert text.startswith("schema_version: 2\n")
    assert "&id" not in text and "*id" not in text
    assert list(data) == FIELDS["manifest"]
    for section in ("submission", "coordinator", "adversarial_review", "version_control"):
        assert list(data[section]) == FIELDS[section]
    for section, items in [(name, data[name]) for name in ("agents", "punch_outs", "not_judged")]:
        assert all(list(item) == FIELDS[section] for item in items)
    for workflow in data["workflows"]:
        assert list(workflow) == [field for field in FIELDS["workflows"] if field in workflow]
        assert all(list(step) == FIELDS["steps"] for step in workflow["steps"])
        assert list(workflow["artifacts"]) == FIELDS["artifacts"]


def test_each_section_follows_the_derivation(tmp_path, tree):
    data = _built(tmp_path, tree)
    assert data["schema_version"] == 2
    assert data["submission"] == {"title": "codebase-health-assessor", "stage": 5}
    assert data["coordinator"] == {
        "entry_point": "src/assessor/coordinator.py",
        "prompt_file": "prompts/coordinator.md",
        "dispatch": "messages-api",
    }
    assert data["agents"] == [
        {
            "name": "security_examiner",
            "role": "subagent",
            "workflows": ["security"],
            "allowed_tools": ["list_files", "read_file"],
            "reviews": [],
            "isolated_context": True,
        },
        {
            "name": "dependency_examiner",
            "role": "subagent",
            "workflows": ["dependency"],
            "allowed_tools": ["list_manifests", "read_manifest", "query_osv"],
            "reviews": [],
            "isolated_context": True,
        },
        {
            "name": "adversarial_reviewer",
            "role": "adversarial",
            "workflows": [],
            "allowed_tools": ["read_file"],
            "reviews": ["security_examiner", "dependency_examiner", "final_review_writer"],
            "isolated_context": True,
        },
        {
            "name": "final_review_writer",
            "role": "subagent",
            "workflows": ["reporting"],
            "allowed_tools": [],
            "reviews": [],
            "isolated_context": True,
        },
        {
            "name": "coordinator",
            "role": "coordinator",
            "workflows": ["security", "dependency", "reporting", "coordination"],
            "allowed_tools": [
                "launch_security_examiner",
                "launch_dependency_examiner",
                "launch_adversarial_reviewer",
                "launch_final_review_writer",
            ],
            "reviews": [],
            "isolated_context": False,
        },
    ]
    assert data["workflows"] == [
        _workflow("security", "security_examiner", ["secrets", "insecure_config"], _evals("security_examiner", "S")),
        _workflow(
            "dependency",
            "dependency_examiner",
            ["known_vulnerabilities", "dependency_hygiene"],
            _evals("dependency_examiner", "D", ["evals/dependency_examiner/osv_replay.json"]),
        ),
        _workflow(
            "reporting",
            "final_review_writer",
            ["final_review"],
            _evals("final_review_writer", "W", ["evals/judges/tone.md"]),
        ),
        _workflow(
            "coordination",
            "coordinator",
            ["dispatch_governance"],
            _evals("coordinator", "K", ["evals/scripted_dispatcher.py"], file="script.json"),
            entry_point=False,
        ),
    ]
    assert data["punch_outs"] == [
        {
            "name": "substance-gate",
            "evidence": [
                f"{ELEVATED}/decisions.jsonl",
                "manifests/substance.json",
                "examples/substance-toy.json",
                *CAMPAIGN_EVIDENCE,
            ],
        },
        {"name": "open-critical-challenge", "evidence": [*CAMPAIGN_EVIDENCE, "evals/results/coordinator.json"]},
        {"name": "coordinator-escalation", "evidence": [*CAMPAIGN_EVIDENCE, "evals/results/coordinator.json"]},
    ]
    assert data["adversarial_review"] == {
        "reviewer_agent": "adversarial_reviewer",
        "evidence": [
            "prompts/adversarial_reviewer.md",
            *_evals("adversarial_reviewer", "R")[:6],
            "evals/results/adversarial_reviewer.json",
            *REVIEWS,
        ],
    }
    assert data["version_control"] == {"evidence": ["git_log.txt"]}


def test_not_judged_is_the_shortest_set_that_accounts_for_every_other_file(tmp_path, tree):
    code, path = _build(tmp_path, tree)
    data = _manifest(path)
    files = [name for name in _entries(path) if name != rules.MANIFEST]
    cited = set(validate.cited(data))
    entries = {item["path"]: item["reason"] for item in data["not_judged"]}
    assert list(entries) == sorted(entries)
    for exclusion, reason in entries.items():
        covered = [name for name in files if rules.covers(exclusion, name)]
        assert covered and not cited.intersection(covered), exclusion
        assert {rules.classify(name).reason for name in covered} == {reason}, exclusion
        parent = exclusion.rstrip("/").rpartition("/")[0]
        if parent:
            beneath = [name for name in files if name.startswith(parent + "/")]
            # The parent directory could not be excluded whole: it holds a cited file or a file of another reason.
            assert cited.intersection(beneath) or len({rules.classify(name).reason for name in beneath}) > 1
    for name in files:
        if name not in cited:
            assert sum(rules.covers(exclusion, name) for exclusion in entries) == 1, name
    for expected in (
        "schemas/",
        "skills/",
        "config/",
        "tests/",
        "submission/",
        "src/assessor/tools/",
        "examples/sample-client-repo/",
        "evals/security_examiner/cases/S1/repo/",
        "evals/adversarial_reviewer/cases/R1/repo/",
        f"{FINALIZED}/examinations/",
        f"{ELEVATED}/drafts/",
        "docs/PRD.md",
        "docs/ARCHITECTURE.md",
        "manifests/coordinator.json",
        "src/assessor/cli.py",
        "src/assessor/agents/__init__.py",
        ".gitignore",
        "evals/__init__.py",
        "evals/results/README.md",
        f"{FINALIZED}/run.json",
        f"{ELEVATED}/report.md",
    ):
        assert expected in entries, expected
    assert entries["schemas/"] == "JSON Schemas for manifests, agent outputs, audit lines and the eval history"
    assert entries["evals/__init__.py"] == "package marker"
    for mixed in ("docs/", "src/", "src/assessor/", "src/assessor/agents/", "manifests/", "examples/", "evals/"):
        assert mixed not in entries


def test_the_agents_section_matches_the_runtime_manifests(tmp_path, tree):
    data = _built(tmp_path, tree)
    runtime = manifest.load_manifests()
    assert [agent["name"] for agent in data["agents"]] == list(evals_run.AGENTS)
    for agent in data["agents"]:
        declared = runtime[agent["name"]]
        assert agent["allowed_tools"] == declared["tools"]
        assert agent["role"] == rules.ROLES[declared["role"]]
        assert agent["reviews"] == declared.get("assignment", [])


def test_agents_and_steps_follow_the_zips_manifests_not_the_checkouts(tmp_path, tree):
    security = _json(tree, "manifests/security_examiner.json")
    security["tools"] = ["read_file"]
    security["steps"] = [{"name": "leaks", "code": "SEC"}, {"name": "insecure_config", "code": "CFG"}]
    coordinator = {**_json(tree, "manifests/coordinator.json"), "prompt": "prompts/coordination.md"}
    files = _with(_with(tree, "manifests/security_examiner.json", security), "manifests/coordinator.json", coordinator)
    data = _built(tmp_path, {**files, "prompts/coordination.md": b"# Coordinator\n"})
    assert data["agents"][0]["allowed_tools"] == ["read_file"]
    assert [step["name"] for step in data["workflows"][0]["steps"]] == ["leaks", "insecure_config"]
    assert data["coordinator"]["prompt_file"] == "prompts/coordination.md"
    assert data["workflows"][3]["steps"][0]["prompt_file"] == "prompts/coordination.md"
    assert {"path": "prompts/coordinator.md", "reason": "prompt that no agent manifest names"} in data["not_judged"]
    assert "substance" not in [agent["name"] for agent in data["agents"]]


def test_a_runtime_role_without_a_manifest_role_fails_the_build(tmp_path, tree, capsys, monkeypatch):
    monkeypatch.delitem(rules.ROLES, "writer")
    problems = _refused(tmp_path, tree, capsys)
    assert f"{WRITER}: role 'writer' has no manifest.yaml role in submission/rules.py" in problems


def test_a_reviewer_manifest_whose_isolated_context_is_not_true_fails_the_build(tmp_path, tree, capsys):
    schema = _json(tree, "schemas/manifest.schema.json")
    schema["$defs"]["reviewer"]["properties"]["isolated_context"] = {"type": "boolean"}
    reviewer = {**_json(tree, "manifests/adversarial_reviewer.json"), "isolated_context": False}
    files = _with(_with(tree, "schemas/manifest.schema.json", schema), "manifests/adversarial_reviewer.json", reviewer)
    problems = _refused(tmp_path, files, capsys)
    assert problems == ["manifests/adversarial_reviewer.json: isolated_context must be true for the reviewer"]


AWKWARD = [
    "yes",
    "no",
    "on",
    "off",
    "true",
    "null",
    "~",
    "",
    "1.0",
    "0o17",
    "0x1F",
    "1e3",
    ".inf",
    "2026-10-29",
    "2026-10-29T10:15:00Z",
    "a: b",
    "#x",
    "x #y",
    "- y",
    "*z",
    "&w",
    "!v",
    "%u",
    "@t",
    "`s",
    "'q",
    '"p',
    "[x]",
    "{x}",
    "?",
    ":",
    "|",
    ">",
    "<<",
    "\\back",
    "é",
    "tab\there",
    "line\nbreak",
    " lead",
    "trail ",
    "\x85next",
    "\u2028separator",
    "\ufeffbom",
]


@pytest.mark.parametrize("text", AWKWARD)
def test_an_awkward_string_survives_the_emitter_and_the_parser(text):
    data = {"not_judged": [{"path": text, "reason": text}], "evidence": [text, text]}
    emitted = build.dump_manifest(data)
    assert yaml.safe_load(emitted) == data
    assert "&id" not in emitted


def test_awkward_step_names_and_file_names_survive_a_build_and_its_validation(tmp_path, tree, capsys):
    security = _json(tree, "manifests/security_examiner.json")
    security["steps"] = [{"name": "yes", "code": "SEC"}, {"name": "null", "code": "CFG"}]
    awkward = ["docs/a: b.md", "docs/x #y.md", "docs/é.md", "docs/- z.md", "docs/2026-10-29"]
    files = {**_with(tree, "manifests/security_examiner.json", security), **dict.fromkeys(awkward, b"")}
    code, path = _build(tmp_path, files)
    assert code == 0
    data = _manifest(path)
    assert [step["name"] for step in data["workflows"][0]["steps"]] == ["yes", "null"]
    assert {item["path"] for item in data["not_judged"]} >= set(awkward)
    assert validate.main([str(path)]) == 0


def test_the_golden_history_passes_the_history_schema():
    schema = json.loads((config.SCHEMAS_DIR / "eval_history.schema.json").read_text(encoding="utf-8"))
    for line in HISTORY:
        jsonschema.validate(line, schema)


def test_the_iteration_log_matches_the_golden_file(tmp_path, tree):
    golden = GOLDEN.read_text(encoding="utf-8")
    assert build.render_iterations(HISTORY) == golden
    code, path = _build(tmp_path, tree)
    assert _entries(path)[rules.ITERATIONS].decode("utf-8") == golden


def test_a_history_without_a_line_for_one_agent_fails_naming_it(tmp_path, tree, capsys):
    files = {**tree, rules.HISTORY: _history([line for line in HISTORY if line["agent"] != "coordinator"])}
    assert _refused(tmp_path, files, capsys) == [f"{rules.HISTORY} has no line for coordinator"]


@pytest.mark.parametrize(
    ("history", "problem"),
    [
        (None, f"{rules.HISTORY} is missing"),
        (b"", f"{rules.HISTORY} has no line for {', '.join(rules.AGENTS)}"),
    ],
    ids=["missing", "empty"],
)
def test_a_missing_or_empty_history_fails_the_build(tmp_path, tree, capsys, history, problem):
    files = _without(tree, rules.HISTORY) if history is None else {**tree, rules.HISTORY: history}
    assert _refused(tmp_path, files, capsys) == [problem]


def _no_note(line):
    return {key: value for key, value in line.items() if key != "note"}


@pytest.mark.parametrize(
    ("bad", "problem"),
    [
        (b"not json", "is not UTF-8 JSON"),
        (b"", "is not UTF-8 JSON"),
        (b'{"agent": "security_examiner", "runs": NaN}', "is not UTF-8 JSON"),
        (b'"\xff"', "is not UTF-8 JSON"),
        (b"[1, 2]", "is not a JSON object"),
        (json.dumps(_no_note(BASELINE)).encode(), f"fails {build.HISTORY_SCHEMA_PATH}: 'note' is a required property"),
        (json.dumps({**BASELINE, "agent": "intruder"}).encode(), "names agent 'intruder', which is not one of the"),
        (json.dumps({**BASELINE, "total_cost_usd": -1}).encode(), f"fails {build.HISTORY_SCHEMA_PATH}"),
    ],
    ids=["text", "blank", "nan", "not utf-8", "array", "no note", "unknown agent", "negative cost"],
)
def test_a_malformed_history_line_fails_the_build_naming_its_line(tmp_path, tree, capsys, bad, problem):
    lines = _history().splitlines(keepends=True)
    files = {**tree, rules.HISTORY: b"".join([*lines[:2], bad + b"\n", *lines[2:]])}
    (found,) = _refused(tmp_path, files, capsys)
    assert found.startswith(f"{rules.HISTORY} line 3 {problem}")


def test_a_torn_last_line_is_named(tmp_path, tree, capsys):
    files = {**tree, rules.HISTORY: _history() + b'{"agent": "coord'}
    assert _refused(tmp_path, files, capsys) == [f"{rules.HISTORY} line {len(HISTORY) + 1} is not UTF-8 JSON"]


SECURITY, WRITER = "manifests/security_examiner.json", "manifests/final_review_writer.json"
EARLIER = "evals/results/punchout/20261028T090000Z-punchout.json"


def _dropping(name):
    return lambda tree: _without(tree, name)


def _replacing(name, data):
    return lambda tree: {**tree, name: data}


def _editing(path, **changes):
    return lambda tree: _with(tree, path, {**_json(tree, path), **changes})


def _writer_named(path, name):
    return lambda tree: _with(tree, path, {**_json(tree, WRITER), "name": name})


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (_dropping(WRITER), "manifests/ must hold exactly the five agent manifests"),
        (_writer_named("manifests/extra_agent.json", "extra_agent"), "manifests/ must hold exactly the five agent"),
        (_replacing(SECURITY, b"{"), f"{SECURITY}: is not JSON"),
        (_replacing(SECURITY, b"[]"), f"{SECURITY}: is not a JSON object"),
        (_editing(SECURITY, tools=["bash"]), f"{SECURITY}: fails schemas/manifest.schema.json"),
        (_editing(SECURITY, name="leak_finder"), f"{SECURITY}: name 'leak_finder' must match the file name"),
        (
            _writer_named("manifests/adversarial_reviewer.json", "adversarial_reviewer"),
            "manifests/ must hold exactly one reviewer manifest, not 0",
        ),
        (_dropping("schemas/manifest.schema.json"), "schemas/manifest.schema.json is missing"),
        (_replacing("schemas/manifest.schema.json", b"[]"), "schemas/manifest.schema.json is not a JSON Schema"),
        (_dropping("schemas/eval_history.schema.json"), "schemas/eval_history.schema.json is missing"),
        (_replacing(EARLIER, b"{"), f"{EARLIER}: is not JSON"),
        (_replacing(EARLIER, b'{"all_held": "true"}'), f"{EARLIER}: needs a boolean all_held"),
        (_editing(CAMPAIGN, all_held=False), "no evals/results/punchout/*-punchout.json file has all_held true"),
    ],
    ids=[
        "four agents",
        "six agents",
        "manifest not JSON",
        "manifest not an object",
        "manifest fails schema",
        "name not the file name",
        "no reviewer",
        "no manifest schema",
        "manifest schema not a schema",
        "no history schema",
        "campaign not JSON",
        "all_held not boolean",
        "no held campaign",
    ],
)
def test_a_bad_input_fails_the_build(tmp_path, tree, capsys, change, problem):
    problems = _refused(tmp_path, change(tree), capsys)
    assert any(found.startswith(problem) for found in problems), problems


def test_a_campaign_file_that_did_not_hold_is_never_cited_and_is_excluded_on_its_own(tmp_path, tree):
    failed = "evals/results/punchout/20261028T090000Z-punchout.json"
    data = _built(tmp_path, _with(tree, failed, {"all_held": False}))
    assert all(failed not in punch_out["evidence"] for punch_out in data["punch_outs"])
    assert {"path": failed, "reason": "campaign run that did not hold"} in data["not_judged"]
    assert CAMPAIGN in data["punch_outs"][0]["evidence"]


def test_every_held_campaign_file_is_cited_in_name_order(tmp_path, tree):
    later = "evals/results/punchout/20261030T090000Z-punchout.json"
    data = _built(tmp_path, _with(tree, later, {"all_held": True}))
    assert data["punch_outs"][1]["evidence"] == ["evals/punchout.py", CAMPAIGN, later, "evals/results/coordinator.json"]


def test_every_unclassified_path_is_listed_and_fails_the_build(tmp_path, tree, capsys):
    stray = ["notes.txt", "src2/x.py", "evals/results/punchout/notes.md", "examples/sample-runs/finalized/stray.txt"]
    problems = _refused(tmp_path, {**tree, **dict.fromkeys(stray, b"")}, capsys)
    assert problems == [f"{name}: matches no classification rule in submission/rules.py" for name in sorted(stray)]


def test_missing_evidence_is_listed_with_every_other_problem(tmp_path, tree, capsys):
    gone = ["git_log.txt", "evals/results/coordinator.json", f"{ELEVATED}/decisions.jsonl", "evals/scoring.py"]
    lines = _history().splitlines(keepends=True)
    files = {**_without(tree, *gone), "notes.txt": b"", rules.HISTORY: b"".join([b"oops\n", *lines])}
    problems = _refused(tmp_path, files, capsys)
    assert problems == [
        "notes.txt: matches no classification rule in submission/rules.py",
        f"{rules.HISTORY} line 1 is not UTF-8 JSON",
        *(f"{name}: cited evidence is not in the ZIP" for name in sorted(gone)),
    ]


@pytest.mark.parametrize("directory", rules.SAMPLE_RUNS)
@pytest.mark.parametrize("count", [0, 2])
def test_a_sample_run_directory_without_exactly_one_run_fails_the_build(tmp_path, tree, capsys, directory, count):
    files = {name: data for name, data in tree.items() if not name.startswith(directory + "/")}
    if count == 2:
        files.update(_run(f"{directory}/20261029T110000Z-2c3d4e5f", decided=True))
        files.update(_run(f"{directory}/20261029T120000Z-3d4e5f60", decided=False))
    problems = _refused(tmp_path, files, capsys)
    assert problems[0].startswith(f"{directory}/ must hold exactly one run directory, not {count}")


def test_directory_entries_are_neither_classified_nor_cited_and_are_copied(tmp_path, tree):
    with_entries, path = _build(tmp_path, tree, extra_directories=["unknown/", "empty/nested/"])
    assert with_entries == 0
    with zipfile.ZipFile(path) as archive:
        directories = [info.filename for info in archive.infolist() if info.is_dir()]
    assert {"unknown/", "empty/nested/", "schemas/", "src/assessor/tools/"} <= set(directories)
    without = tmp_path / "plain"
    without.mkdir()
    code, plain = _build(without, tree, directories=False)
    assert code == 0
    assert _manifest(plain) == _manifest(path)
    assert "unknown/" not in _entries(path)[rules.MANIFEST].decode()


def test_two_builds_of_the_same_inputs_give_byte_identical_zips(tmp_path, tree):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir(), second.mkdir()
    (code_1, path_1), (code_2, path_2) = _build(first, tree), _build(second, tree)
    assert code_1 == code_2 == 0
    assert path_1.read_bytes() == path_2.read_bytes()


def _entry_facts(archive):
    return [(i.filename, i.compress_type, i.external_attr, i.create_system, i.comment) for i in archive.infolist()]


def test_the_copy_keeps_every_entrys_name_order_method_mode_and_comment_and_dates_all_of_them_alike(tmp_path, tree):
    attributes = {"README.md": (0o100755 << 16, b"executable"), "docs/PRD.md": (0o120777 << 16, b"")}
    path = _zip(tmp_path / "submission.zip", tree, attributes=attributes)
    with zipfile.ZipFile(path) as archive:
        before = _entry_facts(archive)
        contents = {info.filename: archive.read(info) for info in archive.infolist()}
    assert build.main([str(path)]) == 0
    with zipfile.ZipFile(path) as archive:
        assert archive.comment == COMMIT
        assert all(archive.read(name) == data for name, data in contents.items())
        assert _entry_facts(archive)[: len(before)] == before
        assert [info.filename for info in archive.infolist()][len(before) :] == [rules.ITERATIONS, rules.MANIFEST]
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_packaging_one_commit_twice_gives_the_same_zip_whatever_time_zip_u_stamped_on_git_log(tmp_path, tree):
    outputs = []
    for seconds in (0, 2):
        directory = tmp_path / str(seconds)
        directory.mkdir()
        path = _zip(directory / "submission.zip", tree, times={"git_log.txt": (2026, 10, 29, 9, 0, seconds)})
        assert build.main([str(path)]) == 0
        outputs.append(path.read_bytes())
    assert outputs[0] == outputs[1]


def test_manifest_yaml_is_written_with_pyyaml_safe_dump(tmp_path, tree, monkeypatch):
    calls, real = [], yaml.safe_dump

    def spy(data, *args, **kwargs):
        calls.append(data)
        return real(data, *args, **kwargs)

    monkeypatch.setattr(yaml, "safe_dump", spy)
    code, path = _build(tmp_path, tree)
    assert code == 0
    assert len(calls) == 1
    assert yaml.safe_load(_entries(path)[rules.MANIFEST]) == calls[0]


def test_the_new_zip_is_fsynced_and_then_renamed_over_the_original_from_beside_it(tmp_path, tree, monkeypatch):
    path = _zip(tmp_path / "submission.zip", tree)
    events, replace, fsync = [], os.replace, os.fsync

    def recording_replace(source, target):
        events.append(("replace", Path(source), Path(target)))
        replace(source, target)

    def recording_fsync(descriptor):
        events.append("fsync")
        fsync(descriptor)

    monkeypatch.setattr(build.os, "replace", recording_replace)
    monkeypatch.setattr(build.os, "fsync", recording_fsync)
    assert build.main([str(path)]) == 0
    assert events == ["fsync", ("replace", tmp_path / "submission.zip.tmp", path)]


def test_a_failed_cleanup_never_masks_the_error_that_caused_it(tmp_path, tree, monkeypatch):
    path = _zip(tmp_path / "submission.zip", tree)
    (tmp_path / "submission.zip.tmp").mkdir()
    before = path.read_bytes()

    def refuse(self, *args, **kwargs):
        raise PermissionError("cannot remove")

    monkeypatch.setattr(Path, "unlink", refuse)
    with pytest.raises(IsADirectoryError):
        build.main([str(path)])
    assert (tmp_path / "submission.zip.tmp").is_dir()
    assert path.read_bytes() == before


def test_a_refused_build_leaves_the_zip_byte_identical_and_no_temporary_file(tmp_path, tree, capsys):
    path = _zip(tmp_path / "submission.zip", {**tree, "notes.txt": b""})
    before = path.read_bytes()
    assert build.main([str(path)]) == 1
    assert path.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [path]


def _disk_full(*args, **kwargs):
    raise OSError("disk full")


@pytest.mark.parametrize("where", ["second new entry", "rename"])
def test_a_failure_after_the_first_write_leaves_the_zip_as_it_was_and_no_temporary_file(
    tmp_path, tree, monkeypatch, where
):
    path = _zip(tmp_path / "submission.zip", tree)
    before = path.read_bytes()
    if where == "rename":
        monkeypatch.setattr(build.os, "replace", _disk_full)
    else:
        writestr = zipfile.ZipFile.writestr

        def failing(archive, info, data, *args, **kwargs):
            if getattr(info, "filename", info) == rules.MANIFEST:
                _disk_full()
            return writestr(archive, info, data, *args, **kwargs)

        monkeypatch.setattr(zipfile.ZipFile, "writestr", failing)
    with pytest.raises(OSError, match="disk full"):
        build.main([str(path)])
    assert path.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [path]
    assert rules.ITERATIONS not in _entries(path) and rules.MANIFEST not in _entries(path)


@pytest.mark.parametrize("output", [rules.MANIFEST, rules.ITERATIONS])
def test_a_zip_that_already_holds_an_output_exits_2_and_is_left_untouched(tmp_path, tree, capsys, output):
    path = _zip(tmp_path / "submission.zip", {**tree, output: b"x"})
    before = path.read_bytes()
    assert build.main([str(path)]) == 2
    assert path.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [path]
    assert _problems(capsys) == [
        f"{path} already holds {output}; package it again from the package line, and do not commit {output}"
    ]


@pytest.mark.parametrize("kind", ["missing", "not a zip", "directory", "corrupt member"])
def test_an_unreadable_zip_exits_2(tmp_path, tree, capsys, kind):
    path = tmp_path / "submission.zip"
    if kind == "not a zip":
        path.write_bytes(b"PK not really a zip")
    elif kind == "directory":
        path.mkdir()
    elif kind == "corrupt member":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("README.md", b"# hello hello hello\n")
        data = bytearray(path.read_bytes())
        offset = data.index(b"hello")
        data[offset : offset + 5] = b"HELLO"
        path.write_bytes(bytes(data))
    assert build.main([str(path)]) == 2
    (problem,) = _problems(capsys)
    assert problem.startswith(f"cannot read {path}: ")


def test_the_builder_never_extracts(tmp_path, tree, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("extracted")

    monkeypatch.setattr(zipfile.ZipFile, "extract", refuse)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", refuse)
    code, path = _build(tmp_path, tree)
    assert code == 0
    assert sorted(tmp_path.iterdir()) == [path]


def _classification_errors(table, names):
    """Return each name that matches no rule or more than one rule of table, then each reason that more than one rule
    gives."""
    matching = (sum(any(rules.matches(pattern, name) for pattern in rule.patterns) for rule in table) for name in names)
    unmatched = [name for name, count in zip(names, matching) if count != 1]
    reasons = [rule.reason for rule in table]
    return [*unmatched, *sorted({reason for reason in reasons if reasons.count(reason) > 1})]


def test_each_shipped_path_matches_exactly_one_classification_rule_with_a_reason_of_its_own(tree):
    assert _classification_errors(rules.CLASSIFICATION, [*tree, rules.ITERATIONS]) == []


def test_a_path_in_two_rules_a_path_in_none_and_a_reason_given_twice_are_reported(tree):
    names = [*tree, rules.ITERATIONS]
    twice = (*rules.CLASSIFICATION, rules.Rule(("README.md",), "another reason"))
    assert _classification_errors(twice, names) == ["README.md"]
    assert _classification_errors(rules.CLASSIFICATION[1:], names) == ["git_log.txt"]
    same = (*rules.CLASSIFICATION, rules.Rule(("nothing/",), rules.CLASSIFICATION[0].reason))
    assert _classification_errors(same, names) == [rules.CLASSIFICATION[0].reason]


def _drift(roles, punch_outs, agents):
    """Return the names of the submission maps that no longer repeat config.AGENT_ROLES, config.GATES and the keys of
    evals.run.AGENTS in their order."""
    return [
        name
        for name, found, expected in (
            ("ROLES", list(roles), list(config.AGENT_ROLES)),
            ("PUNCH_OUTS", list(punch_outs.values()), list(config.GATES)),
            ("AGENTS", list(agents), list(evals_run.AGENTS)),
        )
        if found != expected
    ]


def test_the_submission_maps_match_config_and_the_eval_runner():
    assert _drift(rules.ROLES, rules.PUNCH_OUTS, rules.AGENTS) == []
    assert set(rules.ROLES.values()) == set(rules.MANIFEST_ROLES)
    assert set(rules.MANIFEST_RULES) <= set(rules.RULES)
    assert rules.REVIEWER in rules.AGENTS
    assert rules.REVIEWER not in {agent for _, agent, _ in rules.WORKFLOWS}
    assert [name for name, data in manifest.load_manifests().items() if data["role"] == "reviewer"] == [rules.REVIEWER]
    assert rules.AUDIT_FILE == audit.AUDIT_FILE
    owners = [agent for _, agent, _ in rules.WORKFLOWS]
    assert owners == [agent for agent in rules.AGENTS if agent != "adversarial_reviewer"]


def test_a_drifted_map_is_reported():
    roles = {key: value for key, value in rules.ROLES.items() if key != "writer"}
    gates = dict(zip(rules.PUNCH_OUTS, reversed(list(rules.PUNCH_OUTS.values()))))
    agents = [*rules.AGENTS[1:], rules.AGENTS[0]]
    assert _drift(roles, rules.PUNCH_OUTS, rules.AGENTS) == ["ROLES"]
    assert _drift(rules.ROLES, gates, rules.AGENTS) == ["PUNCH_OUTS"]
    assert _drift(rules.ROLES, rules.PUNCH_OUTS, agents) == ["AGENTS"]


@pytest.mark.parametrize("argv", [[], ["a.zip", "b.zip"], ["--force", "a.zip"]], ids=["none", "two", "option"])
def test_the_parser_takes_exactly_one_zip_path(argv, capsys):
    with pytest.raises(SystemExit) as stop:
        build.build_parser().parse_args(argv)
    assert stop.value.code == 2


def test_help_exits_0_and_says_nothing_is_extracted(capsys):
    with pytest.raises(SystemExit) as stop:
        build.build_parser().parse_args(["--help"])
    assert stop.value.code == 0
    assert "never extracts" in " ".join(capsys.readouterr().out.split())


def test_two_entries_with_one_name_fail_the_build_because_the_copy_would_change_their_bytes(tmp_path, tree, capsys):
    path = _zip(tmp_path / "submission.zip", tree)
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(path, "a") as archive:
        archive.writestr("README.md", b"second\n")
    before = path.read_bytes()
    assert build.main([str(path)]) == 1
    assert _problems(capsys) == ["README.md: appears more than once in the ZIP"]
    assert path.read_bytes() == before


def test_a_repeated_directory_entry_is_refused_like_a_repeated_file(tmp_path, tree, capsys):
    path = _zip(tmp_path / "submission.zip", tree)
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(path, "a") as archive:
        archive.writestr(zipfile.ZipInfo("config/"), b"")
    assert build.main([str(path)]) == 1
    assert _problems(capsys) == ["config/: appears more than once in the ZIP"]


def test_every_manifest_problem_is_listed_even_when_the_manifest_count_is_wrong(tmp_path, tree, capsys):
    problems = _refused(tmp_path, _replacing(SECURITY, b"{")(_dropping(WRITER)(tree)), capsys)
    assert problems[0].startswith("manifests/ must hold exactly the five agent manifests")
    assert f"{SECURITY}: is not JSON" in problems


@pytest.mark.parametrize("schema", [build.MANIFEST_SCHEMA_PATH, build.HISTORY_SCHEMA_PATH])
def test_a_missing_schema_is_the_only_problem_it_causes(tmp_path, tree, capsys, schema):
    assert _refused(tmp_path, _without(tree, schema), capsys) == [f"{schema} is missing"]


def test_a_manifest_beyond_the_five_is_checked_too_and_the_count_is_still_wrong(tmp_path, tree, capsys):
    problems = _refused(tmp_path, {**tree, "manifests/extra_agent.json": b"{"}, capsys)
    assert problems[0].startswith("manifests/ must hold exactly the five agent manifests")
    assert "manifests/extra_agent.json: is not JSON" in problems


def test_five_manifests_under_the_wrong_names_are_a_count_problem_and_not_a_crash(tmp_path, tree, capsys):
    swapped = _dropping(WRITER)(_writer_named("manifests/extra_agent.json", "extra_agent")(tree))
    assert _refused(tmp_path, swapped, capsys) == [
        f"manifests/ must hold exactly the five agent manifests ({', '.join(rules.AGENTS)}) beside "
        f"{build.SUBSTANCE}, not adversarial_reviewer, coordinator, dependency_examiner, extra_agent, security_examiner"
    ]


def test_missing_cited_files_are_listed_even_when_an_agent_manifest_is_broken(tmp_path, tree, capsys):
    files = _without(_replacing(SECURITY, b"{")(tree), "git_log.txt")
    assert _refused(tmp_path, files, capsys) == [
        f"{SECURITY}: is not JSON",
        "git_log.txt: cited evidence is not in the ZIP",
    ]


def test_a_manifest_that_parses_but_fails_a_check_is_not_loaded_either(tmp_path, tree, capsys):
    files = _without(_editing(SECURITY, name="leak_finder")(tree), "prompts/security_examiner.md")
    assert _refused(tmp_path, files, capsys) == [f"{SECURITY}: name 'leak_finder' must match the file name"]


REVIEWER_FILE = "manifests/adversarial_reviewer.json"
CRITERIA = "evals/adversarial_reviewer/criteria.json"
NOT_IN_THE_ZIP = ": cited evidence is not in the ZIP"


def _reviewer_named(tree, name):
    return {**_json(tree, REVIEWER_FILE), "name": name}


def _two_reviewers(tree):
    return _with(tree, WRITER, _reviewer_named(tree, "final_review_writer"))


def test_two_reviewer_manifests_are_a_problem_and_the_reviewers_files_are_still_checked(tmp_path, tree, capsys):
    files = _without(_two_reviewers(tree), "evals/results/adversarial_reviewer.json")
    assert _refused(tmp_path, files, capsys) == [
        "manifests/ must hold exactly one reviewer manifest, not 2",
        "evals/results/adversarial_reviewer.json" + NOT_IN_THE_ZIP,
    ]


def test_an_ambiguous_reviewer_is_never_guessed_so_the_real_reviewers_eval_files_are_still_checked(
    tmp_path, tree, capsys
):
    third = json.dumps(_reviewer_named(tree, "coordinator")).encode()
    copies = {**_two_reviewers(tree), "manifests/coordinator.json": third}
    files = _without(_replacing(REVIEWER_FILE, b"{")(copies), CRITERIA)
    assert _refused(tmp_path, files, capsys) == [
        f"{REVIEWER_FILE}: is not JSON",
        "manifests/ must hold exactly one reviewer manifest, not 2",
        CRITERIA + NOT_IN_THE_ZIP,
    ]


def test_two_reviewers_are_reported_even_when_another_manifest_failed(tmp_path, tree, capsys):
    files = {**_two_reviewers(tree), "manifests/extra.json": b"{"}
    problems = _refused(tmp_path, files, capsys)
    assert "manifests/extra.json: is not JSON" in problems
    assert "manifests/ must hold exactly one reviewer manifest, not 2" in problems


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (_replacing(REVIEWER_FILE, b"{"), f"{REVIEWER_FILE}: is not JSON"),
        (_replacing(REVIEWER_FILE, b"[]"), f"{REVIEWER_FILE}: is not a JSON object"),
        (_editing(REVIEWER_FILE, tools=["bash"]), f"{REVIEWER_FILE}: fails {build.MANIFEST_SCHEMA_PATH}"),
    ],
    ids=["not JSON", "not an object", "fails the schema"],
)
def test_a_broken_reviewer_manifest_is_its_own_problem_and_not_also_a_missing_reviewer(
    tmp_path, tree, capsys, change, problem
):
    (found,) = _refused(tmp_path, change(tree), capsys)
    assert found.startswith(problem)


def test_a_broken_reviewer_manifest_does_not_hide_the_reviewers_missing_eval_files(tmp_path, tree, capsys):
    files = _without(_replacing(REVIEWER_FILE, b"{")(tree), CRITERIA)
    assert _refused(tmp_path, files, capsys) == [f"{REVIEWER_FILE}: is not JSON", CRITERIA + NOT_IN_THE_ZIP]


def test_a_missing_manifest_schema_does_not_hide_missing_eval_files(tmp_path, tree, capsys):
    files = _without(tree, build.MANIFEST_SCHEMA_PATH, CRITERIA)
    assert _refused(tmp_path, files, capsys) == [f"{build.MANIFEST_SCHEMA_PATH} is missing", CRITERIA + NOT_IN_THE_ZIP]


@pytest.mark.parametrize("missing", ["prompt", "tools"])
def test_a_manifest_without_the_prompt_or_tools_the_build_reads_is_a_problem_even_under_a_looser_schema(
    tmp_path, tree, capsys, missing
):
    loose = _with(tree, build.MANIFEST_SCHEMA_PATH, {"type": "object"})
    without = {key: value for key, value in _json(loose, SECURITY).items() if key != missing}
    problems = _refused(tmp_path, _with(loose, SECURITY, without), capsys)
    assert problems == [f"{SECURITY}: needs a prompt and a tools list"]


def test_a_workflow_whose_manifest_failed_still_cites_the_eval_files_that_depend_on_its_agent_alone(
    tmp_path, tree, capsys
):
    files = _without(_replacing(SECURITY, b"{")(tree), "evals/security_examiner/criteria.json")
    assert _refused(tmp_path, files, capsys) == [
        f"{SECURITY}: is not JSON",
        "evals/security_examiner/criteria.json: cited evidence is not in the ZIP",
    ]


def test_a_broken_coordinator_manifest_is_a_problem_and_not_a_crash(tmp_path, tree, capsys):
    files = _without(_replacing("manifests/coordinator.json", b"{")(tree), "prompts/coordinator.md")
    assert _refused(tmp_path, files, capsys) == ["manifests/coordinator.json: is not JSON"]


def test_the_prompt_of_a_manifest_that_failed_is_the_one_file_that_is_not_reported_missing(tmp_path, tree, capsys):
    files = _without(_replacing(SECURITY, b"{")(tree), "prompts/security_examiner.md")
    assert _refused(tmp_path, files, capsys) == [f"{SECURITY}: is not JSON"]


def test_a_manifest_without_the_steps_its_workflow_needs_fails_the_build(tmp_path, tree, capsys):
    problems = _refused(tmp_path, _writer_named(SECURITY, "security_examiner")(tree), capsys)
    assert f"{SECURITY}: has no steps, which the security workflow needs" in problems


@pytest.mark.parametrize("schema", [build.MANIFEST_SCHEMA_PATH, build.HISTORY_SCHEMA_PATH])
def test_a_zip_schema_that_cannot_be_applied_fails_the_build_with_a_problem_and_no_traceback(
    tmp_path, tree, capsys, schema
):
    broken = {"properties": {"name": {"$ref": "#/$defs/nowhere"}, "agent": {"$ref": "#/$defs/nowhere"}}}
    problems = _refused(tmp_path, _with(tree, schema, broken), capsys)
    assert any(f"cannot be checked against {schema}" in problem for problem in problems)


def test_a_schema_check_that_exhausts_the_stack_is_a_problem_and_not_a_crash(tmp_path, tree, capsys, monkeypatch):
    def too_deep(errors):
        raise RecursionError

    monkeypatch.setattr(build.jsonschema.exceptions, "best_match", too_deep)
    problems = _refused(tmp_path, tree, capsys)
    assert f"{rules.HISTORY} line 1 is nested too deeply to check" in problems
    assert any(problem.endswith(": is nested too deeply to check") for problem in problems)


@pytest.mark.parametrize(
    ("replaced", "number"),
    [
        ('"per_run_mean": [1.0, 0.75, 0.833333]', '"per_run_mean": [1.0, 0.75, 1e999]'),
        ('"per_run_mean": [1.0, 0.75, 0.833333]', '"per_run_mean": [1.0, 0.75, 1' + "0" * 400 + "]"),
        ('"per_run_mean": [1.0, 0.75, 0.833333]', '"per_run_mean": [1e308, 1e308]'),
        ('"threshold": 0.8,', '"threshold": 1e999,'),
        ('"total_cost_usd": 0.0123', '"total_cost_usd": 1e999'),
    ],
    ids=["mean", "huge integer mean", "mean that overflows", "threshold", "cost"],
)
def test_a_history_number_that_is_not_finite_fails_the_build_naming_its_line(tmp_path, tree, capsys, replaced, number):
    line = json.dumps(BASELINE).replace(replaced, number).encode()
    files = {**tree, rules.HISTORY: line + b"\n" + _history(HISTORY[1:])}
    assert _refused(tmp_path, files, capsys) == [f"{rules.HISTORY} line 1 holds a number that is not finite"]


def test_a_zero_cost_a_non_ascii_note_and_exponent_floats_render_as_they_are(tmp_path, tree):
    line = {
        **BASELINE,
        "total_cost_usd": -0.0,
        "note": "café ✓",
        "summary": [{**BASELINE["summary"][0], "per_run_mean": [1e-07, 0.1, 1e22]}],
    }
    text = build.render_iterations([line])
    assert "$0.000000" in text and "$-" not in text
    assert "café ✓" in text and "seeded_recall: 1e-07/0.1/1e+22" in text
    code, path = _build(tmp_path, {**tree, rules.HISTORY: _history([line, *HISTORY[1:]])})
    assert code == 0
    assert "café ✓" in _entries(path)[rules.ITERATIONS].decode("utf-8")


def test_control_characters_in_a_problem_are_printed_escaped(tmp_path, tree, capsys):
    problems = _refused(tmp_path, {**tree, "bad\nname.txt": b""}, capsys)
    assert problems == ["bad\\nname.txt: matches no classification rule in submission/rules.py"]


DAMAGE = ["encrypted", "unsupported method", "corrupt deflate", "bad utf-8 name", "bad central directory offset"]


def _header(data, signature, skip, name):
    return next(i for i in range(len(data)) if data[i : i + 4] == signature and data[i + skip :][: len(name)] == name)


def _damage(path, kind, member):
    """Rewrite the ZIP at path with one defect of kind in the entry called member, or in the central directory."""
    data = bytearray(path.read_bytes())
    name = member.encode()
    local, central = _header(data, b"PK\x03\x04", 30, name), _header(data, b"PK\x01\x02", 46, name)
    if kind == "encrypted":
        data[local + 6] |= 1
        data[central + 8] |= 1
    elif kind == "unsupported method":
        struct.pack_into("<H", data, local + 8, 99)
        struct.pack_into("<H", data, central + 10, 99)
    elif kind == "corrupt deflate":
        data[local + 30 + len(name) : local + 36 + len(name)] = b"\xff" * 6
    elif kind == "bad utf-8 name":
        data[central + 9] |= 0x08
        for position in (local + 30, central + 46):
            data[position : position + len(name)] = b"\xff" * len(name)
    elif kind == "bad central directory offset":
        struct.pack_into("<I", data, data.rindex(b"PK\x05\x06") + 16, 0xFFFFFF00)
    path.write_bytes(bytes(data))
    return path


@pytest.mark.parametrize("kind", DAMAGE)
def test_a_damaged_zip_or_member_exits_2_and_the_zip_is_left_untouched(tmp_path, tree, capsys, kind):
    path = _damage(_zip(tmp_path / "submission.zip", tree), kind, "README.md")
    before = path.read_bytes()
    assert build.main([str(path)]) == 2
    (problem,) = _problems(capsys)
    assert problem.startswith(f"cannot read {path}: ")
    assert path.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [path]
