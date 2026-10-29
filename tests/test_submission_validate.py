import copy
import hashlib
import struct
import zipfile

import pytest
import yaml

from submission import rules, validate

FILES = {
    "src/coordinator.py": b"",
    "prompts/coordinator.md": b"",
    "prompts/writer.md": b"",
    "prompts/reviewer.md": b"",
    "evals/writer/criteria.json": b"{}",
    "docs/iterations.md": b"# Iteration log\n",
    "evals/punchout.json": b"{}",
    "decisions.jsonl": b"",
    "git_log.txt": b"",
    "runs/a/audit.jsonl": b"",
}
MANIFEST = {
    "schema_version": 2,
    "submission": {"title": "demo", "stage": 5},
    "coordinator": {"entry_point": "src/coordinator.py", "prompt_file": "prompts/coordinator.md", "dispatch": "cli"},
    "agents": [
        {
            "name": "coordinator",
            "role": "coordinator",
            "workflows": ["reporting"],
            "allowed_tools": ["launch_writer"],
            "reviews": [],
            "isolated_context": False,
        },
        {"name": "writer", "role": "subagent", "workflows": ["reporting"], "isolated_context": True},
        {"name": "reviewer", "role": "adversarial", "reviews": ["writer"], "allowed_tools": ["read_file"]},
    ],
    "workflows": [
        {
            "name": "reporting",
            "sub_agent_entry_point": "src/coordinator.py",
            "steps": [
                {
                    "name": "write",
                    "prompt_file": "prompts/writer.md",
                    "eval_files": ["evals/writer/criteria.json"],
                    "log_files": ["docs/iterations.md"],
                }
            ],
            "artifacts": {"log": "docs/iterations.md", "success_rate": "evals/writer/criteria.json"},
        }
    ],
    "punch_outs": [{"name": "owner-gate", "evidence": ["evals/punchout.json", "decisions.jsonl"]}],
    "adversarial_review": {"reviewer_agent": "reviewer", "evidence": ["prompts/reviewer.md"]},
    "version_control": {"evidence": ["git_log.txt"]},
    "not_judged": [{"path": "runs/", "reason": "run output"}],
}
NEEDS_MANIFEST = {"R6", "R3", "R4", "R8", "LOG"}


def _dirs(names):
    """Return the directory entries git archive writes for names: one per parent directory, before its first file."""
    entries = []
    for name in names:
        parts = name.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            directory = "/".join(parts[:depth]) + "/"
            if directory not in entries:
                entries.append(directory)
        if name not in entries:
            entries.append(name)
    return entries


def _manifest(change=None):
    data = copy.deepcopy(MANIFEST)
    if change:
        change(data)
    return yaml.safe_dump(data, sort_keys=False).encode()


def _check(change=None, *, extra=(), manifest=None, drop=()):
    """Return check's results for FILES plus extra, less drop, and MANIFEST changed by change or the manifest bytes."""
    names = [name for name in _dirs([*FILES, *extra]) if name not in drop]
    return validate.check([*names, rules.MANIFEST], _manifest(change) if manifest is None else manifest)


def _failing(results):
    return {rule for rule, violations in results.items() if violations}


def _zip(path, names=None, manifest=b"", *, files=None):
    """Write a ZIP of the file entries files (FILES when None), with directory entries, plus manifest unless None."""
    files = dict(FILES if files is None else files)
    if manifest is not None:
        files[rules.MANIFEST] = _manifest() if manifest == b"" else manifest
    with zipfile.ZipFile(path, "w") as archive:
        for name in _dirs(files) if names is None else names:
            info = zipfile.ZipInfo(name, (2026, 10, 29, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            if name.endswith("/"):
                info.external_attr = 0x10
            archive.writestr(info, files.get(name, b""))
    return path


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


def _append(key, *path):
    def change(data):
        target = data
        for part in path:
            target = target[part]
        target.append(key)

    return change


def _set(value, *path):
    def change(data):
        target = data
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value

    return change


def _delete(*path):
    def change(data):
        target = data
        for part in path[:-1]:
            target = target[part]
        del target[path[-1]]

    return change


def _both(*changes):
    def change(data):
        for each in changes:
            each(data)

    return change


# Takes the workflow's log away but keeps docs/iterations.md referenced, so a step without log_files breaks LOG only.
_NO_WORKFLOW_LOG = _both(
    _delete("workflows", 0, "artifacts", "log"), _append("docs/iterations.md", "version_control", "evidence")
)


def test_the_valid_sample_passes_every_rule_with_manifest_yaml_its_only_unreferenced_file():
    results = _check()
    assert results == {rule: [] for rule in rules.RULES}


@pytest.mark.parametrize(
    ("extra", "change", "expected"),
    [
        (["docs\\notes.md"], None, "PATH"),
        (["/abs.txt"], None, "PATH"),
        (["logs/a.md"], _append("Logs/a.md", "workflows", 0, "steps", 0, "log_files"), "PATH"),
        ([], _append("../outside.txt", "punch_outs", 0, "evidence"), "PATH"),
        ([], _append("/etc/passwd", "version_control", "evidence"), "PATH"),
        ([], _set(3, "schema_version"), "R2"),
        ([".git/config"], None, "R5"),
        ([".hg/store"], _append({"path": ".hg/", "reason": "x"}, "not_judged"), "R5"),
        (["agents.json"], None, "R6"),
        (["config/agents.yaml"], _append({"path": "config/", "reason": "x"}, "not_judged"), None),
        (["deep/agents.yaml"], None, "R6"),
        ([], _append("evals/writer/cases.json", "workflows", 0, "steps", 0, "eval_files"), "R3"),
        ([], _append("docs/", "workflows", 0, "steps", 0, "log_files"), "R3"),
        (["notes.txt"], None, "R4"),
        ([], _append({"path": "scratch/", "reason": "x"}, "not_judged"), "R4"),
        ([], _append({"path": "runs", "reason": "x"}, "not_judged"), "R4"),
        (["runs2/b.json"], None, "R4"),
        ([], _set("writer", "adversarial_review", "reviewer_agent"), "R8"),
        ([], _set("nobody", "adversarial_review", "reviewer_agent"), "R8"),
        ([], _delete("adversarial_review", "reviewer_agent"), "R8"),
        ([], _both(_delete("workflows", 0, "steps", 0, "log_files"), _NO_WORKFLOW_LOG), "LOG"),
        ([], _both(_set([], "workflows", 0, "steps", 0, "log_files"), _NO_WORKFLOW_LOG), "LOG"),
    ],
    ids=[
        "backslash entry",
        "absolute entry",
        "wrong-case citation",
        "climbing citation",
        "absolute citation",
        "schema_version 3",
        "unlisted .git/config",
        "listed .hg directory",
        "unlisted agents.json",
        "agents.yaml under a bulk exclusion",
        "unlisted nested agents.yaml",
        "cited file missing",
        "cited directory",
        "unlisted file",
        "exclusion covering nothing",
        "exclusion without its slash",
        "runs/ does not cover runs2/",
        "reviewer_agent names a subagent",
        "reviewer_agent names no agent",
        "no reviewer_agent",
        "no log_files and no workflow log",
        "empty log_files and no workflow log",
    ],
)
def test_each_planted_violation_reports_exactly_its_rule_id(extra, change, expected):
    assert _failing(_check(change, extra=extra)) == ({expected} if expected else set())


def test_a_missing_manifest_is_r1_alone():
    results = validate.check(_dirs(FILES), None)
    assert results["R1"] == ["manifest.yaml is not at the ZIP root"]
    assert _failing(results) == {"R1"}


def test_a_manifest_yaml_directory_entry_is_no_manifest():
    assert validate.check([*_dirs(FILES), "manifest.yaml/"], None)["R1"]


@pytest.mark.parametrize("name", [".gitignore", ".github/workflows/ci.yml", "a.git/x", "x/.gitx", "x/git/y", ".hgrc"])
def test_names_that_only_look_like_a_version_control_directory_pass_r5(name):
    results = _check(_append({"path": name, "reason": "project file"}, "not_judged"), extra=[name])
    assert _failing(results) == set()


@pytest.mark.parametrize("entry", [".git/", "x/.svn/", ".hg/"])
def test_a_version_control_directory_entry_alone_fails_r5(entry):
    results = _check(extra=[entry])
    assert _failing(results) == {"R5"}
    assert results["R5"] == [f"{entry}: holds a {entry.rstrip('/').rsplit('/', 1)[-1]} directory"]


def test_a_listed_legacy_agents_file_passes_r6():
    listed = _append({"path": "agents.json", "reason": "legacy manifest, absorbed"}, "not_judged")
    assert _failing(_check(listed, extra=["agents.json"])) == set()


def test_a_file_cited_by_several_steps_is_accepted():
    def two_steps(data):
        step = copy.deepcopy(data["workflows"][0]["steps"][0])
        data["workflows"][0]["steps"].append({**step, "name": "rewrite"})
        data["workflows"].append({**copy.deepcopy(data["workflows"][0]), "name": "again"})

    assert _failing(_check(two_steps)) == set()


def test_a_step_with_no_log_files_passes_when_its_workflow_declares_a_log():
    assert _failing(_check(_delete("workflows", 0, "steps", 0, "log_files"))) == set()


def test_directory_entries_count_for_no_rule_but_r5():
    results = _check(extra=["empty/", "runs/", "runs/a/"])
    assert _failing(results) == set()
    covering_a_directory_entry = _append({"path": "empty/", "reason": "x"}, "not_judged")
    assert _failing(_check(covering_a_directory_entry, extra=["empty/"])) == {"R4"}


def test_an_entry_differing_from_a_citation_only_in_case_is_reported_once_as_path():
    results = _check(_append("Logs/a.md", "workflows", 0, "steps", 0, "log_files"), extra=["logs/a.md"])
    assert results["PATH"] == ["Logs/a.md: cited path matches logs/a.md only when letter case is ignored"]
    assert results["R3"] == results["R4"] == []


def test_an_exclusion_differing_from_the_files_only_in_case_is_path_and_accounts_for_them():
    results = _check(_set([{"path": "Runs/", "reason": "run output"}], "not_judged"))
    assert results["PATH"] == ["Runs/: not_judged path covers runs/a/audit.jsonl only when letter case is ignored"]
    assert _failing(results) == {"PATH"}


@pytest.mark.parametrize(
    ("path", "problem"),
    [("", "is empty"), ("/abs", "is absolute"), ("a\\b", "uses a backslash"), ("a/../b", "has a .. segment")],
)
def test_a_not_judged_path_of_the_wrong_form_is_path(path, problem):
    results = _check(_append({"path": path, "reason": "x"}, "not_judged"))
    assert results["PATH"] == [f"{path}: not_judged path {problem}"]
    assert _failing(results) == {"PATH"}


@pytest.mark.parametrize(
    ("name", "problem"),
    [("/abs.txt", "is absolute"), ("a\\b.txt", "uses a backslash"), ("../up.txt", "has a .. segment")],
)
def test_an_entry_name_of_the_wrong_form_is_path_even_without_a_manifest(name, problem):
    results = validate.check([*_dirs(FILES), name], None)
    assert results["PATH"] == [f"{name}: entry name {problem}"]
    assert _failing(results) == {"PATH", "R1"}


def test_every_violation_is_reported_at_once_each_under_one_rule():
    change = _both(
        _set(3, "schema_version"),
        _append("prompts/missing.md", "workflows", 0, "steps", 0, "eval_files"),
        _set("writer", "adversarial_review", "reviewer_agent"),
        _append({"path": "scratch/", "reason": "x"}, "not_judged"),
    )
    results = _check(change, extra=["notes.txt", ".git/HEAD", "docs\\x.md", "agents.json"])
    assert results == {
        "PATH": ["docs\\x.md: entry name uses a backslash"],
        "R1": [],
        "R2": ["schema_version: 2 was expected"],
        "R5": [".git/: holds a .git directory", ".git/HEAD: holds a .git directory"],
        "R6": ["agents.json: legacy agents file is not listed in not_judged"],
        "R3": ["prompts/missing.md: cited but not in the ZIP"],
        "R4": ["notes.txt: neither referenced nor listed in not_judged", "scratch/: not_judged entry covers no file"],
        "R8": ["adversarial_review.reviewer_agent 'writer' names no agent with role adversarial"],
        "LOG": [],
    }


def _two_coordinators(data):
    data["agents"].append({"name": "boss", "role": "coordinator"})


def _duplicate_step(data):
    steps = data["workflows"][0]["steps"]
    steps.append(copy.deepcopy(steps[0]))


@pytest.mark.parametrize(
    ("change", "where"),
    [
        (_set("2", "schema_version"), "schema_version:"),
        (_set(True, "schema_version"), "schema_version:"),
        (_set(4, "submission", "stage"), "submission/stage:"),
        (_delete("submission"), "the manifest: 'submission' is a required property"),
        (_delete("coordinator", "entry_point"), "coordinator: 'entry_point' is a required property"),
        (_set("http", "coordinator", "dispatch"), "coordinator/dispatch:"),
        (_set("subagent", "agents", 0, "role"), "agents:"),
        (_two_coordinators, "agents:"),
        (_set("boss", "agents", 1, "role"), "agents/1/role:"),
        (_delete("agents", 2, "name"), "agents/2: 'name' is a required property"),
        (_set([], "workflows"), "workflows:"),
        (_set([], "workflows", 0, "steps"), "workflows/0/steps:"),
        (_delete("workflows", 0, "name"), "workflows/0: 'name' is a required property"),
        (_duplicate_step, "workflows/0/steps: step name 'write' appears twice"),
        (_delete("workflows", 0, "steps", 0, "prompt_file"), "workflows/0/steps/0: 'prompt_file' is a required"),
        (_set([], "workflows", 0, "steps", 0, "eval_files"), "workflows/0/steps/0/eval_files:"),
        (_set("evals/x.json", "workflows", 0, "steps", 0, "eval_files"), "workflows/0/steps/0/eval_files:"),
        (_set([], "punch_outs", 0, "evidence"), "punch_outs/0/evidence:"),
        (_delete("punch_outs", 0, "name"), "punch_outs/0: 'name' is a required property"),
        (_delete("adversarial_review"), "the manifest: 'adversarial_review' is a required property"),
        (_delete("version_control"), "the manifest: 'version_control' is a required property"),
        (_set([], "version_control", "evidence"), "version_control/evidence:"),
        (_set([], "adversarial_review", "evidence"), "adversarial_review/evidence:"),
        (_set("", "agents", 1, "name"), "agents/1/name:"),
        (_set("", "workflows", 0, "name"), "workflows/0/name:"),
        (_set("", "workflows", 0, "steps", 0, "name"), "workflows/0/steps/0/name:"),
        (_set("", "punch_outs", 0, "name"), "punch_outs/0/name:"),
        (_set({"path": "runs/", "reason": ""}, "not_judged", 0), "not_judged/0/reason:"),
        (_set({"path": "runs/", "reason": "  "}, "not_judged", 0), "not_judged/0/reason:"),
        (_set({"reason": "x"}, "not_judged", 0), "not_judged/0: 'path' is a required property"),
        (_set("extra", "extras"), "the manifest: Additional properties are not allowed ('extras' was unexpected)"),
        (_set("me", "workflows", 0, "steps", 0, "owner"), "workflows/0/steps/0: Additional properties"),
        (_set({"reporting": {}}, "workflows"), "workflows:"),
        (_set("yes", "agents", 1, "isolated_context"), "agents/1/isolated_context:"),
        (_set(["reviewer"], "adversarial_review", "reviewer_agent"), "adversarial_review/reviewer_agent:"),
    ],
)
def test_each_r2_clause_fails_r2_and_never_raises(change, where):
    results = _check(change)
    assert any(violation.startswith(where) for violation in results["R2"]), results["R2"]


@pytest.mark.parametrize("dispatch", rules.DISPATCH_MODES)
def test_each_dispatch_mode_passes(dispatch):
    assert _failing(_check(_set(dispatch, "coordinator", "dispatch"))) == set()


@pytest.mark.parametrize("change", [_delete("adversarial_review"), _set("reviewer", "adversarial_review")])
def test_a_missing_or_mistyped_adversarial_review_section_is_r2_and_not_also_r8(change):
    results = _check(change)
    assert results["R2"]
    assert results["R8"] == []


def test_a_reviewer_agent_of_the_wrong_type_is_r2_alone_not_also_r8():
    results = _check(_set(["reviewer"], "adversarial_review", "reviewer_agent"))
    assert _failing(results) == {"R2"}


@pytest.mark.parametrize(
    "text",
    [
        "workflows: {a: 1}",
        "agents: 5",
        "not_judged: [[1, 2]]",
        "not_judged: [{path: 1, reason: 2}]",
        "workflows: [{name: x, steps: [{name: s, prompt_file: [1], eval_files: [{}], log_files: 3}], artifacts: 4}]",
        "{1: 2, null: 3}",
        "punch_outs: {x: y}",
        "adversarial_review: {reviewer_agent: [a], evidence: x}\nagents: [{name: [a], role: adversarial}]",
        "version_control: null\ncoordinator: []",
        "submission: {title: 2026-10-29, stage: 5}",
        "agents: [{name: r, role: [adversarial]}]\nadversarial_review: {reviewer_agent: r, evidence: [x]}",
        "not_judged: [{path: [x], reason: y}]\nworkflows: [{name: w, steps: [{name: [s]}, {name: [s]}]}]",
    ],
)
def test_a_manifest_of_the_wrong_types_fails_r2_and_never_raises(text):
    results = _check(manifest=text.encode())
    assert results["R2"]


@pytest.mark.parametrize(
    ("manifest", "problem"),
    [
        (b"[]", "manifest.yaml must be a mapping, not list"),
        (b"", "manifest.yaml must be a mapping, not NoneType"),
        (b"just text", "manifest.yaml must be a mapping, not str"),
        (b"a: [1, 2", "manifest.yaml does not parse as YAML"),
        (b"!!python/object/apply:os.system ['true']", "manifest.yaml does not parse as YAML"),
        (b"a: !!python/name:os.system", "manifest.yaml does not parse as YAML"),
        (b"a: 1\n---\nb: 2\n", "manifest.yaml does not parse as YAML"),
        (b"a: \xc3\x28", "manifest.yaml does not parse as YAML"),
        (b"title: 2026-02-30", "manifest.yaml does not parse as YAML"),
        (b"[" * 5000 + b"]" * 5000, "manifest.yaml does not parse as YAML"),
    ],
    ids=["list", "empty", "scalar", "broken", "unsafe tag", "unsafe name", "two docs", "bad utf-8", "date", "deep"],
)
def test_a_manifest_that_does_not_load_as_a_mapping_fails_r2_and_skips_the_rules_that_need_it(manifest, problem):
    results = _check(manifest=manifest, extra=["notes.txt", ".git/x", "a\\b"])
    assert len(results["R2"]) == 1 and results["R2"][0].startswith(problem)
    assert {rule for rule, violations in results.items() if violations is None} == NEEDS_MANIFEST
    assert results["PATH"] == ["a\\b: entry name uses a backslash"]
    assert results["R1"] == []
    assert results["R5"] == [".git/: holds a .git directory", ".git/x: holds a .git directory"]


def test_without_a_manifest_r2_and_the_rules_that_need_it_are_skipped_and_path_and_r5_still_run():
    results = validate.check([*_dirs(FILES), "/abs", ".svn/"], None)
    assert {rule for rule, violations in results.items() if violations is None} == {"R2", *NEEDS_MANIFEST}
    assert results["PATH"] == ["/abs: entry name is absolute"]
    assert results["R5"] == [".svn/: holds a .svn directory"]


def test_a_long_r2_message_is_shortened_to_one_readable_line():
    results = _check(_set({f"workflow_{number}": "x" * 50 for number in range(40)}, "workflows"))
    (violation,) = [violation for violation in results["R2"] if violation.startswith("workflows:")]
    assert len(violation) <= validate.MESSAGE_MAX_CHARS
    assert violation.endswith("...")


@pytest.mark.parametrize("entry", ["a\\b/", "x/../", "/abs/"])
def test_a_directory_entry_of_the_wrong_form_is_ignored_by_path(entry):
    assert _failing(_check(extra=[entry])) == set()


def test_an_entry_that_breaks_path_and_r5_is_reported_once_as_path():
    results = validate.check(["../.git/x", rules.MANIFEST], _manifest())
    assert results["PATH"] == ["../.git/x: entry name has a .. segment"]
    assert results["R5"] == []


def test_a_legacy_agents_file_inside_a_version_control_directory_is_r5_alone():
    results = _check(extra=[".git/agents.json"])
    assert results["R5"] == [".git/: holds a .git directory", ".git/agents.json: holds a .git directory"]
    assert results["R6"] == results["R4"] == []


def test_a_cited_path_that_is_also_an_exclusion_reports_its_r3_and_its_r4():
    cited = _append("scratch/", "version_control", "evidence")
    results = _check(_both(cited, _append({"path": "scratch/", "reason": "x"}, "not_judged")))
    assert results["R3"] == ["scratch/: cited but not in the ZIP"]
    assert results["R4"] == ["scratch/: not_judged entry covers no file"]


def _alias_bomb(levels=6, fan=9):
    lines = ["a0: &a0 [x]"]
    lines += [f"a{level}: &a{level} [{', '.join([f'*a{level - 1}'] * fan)}]" for level in range(1, levels + 1)]
    return "\n".join(lines).encode()


def test_a_manifest_that_expands_far_past_its_size_through_aliases_fails_r2_without_being_walked():
    results = _check(manifest=_alias_bomb())
    assert results["R2"] == [f"manifest.yaml holds more than {validate.EXPANDED_MAX} values once aliases are expanded"]
    assert {rule for rule, violations in results.items() if violations is None} == NEEDS_MANIFEST


def test_an_alias_bomb_is_sized_by_visiting_each_shared_value_once(monkeypatch):
    calls, real = [], validate._expanded_size

    def counting(value, memo):
        calls.append(1)
        return real(value, memo)

    monkeypatch.setattr(validate, "_expanded_size", counting)
    _check(manifest=_alias_bomb())
    assert len(calls) < 1000


@pytest.mark.parametrize(("items", "loads"), [(8, True), (9, False)])
def test_a_manifest_is_refused_only_above_the_value_cap(monkeypatch, items, loads):
    monkeypatch.setattr(validate, "EXPANDED_MAX", 10)
    results = validate.check([rules.MANIFEST], f"x: [{', '.join(['1'] * items)}]".encode())
    assert (results["R6"] is not None) == loads


def test_nesting_too_deep_to_size_fails_r2_and_skips_the_rules_that_need_the_manifest(monkeypatch):
    def too_deep(value, memo):
        raise RecursionError

    monkeypatch.setattr(validate, "_expanded_size", too_deep)
    results = _check(manifest=b"x: 1")
    assert results["R2"] == ["manifest.yaml nests too deeply or refers to itself"]
    assert results["R6"] is None


@pytest.mark.parametrize("text", ["x: &a [*a]", "x: &a {y: *a}"], ids=["list", "mapping"])
def test_a_value_that_refers_to_itself_fails_r2_and_is_never_walked(text):
    results = _check(manifest=text.encode())
    assert results["R2"] == ["manifest.yaml nests too deeply or refers to itself"]
    assert results["R6"] is None


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("résumé.txt", "résumé.txt"),
        ("a b", "a b"),
        ("a\u202eb", "a\\u202eb"),
        ("tab\there", "tab\\there"),
        ("\x1b[0m", "\\x1b[0m"),
        ("a\xa0b", "a\\xa0b"),
    ],
)
def test_only_the_characters_that_cannot_be_printed_are_escaped(text, shown):
    assert validate.printable(text) == shown


def test_a_rules_violations_are_sorted_by_path_whatever_kind_of_path_they_are():
    results = _check(_append({"path": "aaa/", "reason": "x"}, "not_judged"), extra=["zzz.txt"])
    assert results["R4"] == [
        "aaa/: not_judged entry covers no file",
        "zzz.txt: neither referenced nor listed in not_judged",
    ]


def test_a_manifest_that_reuses_a_list_through_an_alias_still_passes():
    data = copy.deepcopy(MANIFEST)
    steps, shared = data["workflows"][0]["steps"], ["docs/iterations.md"]
    steps[0]["log_files"] = shared
    steps.append({**steps[0], "name": "again", "log_files": shared})
    text = yaml.safe_dump(data, sort_keys=False)
    assert "&id001" in text
    assert _failing(_check(manifest=text.encode())) == set()


def test_cited_lists_every_path_outside_not_judged_in_manifest_order():
    assert validate.cited(MANIFEST) == [
        "src/coordinator.py",
        "prompts/coordinator.md",
        "src/coordinator.py",
        "prompts/writer.md",
        "evals/writer/criteria.json",
        "docs/iterations.md",
        "docs/iterations.md",
        "evals/writer/criteria.json",
        "evals/punchout.json",
        "decisions.jsonl",
        "prompts/reviewer.md",
        "git_log.txt",
    ]


def test_the_cli_prints_the_zip_its_sha256_and_each_rule_and_exits_0_for_a_valid_zip(tmp_path, capsys):
    path = _zip(tmp_path / "submission.zip")
    assert validate.main([str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [
        f"zip: {path}",
        f"sha256: {hashlib.sha256(path.read_bytes()).hexdigest()}",
        *(f"{rule}: PASS" for rule in rules.RULES),
        "result: PASS",
    ]


def test_the_cli_lists_each_violation_under_its_rule_and_exits_1(tmp_path, capsys):
    path = _zip(tmp_path / "submission.zip", files={**FILES, "notes.txt": b"", ".git/HEAD": b""})
    assert validate.main([str(path)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[2:] == [
        "PATH: PASS",
        "R1: PASS",
        "R2: PASS",
        "R5: FAIL",
        "  R5 .git/: holds a .git directory",
        "  R5 .git/HEAD: holds a .git directory",
        "R6: PASS",
        "R3: PASS",
        "R4: FAIL",
        "  R4 notes.txt: neither referenced nor listed in not_judged",
        "R8: PASS",
        "LOG: PASS",
        "result: FAIL, 3 violations",
    ]


def test_the_cli_prints_skipped_rules_for_a_zip_without_a_manifest(tmp_path, capsys):
    assert validate.main([str(_zip(tmp_path / "x.zip", manifest=None))]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[2:] == [
        "PATH: PASS",
        "R1: FAIL",
        "  R1 manifest.yaml is not at the ZIP root",
        "R2: SKIPPED",
        "R5: PASS",
        *(f"{rule}: SKIPPED" for rule in ("R6", "R3", "R4", "R8", "LOG")),
        "result: FAIL, 1 violation",
    ]


def test_an_empty_zip_fails_r1(tmp_path, capsys):
    path = tmp_path / "empty.zip"
    zipfile.ZipFile(path, "w").close()
    assert validate.main([str(path)]) == 1
    assert "R1: FAIL" in capsys.readouterr().out.splitlines()


DAMAGE = ["encrypted", "unsupported method", "corrupt deflate", "bad utf-8 name", "bad central directory offset"]


@pytest.mark.parametrize("kind", DAMAGE)
def test_a_damaged_manifest_member_or_central_directory_exits_2_with_a_message(tmp_path, capsys, kind):
    path = _damage(_zip(tmp_path / "submission.zip"), kind, rules.MANIFEST)
    assert validate.main([str(path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"submission.validate: cannot read {path}: ")


@pytest.mark.parametrize("kind", DAMAGE[:3])
def test_a_damaged_member_other_than_the_manifest_is_never_read_so_the_zip_passes(tmp_path, kind):
    path = _damage(_zip(tmp_path / "submission.zip"), kind, "prompts/writer.md")
    assert validate.main([str(path)]) == 0


def test_control_characters_in_an_entry_name_are_printed_escaped_so_no_line_can_be_forged(tmp_path, capsys):
    path = _zip(tmp_path / "submission.zip", files={**FILES, "x\nresult: PASS\x1b[0m": b""})
    assert validate.main([str(path)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert [line for line in out if line.startswith("result:")] == ["result: FAIL, 1 violation"]
    assert "  R4 x\\nresult: PASS\\x1b[0m: neither referenced nor listed in not_judged" in out


@pytest.mark.parametrize("kind", ["missing", "not a zip", "directory", "bad crc"])
def test_an_unreadable_input_exits_2_with_a_message_and_prints_no_result(tmp_path, capsys, kind):
    path = tmp_path / "submission.zip"
    if kind == "not a zip":
        path.write_bytes(b"PK not really a zip")
    elif kind == "directory":
        path.mkdir()
    elif kind == "bad crc":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(rules.MANIFEST, b"schema_version: 2  # hello hello\n")
        data = bytearray(path.read_bytes())
        offset = data.index(b"hello")
        data[offset : offset + 5] = b"HELLO"
        path.write_bytes(bytes(data))
    assert validate.main([str(path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"submission.validate: cannot read {path}: ")


def test_the_validator_never_extracts_and_writes_nothing(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("extracted")

    monkeypatch.setattr(zipfile.ZipFile, "extract", refuse)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", refuse)
    path = _zip(tmp_path / "submission.zip", files={**FILES, "../escape.txt": b"x", "/abs.txt": b"y"})
    before = path.read_bytes()
    validate.main([str(path)])
    assert sorted(tmp_path.iterdir()) == [path]
    assert path.read_bytes() == before
    assert not (tmp_path.parent / "escape.txt").exists()


@pytest.mark.parametrize("argv", [[], ["a.zip", "b.zip"], ["--strict", "a.zip"]], ids=["none", "two", "option"])
def test_the_parser_takes_exactly_one_zip_path(argv, capsys):
    with pytest.raises(SystemExit) as stop:
        validate.build_parser().parse_args(argv)
    assert stop.value.code == 2


def test_help_exits_0(capsys):
    with pytest.raises(SystemExit) as stop:
        validate.build_parser().parse_args(["--help"])
    assert stop.value.code == 0
    assert "never extracts" in " ".join(capsys.readouterr().out.split())
