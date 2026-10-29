import argparse
import hashlib
import io
import sys
import zipfile
import zlib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import jsonschema
import yaml

from submission import rules

# What reading a ZIP or one of its members raises for a missing file, a non-ZIP, a bad CRC, encryption, an unsupported
# compression method, a corrupt stream, and (ValueError) an entry name that is not UTF-8 or a directory offset that
# points outside the file.
READ_ERRORS = (OSError, EOFError, zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, ValueError)
MESSAGE_MAX_CHARS = 200
EXPANDED_MAX = 100_000
_MANIFEST = jsonschema.Draft202012Validator(rules.MANIFEST_SCHEMA)


def _short(text: str) -> str:
    # jsonschema puts the whole offending value in its message, which can be a long mapping on one line.
    text = " ".join(text.split())
    return text if len(text) <= MESSAGE_MAX_CHARS else text[: MESSAGE_MAX_CHARS - 3] + "..."


def printable(text: str) -> str:
    """Return text with each character that is not printable, a newline among them, written as an escape."""
    return "".join(char if char.isprintable() else char.encode("unicode_escape").decode("ascii") for char in text)


def _expanded_size(value: object, memo: dict[int, int]) -> int:
    """Return how many values value holds once each alias counts as the value it points at; raises RecursionError for
    nesting too deep to walk."""
    if not isinstance(value, list | dict):
        return 1
    if id(value) not in memo:
        children = value.values() if isinstance(value, dict) else value
        memo[id(value)] = 1 + sum(_expanded_size(child, memo) for child in children)
    return memo[id(value)]


def _mappings(value: object) -> list[tuple[int, Mapping]]:
    """Return (index, item) for each mapping in value when it is a list, else nothing."""
    return [(index, item) for index, item in enumerate(_listed(value)) if isinstance(item, Mapping)]


def _mapping(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _strings(*values: object) -> list[str]:
    return [value for value in values if isinstance(value, str)]


def _listed(value: object) -> list:
    return value if isinstance(value, list) else []


def path_problem(path: str) -> str | None:
    """Return why path breaks the PATH form (relative, forward slashes, no .. segment), or None when it keeps it."""
    if not path:
        return "is empty"
    if path.startswith("/"):
        return "is absolute"
    if "\\" in path:
        return "uses a backslash"
    if ".." in path.split("/"):
        return "has a .. segment"
    return None


def cited(data: Mapping) -> list[str]:
    """Return every string path the manifest data cites outside not_judged, in manifest order, repeats kept; values of
    the wrong type are left out."""
    coordinator = _mapping(data.get("coordinator"))
    paths = _strings(coordinator.get("entry_point"), coordinator.get("prompt_file"))
    for _, workflow in _mappings(data.get("workflows")):
        paths += _strings(workflow.get("sub_agent_entry_point"))
        for _, step in _mappings(workflow.get("steps")):
            paths += _strings(step.get("prompt_file"), *_listed(step.get("eval_files")))
            paths += _strings(*_listed(step.get("log_files")))
        artifacts = _mapping(workflow.get("artifacts"))
        paths += _strings(artifacts.get("log"), artifacts.get("success_rate"))
    for _, punch_out in _mappings(data.get("punch_outs")):
        paths += _strings(*_listed(punch_out.get("evidence")))
    for section in ("adversarial_review", "version_control"):
        paths += _strings(*_listed(_mapping(data.get(section)).get("evidence")))
    return paths


def _load(manifest: bytes) -> tuple[Mapping | None, str | None]:
    try:
        data = yaml.safe_load(manifest)
    except (yaml.YAMLError, ValueError, RecursionError) as error:
        # ValueError: a scalar that looks like a date but names none, such as 2026-02-30.
        return None, _short(f"{rules.MANIFEST} does not parse as YAML: {str(error) or type(error).__name__}")
    if not isinstance(data, Mapping):
        return None, f"{rules.MANIFEST} must be a mapping, not {type(data).__name__}"
    # Aliases let a few hundred bytes stand for billions of values, which the schema check would walk one by one.
    try:
        size = _expanded_size(data, {})
    except RecursionError:
        return None, f"{rules.MANIFEST} nests too deeply or refers to itself"
    if size > EXPANDED_MAX:
        return None, f"{rules.MANIFEST} holds more than {EXPANDED_MAX} values once aliases are expanded"
    return data, None


def _structure(data: Mapping) -> list[str]:
    problems = [
        _short(f"{'/'.join(str(part) for part in error.absolute_path) or 'the manifest'}: {error.message}")
        for error in _MANIFEST.iter_errors(data)
    ]
    for number, workflow in _mappings(data.get("workflows")):
        seen = set()
        for _, step in _mappings(workflow.get("steps")):
            name = step.get("name")
            if isinstance(name, str) and name in seen:
                problems.append(f"workflows/{number}/steps: step name {name!r} appears twice")
            if isinstance(name, str):
                seen.add(name)
    return problems


def check(names: Sequence[str], manifest: bytes | None) -> dict[str, list[str] | None]:
    """Return each rule's violations, keyed in rules.RULES order, for a ZIP's entry names (directory entries, ending in
    "/", included) and the bytes of its manifest.yaml, None when it holds none.

    A rule that needs the manifest is None (SKIPPED) when it is missing or does not load as a mapping; a path that
    breaks several rules is reported once for each kind of path it is (an entry name, a cited path, an exclusion),
    under the first of them. It never raises on what the manifest holds.
    """
    files = [name for name in names if not name.endswith("/")]
    found: dict[str, list[str] | None] = {rule: [] for rule in rules.RULES}
    by_path: dict[tuple[str, str], tuple[str, str]] = {}

    def flag(rule: str, kind: str, path: str, message: str) -> None:
        # One violation per path of each kind (an entry, a cited path, an exclusion), under the first rule that applies.
        key = (kind, path)
        if key not in by_path or rules.RULES.index(rule) < rules.RULES.index(by_path[key][0]):
            by_path[key] = (rule, f"{path}: {message}")

    for name in files:
        if problem := path_problem(name):
            flag("PATH", "entry", name, f"entry name {problem}")
    for name in names:
        if part := next((part for part in name.split("/") if part in rules.VCS_DIRS), None):
            flag("R5", "entry", name, f"holds a {part} directory")
    data = None
    if manifest is None:
        found["R1"].append(f"{rules.MANIFEST} is not at the ZIP root")
        found["R2"] = None
    else:
        data, problem = _load(manifest)
        if problem:
            found["R2"].append(problem)
    if data is None:
        found.update(dict.fromkeys(rules.MANIFEST_RULES))
    else:
        found["R2"] += _structure(data)
        _check_paths(data, files, flag)
        found["R8"] += _reviewer(data)
        found["LOG"] += _logs(data)
    for key in sorted(by_path, key=lambda key: (key[1], key[0])):
        rule, message = by_path[key]
        found[rule].append(message)
    return found


def _check_paths(data: Mapping, files: list[str], flag: Callable[[str, str, str, str], None]) -> None:
    """Flag PATH, R6, R3 and R4 for the paths data cites and excludes against the ZIP's files."""
    exact, folded = set(files), {}
    for name in files:
        folded.setdefault(name.casefold(), name)
    # Files a wrong-case path points at: the violation is that path's PATH, so they are not also unaccounted for.
    meant: set[str] = set()
    for path in cited(data):
        if problem := path_problem(path):
            flag("PATH", "cited", path, f"cited path {problem}")
        elif path not in exact and path.casefold() in folded:
            match = folded[path.casefold()]
            flag("PATH", "cited", path, f"cited path matches {match} only when letter case is ignored")
            meant.add(match)
        elif path not in exact:
            flag("R3", "cited", path, "cited but not in the ZIP")
    exclusions = _strings(*(item.get("path") for _, item in _mappings(data.get("not_judged"))))
    valid, excluded = [], set()
    for path in exclusions:
        if problem := path_problem(path):
            flag("PATH", "exclusion", path, f"not_judged path {problem}")
            continue
        valid.append(path)
        if covered := [name for name in files if rules.covers(path, name)]:
            excluded.update(covered)
        elif near := [name for name in files if rules.covers(path.casefold(), name.casefold())]:
            flag("PATH", "exclusion", path, f"not_judged path covers {near[0]} only when letter case is ignored")
            meant.update(near)
        else:
            flag("R4", "exclusion", path, "not_judged entry covers no file")
    for name in files:
        if name.rsplit("/", 1)[-1] in rules.LEGACY_AGENT_FILES and not any(rules.covers(path, name) for path in valid):
            flag("R6", "entry", name, "legacy agents file is not listed in not_judged")
    referenced = {*cited(data), *meant, *excluded, rules.MANIFEST}
    for name in files:
        if name not in referenced:
            flag("R4", "entry", name, "neither referenced nor listed in not_judged")


def _reviewer(data: Mapping) -> list[str]:
    review = data.get("adversarial_review")
    # A missing section, or a reviewer_agent of the wrong type, is R2's to report.
    if not isinstance(review, Mapping):
        return []
    if "reviewer_agent" not in review:
        return ["adversarial_review.reviewer_agent is missing"]
    name = review["reviewer_agent"]
    adversarial = {
        agent.get("name")
        for _, agent in _mappings(data.get("agents"))
        if agent.get("role") == "adversarial" and isinstance(agent.get("name"), str)
    }
    if isinstance(name, str) and name not in adversarial:
        return [f"adversarial_review.reviewer_agent {name!r} names no agent with role adversarial"]
    return []


def _logs(data: Mapping) -> list[str]:
    missing = []
    for number, workflow in _mappings(data.get("workflows")):
        if _mapping(workflow.get("artifacts")).get("log"):
            continue
        for index, step in _mappings(workflow.get("steps")):
            if not step.get("log_files"):
                missing.append(
                    f"workflows/{number}/steps/{index}: no log_files, and the workflow declares no artifacts.log"
                )
    return missing


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m submission.validate",
        description="Check a submission ZIP against the Stage 5 intake rules, all violations at once. It never "
        "extracts the ZIP: it reads the entry names and manifest.yaml, and the whole file only to hash it.",
        allow_abbrev=False,
    )
    parser.add_argument("zip", type=Path, help="the submission ZIP, such as submission.zip")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Return the process exit code for argv (sys.argv when None): 0 with no violation, 1 with any, 2 when the ZIP or
    its manifest.yaml cannot be read; argparse exits 2 itself on a usage error."""
    args = build_parser().parse_args(argv)
    try:
        data = args.zip.read_bytes()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            manifest = archive.read(rules.MANIFEST) if rules.MANIFEST in names else None
    except READ_ERRORS as error:
        print(f"submission.validate: cannot read {args.zip}: {error}", file=sys.stderr)
        return 2
    results = check(names, manifest)
    print(f"zip: {args.zip}")
    print(f"sha256: {hashlib.sha256(data).hexdigest()}")
    for rule, violations in results.items():
        print(f"{rule}: {'SKIPPED' if violations is None else 'FAIL' if violations else 'PASS'}")
        for violation in violations or []:
            print(f"  {rule} {printable(violation)}")
    count = sum(len(violations or []) for violations in results.values())
    print(f"result: FAIL, {count} violation{'' if count == 1 else 's'}" if count else "result: PASS")
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
