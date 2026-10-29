import argparse
import collections
import contextlib
import json
import math
import os
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn

import jsonschema
import yaml

from assessor import config, manifest
from submission import rules, validate


def _relative(path: Path) -> str:
    return path.relative_to(config.ROOT).as_posix()


MANIFESTS_DIR = _relative(config.MANIFESTS_DIR)
SUBSTANCE = _relative(config.SUBSTANCE_FILE)
MANIFEST_SCHEMA_PATH = _relative(config.SCHEMAS_DIR / "manifest.schema.json")
HISTORY_SCHEMA_PATH = _relative(config.SCHEMAS_DIR / "eval_history.schema.json")
# Every entry gets it, so that the time git archive or zip -u stamped on a file does not change the ZIP.
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
UNIX = 3
REGULAR_FILE = 0o100644 << 16
LOG_HEADER = "| # | Date (UTC) | Prompt | Skills | Criteria (per-run means) | All passed | Cost (USD) | Note |"
LOG_SEPARATOR = "|---|---|---|---|---|---|---|---|"
SHORT_HASH = 8


def _finite_only(text: str) -> NoReturn:
    raise ValueError(f"{text} is not a JSON number")


def _where(error: jsonschema.ValidationError, top: str) -> str:
    return "/".join(str(part) for part in error.absolute_path) or top


def _first_error(validator: jsonschema.Draft202012Validator, data: object, schema: str) -> str | None:
    """Return why data fails, or cannot be checked against, the ZIP's schema at path schema, or None when it passes."""
    try:
        invalid = jsonschema.exceptions.best_match(validator.iter_errors(data))
    except RecursionError:
        return "is nested too deeply to check"
    except Exception as error:
        # The schema comes from the ZIP, so what it holds can fail only here: an unresolved $ref, a bad pattern.
        return f"cannot be checked against {schema}: {type(error).__name__}"
    if invalid is None:
        return None
    return f"fails {schema}: {invalid.message} at {_where(invalid, 'the top level')}"


def _schema(contents: Mapping[str, bytes], path: str, problems: list[str]) -> jsonschema.Draft202012Validator | None:
    """Return a validator for the ZIP's JSON Schema at path, or None after adding why it cannot be one to problems."""
    if path not in contents:
        problems.append(f"{path} is missing")
        return None
    try:
        schema = json.loads(contents[path])
        jsonschema.Draft202012Validator.check_schema(schema)
    except (ValueError, RecursionError, jsonschema.SchemaError):
        problems.append(f"{path} is not a JSON Schema")
        return None
    return jsonschema.Draft202012Validator(schema)


def _agent_manifests(contents: Mapping[str, bytes], problems: list[str]) -> dict[str, dict]:
    """Return, by file name, the ZIP's agent manifests that pass every check below, adding to problems each check a file
    fails and the ones that concern them all: a missing or unusable manifest schema, file names that are not the five
    agents, and a reviewer count other than one that can be told from the manifests that loaded.
    """
    validator = _schema(contents, MANIFEST_SCHEMA_PATH, problems)
    paths = {
        name.removeprefix(f"{MANIFESTS_DIR}/").removesuffix(".json"): name
        for name in contents
        if rules.matches(f"{MANIFESTS_DIR}/*.json", name) and name != SUBSTANCE
    }
    if sorted(paths) != sorted(rules.AGENTS):
        problems.append(
            f"{MANIFESTS_DIR}/ must hold exactly the five agent manifests ({', '.join(rules.AGENTS)}) beside "
            f"{SUBSTANCE}, not {', '.join(sorted(paths)) or 'none'}"
        )
    if validator is None:
        return {}
    needs_steps = {agent: workflow for workflow, agent, steps in rules.WORKFLOWS if steps is None}
    manifests = {}
    for agent in [name for name in rules.AGENTS if name in paths] + sorted(set(paths) - set(rules.AGENTS)):
        path, found = paths[agent], len(problems)
        try:
            data = json.loads(contents[path])
        except (ValueError, RecursionError):
            problems.append(f"{path}: is not JSON")
            continue
        if not isinstance(data, dict):
            problems.append(f"{path}: is not a JSON object")
            continue
        if failure := _first_error(validator, data, MANIFEST_SCHEMA_PATH):
            problems.append(f"{path}: {failure}")
            continue
        if data.get("name") != agent:
            problems.append(f"{path}: name {data.get('name')!r} must match the file name")
        if data.get("role") not in rules.ROLES:
            problems.append(f"{path}: role {data.get('role')!r} has no manifest.yaml role in submission/rules.py")
        if data.get("role") == "reviewer" and data.get("isolated_context") is not True:
            problems.append(f"{path}: isolated_context must be true for the reviewer")
        if agent in needs_steps and "steps" not in data:
            problems.append(f"{path}: has no steps, which the {needs_steps[agent]} workflow needs")
        # The sections read these two whatever the ZIP's schema asks for.
        if not isinstance(data.get("prompt"), str) or not isinstance(data.get("tools"), list):
            problems.append(f"{path}: needs a prompt and a tools list")
        if len(problems) == found:
            manifests[agent] = data
    reviewers = [agent for agent, data in manifests.items() if data["role"] == "reviewer"]
    # Two reviewers are one too many whatever else failed; none is only known once every manifest has loaded.
    if len(reviewers) > 1 or (not reviewers and set(manifests) == set(rules.AGENTS)):
        problems.append(f"{MANIFESTS_DIR}/ must hold exactly one reviewer manifest, not {len(reviewers)}")
    return manifests


def _sample_runs(contents: Mapping[str, bytes], problems: list[str]) -> dict[str, str]:
    """Return the one run directory under each of rules.SAMPLE_RUNS that holds exactly one, adding a problem for each
    that does not."""
    runs = {}
    for directory in rules.SAMPLE_RUNS:
        depth = directory.count("/") + 1
        beneath = [name.split("/") for name in contents if name.startswith(f"{directory}/")]
        found = sorted({parts[depth] for parts in beneath if len(parts) > depth + 1})
        if len(found) == 1:
            runs[directory] = f"{directory}/{found[0]}"
        else:
            problems.append(f"{directory}/ must hold exactly one run directory, not {len(found)}")
    return runs


def _held_campaigns(contents: Mapping[str, bytes], problems: list[str]) -> list[str]:
    """Return the campaign results files whose all_held is true, in name order, adding a problem for each file that is
    not JSON or lacks a boolean all_held, and one when none held."""
    held = []
    for name in sorted(name for name in contents if rules.matches(rules.CAMPAIGN_RESULTS, name)):
        try:
            results = json.loads(contents[name], parse_constant=_finite_only)
        except (ValueError, RecursionError):
            problems.append(f"{name}: is not JSON")
            continue
        if not isinstance(results, dict) or not isinstance(results.get("all_held"), bool):
            problems.append(f"{name}: needs a boolean all_held")
        elif results["all_held"]:
            held.append(name)
    if not held:
        problems.append(f"no {rules.CAMPAIGN_RESULTS} file has all_held true")
    return held


def _history(contents: Mapping[str, bytes], problems: list[str]) -> list[dict]:
    """Return the lines of the ZIP's history once each is a JSON object that passes the ZIP's history schema and names
    one of the five agents, adding a problem naming each line that does not, and one for agents with no line."""
    if rules.HISTORY not in contents:
        problems.append(f"{rules.HISTORY} is missing")
        return []
    validator = _schema(contents, HISTORY_SCHEMA_PATH, problems)
    if validator is None:
        return []
    raw = contents[rules.HISTORY].split(b"\n")
    if raw[-1] == b"":
        raw.pop()
    lines = []
    for number, text in enumerate(raw, 1):
        where = f"{rules.HISTORY} line {number}"
        try:
            line = json.loads(text.decode("utf-8"), parse_constant=_finite_only)
        except (ValueError, RecursionError):
            problems.append(f"{where} is not UTF-8 JSON")
            continue
        if not isinstance(line, dict):
            problems.append(f"{where} is not a JSON object")
        elif failure := _first_error(validator, line, HISTORY_SCHEMA_PATH):
            problems.append(f"{where} {failure}")
        elif line["agent"] not in rules.AGENTS:
            problems.append(f"{where} names agent {line['agent']!r}, which is not one of the five")
        elif not _finite(line):
            problems.append(f"{where} holds a number that is not finite")
        else:
            lines.append(line)
    if missing := [agent for agent in rules.AGENTS if all(line["agent"] != agent for line in lines)]:
        problems.append(f"{rules.HISTORY} has no line for {', '.join(missing)}")
    return lines


def _finite(line: Mapping) -> bool:
    """Return whether every number of a history line that passed its schema is finite, an integer too large for a float
    and the sum of a criterion's per-run means included."""
    try:
        numbers = [] if line["total_cost_usd"] is None else [line["total_cost_usd"]]
        for item in line["summary"]:
            numbers += [item["threshold"], sum(item["per_run_mean"]), *item["per_run_mean"]]
        return all(math.isfinite(number) for number in numbers)
    except OverflowError:
        return False


def _beneath(directory: str, pattern: str, contents: Mapping[str, bytes]) -> list[str]:
    """Return, in name order, the files directly in directory whose name matches pattern."""
    return sorted(
        name
        for name in contents
        if name.startswith(f"{directory}/") and rules.matches(pattern, name.removeprefix(f"{directory}/"))
    )


def _eval_set(agent: str, contents: Mapping[str, bytes]) -> list[str]:
    case = rules.SCRIPT_FILE if agent == manifest.COORDINATOR else rules.CASE_FILE
    cases = sorted(name for name in contents if rules.matches(f"evals/{agent}/cases/*/{case}", name))
    return [f"evals/{agent}/{rules.CRITERIA_FILE}", *cases]


def _manifest(
    manifests: Mapping[str, dict], runs: Mapping[str, str], held: list[str], contents: Mapping[str, bytes]
) -> dict:
    """Return manifest.yaml's sections but not_judged, derived as docs/ARCHITECTURE.md, Interfaces, describes.

    manifests may hold fewer than the five: what an agent's manifest would have supplied is then left out, and the
    sections still cite every file that depends on the agent's name alone, the reviewer's by rules.REVIEWER when the
    manifests do not say which agent it is.
    """
    coordinator = manifests.get(manifest.COORDINATOR, {})
    reviewers = [agent for agent in rules.AGENTS if manifests.get(agent, {}).get("role") == "reviewer"]
    reviewer = reviewers[0] if len(reviewers) == 1 else rules.REVIEWER
    found = [runs[directory] for directory in rules.SAMPLE_RUNS if directory in runs]
    decisions = [f"{runs[rules.ELEVATED_RUNS]}/{config.DECISIONS_FILE}"] if rules.ELEVATED_RUNS in runs else []
    reviews = [name for run in found for name in _beneath(f"{run}/{config.REVIEWS_DIR}", "RV-*.json", contents)]
    workflows = []
    for workflow, agent, steps in rules.WORKFLOWS:
        loaded = manifests.get(agent, {})
        names = steps if steps is not None else [step["name"] for step in loaded.get("steps", [])]
        entry: dict = {"name": workflow}
        if agent != manifest.COORDINATOR:
            entry["sub_agent_entry_point"] = rules.SUB_AGENT_ENTRY_POINT
        # Every list is built afresh, because safe_dump writes an object it meets twice as an anchor and an alias.
        entry["steps"] = [
            {
                "name": name,
                "prompt_file": loaded.get("prompt"),
                "eval_files": [*_eval_set(agent, contents), *rules.EVAL_HARNESS, *rules.EVAL_EXTRAS.get(agent, ())],
                "log_files": [rules.ITERATIONS, rules.HISTORY, *(f"{run}/{rules.AUDIT_FILE}" for run in found)],
            }
            for name in names or [None]
        ]
        entry["artifacts"] = {"log": rules.ITERATIONS, "success_rate": f"{rules.RESULTS}/{agent}.json"}
        workflows.append(entry)
    punch_outs = []
    for name, gate in rules.PUNCH_OUTS.items():
        if gate == "SUBSTANCE_ELEVATION":
            evidence = [*decisions, SUBSTANCE, rules.TOY_RATINGS, rules.CAMPAIGN, *held]
        else:
            evidence = [rules.CAMPAIGN, *held, f"{rules.RESULTS}/{manifest.COORDINATOR}.json"]
        punch_outs.append({"name": name, "evidence": evidence})
    own = [
        manifests.get(reviewer, {}).get("prompt"),
        *_eval_set(reviewer, contents),
        f"{rules.RESULTS}/{reviewer}.json",
    ]
    return {
        "schema_version": rules.SCHEMA_VERSION,
        "submission": {"title": rules.TITLE, "stage": rules.STAGE},
        "coordinator": {
            "entry_point": rules.COORDINATOR_ENTRY_POINT,
            "prompt_file": coordinator.get("prompt"),
            "dispatch": rules.DISPATCH,
        },
        "agents": [
            {
                "name": agent,
                "role": rules.ROLES[manifests[agent]["role"]],
                "workflows": [
                    workflow
                    for workflow, owner, _ in rules.WORKFLOWS
                    if owner == agent or manifests[agent]["role"] == "coordinator"
                ],
                "allowed_tools": list(manifests[agent]["tools"]),
                "reviews": list(manifests[agent].get("assignment", [])),
                "isolated_context": manifests[agent]["role"] != "coordinator",
            }
            for agent in rules.AGENTS
            if agent in manifests
        ],
        "workflows": workflows,
        "punch_outs": punch_outs,
        "adversarial_review": {
            "reviewer_agent": reviewer,
            "evidence": [*own, *reviews],
        },
        "version_control": {"evidence": list(rules.VERSION_CONTROL)},
    }


def _not_judged(files: Sequence[str], cited: set[str]) -> list[dict]:
    """Return the shortest not_judged list for files: a directory where every file beneath it is uncited and has one
    reason, each file on its own otherwise, sorted by path."""
    reasons = {name: rules.classify(name).reason for name in files if name not in cited}
    # The reasons of the files beneath each directory, None standing for a cited file.
    beneath: dict[str, set[str | None]] = {}
    for name in files:
        parts = name.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            beneath.setdefault("/".join(parts[:depth]) + "/", set()).add(reasons.get(name))
    entries = {}
    for name, reason in reasons.items():
        parts = name.split("/")[:-1]
        directories = ("/".join(parts[:depth]) + "/" for depth in range(1, len(parts) + 1))
        entries[next((directory for directory in directories if beneath[directory] == {reason}), name)] = reason
    return [{"path": path, "reason": reason} for path, reason in sorted(entries.items())]


def derive(names: Sequence[str], contents: Mapping[str, bytes]) -> tuple[str, str, list[str]]:
    """Return manifest.yaml's text, docs/iterations.md's text and every problem that refuses the build, from a ZIP's
    entry names (directory entries included) and the bytes of each file entry; both texts are empty with a problem."""
    counts = collections.Counter(names)
    problems = [f"{name}: appears more than once in the ZIP" for name in sorted(counts) if counts[name] > 1]
    problems += [
        f"{name}: matches no classification rule in submission/rules.py"
        for name in contents
        if rules.classify(name) is None
    ]
    manifests = _agent_manifests(contents, problems)
    runs = _sample_runs(contents, problems)
    held = _held_campaigns(contents, problems)
    lines = _history(contents, problems)
    data = _manifest(manifests, runs, held, contents)
    cited = set(validate.cited(data))
    # The build writes docs/iterations.md, and a missing history already has a problem of its own.
    missing = cited - set(contents) - {rules.ITERATIONS, rules.HISTORY}
    problems += [f"{path}: cited evidence is not in the ZIP" for path in sorted(missing)]
    if problems:
        return "", "", problems
    data["not_judged"] = _not_judged([*contents, rules.ITERATIONS], cited)
    return dump_manifest(data), render_iterations(lines), []


def _row(number: int, line: Mapping) -> str:
    criteria = "; ".join(
        f"{item['criterion']}: {'/'.join(map(json.dumps, item['per_run_mean']))}" for item in line["summary"]
    )
    cost = line["total_cost_usd"]
    cells = [
        str(number),
        line["generated_at"][:10],
        line["prompt_sha256"][:SHORT_HASH],
        line["skills_sha256"][:SHORT_HASH],
        criteria,
        "yes" if line["all_passed"] else "no",
        "unknown" if cost is None else f"${abs(cost):.6f}",
        line["note"].replace("\\", "\\\\").replace("|", "\\|"),
    ]
    return "| " + " | ".join(cells) + " |"


def _means(line: Mapping) -> dict[str, str]:
    means = {}
    for item in line["summary"]:
        values = item["per_run_mean"]
        means.setdefault(item["criterion"], f"{sum(values) / len(values):.4f}")
    return means


def render_iterations(lines: Sequence[Mapping]) -> str:
    """Return docs/iterations.md for history lines that passed their schema: per agent, in rules.AGENTS order, one row
    per line in history order and, from two lines on, each criterion's mean in the first and the last line."""
    out = ["# Iteration log"]
    for agent in rules.AGENTS:
        own = [line for line in lines if line["agent"] == agent]
        out += ["", f"## {agent}", "", LOG_HEADER, LOG_SEPARATOR, *(_row(n, line) for n, line in enumerate(own, 1))]
        if len(own) < 2:
            out += ["", "One execution recorded."]
            continue
        first, last = _means(own[0]), _means(own[-1])
        out += ["", "### Before and after", "", "| Criterion | First | Last |", "|---|---|---|"]
        out += [f"| {name} | {first.get(name, '-')} | {last.get(name, '-')} |" for name in {**first, **last}]
    return "\n".join(out) + "\n"


def dump_manifest(data: Mapping) -> str:
    """Return data as manifest.yaml text: PyYAML's safe_dump, block style, keys in the order given."""
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)


def _copy(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    copy = zipfile.ZipInfo(info.filename, FIXED_TIME)
    copy.compress_type, copy.external_attr = info.compress_type, info.external_attr
    copy.create_system, copy.comment = info.create_system, info.comment
    return copy


def _added(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_TIME)
    info.compress_type, info.create_system, info.external_attr = zipfile.ZIP_DEFLATED, UNIX, REGULAR_FILE
    return info


def _write(
    path: Path,
    infos: Sequence[zipfile.ZipInfo],
    comment: bytes,
    contents: Mapping[str, bytes],
    added: Mapping[str, str],
) -> None:
    """Write the entries infos describe, then added, to <path>.tmp, fsync it and rename it over path; any error is
    re-raised after the new file is removed, and path is left as it was.

    One build at a time per ZIP: <path>.tmp is the build's own name and an earlier file there is overwritten.
    """
    scratch = path.with_name(path.name + ".tmp")
    try:
        with open(scratch, "wb") as handle:
            with zipfile.ZipFile(handle, "w") as copy:
                copy.comment = comment
                for info in infos:
                    copy.writestr(_copy(info), contents.get(info.filename, b""))
                for name, text in added.items():
                    copy.writestr(_added(name), text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(scratch, path)
    except BaseException:
        # Not ours to report when it fails too: the error that got us here is the one to show.
        with contextlib.suppress(OSError):
            scratch.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m submission.build",
        description="Write manifest.yaml and docs/iterations.md into a submission ZIP, derived from the ZIP's own "
        "entries. It never extracts the ZIP: a new one is written beside it and renamed over it.",
        allow_abbrev=False,
    )
    parser.add_argument("zip", type=Path, help="the ZIP the package line wrote, such as submission.zip")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Return the process exit code for argv (sys.argv when None): 0 when both files were added, 1 when the build was
    refused with every problem printed, 2 when the ZIP cannot be read or already holds one of them.

    argparse exits 2 itself on a usage error. A failed write propagates, leaving the ZIP as it was.
    """
    args = build_parser().parse_args(argv)
    try:
        with zipfile.ZipFile(args.zip) as archive:
            infos, comment = archive.infolist(), archive.comment
            contents = {info.filename: archive.read(info) for info in infos if not info.is_dir()}
    except validate.READ_ERRORS as error:
        print(f"submission.build: cannot read {args.zip}: {error}", file=sys.stderr)
        return 2
    if present := [name for name in (rules.MANIFEST, rules.ITERATIONS) if name in contents]:
        outputs = " and ".join(present)
        print(
            f"submission.build: {args.zip} already holds {outputs}; package it again from the package line, "
            f"and do not commit {outputs}",
            file=sys.stderr,
        )
        return 2
    text, iterations, problems = derive([info.filename for info in infos], contents)
    if problems:
        for problem in problems:
            print(f"submission.build: {validate.printable(problem)}", file=sys.stderr)
        return 1
    _write(args.zip, infos, comment, contents, {rules.ITERATIONS: iterations, rules.MANIFEST: text})
    print(f"submission.build: added {rules.ITERATIONS} and {rules.MANIFEST} to {args.zip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
