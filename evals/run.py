import argparse
import hashlib
import json
import math
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import jsonschema

from assessor import audit, config, manifest
from assessor.agents import runner
from assessor.guardrails import DispatchError, ExaminationContext
from assessor.llm import NoCredentialsError, make_client
from assessor.sandbox import Workspace
from evals import scoring

EVALS_DIR = config.ROOT / "evals"
CRITERIA_FILE, CASES_DIR, CASE_FILE, REPO_DIR = "criteria.json", "cases", "case.json", "repo"
RESULTS_DIR, AUDIT_DIR = "results", ".runs"
MIN_CRITERIA = 3

_TEXT = {"type": "string", "minLength": 1}
_CRITERIA = jsonschema.Draft202012Validator(
    {
        "type": "object",
        "properties": {
            "criteria": {
                "type": "array",
                "minItems": MIN_CRITERIA,
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                        "threshold": {"type": "number"},
                        "comparison": {"enum": list(config.COMPARISONS)},
                        "description": _TEXT,
                    },
                    "required": ["name", "threshold", "comparison", "description"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["criteria"],
        "additionalProperties": False,
    }
)
_CASE = jsonschema.Draft202012Validator(
    {
        "type": "object",
        "properties": {
            "id": _TEXT,
            "description": _TEXT,
            "steps": {"type": "array", "minItems": 1, "uniqueItems": True, "items": _TEXT},
            "expected": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "step": _TEXT,
                        "file": _TEXT,
                        "line": {"type": "integer", "minimum": 1},
                        "severity": {"enum": list(config.FINDING_SEVERITIES)},
                        "contains": _TEXT,
                    },
                    "required": ["step", "file", "line", "severity", "contains"],
                    "additionalProperties": False,
                },
            },
            "criteria": {"type": "array", "minItems": 1, "uniqueItems": True, "items": _TEXT},
        },
        "required": ["id", "description", "steps", "expected", "criteria"],
        "additionalProperties": False,
    }
)


@dataclass(frozen=True)
class EvalSet:
    """One agent's manifest, its criteria in file order and its cases in ID order, each with its repository path."""

    agent: str
    manifest: Mapping
    criteria: list[dict]
    cases: list[dict]


def _examine(client: object, log: audit.AuditLog, agent_manifest: Mapping, case: Mapping) -> tuple[dict, str | None]:
    """Return the accepted examination of each step the case lists, keyed by step, and the code of the DispatchError
    that stopped the case (the steps after it are not run), or None.
    """
    workspace = Workspace(case["repo"])
    outputs = {}
    for step in case["steps"]:
        code = next(item["code"] for item in agent_manifest["steps"] if item["name"] == step)
        task = runner.examiner_task(agent_manifest, step, workspace_label=workspace.root.name, challenges=[], note="")
        ctx = ExaminationContext(agent_manifest["name"], step, code, workspace)
        try:
            outputs[step] = runner.run_subagent(
                client,
                log,
                agent_manifest,
                task,
                ctx,
                workspace=workspace,
                workflow=agent_manifest["name"],
                step=step,
                parent_step_id=None,
            )
        except DispatchError as error:
            return outputs, error.code
    return outputs, None


AGENTS: dict[str, Callable[[object, audit.AuditLog, Mapping, Mapping], tuple[dict, str | None]]] = {
    "security_examiner": _examine
}


def _finite(number: float) -> bool:
    try:
        return math.isfinite(number)
    except OverflowError:  # an integer too large for a float
        return False


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    keys = [key for key, _ in pairs]
    if repeated := sorted({key for key in keys if keys.count(key) > 1}):
        raise ValueError(f"duplicate key {repeated[0]!r}")
    return dict(pairs)


def _read(path: Path, validator: jsonschema.Draft202012Validator) -> dict:
    """Return the JSON object in path once validator accepts it; raises ValueError naming path, or the OSError."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_keys)
    except ValueError as error:
        raise ValueError(f"{path}: not valid JSON: {error}") from error
    if invalid := jsonschema.exceptions.best_match(validator.iter_errors(data)):
        where = "/".join(str(part) for part in invalid.absolute_path) or "top level"
        raise ValueError(f"{path}: {where}: {invalid.message}")
    return data


def load_criteria(path: Path, agent: str) -> list[dict]:
    """Return the criteria in path, each with a scorer for agent.

    Raises ValueError naming path for a file that breaks the format, a name listed twice, a name with no scorer, or a
    threshold that is not finite or that a failed run's worst score would meet.
    """
    criteria = _read(path, _CRITERIA)["criteria"]
    names = [criterion["name"] for criterion in criteria]
    if repeated := sorted({name for name in names if names.count(name) > 1}):
        raise ValueError(f"{path}: {', '.join(repeated)} listed twice")
    if unscored := [name for name in names if name not in scoring.SCORERS[agent]]:
        raise ValueError(f"{path}: no scorer for {', '.join(unscored)} of {agent}")
    for criterion in criteria:
        threshold, comparison = criterion["threshold"], criterion["comparison"]
        if not _finite(threshold):
            raise ValueError(f"{path}: {criterion['name']}: threshold is not finite or too large for a float")
        if scoring.meets(scoring.WORST_SCORE[comparison], threshold, comparison):
            worst = scoring.WORST_SCORE[comparison]
            raise ValueError(f"{path}: {criterion['name']}: a failed run's worst score {worst} would meet {threshold}")
    return criteria


def _load_case(directory: Path, agent_manifest: Mapping, criteria: set[str]) -> dict:
    source = directory / CASE_FILE
    case = _read(source, _CASE)
    if case["id"] != directory.name:
        raise ValueError(f"{source}: id {case['id']!r} must match the directory name {directory.name!r}")
    steps = [step["name"] for step in agent_manifest["steps"]]
    if unknown := [step for step in case["steps"] if step not in steps]:
        raise ValueError(f"{source}: {unknown[0]!r} is not a step of {agent_manifest['name']}")
    if unlisted := [name for name in case["criteria"] if name not in criteria]:
        raise ValueError(f"{source}: criterion {unlisted[0]!r} is not in criteria.json")
    workspace = Workspace(directory / REPO_DIR)
    for item in case["expected"]:
        if item["step"] not in case["steps"]:
            raise ValueError(f"{source}: expected finding step {item['step']!r} is not one of the case's steps")
        try:
            lines = workspace.read_lines(item["file"])
        except ValueError as error:
            raise ValueError(f"{source}: {error}") from error
        if type(item["line"]) is not int:
            raise ValueError(f"{source}: line {item['line']!r} of {item['file']} must be a whole number")
        if item["line"] > len(lines):
            raise ValueError(f"{source}: {item['file']} has {len(lines)} lines, not line {item['line']}")
        if item["contains"] not in lines[item["line"] - 1]:
            raise ValueError(f"{source}: {item['file']} line {item['line']} does not hold {item['contains']!r}")
    ordered = sorted(case["expected"], key=lambda item: (item["step"], scoring.normal_path(item["file"]), item["line"]))
    for before, after in zip(ordered, ordered[1:]):
        place = [(item["step"], scoring.normal_path(item["file"])) for item in (before, after)]
        if place[0] == place[1] and after["line"] - before["line"] <= 2 * scoring.LINE_TOLERANCE:
            raise ValueError(
                f"{source}: expected findings at lines {before['line']} and {after['line']} of {after['file']} "
                "share a scoring window"
            )
    return {**case, "repo": directory / REPO_DIR}


def load_eval_set(agent: str, manifests: Mapping[str, Mapping], evals_dir: Path = EVALS_DIR) -> EvalSet:
    """Return the criteria and cases under evals_dir/<agent>, checked against the agent's manifest and each other
    before any model call: every case's expected line exists and holds its text, and every criterion has a case.

    Raises ValueError naming the path that breaks a rule; an OSError reading a file or listing the cases propagates.
    """
    folder = evals_dir / agent
    criteria = load_criteria(folder / CRITERIA_FILE, agent)
    directories = sorted(path for path in (folder / CASES_DIR).iterdir() if path.is_dir())
    if not directories:
        raise ValueError(f"{folder / CASES_DIR}: no cases")
    named = {criterion["name"] for criterion in criteria}
    cases = [_load_case(directory, manifests[agent], named) for directory in directories]
    listed = {name for case in cases for name in case["criteria"]}
    if unused := [name for name in named if name not in listed]:
        raise ValueError(f"{folder / CRITERIA_FILE}: no case lists {', '.join(sorted(unused))}")
    return EvalSet(agent, manifests[agent], criteria, cases)


def run_eval_set(
    client: object, eval_set: EvalSet, *, runs: int, runs_dir: Path, clock: Callable[[], datetime] = audit.utc_now
) -> dict:
    """Return the results of running every case of eval_set runs times, each case run with an audit log of its own
    under runs_dir; the prompt and skills are hashed before the first call.

    A DispatchError ends only its case run, which records the code and scores its criteria at their worst; any other
    error from the agent's code propagates.
    """
    prompt_sha256 = hashlib.sha256((config.ROOT / eval_set.manifest["prompt"]).read_bytes()).hexdigest()
    skills = hashlib.sha256()
    for path in eval_set.manifest["skills"]:
        skills.update((config.ROOT / path).read_bytes())
    pricing, entries = config.load_pricing(), []
    for number in range(1, runs + 1):
        for case in eval_set.cases:
            log = audit.AuditLog(audit.new_correlation_id(clock()), runs_dir=runs_dir, clock=clock, pricing=pricing)
            outputs, error = AGENTS[eval_set.agent](client, log, eval_set.manifest, case)
            scores = (
                scoring.worst_scores(eval_set.criteria, case) if error else scoring.score(eval_set.agent, case, outputs)
            )
            total = log.summary()["total"]
            entries.append(
                {
                    "case_id": case["id"],
                    "run": number,
                    "scores": scores,
                    "passed": scoring.passed(eval_set.criteria, scores),
                    "input_tokens": total["input_tokens"],
                    "output_tokens": total["output_tokens"],
                    "cost_usd": None if total["unpriced_calls"] else total["cost_usd"],
                    "error": error,
                }
            )
    costs = [entry["cost_usd"] for entry in entries]
    return {
        "agent": eval_set.agent,
        "model": eval_set.manifest["model"],
        "effort": eval_set.manifest["effort"],
        "prompt_sha256": prompt_sha256,
        "skills_sha256": skills.hexdigest(),
        "generated_at": audit.timestamp(clock()),
        "runs": runs,
        "cases": entries,
        "summary": scoring.summarize(eval_set.criteria, entries, runs),
        "total_cost_usd": None if None in costs else round(sum(costs), 6),
    }


def write_results(results: Mapping, path: Path) -> None:
    """Write results to path as ASCII JSON with a trailing newline, creating its directory; an earlier file is replaced
    whole or left as it was.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_name(path.name + ".tmp")
    try:
        scratch.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        os.replace(scratch, path)
    except BaseException:
        scratch.unlink(missing_ok=True)
        raise


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m evals.run",
        description="Run an agent's eval set through the real API and write its results. Every run spends API credit.",
        allow_abbrev=False,
    )
    parser.add_argument("--agent", required=True, choices=[*AGENTS, "all"])
    parser.add_argument("--runs", required=True, type=_positive, metavar="N", help="times to run each case")
    return parser


def _report(eval_set: EvalSet, results: Mapping, path: Path) -> bool:
    """Print one agent's outcome and return whether every criterion met its threshold in every run."""
    cost = results["total_cost_usd"]
    spent = "cost unknown (a call used an unpriced model)" if cost is None else f"cost ${cost:.6f}"
    print(f"{results['agent']}: {len(results['cases'])} case runs, {spent}, results in {path}")
    for criterion, item in zip(eval_set.criteria, results["summary"]):
        outcome = "PASS" if item["passed_all_runs"] else "FAIL"
        means = ", ".join(str(mean) for mean in item["per_run_mean"])
        print(f"  {outcome} {item['criterion']} ({criterion['comparison']} {item['threshold']}): {means}")
    return all(item["passed_all_runs"] for item in results["summary"])


def main(
    argv: list[str] | None = None, *, clock: Callable[[], datetime] = audit.utc_now, evals_dir: Path = EVALS_DIR
) -> int:
    """Return the process exit code for argv (sys.argv when None): 0 when every criterion met its threshold in every
    run, 1 when one missed, 2 when an eval set, a manifest or the credentials are unusable (before any model call).

    argparse raises SystemExit itself, 2 on a usage error; each agent's results are written as it finishes, and any
    other error propagates without results for the agent it hit.
    """
    args = build_parser().parse_args(argv)
    names = list(AGENTS) if args.agent == "all" else [args.agent]
    try:
        manifests = manifest.load_manifests()
        sets = [load_eval_set(name, manifests, evals_dir) for name in names]
        client = make_client()
    except (ValueError, OSError, NoCredentialsError) as error:
        print(f"evals.run: {error}", file=sys.stderr)
        return 2
    every_criterion_met = True
    for eval_set in sets:
        results = run_eval_set(client, eval_set, runs=args.runs, runs_dir=evals_dir / AUDIT_DIR, clock=clock)
        path = evals_dir / RESULTS_DIR / f"{eval_set.agent}.json"
        write_results(results, path)
        every_criterion_met &= _report(eval_set, results, path)
    return 0 if every_criterion_met else 1


if __name__ == "__main__":
    sys.exit(main())
