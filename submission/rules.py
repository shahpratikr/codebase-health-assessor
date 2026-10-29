from fnmatch import fnmatchcase
from typing import NamedTuple

MANIFEST = "manifest.yaml"
ITERATIONS = "docs/iterations.md"
RESULTS = "evals/results"
HISTORY = f"{RESULTS}/history.jsonl"
# Repeats assessor.audit.AUDIT_FILE, because submission imports only assessor.config and the manifest constants; a test
# keeps the two equal.
AUDIT_FILE = "audit.jsonl"
SCHEMA_VERSION = 2
STAGE = 5

# Validator rules in precedence order, which is also the order they are printed in. R7 (shared files are legal) is
# allowed behaviour, not a check.
RULES = ("PATH", "R1", "R2", "R5", "R6", "R3", "R4", "R8", "LOG")
# The rules that read the manifest: they are SKIPPED when it is missing or does not load as a mapping.
MANIFEST_RULES = ("R6", "R3", "R4", "R8", "LOG")
VCS_DIRS = (".git", ".svn", ".hg")
LEGACY_AGENT_FILES = ("agents.json", "agents.yaml")
DISPATCH_MODES = ("messages-api", "subprocess", "cli")
MANIFEST_ROLES = ("coordinator", "subagent", "adversarial")

# The LLM agents in the order of evals.run.AGENTS, which submission may not import; a test keeps them equal.
AGENTS = ("security_examiner", "dependency_examiner", "adversarial_reviewer", "final_review_writer", "coordinator")
# The one of AGENTS that no workflow owns. Its eval files are cited by this name when its manifest did not load; a test
# keeps it equal to the runtime reviewer.
REVIEWER = "adversarial_reviewer"
# Runtime role (config.AGENT_ROLES) to manifest.yaml role.
ROLES = {"coordinator": "coordinator", "examiner": "subagent", "reviewer": "adversarial", "writer": "subagent"}
# Punch-out name to the gate (config.GATES) a human decides.
PUNCH_OUTS = {
    "substance-gate": "SUBSTANCE_ELEVATION",
    "open-critical-challenge": "OPEN_CRITICAL_CHALLENGE",
    "coordinator-escalation": "COORDINATOR_ESCALATION",
}
# (workflow, agent, steps); None takes the steps from the agent's manifest.
WORKFLOWS = (
    ("security", "security_examiner", None),
    ("dependency", "dependency_examiner", None),
    ("reporting", "final_review_writer", ("final_review",)),
    ("coordination", "coordinator", ("dispatch_governance",)),
)

TITLE = "codebase-health-assessor"
DISPATCH = "messages-api"
COORDINATOR_ENTRY_POINT = "src/assessor/coordinator.py"
SUB_AGENT_ENTRY_POINT = "src/assessor/agents/runner.py"
CRITERIA_FILE, CASE_FILE, SCRIPT_FILE = "criteria.json", "case.json", "script.json"
EVAL_HARNESS = ("evals/run.py", "evals/scoring.py")
EVAL_EXTRAS = {
    "dependency_examiner": ("evals/dependency_examiner/osv_replay.json",),
    "final_review_writer": ("evals/judges/tone.md",),
    "coordinator": ("evals/scripted_dispatcher.py",),
}
CAMPAIGN = "evals/punchout.py"
CAMPAIGN_RESULTS = f"{RESULTS}/punchout/*-punchout.json"
TOY_RATINGS = "examples/substance-toy.json"
FINALIZED_RUNS, ELEVATED_RUNS = "examples/sample-runs/finalized", "examples/sample-runs/elevated"
SAMPLE_RUNS = (FINALIZED_RUNS, ELEVATED_RUNS)
VERSION_CONTROL = ("git_log.txt",)


class Rule(NamedTuple):
    patterns: tuple[str, ...]
    reason: str


# Every file in the ZIP must match a rule; the first that matches classifies it, and its reason is what not_judged says
# for a file that no section cites. A pattern ending in "/" covers every path beneath a directory it names, and "*"
# matches within one path segment.
CLASSIFICATION = (
    Rule(VERSION_CONTROL, "exported commit log"),
    Rule(("prompts/",), "prompt that no agent manifest names"),
    Rule(("manifests/",), "runtime agent manifest; the agents section is derived from it"),
    Rule(("evals/run.py", "evals/scoring.py", "evals/scripted_dispatcher.py", CAMPAIGN), "eval harness module"),
    Rule(
        (
            f"evals/*/{CRITERIA_FILE}",
            f"evals/*/cases/*/{CASE_FILE}",
            f"evals/coordinator/cases/*/{SCRIPT_FILE}",
            "evals/dependency_examiner/osv_replay.json",
            "evals/judges/",
        ),
        "eval set file that no step cites",
    ),
    Rule((f"{RESULTS}/*.json", HISTORY), "eval results file of no agent"),
    Rule((CAMPAIGN_RESULTS,), "campaign run that did not hold"),
    Rule((TOY_RATINGS,), "substance ratings that no punch-out cites"),
    Rule(("src/",), "harness code beside the cited coordinator and sub-agent entry points"),
    Rule(("submission/",), "packaging tools that write and check this manifest"),
    Rule(("tests/",), "offline test suite"),
    Rule(
        ("README.md", "CLAUDE.md", "docs/", f"{RESULTS}/README.md", "examples/sample-runs/README.md"),
        "documentation",
    ),
    Rule(("schemas/",), "JSON Schemas for manifests, agent outputs, audit lines and the eval history"),
    Rule(("skills/",), "examiner checklists, appended to the examiners' system prompts"),
    Rule(("config/",), "model prices used to cost each call"),
    Rule(("evals/*/cases/*/repo/",), "client files an eval case gives its agent"),
    Rule(("examples/sample-client-repo/",), "the client repository the sample runs assessed"),
    Rule(tuple(f"{directory}/*/" for directory in SAMPLE_RUNS), "sample run output that no section cites"),
    Rule((".gitignore", "pyproject.toml", "poetry.lock", "poetry.toml"), "project settings for poetry, pytest and git"),
    Rule(("evals/__init__.py",), "package marker"),
)


def matches(pattern: str, path: str) -> bool:
    """Return whether path matches pattern segment by segment, a pattern ending in "/" matching every path beneath."""
    wanted, parts = pattern.removesuffix("/").split("/"), path.split("/")
    if pattern.endswith("/"):
        if len(parts) <= len(wanted):
            return False
        parts = parts[: len(wanted)]
    return len(parts) == len(wanted) and all(fnmatchcase(part, want) for part, want in zip(parts, wanted))


def classify(path: str) -> Rule | None:
    """Return the first rule of CLASSIFICATION that path matches, or None."""
    return next((rule for rule in CLASSIFICATION if any(matches(pattern, path) for pattern in rule.patterns)), None)


def covers(exclusion: str, path: str) -> bool:
    """Return whether not_judged path exclusion covers path: every path beneath it when it ends in "/", else itself."""
    return path.startswith(exclusion) if exclusion.endswith("/") else path == exclusion


_TEXT = {"type": "string"}
_NAME = {"type": "string", "minLength": 1}
_NAMES = {"type": "array", "items": _TEXT}
_EVIDENCE = {"type": "array", "minItems": 1, "items": _TEXT}


def _closed(required: list[str], properties: dict) -> dict:
    return {"type": "object", "required": required, "properties": properties, "additionalProperties": False}


# The manifest.yaml shape the intake publishes, with its R2 requirements; the form of a path is PATH's to check.
MANIFEST_SCHEMA = _closed(
    ["schema_version", "submission", "coordinator", "agents", "workflows", "adversarial_review", "version_control"],
    {
        "schema_version": {"const": SCHEMA_VERSION},
        "submission": _closed(["stage"], {"title": _TEXT, "stage": {"const": STAGE}}),
        "coordinator": _closed(
            ["entry_point", "dispatch"],
            {"entry_point": _TEXT, "prompt_file": _TEXT, "dispatch": {"enum": list(DISPATCH_MODES)}},
        ),
        "agents": {
            "type": "array",
            "items": _closed(
                ["name", "role"],
                {
                    "name": _NAME,
                    "role": {"enum": list(MANIFEST_ROLES)},
                    "workflows": _NAMES,
                    "allowed_tools": _NAMES,
                    "reviews": _NAMES,
                    "isolated_context": {"type": "boolean"},
                },
            ),
            "contains": {"type": "object", "required": ["role"], "properties": {"role": {"const": "coordinator"}}},
            "minContains": 1,
            "maxContains": 1,
        },
        "workflows": {
            "type": "array",
            "minItems": 1,
            "items": _closed(
                ["name", "steps"],
                {
                    "name": _NAME,
                    "sub_agent_entry_point": _TEXT,
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "items": _closed(
                            ["name", "prompt_file", "eval_files"],
                            {"name": _NAME, "prompt_file": _TEXT, "eval_files": _EVIDENCE, "log_files": _NAMES},
                        ),
                    },
                    "artifacts": _closed([], {"log": _TEXT, "success_rate": _TEXT}),
                },
            ),
        },
        "punch_outs": {"type": "array", "items": _closed(["name", "evidence"], {"name": _NAME, "evidence": _EVIDENCE})},
        "adversarial_review": _closed(["evidence"], {"reviewer_agent": _TEXT, "evidence": _EVIDENCE}),
        "version_control": _closed(["evidence"], {"evidence": _EVIDENCE}),
        "not_judged": {
            "type": "array",
            "items": _closed(["path", "reason"], {"path": _TEXT, "reason": {"type": "string", "pattern": r"\S"}}),
        },
    },
)
