import json
import math
import os
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRICING_FILE = ROOT / "config" / "pricing.json"
SCHEMAS_DIR = ROOT / "schemas"
MANIFESTS_DIR = ROOT / "manifests"
SUBSTANCE_FILE = MANIFESTS_DIR / "substance.json"

# Correlation IDs name run directories, so the full-shape match also refuses path-like values such as ../x.
CORRELATION_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")

AUDIT_EVENTS = (
    "run_started",
    "llm_call",
    "tool_call",
    "dispatch_started",
    "dispatch_finished",
    "guardrail_rejected",
    "gate_opened",
    "run_finished",
    "decision_recorded",
)

LLM_ERROR_CODES = ("REFUSAL", "MAX_TOKENS", "API_ERROR")
DISPATCH_ERROR_CODES = (
    "SCHEMA_INVALID",
    "EVIDENCE_INVALID",
    "PRECONDITION_FAILED",
    "UNKNOWN_TARGET",
    "RETRY_CAP_REACHED",
    "TOOL_LOOP_LIMIT",
    *LLM_ERROR_CODES,
)
# An agent's output that failed with one of these can pass when the same dispatch is sent again. A launch the
# coordinator refuses on its own checks passes only once it is fixed or what it waits for exists, whatever its code.
RETRYABLE_DISPATCH_ERRORS = ("SCHEMA_INVALID", "EVIDENCE_INVALID", "TOOL_LOOP_LIMIT", "MAX_TOKENS", "API_ERROR")
DISPATCH_ERROR_MAX_DETAILS = 20
DISPATCH_ERROR_TEXT_MAX_CHARS = 300

AGENT_ROLES = ("coordinator", "examiner", "reviewer", "writer")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
SUBAGENT_TOOLS = ("list_files", "read_file", "list_manifests", "read_manifest", "query_osv")
SUBSTANCE_RATINGS = ("core", "peripheral", "toy")

CONTRACTS = ("examination", "review", "writer_output", "disposition")
FINDING_SEVERITIES = ("critical", "high", "medium", "low")
CHALLENGE_RESPONSES = ("upheld", "rejected")
REVIEW_VERDICTS = ("pass", "challenge", "block")
LENSES = ("challenge", "catch", "detect")
CHALLENGE_SEVERITIES = ("critical", "major", "minor")
DISPOSITION_DECISIONS = ("accept", "escalate")
SECTION_STATUSES = ("PASS", "FAIL")
FAILING_SEVERITIES = ("critical", "high")
HALT_REASONS = (
    "COORDINATOR_TURN_LIMIT",
    "COORDINATOR_REFUSAL",
    "COORDINATOR_MAX_TOKENS",
    "COORDINATOR_API_ERROR",
    "NO_REPORT",
    "REPORT_NOT_REVIEWED",
)
ADVISORY_STEP = "known_vulnerabilities"
REDACT_KEEP_CHARS = 4

RUN_STATUSES = ("finalized", "pending_human", "halted")
RUN_EXIT_CODES = {"finalized": 0, "halted": 1, "pending_human": 3}
GATES = ("SUBSTANCE_ELEVATION", "OPEN_CRITICAL_CHALLENGE", "COORDINATOR_ESCALATION")
HUMAN_DECISIONS = ("continue", "reject")
HUMAN_STATUSES = {"continue": "finalized_by_human", "reject": "rejected_by_human"}
ELEVATING_PERIPHERAL_COUNT = 2
# Report order, keyed by the writer's section key, <workflow>.<step>.
REPORT_TITLES = {
    "security_examiner.secrets": "Secrets exposure",
    "security_examiner.insecure_config": "Insecure configuration",
    "dependency_examiner.known_vulnerabilities": "Known vulnerable dependencies",
    "dependency_examiner.dependency_hygiene": "Dependency hygiene",
}
# How an eval criterion's mean score must stand to its threshold; only evals read it.
COMPARISONS = ("at_least", "at_most")

MAX_TOKENS = 16000
SDK_MAX_RETRIES = 2
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACKS = "default"
PRICE_FIELDS = ("input", "output", "cache_write", "cache_read")

WORKSPACE_DIR = "workspace"
EXAMINATIONS_DIR, REVIEWS_DIR, DRAFTS_DIR = "examinations", "reviews", "drafts"
TOKEN_FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
RUN_FILE, SUMMARY_FILE, DISPOSITION_FILE = "run.json", "summary.json", "disposition.json"
REPORT_FILE, DECISIONS_FILE = "report.md", "decisions.jsonl"
ZIP_MAX_ENTRIES = 5000
ZIP_MAX_BYTES = 50_000_000
READ_MAX_LINES = 400
READ_MAX_BYTES = 256_000
LIST_MAX_ENTRIES = 500
SKIPPED_DIRS = (".git", "node_modules", ".venv")

OSV_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 10.0
OSV_ECOSYSTEMS = ("PyPI", "npm")
# OSV's third range type, GIT, records fixes as commit hashes, which are no version to upgrade to.
OSV_VERSION_RANGES = ("ECOSYSTEM", "SEMVER")
OSV_SUMMARY_MAX_CHARS = 300
DEPENDENCY_FILE_KINDS = ("manifest", "lockfile")
# (file-name glob, ecosystem, kind): the only files list_manifests and read_manifest see.
DEPENDENCY_FILES = (
    ("requirements*.txt", "PyPI", "manifest"),
    ("pyproject.toml", "PyPI", "manifest"),
    ("Pipfile", "PyPI", "manifest"),
    ("Pipfile.lock", "PyPI", "lockfile"),
    ("poetry.lock", "PyPI", "lockfile"),
    ("uv.lock", "PyPI", "lockfile"),
    ("package.json", "npm", "manifest"),
    ("package-lock.json", "npm", "lockfile"),
    ("npm-shrinkwrap.json", "npm", "lockfile"),
    ("yarn.lock", "npm", "lockfile"),
    ("pnpm-lock.yaml", "npm", "lockfile"),
)


def runs_dir() -> Path:
    return Path(os.environ.get("ASSESSOR_RUNS_DIR") or "runs")


def anthropic_api_key() -> str | None:
    """Return the key named by ANTHROPIC_API_KEY without surrounding whitespace, or None when unset or blank."""
    return os.environ.get("ANTHROPIC_API_KEY", "").strip() or None


def osv_replay() -> Path | None:
    """Return the OSV replay file named by ASSESSOR_OSV_REPLAY, or None (query live OSV) when unset or empty."""
    value = os.environ.get("ASSESSOR_OSV_REPLAY")
    return Path(value) if value else None


def load_pricing(path: Path = PRICING_FILE) -> dict[str, dict[str, float]]:
    """Return the $/MTok prices per model in path, after check_pricing."""
    with open(path, encoding="utf-8") as file:
        return check_pricing(json.load(file), str(path))


def check_pricing(pricing: object, source: str = "pricing") -> dict[str, dict[str, float]]:
    """Return a copy of pricing if it maps at least one model to exactly the PRICE_FIELDS, each finite and >= 0.

    Raises ValueError naming source otherwise.
    """
    if not isinstance(pricing, Mapping) or not pricing:
        raise ValueError(f"{source}: pricing must map at least one model ID to its prices")
    for model, prices in pricing.items():
        if not isinstance(prices, Mapping) or set(prices) != set(PRICE_FIELDS):
            raise ValueError(f"{source}: pricing for {model} must have exactly {', '.join(PRICE_FIELDS)}")
        for field, price in prices.items():
            if isinstance(price, bool) or not isinstance(price, int | float) or not math.isfinite(price) or price < 0:
                raise ValueError(f"{source}: pricing for {model} {field} must be a finite non-negative number")
    return {model: dict(prices) for model, prices in pricing.items()}
