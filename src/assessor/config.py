import json
import math
import os
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRICING_FILE = ROOT / "config" / "pricing.json"
SCHEMAS_DIR = ROOT / "schemas"

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

MAX_TOKENS = 16000
SDK_MAX_RETRIES = 2
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACKS = "default"
PRICE_FIELDS = ("input", "output", "cache_write", "cache_read")


def runs_dir() -> Path:
    return Path(os.environ.get("ASSESSOR_RUNS_DIR") or "runs")


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
