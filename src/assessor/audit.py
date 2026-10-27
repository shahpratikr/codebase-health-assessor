import json
import os
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from assessor import config

AUDIT_FILE = "audit.jsonl"
ENVELOPE = ("correlation_id", "seq", "step_id", "ts", "event")
_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads((config.SCHEMAS_DIR / "audit_event.schema.json").read_text(encoding="utf-8"))
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(moment: datetime) -> datetime:
    if moment.utcoffset() is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return moment.astimezone(UTC)


def new_correlation_id(now: datetime | None = None) -> str:
    """Return a YYYYMMDDTHHMMSSZ-<8 hex> correlation ID for a run started at now (the current time when None)."""
    return f"{_as_utc(now or utc_now()):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"


class AuditLog:
    """Append-only JSONL audit trail of one run, at <runs_dir>/<correlation_id>/audit.jsonl.

    A line's seq is its line number, so a reopened log continues after its lines; a torn last line stays as its own
    unparseable line, which readers must skip.
    """

    def __init__(
        self,
        correlation_id: str,
        runs_dir: Path | None = None,
        clock: Callable[[], datetime] = utc_now,
        pricing: Mapping[str, Mapping[str, float]] | None = None,
    ) -> None:
        if not config.CORRELATION_ID.fullmatch(correlation_id):
            raise ValueError(f"not a correlation ID: {correlation_id!r}")
        self.correlation_id = correlation_id
        self.path = (config.runs_dir() if runs_dir is None else runs_dir) / correlation_id / AUDIT_FILE
        self.pricing = config.load_pricing() if pricing is None else config.check_pricing(pricing)
        self._clock = clock
        self._seq, self._torn = self._scan()

    def _scan(self) -> tuple[int, bool]:
        """Return the number of lines in the log and whether the last one lacks its newline."""
        try:
            with open(self.path, "rb") as existing:
                count, last = 0, b"\n"
                for last in existing:
                    count += 1
        except FileNotFoundError:
            return 0, False
        return count, not last.endswith(b"\n")

    def cost(self, model: str, tokens: Mapping[str, int]) -> dict:
        """Return cost_usd for the token counts at model's $/MTok prices, or null with pricing_missing if unpriced."""
        prices = self.pricing.get(model)
        if prices is None:
            return {"cost_usd": None, "pricing_missing": True}
        total = (
            tokens["input_tokens"] * prices["input"]
            + tokens["output_tokens"] * prices["output"]
            + tokens["cache_creation_input_tokens"] * prices["cache_write"]
            + tokens["cache_read_input_tokens"] * prices["cache_read"]
        )
        return {"cost_usd": round(total / 1_000_000, 6), "pricing_missing": False}

    def check(self, event: str, /, **fields: object) -> dict:
        """Return the next line append would write, validated against schemas/audit_event.schema.json, unwritten."""
        if clash := sorted(set(fields) & set(ENVELOPE)):
            raise ValueError(f"audit fields cannot override the envelope: {', '.join(clash)}")
        if self._seq is None:
            self._seq, self._torn = self._scan()
        moment = _as_utc(self._clock())
        seq = self._seq + 1
        record = {
            "correlation_id": self.correlation_id,
            "seq": seq,
            "step_id": f"{self.correlation_id}:{seq}",
            "ts": f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z",
            "event": event,
            **fields,
        }
        _VALIDATOR.validate(record)
        return record

    def append(self, event: str, /, **fields: object) -> dict:
        """Write the checked line, flushed and fsynced, and return it; a rejected event raises and writes nothing.

        A failed write raises its own error and may still have reached the file, so the next line rescans it first.
        """
        record = self.check(event, **fields)
        line = json.dumps(record, allow_nan=False) + "\n"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as log:
                log.write("\n" + line if self._torn else line)
                log.flush()
                os.fsync(log.fileno())
        except BaseException:
            self._seq = None
            raise
        self._seq, self._torn = record["seq"], False
        return record
