import json
from pathlib import Path

import pytest

from assessor import config

ROOT = Path(__file__).parents[1]


def test_root_is_the_repository():
    assert config.ROOT == ROOT.resolve()
    assert config.PRICING_FILE == ROOT.resolve() / "config" / "pricing.json"
    assert config.SCHEMAS_DIR == ROOT.resolve() / "schemas"
    assert config.MANIFESTS_DIR == ROOT.resolve() / "manifests"
    assert config.SUBSTANCE_FILE == ROOT.resolve() / "manifests" / "substance.json"


def test_runs_dir_defaults_to_runs(monkeypatch):
    monkeypatch.delenv("ASSESSOR_RUNS_DIR", raising=False)
    assert config.runs_dir() == Path("runs")


def test_runs_dir_reads_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(tmp_path / "elsewhere"))
    assert config.runs_dir() == tmp_path / "elsewhere"


def test_empty_runs_dir_env_counts_as_unset(monkeypatch):
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", "")
    assert config.runs_dir() == Path("runs")


def test_shipped_pricing_has_the_verified_prices():
    # Copied from https://platform.claude.com/docs/en/about-claude/pricing on 2026-10-27; claude-sonnet-5 is the
    # server-side fallback target of claude-sonnet-5-5.
    assert config.load_pricing() == {
        "claude-sonnet-5-5": {"input": 2.0, "output": 10.0, "cache_write": 2.5, "cache_read": 0.1},
        "claude-sonnet-5": {"input": 2.0, "output": 10.0, "cache_write": 2.5, "cache_read": 0.2},
        "claude-opus-5-5": {"input": 4.0, "output": 20.0, "cache_write": 5.0, "cache_read": 0.2},
        "claude-haiku-5-5": {"input": 0.1, "output": 0.5, "cache_write": 0.125, "cache_read": 0.01},
    }


def test_audit_events_are_the_planned_closed_set():
    assert config.AUDIT_EVENTS == (
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


def test_agent_closed_sets_are_the_planned_ones():
    assert config.AGENT_ROLES == ("coordinator", "examiner", "reviewer", "writer")
    assert config.SUBAGENT_TOOLS == ("list_files", "read_file", "list_manifests", "read_manifest", "query_osv")
    assert config.SUBSTANCE_RATINGS == ("core", "peripheral", "toy")


def test_load_pricing_reads_another_file(tmp_path):
    path = tmp_path / "pricing.json"
    path.write_text(json.dumps({"m": {"input": 1, "output": 2, "cache_write": 0, "cache_read": 0.5}}))
    assert config.load_pricing(path) == {"m": {"input": 1, "output": 2, "cache_write": 0, "cache_read": 0.5}}


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "{}",
        '{"m": []}',
        '{"m": {"input": 1, "output": 2, "cache_write": 3}}',
        '{"m": {"input": 1, "output": 2, "cache_write": 3, "cache_read": 4, "batch": 5}}',
        '{"m": {"input": -1, "output": 2, "cache_write": 3, "cache_read": 4}}',
        '{"m": {"input": "1", "output": 2, "cache_write": 3, "cache_read": 4}}',
        '{"m": {"input": true, "output": 2, "cache_write": 3, "cache_read": 4}}',
        '{"m": {"input": null, "output": 2, "cache_write": 3, "cache_read": 4}}',
        '{"m": {"input": NaN, "output": 2, "cache_write": 3, "cache_read": 4}}',
        '{"m": {"input": Infinity, "output": 2, "cache_write": 3, "cache_read": 4}}',
    ],
)
def test_load_pricing_rejects_malformed_prices(tmp_path, text):
    path = tmp_path / "pricing.json"
    path.write_text(text)
    with pytest.raises(ValueError, match="pricing"):
        config.load_pricing(path)


@pytest.mark.parametrize("pricing", [{}, {"m": {"input": 1, "output": 2, "cache_write": 3}}, [("m", {})]])
def test_check_pricing_rejects_malformed_prices(pricing):
    with pytest.raises(ValueError, match="pricing"):
        config.check_pricing(pricing)


def test_check_pricing_returns_an_equal_copy():
    pricing = {"m": {"input": 1, "output": 2, "cache_write": 0, "cache_read": 0.5}}
    checked = config.check_pricing(pricing)
    assert checked == pricing
    assert checked is not pricing
    assert checked["m"] is not pricing["m"]


def test_load_pricing_rejects_invalid_json(tmp_path):
    path = tmp_path / "pricing.json"
    path.write_text('{"m": ')
    with pytest.raises(ValueError):
        config.load_pricing(path)
