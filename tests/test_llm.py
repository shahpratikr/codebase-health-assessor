import inspect
import json
import os
import typing
from datetime import UTC, datetime

import anthropic

# anthropic 2.x is built on httpx2 (its own dependency, not the httpx package), and its exceptions take httpx2 objects.
import httpx2
import jsonschema
import pytest
from anthropic import _client as sdk_client
from anthropic._models import FinalRequestOptions
from anthropic.resources.beta.messages import Messages
from anthropic.types.anthropic_beta_param import AnthropicBetaParam
from anthropic.types.beta import BetaMessage

from assessor import audit, config, llm

CID = "20261027T101500Z-0a1b2c3d"
SONNET = "claude-sonnet-5-5"
OPUS = "claude-opus-5-5"
PRICING = {
    SONNET: {"input": 2.0, "output": 10.0, "cache_write": 2.5, "cache_read": 0.1},
    OPUS: {"input": 4.0, "output": 20.0, "cache_write": 5.0, "cache_read": 0.2},
}
REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _message(
    stop_reason="end_turn",
    model=SONNET,
    content=None,
    input_tokens=1000,
    output_tokens=200,
    cache_creation=0,
    cache_read=0,
    iterations=None,
):
    return BetaMessage.model_validate(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": "done"}] if content is None else content,
            "stop_reason": stop_reason,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": cache_creation,
                "cache_read_input_tokens": cache_read,
                "iterations": iterations,
            },
        }
    )


def _declined_iteration(output_tokens=0):
    return {
        "type": "message",
        "model": SONNET,
        "input_tokens": 900,
        "output_tokens": output_tokens,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }


def _fallback_iterations(model=OPUS):
    return [
        _declined_iteration(),
        {
            "type": "fallback_message",
            "model": model,
            "input_tokens": 1000,
            "output_tokens": 200,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        },
    ]


def _fallback_block(to=OPUS):
    return {
        "type": "fallback",
        "from": {"model": SONNET},
        "to": {"model": to},
        "trigger": {"type": "refusal", "category": "cyber"},
    }


@pytest.fixture
def log(tmp_path):
    return audit.AuditLog(
        CID, runs_dir=tmp_path, clock=lambda: datetime(2026, 10, 27, 10, 15, tzinfo=UTC), pricing=PRICING
    )


def _lines(log):
    return [json.loads(line) for line in log.path.read_text().splitlines()]


def _call(client, log, **overrides):
    kwargs = {
        "agent": "security_examiner",
        "workflow": "security_examiner",
        "step": "secrets",
        "parent_step_id": f"{CID}:4",
        "model": SONNET,
        "effort": "medium",
        "system": "You examine repositories.",
        "messages": [{"role": "user", "content": "Examine the secrets step."}],
        "timer": iter([10.0, 10.25]).__next__,
    }
    return llm.call(client, log, **{**kwargs, **overrides})


def test_llm_call_line_has_every_field(fake_anthropic, log):
    _call(fake_anthropic([_message(cache_creation=100, cache_read=50)]), log)
    assert _lines(log) == [
        {
            "correlation_id": CID,
            "seq": 1,
            "step_id": f"{CID}:1",
            "ts": "2026-10-27T10:15:00.000Z",
            "event": "llm_call",
            "parent_step_id": f"{CID}:4",
            "agent": "security_examiner",
            "workflow": "security_examiner",
            "step": "secrets",
            "requested_model": SONNET,
            "effort": "medium",
            "served_model": SONNET,
            "fallback_ran": False,
            "input_tokens": 1000,
            "output_tokens": 200,
            "cache_creation_input_tokens": 100,
            "cache_read_input_tokens": 50,
            "cost_usd": 0.004255,
            "pricing_missing": False,
            "stop_reason": "end_turn",
            "latency_ms": 250,
            "error": None,
        }
    ]


def test_coordinator_call_has_null_workflow_step_and_parent(fake_anthropic, log):
    client = fake_anthropic([_message("tool_use")])
    _call(client, log, agent="coordinator", workflow=None, step=None, parent_step_id=None)
    (line,) = _lines(log)
    assert (line["agent"], line["workflow"], line["step"], line["parent_step_id"]) == ("coordinator", None, None, None)


@pytest.mark.parametrize(
    ("tokens", "cost"),
    [
        ({"input_tokens": 1_000_000, "output_tokens": 0}, 2.0),
        ({"input_tokens": 0, "output_tokens": 1_000_000}, 10.0),
        ({"input_tokens": 0, "output_tokens": 0, "cache_creation": 1_000_000}, 2.5),
        ({"input_tokens": 0, "output_tokens": 0, "cache_read": 1_000_000}, 0.1),
        ({"input_tokens": 0, "output_tokens": 0}, 0.0),
        ({"input_tokens": 1, "output_tokens": 0}, 0.000002),
        ({"input_tokens": 0, "output_tokens": 0, "cache_read": 1}, 0.0),
        ({"input_tokens": 0, "output_tokens": 0, "cache_read": 7}, 0.000001),
        ({"input_tokens": 0, "output_tokens": 0, "cache_creation": None, "cache_read": None}, 0.0),
    ],
)
def test_cost_prices_four_token_kinds_by_served_model(fake_anthropic, log, tokens, cost):
    _call(fake_anthropic([_message(**tokens)]), log)
    (line,) = _lines(log)
    assert line["cost_usd"] == cost
    assert line["pricing_missing"] is False


def test_none_cache_tokens_are_recorded_as_zero(fake_anthropic, log):
    _call(fake_anthropic([_message(cache_creation=None, cache_read=None)]), log)
    (line,) = _lines(log)
    assert (line["cache_creation_input_tokens"], line["cache_read_input_tokens"]) == (0, 0)


def test_unpriced_served_model_gives_null_cost_and_flag(fake_anthropic, log):
    _call(fake_anthropic([_message(model="claude-opus-4-8", iterations=_fallback_iterations("claude-opus-4-8"))]), log)
    (line,) = _lines(log)
    assert (line["served_model"], line["cost_usd"], line["pricing_missing"]) == ("claude-opus-4-8", None, True)
    assert (line["input_tokens"], line["output_tokens"]) == (1000, 200)


def test_fallback_served_model_is_recorded_and_priced(fake_anthropic, log):
    response = _message(
        model=OPUS, content=[_fallback_block(), {"type": "text", "text": "done"}], iterations=_fallback_iterations()
    )
    assert _call(fake_anthropic([response]), log) is response
    (line,) = _lines(log)
    assert (line["requested_model"], line["served_model"], line["fallback_ran"]) == (SONNET, OPUS, True)
    assert line["cost_usd"] == 0.008


def test_declined_fallback_attempt_is_not_counted(fake_anthropic, log):
    iterations = [_declined_iteration(output_tokens=50), _fallback_iterations()[1]]
    _call(fake_anthropic([_message(model=OPUS, content=[_fallback_block()], iterations=iterations)]), log)
    (line,) = _lines(log)
    assert (line["input_tokens"], line["output_tokens"], line["cost_usd"]) == (1000, 200, 0.008)


def test_sticky_fallback_turn_without_block_counts_as_fallback(fake_anthropic, log):
    _call(fake_anthropic([_message(model=OPUS, iterations=_fallback_iterations())]), log)
    assert _lines(log)[0]["fallback_ran"] is True


def test_plain_message_iterations_are_not_a_fallback(fake_anthropic, log):
    _call(fake_anthropic([_message(iterations=[_declined_iteration(output_tokens=200)])]), log)
    assert _lines(log)[0]["fallback_ran"] is False


def test_latency_ms_comes_from_the_timer(fake_anthropic, log):
    _call(fake_anthropic([_message()]), log, timer=iter([3.0, 4.5006]).__next__)
    assert _lines(log)[0]["latency_ms"] == 1501


def test_message_content_never_reaches_the_audit(fake_anthropic, log, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-CANARY-KEY")
    response = _message(content=[{"type": "text", "text": "CANARY-RESPONSE"}])
    tool_turn = _message(
        "tool_use",
        content=[{"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "CANARY-TOOL"}}],
    )
    client = fake_anthropic([tool_turn, response])
    _call(client, log, system="CANARY-SYSTEM", messages=[{"role": "user", "content": "CANARY-USER"}])
    tools = [{"name": "read_file", "description": "CANARY-TOOL-DESC", "input_schema": {"type": "object"}}]
    _call(client, log, tools=tools)
    text = log.path.read_text()
    assert [line["event"] for line in _lines(log)] == ["llm_call", "llm_call"]
    assert "CANARY" not in text


@pytest.mark.parametrize(
    "labels",
    [
        {"agent": ""},
        {"effort": ""},
        {"model": ""},
        {"parent_step_id": "bad"},
        {"parent_step_id": f"{CID}:0"},
        {"workflow": 3},
        {"agent": "security examiner"},
        {"agent": "Coordinator"},
        {"agent": "-coordinator"},
        {"agent": "_coordinator"},
        {"agent": ".coordinator"},
        {"workflow": "Security Examiner"},
        {"step": "secrets\nprompt text"},
        {"effort": "x" * 65},
        {"model": "Claude Sonnet"},
    ],
)
def test_invalid_labels_are_refused_before_the_request(fake_anthropic, log, labels):
    client = fake_anthropic([])
    with pytest.raises(jsonschema.ValidationError):
        _call(client, log, **labels)
    assert client.requests == []
    assert not log.path.exists()


@pytest.mark.parametrize("label", ["a", "a.b", "x" * 64, "claude-sonnet-5-5", "known_vulnerabilities"])
@pytest.mark.parametrize("field", ["agent", "workflow", "step", "model", "effort"])
def test_identifier_labels_are_accepted(fake_anthropic, log, field, label):
    client = fake_anthropic([_message()])
    _call(client, log, **{field: label})
    expected = "requested_model" if field == "model" else field
    assert _lines(log)[0][expected] == label


def test_unreadable_log_after_a_failed_write_refuses_the_next_request(fake_anthropic, log):
    log.path.parent.write_text("not a directory")
    with pytest.raises(FileExistsError):
        log.append("run_started")
    client = fake_anthropic([])
    with pytest.raises(OSError):
        _call(client, log)
    assert client.requests == []


def test_audit_write_failure_after_a_response_propagates(fake_anthropic, log, monkeypatch):
    def failing_fsync(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(audit.os, "fsync", failing_fsync)
    client = fake_anthropic([_message()])
    with pytest.raises(OSError, match="No space left"):
        _call(client, log)
    assert len(client.requests) == 1


def test_audit_write_failure_after_an_sdk_error_propagates_with_it(fake_anthropic, log, monkeypatch):
    def failing_fsync(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(audit.os, "fsync", failing_fsync)
    error = anthropic.APIConnectionError(request=REQUEST)
    with pytest.raises(OSError, match="No space left") as raised:
        _call(fake_anthropic([error]), log)
    assert raised.value.__context__ is error


def test_request_sends_default_fallbacks_and_beta(fake_anthropic, log):
    client = fake_anthropic([_message("tool_use"), _message()])
    _call(client, log, agent="coordinator", workflow=None, step=None, parent_step_id=None)
    _call(client, log, agent="final_review_writer", effort="low")
    for request in client.requests:
        assert request["fallbacks"] == "default"
        assert request["betas"] == ["server-side-fallback-2026-07-01"]


def test_request_keys_are_installed_sdk_parameters(fake_anthropic, log):
    client = fake_anthropic([_message()])
    _call(client, log, tools=[{"name": "t", "input_schema": {"type": "object"}}], output_schema={"type": "object"})
    parameters = inspect.signature(Messages.create).parameters
    assert set(client.requests[0]) <= set(parameters)
    assert "server-side-fallback-2026-07-01" in typing.get_args(typing.get_args(AnthropicBetaParam)[1])


@pytest.mark.parametrize("stop_reason", ["end_turn", "tool_use"])
def test_usable_stop_reason_returns_the_response(fake_anthropic, log, stop_reason):
    response = _message(stop_reason)
    assert _call(fake_anthropic([response]), log) is response
    assert _lines(log)[0]["stop_reason"] == stop_reason


@pytest.mark.parametrize(
    ("stop_reason", "code"),
    [
        ("refusal", "REFUSAL"),
        ("max_tokens", "MAX_TOKENS"),
        ("model_context_window_exceeded", "MAX_TOKENS"),
        ("pause_turn", "API_ERROR"),
        ("stop_sequence", "API_ERROR"),
        ("compaction", "API_ERROR"),
        (None, "API_ERROR"),
    ],
)
def test_unusable_stop_reason_is_audited_then_raised(fake_anthropic, log, stop_reason, code):
    with pytest.raises(llm.LLMError) as raised:
        _call(fake_anthropic([_message(stop_reason)]), log)
    assert raised.value.code == code
    (line,) = _lines(log)
    assert (line["stop_reason"], line["error"], line["cost_usd"]) == (stop_reason, None, 0.004)


def test_refusal_after_fallback_is_a_refusal(fake_anthropic, log):
    response = _message("refusal", model=OPUS, content=[_fallback_block()], iterations=[_declined_iteration()])
    with pytest.raises(llm.LLMError) as raised:
        _call(fake_anthropic([response]), log)
    assert raised.value.code == "REFUSAL"
    (line,) = _lines(log)
    assert (line["served_model"], line["fallback_ran"], line["stop_reason"]) == (OPUS, True, "refusal")


@pytest.mark.parametrize(
    "error",
    [
        anthropic.RateLimitError("rate limited", response=httpx2.Response(429, request=REQUEST), body=None),
        anthropic.InternalServerError("overloaded", response=httpx2.Response(529, request=REQUEST), body=None),
        anthropic.BadRequestError("bad", response=httpx2.Response(400, request=REQUEST), body=None),
        anthropic.APIConnectionError(request=REQUEST),
        anthropic.APITimeoutError(request=REQUEST),
        anthropic.CredentialsError("no credentials"),
    ],
    ids=lambda error: type(error).__name__,
)
def test_sdk_error_is_audited_then_raised_as_api_error(fake_anthropic, log, error):
    with pytest.raises(llm.LLMError) as raised:
        _call(fake_anthropic([error]), log)
    assert raised.value.code == "API_ERROR"
    assert raised.value.__cause__ is error
    assert _lines(log) == [
        {
            "correlation_id": CID,
            "seq": 1,
            "step_id": f"{CID}:1",
            "ts": "2026-10-27T10:15:00.000Z",
            "event": "llm_call",
            "parent_step_id": f"{CID}:4",
            "agent": "security_examiner",
            "workflow": "security_examiner",
            "step": "secrets",
            "requested_model": SONNET,
            "effort": "medium",
            "served_model": None,
            "fallback_ran": False,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "cost_usd": 0.0,
            "pricing_missing": False,
            "stop_reason": None,
            "latency_ms": 250,
            "error": type(error).__name__,
        }
    ]


def test_non_sdk_exception_propagates_unaudited(fake_anthropic, log):
    with pytest.raises(TypeError):
        _call(fake_anthropic([TypeError("bug")]), log)
    assert not log.path.exists()


def test_llm_error_codes_are_the_closed_set():
    assert config.LLM_ERROR_CODES == ("REFUSAL", "MAX_TOKENS", "API_ERROR")
    for code in config.LLM_ERROR_CODES:
        assert llm.LLMError(code).code == code
    with pytest.raises(ValueError, match="TOOL_LOOP_LIMIT"):
        llm.LLMError("TOOL_LOOP_LIMIT")


@pytest.fixture
def no_credentials(monkeypatch, tmp_path):
    for name in [name for name in os.environ if name.startswith("ANTHROPIC_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def _auth_headers(client):
    # The SDK merges its headers per request, so only a built request shows which ones go out.
    request = client._build_request(FinalRequestOptions.construct(method="post", url="/v1/messages"))
    return {name: value for name, value in request.headers.items() if name in ("x-api-key", "authorization")}


def _set_federation_env(monkeypatch, tmp_path):
    token_file = tmp_path / "identity-token"
    token_file.write_text("header.payload.signature")
    for name, value in {
        "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_test",
        "ANTHROPIC_ORGANIZATION_ID": "org_test",
        "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_test",
        "ANTHROPIC_IDENTITY_TOKEN_FILE": str(token_file),
    }.items():
        monkeypatch.setenv(name, value)


def _refuse_credential_lookups(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the SDK looked for credentials beside the key")

    for name in ("static_credential_from_env", "default_credentials"):
        monkeypatch.setattr(sdk_client, name, refuse)


def test_make_client_uses_two_sdk_retries(no_credentials, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = llm.make_client()
    assert isinstance(client, anthropic.Anthropic)
    assert client.max_retries == 2


def test_make_client_sends_the_key_as_x_api_key_and_no_authorization_header(no_credentials, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert _auth_headers(llm.make_client()) == {"x-api-key": "test-key"}


@pytest.mark.parametrize(
    ("name", "value"), [("ANTHROPIC_AUTH_TOKEN", "test-token"), ("ANTHROPIC_PROFILE", "no-such-profile")]
)
def test_make_client_ignores_other_credentials_set_beside_the_key(no_credentials, monkeypatch, name, value):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv(name, value)
    _refuse_credential_lookups(monkeypatch)
    assert _auth_headers(llm.make_client()) == {"x-api-key": "test-key"}


def test_make_client_ignores_a_credentials_provider_set_beside_the_key(no_credentials, monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    _set_federation_env(monkeypatch, tmp_path)
    _refuse_credential_lookups(monkeypatch)
    assert _auth_headers(llm.make_client()) == {"x-api-key": "test-key"}


def test_make_client_keeps_its_auth_headers_over_custom_headers_that_spell_each_name_once(no_credentials, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    # Two spellings of one name in this variable still beat the key: the SDK merges them case-sensitively.
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "authorization: Bearer other\nX-API-Key: other")
    assert _auth_headers(llm.make_client()) == {"x-api-key": "test-key"}


def test_make_client_reads_the_key_through_config(no_credentials, monkeypatch):
    monkeypatch.setattr(config, "anthropic_api_key", lambda: "from-config")
    assert _auth_headers(llm.make_client()) == {"x-api-key": "from-config"}


def test_make_client_follows_no_redirects(no_credentials, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    # httpx2 strips only Authorization when a redirect leaves the origin, so a followed one would carry x-api-key along.
    assert llm.make_client()._client.follow_redirects is False


def test_make_client_keeps_the_sdk_default_http_client_settings(no_credentials, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client, default = llm.make_client(), anthropic.Anthropic()
    # A plain httpx2.Client would drop the SDK's connection limits and socket options.
    assert isinstance(client._client, anthropic.DefaultHttpxClient)
    assert client.timeout == default.timeout
    assert client._client.timeout == default._client.timeout


def test_make_client_honors_anthropic_base_url(no_credentials, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://proxy.example.test")
    assert llm.make_client().base_url.host == "proxy.example.test"


@pytest.mark.parametrize(
    "url",
    [
        "https://alice:s3cret@proxy.example.test",
        "https://alice@proxy.example.test",
        "https://:s3cret@proxy.example.test",
    ],
)
def test_make_client_refuses_a_base_url_that_carries_credentials(no_credentials, monkeypatch, url):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", url)
    with pytest.raises(ValueError, match="^ANTHROPIC_BASE_URL must not carry a username or password") as raised:
        llm.make_client()
    assert "alice" not in str(raised.value)
    assert "s3cret" not in str(raised.value)


@pytest.mark.parametrize(
    ("name", "value"), [("ANTHROPIC_AUTH_TOKEN", "test-token"), ("ANTHROPIC_PROFILE", "some-profile")]
)
def test_make_client_refuses_other_credentials_without_the_key(no_credentials, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(llm.NoCredentialsError, match="^no Anthropic credentials: set ANTHROPIC_API_KEY$"):
        llm.make_client()


def test_make_client_refuses_a_credentials_provider_without_the_key(no_credentials, monkeypatch, tmp_path):
    _set_federation_env(monkeypatch, tmp_path)
    with pytest.raises(llm.NoCredentialsError, match="^no Anthropic credentials: set ANTHROPIC_API_KEY$"):
        llm.make_client()


@pytest.mark.parametrize("key", [None, "", "   ", "\n"])
def test_make_client_fails_fast_without_a_key(no_credentials, monkeypatch, key):
    if key is not None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", key)
    with pytest.raises(llm.NoCredentialsError, match="^no Anthropic credentials: set ANTHROPIC_API_KEY$") as raised:
        llm.make_client()
    assert raised.value.__cause__ is None


def test_request_has_only_gateway_keys(fake_anthropic, log):
    client = fake_anthropic([_message()])
    _call(client, log)
    assert client.requests == [
        {
            "model": SONNET,
            "max_tokens": 16000,
            "system": "You examine repositories.",
            "messages": [{"role": "user", "content": "Examine the secrets step."}],
            "output_config": {"effort": "medium"},
            "betas": ["server-side-fallback-2026-07-01"],
            "fallbacks": "default",
        }
    ]


def test_request_with_tools_and_schema_has_only_gateway_keys(fake_anthropic, log):
    tools = [{"name": "read_file", "strict": True, "input_schema": {"type": "object", "additionalProperties": False}}]
    schema = {"type": "object", "properties": {"summary": {"type": "string"}}}
    client = fake_anthropic([_message()])
    _call(client, log, tools=tools, output_schema=schema)
    assert client.requests == [
        {
            "model": SONNET,
            "max_tokens": 16000,
            "system": "You examine repositories.",
            "messages": [{"role": "user", "content": "Examine the secrets step."}],
            "tools": tools,
            "output_config": {"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
            "betas": ["server-side-fallback-2026-07-01"],
            "fallbacks": "default",
        }
    ]


@pytest.mark.parametrize("effort", ["low", "medium", "high"])
def test_effort_goes_to_output_config(fake_anthropic, log, effort):
    client = fake_anthropic([_message()])
    _call(client, log, effort=effort)
    assert client.requests[0]["output_config"] == {"effort": effort}
    assert _lines(log)[0]["effort"] == effort


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
            "additionalProperties": False,
        },
        {},
    ],
)
def test_output_schema_goes_to_output_config_format(fake_anthropic, log, schema):
    client = fake_anthropic([_message()])
    _call(client, log, output_schema=schema, effort="high")
    output_config = client.requests[0]["output_config"]
    assert output_config == {"effort": "high", "format": {"type": "json_schema", "schema": schema}}


def test_tools_are_sent_verbatim_and_omitted_when_empty(fake_anthropic, log):
    tools = [{"name": "read_file", "strict": True, "input_schema": {"type": "object", "additionalProperties": False}}]
    client = fake_anthropic([_message(), _message(), _message()])
    _call(client, log, tools=tools)
    _call(client, log, tools=[])
    _call(client, log)
    assert client.requests[0]["tools"] == tools
    assert "tools" not in client.requests[1]
    assert "tools" not in client.requests[2]


@pytest.mark.parametrize("banned", ["temperature", "top_p", "top_k", "thinking", "tool_choice"])
def test_gateway_has_no_parameter_for_banned_request_fields(fake_anthropic, log, banned):
    with pytest.raises(TypeError, match=banned):
        _call(fake_anthropic([]), log, **{banned: None})
    assert not log.path.exists()


def test_caller_messages_are_not_mutated(fake_anthropic, log):
    messages = [{"role": "user", "content": "task"}]
    _call(fake_anthropic([_message("tool_use")]), log, messages=messages)
    assert messages == [{"role": "user", "content": "task"}]
