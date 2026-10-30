import time
from collections.abc import Callable, Sequence

import anthropic
from anthropic.types.beta import BetaMessage

from assessor import config
from assessor.audit import AuditLog

RETURNED_STOP_REASONS = ("end_turn", "tool_use")
# The context window cuts the output short the same way max_tokens does.
MAX_TOKENS_STOP_REASONS = ("max_tokens", "model_context_window_exceeded")
_NO_CREDENTIALS = "no Anthropic credentials: set ANTHROPIC_API_KEY"
_NO_RESPONSE = {
    "served_model": None,
    "fallback_ran": False,
    "input_tokens": 0,
    "output_tokens": 0,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "cost_usd": 0.0,
    "pricing_missing": False,
    "stop_reason": None,
}


class NoCredentialsError(Exception):
    """ANTHROPIC_API_KEY is unset or blank, so every request would fail."""


class LLMError(Exception):
    """A call that yielded no usable response; code is one of config.LLM_ERROR_CODES."""

    def __init__(self, code: str) -> None:
        if code not in config.LLM_ERROR_CODES:
            raise ValueError(f"not an LLM error code: {code}")
        super().__init__(code)
        self.code = code


def make_client() -> anthropic.Anthropic:
    """Return an SDK client authenticated by ANTHROPIC_API_KEY, or raise NoCredentialsError when it is unset or blank.

    Raises ValueError when the base URL the SDK resolved from ANTHROPIC_BASE_URL carries a username or password.
    """
    key = config.anthropic_api_key()
    if key is None:
        raise NoCredentialsError(_NO_CREDENTIALS)
    # The SDK sends an api_key as "Authorization: Bearer", which the proxy in front of the API strips, so the key goes
    # in x-api-key and the bearer header is omitted. An explicit api_key also stops the SDK reading other credentials.
    client = anthropic.Anthropic(
        api_key=key,
        default_headers={"x-api-key": key, "Authorization": anthropic.Omit()},
        # httpx2 strips only Authorization when a redirect leaves the origin, so a followed one would carry x-api-key.
        http_client=anthropic.DefaultHttpxClient(follow_redirects=False),
        max_retries=config.SDK_MAX_RETRIES,
    )
    # httpx2 turns such a URL into an Authorization: Basic header when it sends. The message leaves the URL out
    # because it holds a secret.
    if client.base_url.username or client.base_url.password:
        raise ValueError("ANTHROPIC_BASE_URL must not carry a username or password; the key goes in x-api-key")
    return client


def call(
    client: anthropic.Anthropic,
    audit: AuditLog,
    *,
    agent: str,
    workflow: str | None,
    step: str | None,
    parent_step_id: str | None,
    model: str,
    effort: str,
    system: str,
    messages: Sequence[dict],
    tools: Sequence[dict] = (),
    output_schema: dict | None = None,
    timer: Callable[[], float] = time.perf_counter,
) -> BetaMessage:
    """Send one Messages API request, append its llm_call audit line and return the response.

    Once that line is written, raises LLMError if the SDK raised an AnthropicError or the stop reason is not end_turn or
    tool_use; invalid labels (checked before sending) and audit write failures raise AuditLog's own errors instead.
    """
    output_config = {"effort": effort}
    if output_schema is not None:
        output_config["format"] = {"type": "json_schema", "schema": output_schema}
    request = {
        "model": model,
        "max_tokens": config.MAX_TOKENS,
        "system": system,
        "messages": messages,
        "output_config": output_config,
        "betas": [config.FALLBACK_BETA],
        "fallbacks": config.FALLBACKS,
    }
    if tools:
        request["tools"] = list(tools)
    line = {
        "parent_step_id": parent_step_id,
        "agent": agent,
        "workflow": workflow,
        "step": step,
        "requested_model": model,
        "effort": effort,
    }
    audit.check("llm_call", **line, **_NO_RESPONSE, latency_ms=0, error=None)
    started = timer()
    try:
        response = client.beta.messages.create(**request)
    except anthropic.AnthropicError as error:
        latency_ms = round((timer() - started) * 1000)
        audit.append("llm_call", **line, **_NO_RESPONSE, latency_ms=latency_ms, error=type(error).__name__)
        raise LLMError("API_ERROR") from error
    latency_ms = round((timer() - started) * 1000)
    usage = response.usage
    tokens = {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_creation_input_tokens": usage.cache_creation_input_tokens or 0,
        "cache_read_input_tokens": usage.cache_read_input_tokens or 0,
    }
    audit.append(
        "llm_call",
        **line,
        served_model=response.model,
        fallback_ran=_fallback_ran(response),
        **tokens,
        **audit.cost(response.model, tokens),
        stop_reason=response.stop_reason,
        latency_ms=latency_ms,
        error=None,
    )
    if response.stop_reason == "refusal":
        raise LLMError("REFUSAL")
    if response.stop_reason in MAX_TOKENS_STOP_REASONS:
        raise LLMError("MAX_TOKENS")
    if response.stop_reason not in RETURNED_STOP_REASONS:
        raise LLMError("API_ERROR")
    return response


def _fallback_ran(response: BetaMessage) -> bool:
    # A fallback-served turn carries a fallback_message iteration; a fallback block marks each hop where a model ran
    # and declined, so it also shows a fallback that ran and refused in turn.
    return any(entry.type == "fallback_message" for entry in response.usage.iterations or []) or any(
        block.type == "fallback" for block in response.content
    )
