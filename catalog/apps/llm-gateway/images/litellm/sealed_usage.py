"""Sealed usage metering callback for the LiteLLM proxy (MIT core, v1.106.5).

Loaded by `litellm_settings.callbacks: ["sealed_usage.usage_logger"]`. For every
successful call it posts one token-count event to sealed-agent
(INTERFACES section 11):

    {"app": "llm-gateway", "unit": "tokens", "quantity": <prompt + completion>,
     "meta": {"model": ..., "prompt_tokens": ..., "completion_tokens": ..., "key_alias": ...}}

Only counts and names leave this module. Prompts, outputs, headers and request
bodies are never read or sent.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Callable, Optional

import httpx
from litellm.integrations.custom_logger import CustomLogger

DEFAULT_URL = "http://sealed-agent:7070/v1/usage-events"
APP_ID = "llm-gateway"
UNIT = "tokens"


def _count(value: Any) -> int:
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def build_event(slo: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map a LiteLLM StandardLoggingPayload to a usage event, or None if it carries no tokens."""
    prompt = _count(slo.get("prompt_tokens"))
    completion = _count(slo.get("completion_tokens"))
    if prompt + completion == 0:
        return None
    metadata = slo.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    # model_group is the public route name the client asked for (local/..., relay/...).
    model = _text(slo.get("model_group")) or _text(slo.get("model"))
    return {
        "app": APP_ID,
        "unit": UNIT,
        "quantity": prompt + completion,
        "meta": {
            "model": model,
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "key_alias": _text(metadata.get("user_api_key_alias")),
        },
    }


class SealedUsageLogger(CustomLogger):
    def __init__(
        self,
        url: Optional[str] = None,
        timeout_s: Optional[float] = None,
        attempts: Optional[int] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ) -> None:
        # LiteLLM hands this instance a payload copy with messages and responses redacted.
        super().__init__(turn_off_message_logging=True)
        self.url = url or os.environ.get("SEALED_USAGE_URL", DEFAULT_URL)
        self.timeout_s = timeout_s if timeout_s is not None else float(os.environ.get("SEALED_USAGE_TIMEOUT_S", "2.0"))
        self.attempts = max(1, attempts if attempts is not None else int(os.environ.get("SEALED_USAGE_ATTEMPTS", "3")))
        self._transport = transport
        self._sleep = sleep
        self._client: Optional[httpx.AsyncClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            # trust_env=False: sealed-agent is local, never route it through HTTP(S)_PROXY.
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_s),
                trust_env=False,
                follow_redirects=False,
                transport=self._transport,
            )
            self._loop = loop
        return self._client

    async def send(self, event: dict[str, Any]) -> bool:
        """Post one event, retrying transport errors and 5xx. Never raises."""
        for attempt in range(self.attempts):
            if attempt:
                await self._sleep(0.25 * attempt)
            try:
                response = await self._http().post(self.url, json=event)
            except Exception:  # transport error: retry, never log the body
                continue
            if response.status_code < 300:
                return True
            if response.status_code < 500:
                return False  # rejected by the agent; retrying will not help
        return False

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        slo = kwargs.get("standard_logging_object") if isinstance(kwargs, dict) else None
        if not isinstance(slo, dict):
            return
        event = build_event(slo)
        if event is not None:
            await self.send(event)

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()


usage_logger = SealedUsageLogger()
