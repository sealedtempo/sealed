"""Sealed usage metering callback for the LiteLLM proxy (MIT core, v1.106.5).

Loaded by `litellm_settings.callbacks: ["sealed_usage.usage_logger"]`. For every
successful call it posts one token-count event to sealed-agent
(INTERFACES section 11):

    {"app": "llm-gateway", "unit": "tokens", "quantity": <prompt + completion>,
     "id": <litellm call id>,
     "meta": {"model": ..., "prompt_tokens": ..., "completion_tokens": ..., "key_alias": ...}}

`id` is LiteLLM's per-call id. sealed-agent deduplicates on it, so a retry after an
ambiguous failure (for example a read timeout after the agent already recorded the
event) never bills the same call twice. Events the agent could not take are kept in a
bounded in-memory queue and retried with backoff, so a restart of the agent does not
lose them. Without an id, only failures that cannot have reached the agent are retried.

Only counts, names and the call id leave this module. Prompts, outputs and headers are
never read or sent.

The same callback also keeps paid relay calls from being retried (D-067), because a retried
paid request is a new payment. Its pre-call hook reads only the request's model, its fallback
lists and its retry settings: it drops retry settings a client sent (num_retries, max_retries,
retry_policy, model_group_retry_policy), so the gateway's config decides, and it sets
num_retries and max_retries to 0 on every request that names a relay/ route. A request-level 0
is what LiteLLM 1.106.5 ranks first (Router.async_function_with_retries), above the
deployment's own num_retries and any retry policy.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import os
import time
from typing import Any, Callable, Optional

import httpx
from litellm.integrations.custom_logger import CustomLogger

DEFAULT_URL = "http://sealed-agent:7070/v1/usage-events"
APP_ID = "llm-gateway"
UNIT = "tokens"
MAX_ID_LEN = 200  # @sealed/core usageEventSchema: id is a string of at most 200 chars

DELIVERED = "delivered"  # 2xx: recorded or recognized as a duplicate
REJECTED = "rejected"    # 4xx: the agent will never take this event
RETRY = "retry"          # the agent certainly did not record it
AMBIGUOUS = "ambiguous"  # the agent may have recorded it

# Transport errors raised before the request could reach the agent.
_NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.UnsupportedProtocol)

log = logging.getLogger("sealed_usage")


def _count(value: Any) -> int:
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def event_id(slo: dict[str, Any]) -> Optional[str]:
    """LiteLLM's call id (StandardLoggingPayload.id, else litellm_call_id), if usable."""
    for key in ("id", "litellm_call_id"):
        value = slo.get(key)
        if isinstance(value, str) and 0 < len(value) <= MAX_ID_LEN and value.strip() == value:
            return value
    return None


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
    event: dict[str, Any] = {
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
    call_id = event_id(slo)
    if call_id is not None:
        event["id"] = call_id
    return event


RELAY_PREFIX = "relay/"
# Request keys that change how often LiteLLM sends a request.
RETRY_KEYS = ("num_retries", "max_retries", "retry_policy", "model_group_retry_policy")
# Request keys that name other routes LiteLLM may try after the requested one fails.
FALLBACK_KEYS = ("fallbacks", "context_window_fallbacks", "content_policy_fallbacks")


def _names_relay(value: Any, depth: int = 0) -> bool:
    """True if value is, or contains (lists and mapping keys or values), a relay/ route name."""
    if depth > 8:
        return True  # an absurdly nested fallback spec: treat it as reaching the relay
    if isinstance(value, str):
        return value.startswith(RELAY_PREFIX)
    if isinstance(value, dict):
        return any(_names_relay(k, depth + 1) or _names_relay(v, depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_names_relay(v, depth + 1) for v in value)
    return False


def reaches_relay(data: dict[str, Any]) -> bool:
    """True if this request may be sent to a relay/ route: as its model or as a fallback."""
    return _names_relay(data.get("model")) or any(_names_relay(data.get(k)) for k in FALLBACK_KEYS)


def without_relay_retries(data: Any) -> Any:
    """The request data with client retry settings removed, and no retries if it may reach the relay."""
    if not isinstance(data, dict):
        return data
    for key in RETRY_KEYS:
        data.pop(key, None)
    if reaches_relay(data):
        data["num_retries"] = 0
        data["max_retries"] = 0
    return data


def _env_number(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class SealedUsageLogger(CustomLogger):
    def __init__(
        self,
        url: Optional[str] = None,
        timeout_s: Optional[float] = None,
        attempts: Optional[int] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        queue_max: Optional[int] = None,
        queue_ttl_s: Optional[float] = None,
        backoff_max_s: Optional[float] = None,
    ) -> None:
        # LiteLLM hands this instance a payload copy with messages and responses redacted.
        super().__init__(turn_off_message_logging=True)
        self.url = url or os.environ.get("SEALED_USAGE_URL", DEFAULT_URL)
        self.timeout_s = timeout_s if timeout_s is not None else _env_number("SEALED_USAGE_TIMEOUT_S", 2.0)
        self.attempts = max(1, attempts if attempts is not None else int(_env_number("SEALED_USAGE_ATTEMPTS", 3)))
        self.queue_ttl_s = queue_ttl_s if queue_ttl_s is not None else _env_number("SEALED_USAGE_QUEUE_TTL_S", 86400)
        self.backoff_max_s = backoff_max_s if backoff_max_s is not None else 60.0
        size = queue_max if queue_max is not None else int(_env_number("SEALED_USAGE_QUEUE_MAX", 10000))
        self._pending: collections.deque[tuple[dict[str, Any], float]] = collections.deque(maxlen=max(1, size))
        self.dropped = 0
        self._transport = transport
        self._sleep = sleep
        self._clock = clock
        self._client: Optional[httpx.AsyncClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._drain_task: Optional[asyncio.Task] = None

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

    async def post_once(self, event: dict[str, Any]) -> str:
        """One POST, classified as DELIVERED, REJECTED, RETRY or AMBIGUOUS. Never raises."""
        try:
            response = await self._http().post(self.url, json=event)
        except _NOT_SENT:
            return RETRY
        except Exception:  # read timeout, reset, protocol error: the agent may have recorded it
            return AMBIGUOUS
        if response.status_code < 300:
            return DELIVERED
        if response.status_code == 503:
            return RETRY  # agent not ready: it rejects before recording
        if response.status_code < 500:
            return REJECTED
        return AMBIGUOUS

    @staticmethod
    def _retryable(event: dict[str, Any], outcome: str) -> bool:
        return outcome == RETRY or (outcome == AMBIGUOUS and "id" in event)

    async def send(self, event: dict[str, Any]) -> bool:
        """Post one event with quick retries; queue it for later if the agent stays away."""
        outcome = RETRY
        for attempt in range(self.attempts):
            if attempt:
                await self._sleep(0.25 * attempt)
            outcome = await self.post_once(event)
            if outcome == DELIVERED:
                return True
            if not self._retryable(event, outcome):
                break
        if self._retryable(event, outcome):
            self._enqueue(event)
        else:
            self.dropped += 1
            log.warning("sealed usage event dropped (%s); %d dropped so far", outcome, self.dropped)
        return False

    def _enqueue(self, event: dict[str, Any]) -> None:
        if len(self._pending) == self._pending.maxlen:
            self.dropped += 1
            log.warning("sealed usage queue full; %d events dropped so far", self.dropped)
        self._pending.append((event, self._clock()))
        loop = asyncio.get_running_loop()
        task = self._drain_task
        if task is None or task.done() or task.get_loop() is not loop:
            self._drain_task = loop.create_task(self._drain())

    async def _drain(self) -> None:
        delay = 1.0
        while self._pending:
            event, since = self._pending[0]
            if self._clock() - since > self.queue_ttl_s:
                self._pending.popleft()
                self.dropped += 1
                log.warning("sealed usage event expired in the queue; %d dropped so far", self.dropped)
                continue
            outcome = await self.post_once(event)
            if outcome == DELIVERED or not self._retryable(event, outcome):
                self._pending.popleft()
                if outcome != DELIVERED:
                    self.dropped += 1
                delay = 1.0
                continue
            await self._sleep(delay)
            delay = min(self.backoff_max_s, delay * 2)

    @property
    def pending(self) -> int:
        return len(self._pending)

    async def flush(self) -> None:
        """Wait until the retry queue is empty (tests and shutdown)."""
        task = self._drain_task
        if task is not None and not task.done():
            await task

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Runs before LiteLLM routes a proxy request: no retries on paid relay routes (D-067)."""
        return without_relay_retries(data)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        if not isinstance(kwargs, dict):
            return
        slo = kwargs.get("standard_logging_object")
        if not isinstance(slo, dict):
            return
        if "id" not in slo and isinstance(kwargs.get("litellm_call_id"), str):
            slo = {**slo, "id": kwargs["litellm_call_id"]}
        event = build_event(slo)
        if event is not None:
            await self.send(event)

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()


usage_logger = SealedUsageLogger()
