"""Unit tests for images/litellm/sealed_usage.py (the LiteLLM usage callback).

LiteLLM is not installed for unit tests: a minimal stand-in for
litellm.integrations.custom_logger is registered before import. The image build
re-checks the module against the real LiteLLM CustomLogger.
"""
from __future__ import annotations

import asyncio
import http.server
import importlib.util
import json
import os
import sys
import threading
import types
import unittest
from unittest import mock

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "..", "images", "litellm", "sealed_usage.py")


class FakeCustomLogger:
    def __init__(self, turn_off_message_logging: bool = False, **kwargs) -> None:
        self.turn_off_message_logging = turn_off_message_logging


def load_module():
    pkg = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")
    custom_logger.CustomLogger = FakeCustomLogger
    with mock.patch.dict(sys.modules, {
        "litellm": pkg,
        "litellm.integrations": integrations,
        "litellm.integrations.custom_logger": custom_logger,
    }):
        spec = importlib.util.spec_from_file_location("sealed_usage_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


sealed_usage = load_module()

SECRET_PROMPT = "my secret prompt text"
SECRET_OUTPUT = "my secret model output"


def slo(**overrides):
    payload = {
        "id": "chatcmpl-1",
        "litellm_call_id": "call-1",
        "call_type": "acompletion",
        "model": "qwen3:4b-instruct-2507-q4_K_M",
        "model_group": "local/qwen3-4b",
        "custom_llm_provider": "ollama_chat",
        "prompt_tokens": 23,
        "completion_tokens": 64,
        "total_tokens": 87,
        "messages": [{"role": "user", "content": SECRET_PROMPT}],
        "response": {"choices": [{"message": {"content": SECRET_OUTPUT}}]},
        "metadata": {
            "user_api_key_alias": "coding-agent",
            "user_api_key_hash": "9b2e" * 16,
            "headers": {"authorization": "Bearer sk-abc"},
        },
    }
    payload.update(overrides)
    return payload


CONNECT_FAIL = -1   # httpx.ConnectError: the request never reached the agent
READ_TIMEOUT = -2   # httpx.ReadTimeout: the agent may have recorded the event


class Recorder:
    def __init__(self, statuses=None):
        self.requests: list[httpx.Request] = []
        self.statuses = list(statuses or [204])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if status == CONNECT_FAIL:
            raise httpx.ConnectError("agent down", request=request)
        if status == READ_TIMEOUT:
            raise httpx.ReadTimeout("no response", request=request)
        return httpx.Response(status)

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


class DedupAgent:
    """sealed-agent's dedup on id: the first request is recorded and then times out."""

    def __init__(self, timeouts_after_record=1):
        self.recorded: dict[str, dict] = {}
        self.requests = 0
        self.timeouts_after_record = timeouts_after_record

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        event = json.loads(request.content)
        key = event.get("id")
        duplicate = key in self.recorded
        if not duplicate:
            self.recorded[key] = event
        if self.timeouts_after_record > 0:
            self.timeouts_after_record -= 1
            raise httpx.ReadTimeout("agent slow", request=request)
        return httpx.Response(202, json={"status": "duplicate" if duplicate else "accepted"})


async def no_sleep(_seconds):
    await asyncio.sleep(0)  # yield, like a real sleep, so queued work can run


def make_logger(recorder, attempts: int = 3, **kwargs):
    return sealed_usage.SealedUsageLogger(
        url="http://sealed-agent:7070/v1/usage-events",
        timeout_s=1.0,
        attempts=attempts,
        transport=httpx.MockTransport(recorder.handler),
        sleep=no_sleep,
        **kwargs,
    )


def run(coro):
    return asyncio.run(coro)


class BuildEventTest(unittest.TestCase):
    def test_interface_shape(self):
        event = sealed_usage.build_event(slo())
        self.assertEqual(event, {
            "app": "llm-gateway",
            "unit": "tokens",
            "quantity": 87,
            "id": "chatcmpl-1",
            "meta": {
                "model": "local/qwen3-4b",
                "prompt_tokens": 23,
                "completion_tokens": 64,
                "key_alias": "coding-agent",
            },
        })

    def test_never_contains_content_or_key_material(self):
        encoded = json.dumps(sealed_usage.build_event(slo()))
        for forbidden in (SECRET_PROMPT, SECRET_OUTPUT, "sk-abc", "9b2e9b2e", "messages", "response", "headers"):
            self.assertNotIn(forbidden, encoded)

    def test_falls_back_to_provider_model_and_empty_alias(self):
        event = sealed_usage.build_event(slo(model_group=None, metadata={"user_api_key_alias": None}))
        self.assertEqual(event["meta"]["model"], "qwen3:4b-instruct-2507-q4_K_M")
        self.assertEqual(event["meta"]["key_alias"], "")

    def test_bad_and_negative_counts(self):
        event = sealed_usage.build_event(slo(prompt_tokens="12", completion_tokens=-4))
        self.assertEqual((event["quantity"], event["meta"]["completion_tokens"]), (12, 0))
        self.assertIsNone(sealed_usage.build_event(slo(prompt_tokens=None, completion_tokens="x")))

    def test_metadata_not_a_dict(self):
        self.assertEqual(sealed_usage.build_event(slo(metadata="junk"))["meta"]["key_alias"], "")

    def test_id_falls_back_to_litellm_call_id(self):
        self.assertEqual(sealed_usage.build_event(slo(id=None))["id"], "call-1")
        self.assertEqual(sealed_usage.build_event(slo(id=""))["id"], "call-1")

    def test_unusable_id_is_omitted(self):
        for bad in ("x" * 201, " padded ", 42):
            self.assertNotIn("id", sealed_usage.build_event(slo(id=bad, litellm_call_id=None)), bad)
        self.assertEqual(len(sealed_usage.build_event(slo(id="y" * 200))["id"]), 200)


class LoggerTest(unittest.TestCase):
    def test_turns_off_message_logging(self):
        self.assertTrue(make_logger(Recorder()).turn_off_message_logging)
        self.assertIsInstance(sealed_usage.usage_logger, FakeCustomLogger)

    def test_posts_one_event(self):
        recorder = Recorder([202])
        logger = make_logger(recorder)
        run(logger.async_log_success_event({"standard_logging_object": slo()}, None, 0, 1))
        self.assertEqual(len(recorder.requests), 1)
        request = recorder.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "http://sealed-agent:7070/v1/usage-events")
        self.assertEqual(request.headers["content-type"], "application/json")
        body = json.loads(request.content)
        self.assertEqual(body["quantity"], 87)
        self.assertNotIn(SECRET_PROMPT, request.content.decode())

    def test_skips_missing_payload_and_zero_tokens(self):
        recorder = Recorder()
        logger = make_logger(recorder)
        run(logger.async_log_success_event({}, None, 0, 1))
        run(logger.async_log_success_event({"standard_logging_object": "x"}, None, 0, 1))
        run(logger.async_log_success_event({"standard_logging_object": slo(prompt_tokens=0, completion_tokens=0)}, None, 0, 1))
        self.assertEqual(recorder.requests, [])

    def test_retries_server_errors_then_succeeds(self):
        recorder = Recorder([503, CONNECT_FAIL, 204])
        self.assertTrue(run(make_logger(recorder).send({"id": "c1", "x": 1})))
        self.assertEqual(len(recorder.requests), 3)

    def test_same_id_on_every_retry(self):
        recorder = Recorder([500, READ_TIMEOUT, CONNECT_FAIL, 202])
        logger = make_logger(recorder, attempts=4)
        run(logger.async_log_success_event({"standard_logging_object": slo()}, None, 0, 1))
        self.assertEqual([b["id"] for b in recorder.bodies()], ["chatcmpl-1"] * 4)
        self.assertEqual(logger.pending, 0)

    def test_read_timeout_after_record_is_billed_once(self):
        agent = DedupAgent(timeouts_after_record=1)
        logger = make_logger(agent)
        self.assertTrue(run(logger.send(sealed_usage.build_event(slo()))))
        self.assertEqual(agent.requests, 2)
        self.assertEqual(list(agent.recorded), ["chatcmpl-1"])

    def test_ambiguous_failure_without_id_is_not_retried(self):
        for status in (READ_TIMEOUT, 500):
            recorder = Recorder([status])
            logger = make_logger(recorder)
            self.assertFalse(run(logger.send({"app": "llm-gateway", "quantity": 1})))
            self.assertEqual(len(recorder.requests), 1, status)
            self.assertEqual((logger.pending, logger.dropped), (0, 1))

    def test_unsent_failure_without_id_is_retried(self):
        recorder = Recorder([CONNECT_FAIL, 503, 202])
        self.assertTrue(run(make_logger(recorder).send({"app": "llm-gateway", "quantity": 1})))
        self.assertEqual(len(recorder.requests), 3)

    def test_does_not_retry_client_errors(self):
        recorder = Recorder([400])
        logger = make_logger(recorder)
        self.assertFalse(run(logger.send({"id": "c1", "x": 1})))
        self.assertEqual(len(recorder.requests), 1)
        self.assertEqual((logger.pending, logger.dropped), (0, 1))

    def test_never_raises_when_agent_is_down(self):
        recorder = Recorder([CONNECT_FAIL])
        logger = make_logger(recorder, attempts=2)

        async def go():
            await logger.async_log_success_event({"standard_logging_object": slo()}, None, 0, 1)
            self.assertEqual(len(recorder.requests), 2)
            self.assertEqual(logger.pending, 1)
            logger._drain_task.cancel()

        run(go())

    def test_queue_delivers_after_agent_recovers(self):
        recorder = Recorder([CONNECT_FAIL] * 6 + [READ_TIMEOUT, 202])
        logger = make_logger(recorder, attempts=2)

        async def go():
            await logger.async_log_success_event({"standard_logging_object": slo()}, None, 0, 1)
            self.assertEqual(logger.pending, 1)
            await logger.flush()

        run(go())
        self.assertEqual(logger.pending, 0)
        self.assertEqual(logger.dropped, 0)
        self.assertEqual(len(recorder.requests), 8)
        self.assertEqual({b["id"] for b in recorder.bodies()}, {"chatcmpl-1"})

    def test_queue_is_bounded(self):
        recorder = Recorder([CONNECT_FAIL])
        logger = make_logger(recorder, attempts=1, queue_max=2)

        async def go():
            for n in range(3):
                await logger.send({"id": f"c{n}", "quantity": 1})
            self.assertEqual(logger.pending, 2)
            self.assertEqual(logger.dropped, 1)
            self.assertEqual([e["id"] for e, _ in logger._pending], ["c1", "c2"])
            logger._drain_task.cancel()

        run(go())

    def test_queue_drops_expired_events(self):
        now = [0.0]
        recorder = Recorder([CONNECT_FAIL])
        logger = make_logger(recorder, attempts=1, queue_ttl_s=10, clock=lambda: now[0])

        async def go():
            await logger.send({"id": "old", "quantity": 1})
            now[0] = 11.0
            await logger.flush()

        run(go())
        self.assertEqual((logger.pending, logger.dropped), (0, 1))
        self.assertEqual(len(recorder.requests), 1)

    def test_call_id_from_kwargs_when_payload_has_none(self):
        recorder = Recorder([202])
        payload = slo()
        del payload["id"]
        payload["litellm_call_id"] = None
        run(make_logger(recorder).async_log_success_event(
            {"standard_logging_object": payload, "litellm_call_id": "kw-call"}, None, 0, 1))
        self.assertEqual(recorder.bodies()[0]["id"], "kw-call")

    def test_client_is_created_without_env_proxies(self):
        logger = make_logger(Recorder())

        async def check():
            client = logger._http()
            self.assertFalse(client.trust_env)
            self.assertIs(client, logger._http())
            await logger.aclose()

        run(check())


class _Handler(http.server.BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        _Handler.received.append((self.path, json.loads(self.rfile.read(length))))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


class RealHttpTest(unittest.TestCase):
    """End to end over a real socket, with proxy env vars pointing at a dead proxy."""

    def test_ignores_http_proxy_env(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _Handler.received = []
        try:
            url = f"http://127.0.0.1:{server.server_port}/v1/usage-events"
            dead_proxy = "http://127.0.0.1:9"
            with mock.patch.dict(os.environ, {"HTTP_PROXY": dead_proxy, "http_proxy": dead_proxy,
                                              "ALL_PROXY": dead_proxy, "NO_PROXY": "", "no_proxy": ""}):
                logger = sealed_usage.SealedUsageLogger(url=url, attempts=1, sleep=no_sleep)

                async def go():
                    await logger.async_log_success_event({"standard_logging_object": slo()}, None, 0, 1)
                    await logger.aclose()

                run(go())
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(_Handler.received), 1)
        path, body = _Handler.received[0]
        self.assertEqual(path, "/v1/usage-events")
        self.assertEqual(body["meta"]["key_alias"], "coding-agent")
        self.assertEqual(body["id"], "chatcmpl-1")


class RelayRetryGuardTest(unittest.TestCase):
    """D-067: the pre-call hook keeps paid relay requests from being retried, whatever the client sends."""

    def hook(self, data):
        logger = make_logger(Recorder())
        return run(logger.async_pre_call_hook(None, None, data, "acompletion"))

    def test_overrides_the_proxy_hook(self):
        # LiteLLM's ProxyLogging calls the hook only when the class itself defines it.
        self.assertIn("async_pre_call_hook", vars(sealed_usage.SealedUsageLogger))

    def test_relay_requests_get_no_retries(self):
        for data in (
            {"model": "relay/default", "messages": [{"role": "user", "content": SECRET_PROMPT}]},
            {"model": "relay/tinfoil/glm-5-3", "num_retries": 5, "max_retries": 3},
            {"model": "relay/default", "retry_policy": {"RateLimitErrorRetries": 4},
             "model_group_retry_policy": {"relay/default": {"InternalServerErrorRetries": 4}}},
        ):
            out = self.hook(dict(data))
            self.assertEqual((out["num_retries"], out["max_retries"]), (0, 0), data)
            self.assertNotIn("retry_policy", out)
            self.assertNotIn("model_group_retry_policy", out)
            self.assertEqual(out["model"], data["model"])
            if "messages" in data:
                self.assertEqual(out["messages"], data["messages"])  # content is left alone

    def test_fallbacks_to_the_relay_count_as_relay_requests(self):
        for key in ("fallbacks", "context_window_fallbacks", "content_policy_fallbacks"):
            for spec in (["relay/default"], [{"model": "relay/x"}], [{"local/qwen3-4b": ["relay/x"]}]):
                out = self.hook({"model": "local/qwen3-4b", "num_retries": 3, key: spec})
                self.assertEqual((out["num_retries"], out["max_retries"]), (0, 0), (key, spec))

    def test_other_requests_lose_only_client_retry_settings(self):
        out = self.hook({"model": "local/qwen3-4b", "num_retries": 9, "max_retries": 9, "temperature": 0.2,
                         "fallbacks": ["local/qwen3-4b"]})
        self.assertEqual(out, {"model": "local/qwen3-4b", "temperature": 0.2, "fallbacks": ["local/qwen3-4b"]})
        # The x-litellm-num-retries header ends up as data["num_retries"] before the hook runs.
        self.assertEqual(self.hook({"model": "external/openai/gpt-4o", "num_retries": 4}),
                         {"model": "external/openai/gpt-4o"})

    def test_names_that_only_look_like_relay_are_not_relay(self):
        self.assertFalse(sealed_usage.reaches_relay({"model": "local/relay-default"}))
        self.assertFalse(sealed_usage.reaches_relay({"model": "byok/tinfoil/relay/x"}))
        self.assertTrue(sealed_usage.reaches_relay({"model": "local/x", "fallbacks": [{"relay/a": []}]}))

    def test_never_raises_on_odd_input(self):
        self.assertIsNone(self.hook(None))
        self.assertEqual(self.hook("text"), "text")
        out = self.hook({"model": None, "fallbacks": "relay/x"})
        self.assertEqual(out["num_retries"], 0)
        nested = ["local/x"]
        for _ in range(20):
            nested = [nested]
        self.assertEqual(self.hook({"model": "local/x", "fallbacks": nested})["num_retries"], 0)

    def test_hook_reads_and_sends_nothing(self):
        recorder = Recorder()
        logger = make_logger(recorder)
        run(logger.async_pre_call_hook(None, None, {"model": "relay/default"}, "acompletion"))
        self.assertEqual(recorder.requests, [])
        self.assertEqual(logger.pending, 0)


if __name__ == "__main__":
    unittest.main()
