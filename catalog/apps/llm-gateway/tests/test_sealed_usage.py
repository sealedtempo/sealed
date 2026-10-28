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


class Recorder:
    def __init__(self, statuses=None):
        self.requests: list[httpx.Request] = []
        self.statuses = list(statuses or [204])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if status == -1:
            raise httpx.ConnectError("agent down", request=request)
        return httpx.Response(status)


async def no_sleep(_seconds):
    return None


def make_logger(recorder: Recorder, attempts: int = 3):
    return sealed_usage.SealedUsageLogger(
        url="http://sealed-agent:7070/v1/usage-events",
        timeout_s=1.0,
        attempts=attempts,
        transport=httpx.MockTransport(recorder.handler),
        sleep=no_sleep,
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
        recorder = Recorder([503, -1, 204])
        self.assertTrue(run(make_logger(recorder).send({"x": 1})))
        self.assertEqual(len(recorder.requests), 3)

    def test_does_not_retry_client_errors(self):
        recorder = Recorder([400])
        self.assertFalse(run(make_logger(recorder).send({"x": 1})))
        self.assertEqual(len(recorder.requests), 1)

    def test_never_raises_when_agent_is_down(self):
        recorder = Recorder([-1])
        logger = make_logger(recorder, attempts=2)
        run(logger.async_log_success_event({"standard_logging_object": slo()}, None, 0, 1))
        self.assertEqual(len(recorder.requests), 2)

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


if __name__ == "__main__":
    unittest.main()
