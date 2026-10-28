"""Tests for bootstrap/seed.py against fake LiteLLM and OpenHands servers over real HTTP."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fakes import FakeGateway, FakeOpenHands  # noqa: E402

SEED_PATH = os.path.join(HERE, "..", "bootstrap", "seed.py")
spec = importlib.util.spec_from_file_location("seed", SEED_PATH)
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)

MASTER = "sk-" + "c3" * 32
SESSION = "session-key-0123456789"


class SeedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.done = os.path.join(self.tmp.name, "workspace", ".sealed", "bootstrap.done")
        self.keyfile = os.path.join(self.tmp.name, "workspace", ".sealed", "llm-gateway-key")

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, gateway, agent=None, **extra):
        env = {
            "SEALED_GATEWAY_URL": gateway.url,
            "SEALED_AGENT_SERVER_URL": agent.url if agent else "http://127.0.0.1:9",
            "SEALED_DONE_FILE": self.done,
            "SEALED_KEY_FILE": self.keyfile,
            "SEALED_POLL_INTERVAL_S": "0.01",
            "SEALED_WAIT_TIMEOUT_S": "5",
            "SEALED_BOOTSTRAP_IDLE": "0",
            "LITELLM_MASTER_KEY": MASTER,
            "OH_SESSION_API_KEYS_0": SESSION,
            # The bootstrap must ignore proxy env: these would break every call.
            "HTTP_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
        }
        env.update(extra)
        return env

    def run_main(self, env):
        err = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), redirect_stderr(err):
            code = seed.main(env)
        return code, err.getvalue()

    def test_openhands_seeds_relay_model_with_fallback(self):
        with FakeGateway(MASTER, not_ready_polls=3) as gw, FakeOpenHands(SESSION, self.tmp.name, not_ready_polls=2) as oh:
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 0, err)
            key = gw.keys["coding-agent"]
            self.assertEqual(key["models"], ["relay/*", "local/*"])
            self.assertEqual(key["key_type"], "llm_api")
            self.assertEqual(key["metadata"], {"sealed_app": "coding-agent"})
            llm = oh.settings["agent_settings"]["llm"]
            self.assertEqual(llm, {
                "model": "litellm_proxy/relay/default",
                "base_url": gw.url,
                "api_key": key["key"],
                "usage_id": "coding-agent",
                "litellm_extra_body": {"fallbacks": ["local/qwen3-4b"]},
            })
            patch = [c for c in oh.calls if c[0] == "PATCH"][0]
            self.assertEqual(patch[3]["x-session-api-key"], SESSION)
        with open(self.done) as handle:
            done = json.load(handle)
        self.assertEqual(done["model"], "litellm_proxy/relay/default")
        self.assertEqual(done["mode"], "openhands")
        self.assertNotIn(key["key"], json.dumps(done))
        for secret in (MASTER, SESSION, key["key"]):
            self.assertNotIn(secret, err)

    def test_falls_back_to_local_model(self):
        with FakeGateway(MASTER, models=("local/qwen3-4b", "local/*")) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 0, err)
            llm = oh.settings["agent_settings"]["llm"]
            self.assertEqual(llm["model"], "litellm_proxy/local/qwen3-4b")
            self.assertNotIn("litellm_extra_body", llm)
            self.assertIn("relay model unavailable", err)

    def test_retries_without_extra_body_on_422(self):
        with FakeGateway(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name, reject_extra_body=True) as oh:
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 0, err)
            self.assertEqual(len(oh.paths("PATCH")), 2)
            self.assertNotIn("litellm_extra_body", oh.settings["agent_settings"]["llm"])

    def test_rerun_rotates_key_and_done_file_skips(self):
        with FakeGateway(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            self.assertEqual(self.run_main(self.env(gw, oh))[0], 0)
            first = gw.keys["coding-agent"]["key"]
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 0)
            self.assertIn("already bootstrapped", err)
            self.assertEqual(gw.keys["coding-agent"]["key"], first)
            os.unlink(self.done)
            self.assertEqual(self.run_main(self.env(gw, oh))[0], 0)
            second = gw.keys["coding-agent"]["key"]
            self.assertNotEqual(first, second)
            self.assertEqual(oh.settings["agent_settings"]["llm"]["api_key"], second)
            self.assertEqual(len(gw.keys), 1)

    def test_key_file_mode(self):
        with FakeGateway(MASTER) as gw:
            env = self.env(gw, SEALED_BOOTSTRAP_MODE="key-file")
            env.pop("OH_SESSION_API_KEYS_0")
            code, err = self.run_main(env)
            self.assertEqual(code, 0, err)
            with open(self.keyfile) as handle:
                self.assertEqual(handle.read(), gw.keys["coding-agent"]["key"])
            self.assertEqual(stat.S_IMODE(os.stat(self.keyfile).st_mode), 0o600)
            self.assertFalse(any(p.startswith("/api/") for p in gw.paths()))

    def test_wrong_master_key(self):
        with FakeGateway("sk-other" + "0" * 40) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 1)
            self.assertIn("rejected the master key", err)
            self.assertFalse(os.path.exists(self.done))

    def test_settings_conflict_is_reported(self):
        with FakeGateway(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name, settings_status=409) as oh:
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 1)
            self.assertIn("different OH_SECRET_KEY", err)

    def test_no_model_available(self):
        with FakeGateway(MASTER, models=("relay/*",)) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 1)
            self.assertIn("neither relay/default nor local/qwen3-4b", err)

    def test_gateway_timeout(self):
        with FakeGateway(MASTER, not_ready_polls=10_000) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, err = self.run_main(self.env(gw, oh, SEALED_WAIT_TIMEOUT_S="0.2"))
            self.assertEqual(code, 1)
            self.assertIn("timed out waiting for llm-gateway", err)

    def test_unreachable_gateway_times_out_cleanly(self):
        env = {"SEALED_GATEWAY_URL": "http://127.0.0.1:9", "SEALED_WAIT_TIMEOUT_S": "0.1",
               "SEALED_POLL_INTERVAL_S": "0.01", "SEALED_DONE_FILE": self.done, "SEALED_BOOTSTRAP_IDLE": "0",
               "LITELLM_MASTER_KEY": MASTER, "OH_SESSION_API_KEYS_0": SESSION}
        code, err = self.run_main(env)
        self.assertEqual(code, 1)
        self.assertIn("timed out", err)

    def test_missing_secrets(self):
        self.assertEqual(self.run_main({"SEALED_BOOTSTRAP_IDLE": "0"})[0], 1)
        code, err = self.run_main({"LITELLM_MASTER_KEY": MASTER, "SEALED_BOOTSTRAP_IDLE": "0"})
        self.assertEqual(code, 1)
        self.assertIn("OH_SESSION_API_KEYS_0", err)
        self.assertEqual(self.run_main({"LITELLM_MASTER_KEY": MASTER, "SEALED_BOOTSTRAP_MODE": "nope"})[0], 1)

    def test_wait_for_uses_injected_clock(self):
        now = [0.0]
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            now[0] += s

        with self.assertRaises(seed.BootstrapError):
            seed.wait_for("x", lambda: False, 10, 3, sleep=sleep, clock=lambda: now[0])
        self.assertEqual(sleeps, [3, 3, 3, 3])

    def test_source_is_embeddable(self):
        with open(SEED_PATH) as handle:
            text = handle.read()
        self.assertNotIn("$", text)
        self.assertNotIn("\t", text)
        self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))


if __name__ == "__main__":
    unittest.main()
