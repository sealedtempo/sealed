"""Tests for bootstrap/seed.py against fake LiteLLM and OpenHands servers over real HTTP.

The gateway side is the shared LiteLLM fake; the end-to-end test provisions the key with
llm-gateway's real keys job (images/litellm/sealed_keys.py) first, the way the stack does.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fakes import FakeLiteLLM, FakeOpenHands  # noqa: E402

GATEWAY_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "llm-gateway"))
SEED_PATH = os.path.join(HERE, "..", "bootstrap", "seed.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed = load("seed", SEED_PATH)
sealed_keys = load("sealed_keys", os.path.join(GATEWAY_DIR, "images", "litellm", "sealed_keys.py"))

MASTER = "sk-" + "c3" * 32
APP_KEY = "sk-" + "d4" * 32
SESSION = "session-key-0123456789"


class SeedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.done = os.path.join(self.tmp.name, "run", "bootstrap", "done")

    def tearDown(self):
        self.tmp.cleanup()

    def provision(self, gw, value=APP_KEY):
        gw.add_key(value, key_alias="coding-agent", models=["relay/*", "local/*"], key_type="llm_api")

    def env(self, gateway, agent=None, **extra):
        env = {
            "SEALED_GATEWAY_URL": gateway.url,
            "SEALED_AGENT_SERVER_URL": agent.url if agent else "http://127.0.0.1:9",
            "SEALED_DONE_FILE": self.done,
            "SEALED_POLL_INTERVAL_S": "0.01",
            "SEALED_WAIT_TIMEOUT_S": "5",
            "SEALED_BOOTSTRAP_IDLE": "0",
            "LLM_GATEWAY_KEY": APP_KEY,
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

    def test_seeds_relay_default_with_the_app_key(self):
        with FakeLiteLLM(MASTER, not_ready_polls=3) as gw, FakeOpenHands(SESSION, self.tmp.name, not_ready_polls=2) as oh:
            self.provision(gw)
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 0, err)
            llm = oh.settings["agent_settings"]["llm"]
            self.assertEqual(llm, {"model": "litellm_proxy/relay/default", "base_url": gw.url,
                                   "api_key": APP_KEY, "usage_id": "coding-agent"})
            patch = [c for c in oh.calls if c[0] == "PATCH"][0]
            self.assertEqual(patch[3]["x-session-api-key"], SESSION)
            models_call = [c for c in gw.calls if c[1] == "/v1/models"][-1]
            self.assertEqual(models_call[3]["authorization"], "Bearer " + APP_KEY)
            # The bootstrap never calls an admin endpoint: it has no master key to call them with.
            self.assertFalse([p for p in gw.paths() if p.startswith(("/key/", "/spend/"))])
        with open(self.done) as handle:
            done = json.load(handle)
        self.assertEqual(done["model"], "litellm_proxy/relay/default")
        self.assertNotIn(APP_KEY, json.dumps(done))
        for secret in (APP_KEY, SESSION):
            self.assertNotIn(secret, err)

    def test_waits_for_the_gateway_to_provision_the_key(self):
        with FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            timer = threading.Timer(0.3, self.provision, args=(gw,))
            timer.start()
            try:
                code, err = self.run_main(self.env(gw, oh))
            finally:
                timer.cancel()
            self.assertEqual(code, 0, err)
            self.assertGreater(len([p for p in gw.paths() if p == "/v1/models"]), 1)
            self.assertEqual(oh.settings["agent_settings"]["llm"]["api_key"], APP_KEY)

    def test_key_never_provisioned_is_reported(self):
        with FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, err = self.run_main(self.env(gw, oh, SEALED_WAIT_TIMEOUT_S="0.2"))
            self.assertEqual(code, 1)
            self.assertIn("rejects LLM_GATEWAY_KEY (HTTP 401)", err)
            self.assertIn("APP_KEY_CODING_AGENT", err)
            self.assertNotIn(APP_KEY, err)
            self.assertFalse(os.path.exists(self.done))
            self.assertEqual(oh.paths("PATCH"), [])

    def test_keeps_a_gateway_model_the_customer_chose(self):
        with FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            self.provision(gw)
            oh.settings["agent_settings"]["llm"] = {"model": "litellm_proxy/local/qwen3-4b", "base_url": gw.url,
                                                    "api_key": "sk-stale-key-value-0000"}
            self.assertEqual(self.run_main(self.env(gw, oh))[0], 0)
            llm = oh.settings["agent_settings"]["llm"]
            self.assertEqual(llm["model"], "litellm_proxy/local/qwen3-4b")
            self.assertEqual(llm["api_key"], APP_KEY)  # a rotated key is always re-seeded

    def test_replaces_models_of_other_providers(self):
        for stored in ({"model": "gpt-4o", "base_url": "https://api.openai.com/v1"},
                       {"model": "litellm_proxy/relay/default", "base_url": "http://elsewhere:4000"},
                       {"model": "litellm_proxy/", "base_url": "SAME"}):
            with FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
                self.provision(gw)
                stored = dict(stored, base_url=gw.url if stored["base_url"] == "SAME" else stored["base_url"])
                oh.settings["agent_settings"]["llm"] = dict(stored)
                self.assertEqual(self.run_main(self.env(gw, oh))[0], 0)
                self.assertEqual(oh.settings["agent_settings"]["llm"]["model"], "litellm_proxy/relay/default")
                self.assertEqual(oh.settings["agent_settings"]["llm"]["base_url"], gw.url)

    def test_reruns_on_every_start_and_ignores_stale_done_file(self):
        os.makedirs(os.path.dirname(self.done))
        with open(self.done, "w") as handle:
            handle.write("{}\n")
        with FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            self.provision(gw)
            self.assertEqual(self.run_main(self.env(gw, oh))[0], 0)
            self.assertEqual(self.run_main(self.env(gw, oh))[0], 0)
            self.assertEqual(len(oh.paths("PATCH")), 2)

    def test_failed_run_removes_the_done_file(self):
        os.makedirs(os.path.dirname(self.done))
        with open(self.done, "w") as handle:
            handle.write("{}\n")
        with FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, self.tmp.name, settings_status=409) as oh:
            self.provision(gw)
            code, err = self.run_main(self.env(gw, oh))
            self.assertEqual(code, 1)
            self.assertIn("different OH_SECRET_KEY", err)
        self.assertFalse(os.path.exists(self.done))

    def test_gateway_timeout(self):
        with FakeLiteLLM(MASTER, not_ready_polls=10_000) as gw, FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, err = self.run_main(self.env(gw, oh, SEALED_WAIT_TIMEOUT_S="0.2"))
            self.assertEqual(code, 1)
            self.assertIn("timed out waiting for llm-gateway", err)

    def test_unreachable_gateway_times_out_cleanly(self):
        env = {"SEALED_GATEWAY_URL": "http://127.0.0.1:9", "SEALED_WAIT_TIMEOUT_S": "0.1",
               "SEALED_POLL_INTERVAL_S": "0.01", "SEALED_DONE_FILE": self.done, "SEALED_BOOTSTRAP_IDLE": "0",
               "LLM_GATEWAY_KEY": APP_KEY, "OH_SESSION_API_KEYS_0": SESSION}
        code, err = self.run_main(env)
        self.assertEqual(code, 1)
        self.assertIn("timed out", err)

    def test_missing_secrets(self):
        code, err = self.run_main({"SEALED_BOOTSTRAP_IDLE": "0"})
        self.assertEqual(code, 1)
        self.assertIn("LLM_GATEWAY_KEY", err)
        code, err = self.run_main({"LLM_GATEWAY_KEY": APP_KEY, "SEALED_BOOTSTRAP_IDLE": "0"})
        self.assertEqual(code, 1)
        self.assertIn("OH_SESSION_API_KEYS_0", err)
        with open(SEED_PATH) as handle:
            self.assertNotIn("LITELLM_MASTER_KEY", handle.read())

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


class GatewayProvisioningEndToEndTest(unittest.TestCase):
    """llm-gateway's keys job creates the key; coding-agent's bootstrap uses it; the master key stays put."""

    def test_keys_job_then_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp, FakeLiteLLM(MASTER) as gw, FakeOpenHands(SESSION, tmp) as oh:
            gateway_env = {
                "SEALED_GATEWAY_URL": gw.url, "SEALED_SECRETS_DIR": os.path.join(tmp, "none"),
                "SEALED_KEYS_STATUS_FILE": os.path.join(tmp, "status.json"),
                "SEALED_APP_KEYS_FILE": os.path.join(GATEWAY_DIR, "images", "litellm", "app_keys.yaml"),
                "LITELLM_MASTER_KEY": MASTER, "APP_KEY_CODING_AGENT": APP_KEY, "SEALED_KEYS_POLL_S": "0.01",
            }
            agent_env = {
                "SEALED_GATEWAY_URL": gw.url, "SEALED_AGENT_SERVER_URL": oh.url,
                "SEALED_DONE_FILE": os.path.join(tmp, "done"), "SEALED_POLL_INTERVAL_S": "0.02",
                "SEALED_WAIT_TIMEOUT_S": "10", "SEALED_BOOTSTRAP_IDLE": "0",
                "LLM_GATEWAY_KEY": APP_KEY, "OH_SESSION_API_KEYS_0": SESSION,
            }
            err = io.StringIO()
            results: list[int] = []
            with redirect_stderr(err):
                agent = threading.Thread(target=lambda: results.append(seed.main(agent_env)))
                agent.start()
                time.sleep(0.2)  # the agent's bootstrap starts first and waits for its key
                self.assertEqual(sealed_keys.main(["--once"], env=gateway_env), 0)
                agent.join(15)
            self.assertEqual(results, [0], err.getvalue())
            self.assertEqual(oh.settings["agent_settings"]["llm"]["api_key"], APP_KEY)
            key = gw.by_alias("coding-agent")
            self.assertEqual((key["models"], key["key_type"]), (["relay/*", "local/*"], "llm_api"))
            admin_calls = [c for c in gw.calls if c[3].get("authorization") == "Bearer " + MASTER]
            self.assertTrue(admin_calls)
            agent_calls = [c for c in gw.calls if c[3].get("authorization") == "Bearer " + APP_KEY]
            self.assertEqual({c[1].split("?")[0] for c in agent_calls}, {"/v1/models"})
            self.assertNotIn(MASTER, err.getvalue())
            self.assertNotIn(APP_KEY, err.getvalue())


if __name__ == "__main__":
    unittest.main()
