"""Tests for images/litellm/sealed_keys.py (gateway-side app key provisioning) over real HTTP."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
IMAGE_DIR = os.path.normpath(os.path.join(HERE, "..", "images", "litellm"))
APP_DIR = os.path.normpath(os.path.join(HERE, ".."))

from fake_litellm import FakeLiteLLM, hash_token  # noqa: E402

spec = importlib.util.spec_from_file_location("sealed_keys", os.path.join(IMAGE_DIR, "sealed_keys.py"))
keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(keys)

MASTER = "sk-" + "a1" * 32
APP_KEY = "sk-" + "c3" * 32
SPECS = os.path.join(IMAGE_DIR, "app_keys.yaml")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class KeysJobTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.status = os.path.join(self.tmp.name, "status", "status.json")
        self.secret_dir = os.path.join(self.tmp.name, "secrets")
        os.makedirs(self.secret_dir)

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, gw, **secrets):
        env = {
            "SEALED_GATEWAY_URL": gw.url, "SEALED_SECRETS_DIR": self.secret_dir,
            "SEALED_KEYS_STATUS_FILE": self.status, "SEALED_APP_KEYS_FILE": SPECS,
            "SEALED_KEYS_POLL_S": "0.01", "SEALED_KEYS_WAIT_TIMEOUT_S": "5",
            "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
            "LITELLM_MASTER_KEY": MASTER,
        }
        env.update(secrets)
        return env

    def run_once(self, env):
        err = io.StringIO()
        with redirect_stderr(err):
            code = keys.main(["--once"], env=env)
        return code, err.getvalue()

    def status_file(self):
        with open(self.status) as handle:
            return json.load(handle)

    def test_creates_the_app_key_with_its_exact_value_and_scope(self):
        with FakeLiteLLM(MASTER, not_ready_polls=2) as gw:
            code, err = self.run_once(self.env(gw, APP_KEY_CODING_AGENT=APP_KEY))
            self.assertEqual(code, 0, err)
            record = gw.keys[hash_token(APP_KEY)]
            self.assertEqual(record["key_alias"], "coding-agent")
            self.assertEqual(record["models"], ["relay/*", "local/*"])
            self.assertEqual(record["key_type"], "llm_api")
            self.assertEqual((record["rpm_limit"], record["tpm_limit"], record["max_parallel_requests"]),
                             (300, 2000000, 8))
            self.assertEqual(record["metadata"], {"sealed_app": "coding-agent", "sealed_managed": True})
            self.assertEqual(self.status_file()["apps"], {"coding-agent": "created"})
            self.assertTrue(self.status_file()["ok"])
            for _, path, _, _ in gw.calls:
                self.assertNotIn(APP_KEY, path)  # looked up by hash, never in a URL
            self.assertIn("/key/info?key=" + hash_token(APP_KEY), gw.paths("GET"))
            for value in (MASTER, APP_KEY):
                self.assertNotIn(value, err)

    def test_second_run_is_a_no_op(self):
        with FakeLiteLLM(MASTER) as gw:
            env = self.env(gw, APP_KEY_CODING_AGENT=APP_KEY)
            self.run_once(env)
            before = len(gw.paths("POST"))
            self.assertEqual(self.run_once(env)[0], 0)
            self.assertEqual(len(gw.paths("POST")), before)
            self.assertEqual(self.status_file()["apps"], {"coding-agent": "ok"})

    def test_restores_scope_after_drift(self):
        with FakeLiteLLM(MASTER) as gw:
            env = self.env(gw, APP_KEY_CODING_AGENT=APP_KEY)
            self.run_once(env)
            gw.keys[hash_token(APP_KEY)].update({"models": ["external/*", "relay/*"], "rpm_limit": None})
            self.assertEqual(self.run_once(env)[0], 0)
            record = gw.keys[hash_token(APP_KEY)]
            self.assertEqual(record["models"], ["relay/*", "local/*"])
            self.assertEqual(record["rpm_limit"], 300)
            self.assertEqual(self.status_file()["apps"], {"coding-agent": "updated"})

    def test_heals_after_database_reset_and_admin_delete(self):
        with FakeLiteLLM(MASTER) as gw:
            env = self.env(gw, APP_KEY_CODING_AGENT=APP_KEY)
            self.run_once(env)
            gw.reset_database()
            self.run_once(env)
            self.assertIn(hash_token(APP_KEY), gw.keys)
            gw.deleted[hash_token(APP_KEY)] = gw.keys.pop(hash_token(APP_KEY))
            self.run_once(env)
            self.assertIn(hash_token(APP_KEY), gw.keys)
            self.assertEqual(self.status_file()["apps"], {"coding-agent": "created"})

    def test_replaces_an_older_key_holding_the_alias(self):
        with FakeLiteLLM(MASTER) as gw:
            gw.add_key("sk-old-bootstrap-minted-0001", key_alias="coding-agent", models=["relay/*"])
            self.assertEqual(self.run_once(self.env(gw, APP_KEY_CODING_AGENT=APP_KEY))[0], 0)
            self.assertEqual([k["token"] for k in gw.keys.values()], [hash_token(APP_KEY)])
            self.assertIn(hash_token("sk-old-bootstrap-minted-0001"), gw.deleted)

    def test_blocked_key_is_left_alone(self):
        with FakeLiteLLM(MASTER) as gw:
            env = self.env(gw, APP_KEY_CODING_AGENT=APP_KEY)
            self.run_once(env)
            gw.keys[hash_token(APP_KEY)]["blocked"] = True
            before = len(gw.paths("POST"))
            self.assertEqual(self.run_once(env)[0], 0)
            self.assertEqual(len(gw.paths("POST")), before)
            self.assertTrue(gw.keys[hash_token(APP_KEY)]["blocked"])
            self.assertEqual(self.status_file()["apps"], {"coding-agent": "left-revoked"})

    def test_unset_secret_removes_the_alias(self):
        with FakeLiteLLM(MASTER) as gw:
            self.run_once(self.env(gw, APP_KEY_CODING_AGENT=APP_KEY))
            self.assertEqual(self.run_once(self.env(gw))[0], 0)
            self.assertEqual(gw.keys, {})
            self.assertEqual(self.status_file()["apps"], {"coding-agent": "unset"})

    def test_secret_from_file(self):
        with open(os.path.join(self.secret_dir, "APP_KEY_CODING_AGENT"), "w") as handle:
            handle.write(APP_KEY + "\n")
        with FakeLiteLLM(MASTER) as gw:
            self.assertEqual(self.run_once(self.env(gw))[0], 0)
            self.assertIn(hash_token(APP_KEY), gw.keys)

    def test_unusable_values_are_refused(self):
        for bad in ("hex-without-prefix-" + "0" * 40, "sk-short", MASTER):
            with FakeLiteLLM(MASTER) as gw:
                code, err = self.run_once(self.env(gw, APP_KEY_CODING_AGENT=bad))
                self.assertEqual(code, 1, bad)
                self.assertEqual(gw.paths("POST"), [])
                self.assertIn("APP_KEY_CODING_AGENT", err)
                self.assertNotIn(bad, err)
                self.assertFalse(self.status_file()["ok"])

    def test_wrong_master_key(self):
        with FakeLiteLLM("sk-" + "f0" * 32) as gw:
            code, err = self.run_once(self.env(gw, APP_KEY_CODING_AGENT=APP_KEY))
            self.assertEqual(code, 1)
            self.assertIn("rejected the master key", err)

    def test_gateway_timeout_and_missing_master(self):
        with FakeLiteLLM(MASTER, not_ready_polls=10_000) as gw:
            env = self.env(gw, APP_KEY_CODING_AGENT=APP_KEY, SEALED_KEYS_WAIT_TIMEOUT_S="0.1")
            code, err = self.run_once(env)
            self.assertEqual(code, 1)
            self.assertIn("timed out", err)
            env.pop("LITELLM_MASTER_KEY")
            code, err = self.run_once(env)
            self.assertEqual(code, 1)
            self.assertIn("LITELLM_MASTER_KEY is missing", err)

    def test_loop_retries_sooner_after_errors(self):
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) >= 2:
                raise KeyboardInterrupt

        with FakeLiteLLM("sk-" + "f0" * 32) as gw:
            env = self.env(gw, APP_KEY_CODING_AGENT=APP_KEY, SEALED_KEYS_INTERVAL_S="300", SEALED_KEYS_RETRY_S="30")
            with redirect_stderr(io.StringIO()), self.assertRaises(KeyboardInterrupt):
                keys.main([], env=env, sleep=sleep)
        self.assertEqual(sleeps, [30.0, 30.0])

    def test_status_file_feeds_the_fragment_healthcheck(self):
        fragment = load(os.path.join(APP_DIR, "compose.fragment.yaml"))
        svc = fragment["services"]["llm-gateway-keys"]
        probe = svc["healthcheck"]["test"]
        self.assertIn(svc["environment"]["SEALED_KEYS_STATUS_FILE"], probe[-1])
        with FakeLiteLLM(MASTER) as gw:
            self.run_once(self.env(gw, APP_KEY_CODING_AGENT=APP_KEY))
        script = probe[-1].replace(svc["environment"]["SEALED_KEYS_STATUS_FILE"], self.status)
        self.assertEqual(subprocess.run([sys.executable, "-I", "-c", script]).returncode, 0)
        keys.write_status(self.status, {"coding-agent": "error: x"}, 0)
        self.assertEqual(subprocess.run([sys.executable, "-I", "-c", script]).returncode, 1)


class SpecsTest(unittest.TestCase):
    def write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.safe_dump(data, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def entry(self, **over):
        base = {"app": "coding-agent", "secret": "APP_KEY_CODING_AGENT", "key_alias": "coding-agent",
                "models": ["relay/*", "local/*"], "rpm_limit": 10}
        base.update(over)
        return base

    def test_shipped_file(self):
        specs = keys.load_specs(SPECS)
        self.assertEqual([(s.app, s.secret, s.alias) for s in specs],
                         [("coding-agent", "APP_KEY_CODING_AGENT", "coding-agent")])
        manifest = load(os.path.join(APP_DIR, "manifest.yaml"))
        secrets = {s["name"]: s for s in manifest["secrets"]}
        for s in specs:
            self.assertEqual(secrets[s.secret]["generate"], "sk-hex32")
            self.assertTrue(secrets[s.secret]["optional"])
        self.assertEqual(keys.main(["--check-config"], env={"SEALED_APP_KEYS_FILE": SPECS}), 0)

    def test_rejects_routes_that_leave_the_vm(self):
        for models in (["byok/tinfoil/*"], ["relay/*", "external/openai/*"], ["*"], [], [""]):
            with self.assertRaises(keys.KeysError, msg=models):
                keys.load_specs(self.write({"apps": [self.entry(models=models)]}))

    def test_rejects_bad_entries(self):
        bad = [self.entry(key_alias="Bad Alias"), self.entry(secret="LITELLM_MASTER_KEY"),
               self.entry(rpm_limit=0), self.entry(tpm_limit="many"), self.entry(max_parallel_requests=True)]
        for entry in bad:
            with self.assertRaises(keys.KeysError, msg=entry):
                keys.load_specs(self.write({"apps": [entry]}))
        with self.assertRaises(keys.KeysError):
            keys.load_specs(self.write({"apps": [self.entry(), self.entry(secret="APP_KEY_OTHER")]}))
        with self.assertRaises(keys.KeysError):
            keys.load_specs(self.write({"nope": []}))
        with redirect_stderr(io.StringIO()):
            self.assertEqual(keys.main(["--check-config"], env={"SEALED_APP_KEYS_FILE": "/nonexistent"}), 2)

    def test_drift(self):
        desired = {"key_alias": "a", "models": ["relay/*", "local/*"], "rpm_limit": 5}
        self.assertEqual(keys.drift({"key_alias": "a", "models": ["local/*", "relay/*"], "rpm_limit": 5}, desired), {})
        self.assertEqual(keys.drift({"key_alias": "a", "models": ["relay/*"], "rpm_limit": 6}, desired),
                         {"models": ["relay/*", "local/*"], "rpm_limit": 5})


if __name__ == "__main__":
    unittest.main()
