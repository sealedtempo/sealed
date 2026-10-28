"""Unit tests for images/litellm/sealed_entrypoint.py (config renderer and boot checks)."""
from __future__ import annotations

import importlib.util
import io
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.normpath(os.path.join(HERE, "..", "images", "litellm"))

spec = importlib.util.spec_from_file_location("sealed_entrypoint", os.path.join(IMAGE_DIR, "sealed_entrypoint.py"))
ep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ep)

MASTER = "sk-" + "a1" * 32
SALT = "sk-" + "b2" * 32
PG_PASSWORD = "p@ss/w:rd%#?"
TINFOIL = "tinfoil-key-value-123"
OPENAI = "sk-openai-key-value-456"

# Enterprise-only general_settings / litellm_settings keys (docs/notes/litellm.md section 3).
ENTERPRISE_KEYS = {
    "enable_jwt_auth", "allowed_routes", "admin_only_routes", "allowed_ips", "max_request_size_mb",
    "max_response_size_mb", "worker_registry", "enforced_params", "guardrails", "callback_settings",
}
ENTERPRISE_CALLBACKS = {
    "llmguard_moderations", "llamaguard_moderations", "hide_secrets", "openai_moderations",
    "google_text_moderation", "lakera_prompt_injection", "aporia_prompt_injection", "banned_keywords",
    "blocked_user_list", "generic_api", "pagerduty", "resend_email", "sendgrid_email", "smtp_email",
}


class Env:
    """A throwaway secrets dir and render dir, plus the env the container would have."""

    def __init__(self, files=None, env=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.secrets = os.path.join(self.tmp.name, "secrets")
        self.out = os.path.join(self.tmp.name, "out")
        os.makedirs(self.secrets)
        base = {"LITELLM_MASTER_KEY": MASTER, "LITELLM_SALT_KEY": SALT, "POSTGRES_PASSWORD": PG_PASSWORD}
        if files is not None:
            base = files
        for name, value in base.items():
            with open(os.path.join(self.secrets, name), "w") as handle:
                handle.write(value)
        self.env = {
            "SEALED_SECRETS_DIR": self.secrets,
            "SEALED_LITELLM_CONF_DIR": IMAGE_DIR,
            "SEALED_LITELLM_RENDER_DIR": self.out,
            "PATH": "/app/.venv/bin:/usr/bin",
        }
        self.env.update(env or {})

    def add(self, name, value):
        with open(os.path.join(self.secrets, name), "w") as handle:
            handle.write(value)

    def prepare(self, args=("--port", "4000")):
        return ep.prepare(self.env, list(args))

    def rendered(self):
        with open(os.path.join(self.out, "config.yaml")) as handle:
            return handle.read()

    def close(self):
        self.tmp.cleanup()


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.close()

    def names(self, config_text):
        return [m["model_name"] for m in yaml.safe_load(config_text)["model_list"]]

    def test_default_routes_only_local_and_relay(self):
        argv, child, summary = self.e.prepare()
        self.assertEqual(argv, ["litellm", "--config", os.path.join(self.e.out, "config.yaml"), "--port", "4000"])
        self.assertEqual(self.names(self.e.rendered()), ["local/qwen3-4b", "local/*", "relay/default", "relay/*"])
        self.assertFalse(summary["external_opt_in"])
        self.assertTrue(os.path.exists(os.path.join(self.e.out, "sealed_usage.py")))

    def test_rendered_config_contents(self):
        self.e.prepare()
        config = yaml.safe_load(self.e.rendered())
        self.assertEqual(config["litellm_settings"]["callbacks"], ["sealed_usage.usage_logger"])
        self.assertTrue(config["litellm_settings"]["turn_off_message_logging"])
        self.assertIs(config["general_settings"]["store_model_in_db"], False)
        self.assertIs(config["general_settings"]["store_prompts_in_spend_logs"], False)
        self.assertEqual(config["general_settings"]["master_key"], "os.environ/LITELLM_MASTER_KEY")
        relay = [m for m in config["model_list"] if m["model_name"].startswith("relay/")]
        for entry in relay:
            self.assertEqual(entry["litellm_params"]["api_base"], "http://sealed-mpp-payer:8090/v1")
        local = config["model_list"][0]
        self.assertEqual(local["litellm_params"]["model"], "ollama_chat/qwen3:4b-instruct-2507-q4_K_M")
        self.assertEqual(local["litellm_params"]["api_base"], "http://llm-gateway-ollama:11434")
        mode = stat.S_IMODE(os.stat(os.path.join(self.e.out, "config.yaml")).st_mode)
        self.assertEqual(mode, 0o644)

    def test_no_enterprise_settings(self):
        self.e.add("BYOK_ROUTES_ENABLED", "true")
        self.e.add("BYOK_TINFOIL_API_KEY", TINFOIL)
        self.e.add("EXTERNAL_ROUTES_ENABLED", "true")
        self.e.add("EXTERNAL_OPENAI_API_KEY", OPENAI)
        self.e.prepare()
        config = yaml.safe_load(self.e.rendered())
        for section in ("general_settings", "litellm_settings", "router_settings"):
            self.assertFalse(ENTERPRISE_KEYS & set(config.get(section) or {}), section)
        callbacks = set(config["litellm_settings"].get("callbacks", []))
        callbacks |= set(config["litellm_settings"].get("success_callback", []))
        self.assertFalse(ENTERPRISE_CALLBACKS & callbacks)

    def test_byok_needs_opt_in(self):
        self.e.add("BYOK_TINFOIL_API_KEY", TINFOIL)
        _, child, summary = self.e.prepare()
        self.assertNotIn("byok/tinfoil/*", self.names(self.e.rendered()))
        self.assertNotIn("BYOK_TINFOIL_API_KEY", child)
        self.assertFalse(summary["byok_opt_in"])
        self.e.add("BYOK_ROUTES_ENABLED", "1")
        self.e.prepare()
        self.assertNotIn("byok/tinfoil/*", self.names(self.e.rendered()))

    def test_byok_enabled_only_with_key(self):
        self.e.add("BYOK_ROUTES_ENABLED", "true")
        self.e.add("BYOK_TINFOIL_API_KEY", TINFOIL + "\n")
        argv, child, summary = self.e.prepare()
        self.assertTrue(summary["byok_opt_in"])
        self.assertNotIn("BYOK_ROUTES_ENABLED", child)
        text = self.e.rendered()
        self.assertIn("byok/tinfoil/*", self.names(text))
        self.assertNotIn("byok/redpill/*", self.names(text))
        entry = [m for m in yaml.safe_load(text)["model_list"] if m["model_name"] == "byok/tinfoil/*"][0]
        self.assertEqual(entry["litellm_params"], {
            "model": "openai/*",
            "api_base": "https://inference.tinfoil.sh/v1",
            "api_key": "os.environ/BYOK_TINFOIL_API_KEY",
        })
        self.assertEqual(entry["model_info"]["sealed_route"], "byok")
        self.assertIn("data leaves your cloud", entry["model_info"]["sealed_data_location"])
        self.assertIn("not verified", entry["model_info"]["sealed_data_location"])
        self.assertEqual(child["BYOK_TINFOIL_API_KEY"], TINFOIL)
        self.assertNotIn(TINFOIL, text)

    def test_external_needs_opt_in(self):
        self.e.add("EXTERNAL_OPENAI_API_KEY", OPENAI)
        _, child, summary = self.e.prepare()
        self.assertNotIn("external/openai/*", self.names(self.e.rendered()))
        self.assertNotIn("EXTERNAL_OPENAI_API_KEY", child)
        self.assertFalse(summary["external_opt_in"])

    def test_external_opt_in_must_be_true(self):
        self.e.add("EXTERNAL_OPENAI_API_KEY", OPENAI)
        self.e.add("EXTERNAL_ROUTES_ENABLED", "yes")
        self.e.prepare()
        self.assertNotIn("external/openai/*", self.names(self.e.rendered()))

    def test_external_enabled_and_labeled(self):
        self.e.add("EXTERNAL_OPENAI_API_KEY", OPENAI)
        self.e.add("EXTERNAL_ROUTES_ENABLED", "TRUE\n")
        _, child, summary = self.e.prepare()
        text = self.e.rendered()
        entry = [m for m in yaml.safe_load(text)["model_list"] if m["model_name"] == "external/openai/*"][0]
        self.assertEqual(entry["model_info"]["sealed_data_location"], "data leaves your cloud")
        self.assertEqual(entry["model_info"]["sealed_route"], "external")
        self.assertEqual(child["EXTERNAL_OPENAI_API_KEY"], OPENAI)
        self.assertNotIn("EXTERNAL_ROUTES_ENABLED", child)
        self.assertTrue(summary["external_opt_in"])
        self.assertNotIn(OPENAI, text)

    def test_secrets_from_env_win_over_files(self):
        self.e.env["BYOK_ROUTES_ENABLED"] = "true"
        self.e.env["BYOK_NEARAI_API_KEY"] = "near-from-env"
        _, child, _ = self.e.prepare()
        self.assertIn("byok/nearai/*", self.names(self.e.rendered()))
        self.assertEqual(child["BYOK_NEARAI_API_KEY"], "near-from-env")

    def test_empty_secret_counts_as_missing(self):
        self.e.add("BYOK_ROUTES_ENABLED", "true")
        self.e.add("BYOK_TINFOIL_API_KEY", "  \n")
        self.e.prepare()
        self.assertNotIn("byok/tinfoil/*", self.names(self.e.rendered()))

    def test_child_env(self):
        self.e.env.update({
            "OPENAI_API_KEY": "sk-should-not-pass", "LITELLM_LICENSE": "x", "POSTGRES_PASSWORD": PG_PASSWORD,
            "DISABLE_AIOHTTP_TRUST_ENV": "True", "LITELLM_LOG": "debug", "HTTPS_PROXY": "http://172.30.0.2:3128",
            "BYOK_REDPILL_API_KEY": "",
        })
        _, child, _ = self.e.prepare()
        for name in ("OPENAI_API_KEY", "LITELLM_LICENSE", "POSTGRES_PASSWORD", "DISABLE_AIOHTTP_TRUST_ENV",
                     "BYOK_REDPILL_API_KEY"):
            self.assertNotIn(name, child)
        self.assertEqual(child["LITELLM_LOG"], "ERROR")
        self.assertEqual(child["HTTPS_PROXY"], "http://172.30.0.2:3128")
        self.assertEqual(child["LITELLM_MASTER_KEY"], MASTER)
        self.assertEqual(child["LITELLM_SALT_KEY"], SALT)
        self.assertEqual(child["DATABASE_URL"],
                         "postgresql://litellm:p%40ss%2Fw%3Ard%25%23%3F@llm-gateway-db:5432/litellm")

    def test_rendered_config_never_contains_secrets(self):
        self.e.add("BYOK_ROUTES_ENABLED", "true")
        self.e.add("BYOK_TINFOIL_API_KEY", TINFOIL)
        self.e.prepare()
        text = self.e.rendered()
        for value in (MASTER, SALT, PG_PASSWORD, TINFOIL):
            self.assertNotIn(value, text)

    def test_config_flag_is_rejected(self):
        with self.assertRaises(ep.ConfigError):
            self.e.prepare(["--config", "/tmp/other.yaml"])

    def test_relay_falls_back_to_local_in_the_gateway(self):
        self.e.prepare()
        config = yaml.safe_load(self.e.rendered())
        self.assertEqual(config["router_settings"]["fallbacks"], [{"relay/default": ["local/qwen3-4b"]}])
        names = set(self.names(self.e.rendered()))
        for item in config["router_settings"]["fallbacks"]:
            for source, targets in item.items():
                self.assertIn(source, names)
                self.assertTrue(all(t in names and t.startswith("local/") for t in targets))

    def test_fallback_rules_are_enforced(self):
        base = ep.load_yaml(os.path.join(IMAGE_DIR, "config.yaml"))
        for bad in ([{"relay/default": ["external/openai/gpt-4o"]}], [{"relay/default": ["local/missing"]}],
                    [{"relay/nope": ["local/qwen3-4b"]}], ["local/qwen3-4b"],
                    [{"relay/default": ["local/qwen3-4b"], "relay/*": ["local/qwen3-4b"]}]):
            config = dict(base, router_settings={"fallbacks": bad})
            with self.assertRaises(ep.ConfigError, msg=bad):
                ep.render(config, [])


class BootChecksTest(unittest.TestCase):
    def run_main(self, files, argv=("--port", "4000")):
        e = Env(files=files)
        calls = []
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                code = ep.main(list(argv), env=e.env, execvpe=lambda f, a, env: calls.append((f, a, env)))
        finally:
            e.close()
        return code, calls, err.getvalue()

    def test_missing_master_key(self):
        code, calls, err = self.run_main({"LITELLM_SALT_KEY": SALT, "POSTGRES_PASSWORD": "x"})
        self.assertEqual((code, calls), (2, []))
        self.assertIn("LITELLM_MASTER_KEY is missing", err)

    def test_weak_master_keys(self):
        for weak in ("sk-1234", "abc" * 20, "sk-short", "sk-" + "a" * 20 + " " + "b" * 20):
            code, calls, err = self.run_main({"LITELLM_MASTER_KEY": weak, "LITELLM_SALT_KEY": SALT,
                                              "POSTGRES_PASSWORD": "x"})
            self.assertEqual((code, calls), (2, []), weak)
            self.assertNotIn(weak, err)

    def test_missing_salt_and_db_password(self):
        self.assertEqual(self.run_main({"LITELLM_MASTER_KEY": MASTER, "POSTGRES_PASSWORD": "x"})[0], 2)
        self.assertEqual(self.run_main({"LITELLM_MASTER_KEY": MASTER, "LITELLM_SALT_KEY": SALT})[0], 2)

    def test_execs_litellm(self):
        files = {"LITELLM_MASTER_KEY": MASTER, "LITELLM_SALT_KEY": SALT, "POSTGRES_PASSWORD": "pw"}
        code, calls, err = self.run_main(files, ["--port", "4000", "--num_workers", "2"])
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        file, args, env = calls[0]
        self.assertEqual(file, "litellm")
        self.assertEqual(args[:2], ["litellm", "--config"])
        self.assertEqual(args[3:], ["--port", "4000", "--num_workers", "2"])
        self.assertIn("routes=local/qwen3-4b,local/*,relay/default,relay/*", err)
        self.assertIn("byok_opt_in=false external_opt_in=false", err)
        for value in (MASTER, SALT, "pw@"):
            self.assertNotIn(value, err)

    def test_render_only_does_not_exec(self):
        files = {"LITELLM_MASTER_KEY": MASTER, "LITELLM_SALT_KEY": SALT, "POSTGRES_PASSWORD": "pw"}
        code, calls, _ = self.run_main(files, ["--render-only", "--port", "4000"])
        self.assertEqual((code, calls), (0, []))


class ProvidersCatalogTest(unittest.TestCase):
    def test_provider_entries_are_https_and_unique(self):
        providers = ep.load_yaml(os.path.join(IMAGE_DIR, "providers.yaml"))
        seen = set()
        for family in ("byok", "external"):
            for p in providers[family]:
                self.assertTrue(p["api_base"].startswith("https://"), p["id"])
                self.assertTrue(p["secret"].startswith(family.upper() + "_"), p["id"])
                host = p["api_base"].split("/")[2]
                self.assertEqual(p["egress"], f"{host}:443")
                self.assertNotIn((family, p["id"]), seen)
                seen.add((family, p["id"]))

    def test_bad_provider_entry(self):
        with self.assertRaises(ep.ConfigError):
            ep.select_providers({"byok": [{"id": "x", "name": "X", "secret": "BYOK_X"}]}, ep.Secrets({}, "/nonexistent"))


if __name__ == "__main__":
    unittest.main()
