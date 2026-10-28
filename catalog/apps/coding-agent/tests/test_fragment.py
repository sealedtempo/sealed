"""Packaging tests for coding-agent and its OpenCode fallback: fragments, manifests, egress, images."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.normpath(os.path.join(HERE, ".."))
FALLBACK_DIR = os.path.join(APP_DIR, "fallback-opencode")
GATEWAY_DIR = os.path.normpath(os.path.join(APP_DIR, "..", "llm-gateway"))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(GATEWAY_DIR, "tests"))

import catalog_lint  # noqa: E402
import dockerfile_lint  # noqa: E402
from fakes import FakeGateway, FakeOpenHands  # noqa: E402

AGENT_SERVER_DIGEST = "sha256:9e04bf35e5f44f987f2bd7bb82b8f967104def33183da85bd6e95c9eb34ddfb3"
OPENCODE_BASE = ("ghcr.io/anomalyco/opencode:1.19.5"
                 "@sha256:f4cfe16d91efbbfca01a51c44094fba4cf82e15c7fa17de5f11f9059699b1e6e")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def load_tool():
    spec = importlib.util.spec_from_file_location("build_fragment", os.path.join(APP_DIR, "tools", "build_fragment.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gateway_model_names():
    config = yaml.safe_load(read(os.path.join(GATEWAY_DIR, "images", "litellm", "config.yaml")))
    return {m["model_name"] for m in config["model_list"]}


class OpenHandsPackagingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = catalog_lint.load_app(APP_DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.server = cls.services["coding-agent-server"]
        cls.boot = cls.services["coding-agent-bootstrap"]

    def test_fragments_up_to_date(self):
        self.assertEqual(load_tool().main(["--check"]), 0)

    def test_scripts_embedded_verbatim(self):
        self.assertEqual(self.server["entrypoint"][:3], ["python3", "-I", "-c"])
        self.assertEqual(self.server["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "dropuid.py")))
        self.assertEqual(self.boot["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "seed.py")))

    def test_lint_clean(self):
        self.assertEqual(catalog_lint.lint_app(APP_DIR), [])

    def test_manifest_schema(self):
        errors = catalog_lint.schema_errors(self.manifest)
        if errors is None:
            self.skipTest("jsonschema not installed")
        self.assertEqual(errors, [])

    def test_compose_config(self):
        result = catalog_lint.compose_config(self.app["fragment_text"])
        if result is None:
            self.skipTest("docker CLI not installed")
        self.assertEqual(result[0], 0, result[1])
        parsed = yaml.safe_load(result[1])
        self.assertEqual(sorted(parsed["services"]), ["coding-agent-bootstrap", "coding-agent-server"])
        self.assertEqual(parsed["services"]["coding-agent-server"]["entrypoint"][3], self.server["entrypoint"][3])

    def test_image_pin(self):
        image = self.manifest["images"][0]
        self.assertEqual(image["name"], "openhands-agent-server")
        self.assertEqual(image["source"], "ghcr.io/openhands/agent-server:1.58.2-python-minimal")
        self.assertEqual(image["digest"], AGENT_SERVER_DIGEST)
        self.assertEqual(image["license_spdx"], "MIT")

    def test_local_runtime_and_disabled_features(self):
        env = self.server["environment"]
        self.assertEqual(env["OH_CONVERSATION_RUNTIME"], "local")
        self.assertEqual(env["OH_CONVERSATION_RUNTIME_SELECTABLE"], "false")
        self.assertEqual(env["OH_ENABLE_VSCODE"], "false")
        self.assertEqual(env["OH_ENABLE_BROWSER"], "false")
        self.assertEqual(env["OH_PRELOAD_TOOLS"], "false")
        self.assertEqual(self.server["command"][-4:], ["--host", "0.0.0.0", "--port", "8000"])

    def test_persistence_under_the_volume(self):
        env = self.server["environment"]
        owned = env["SEALED_OWNED_DIRS"].split(",")
        for key in ("OH_WORKSPACE_PATH", "OH_CONVERSATIONS_PATH", "OH_BASH_EVENTS_DIR", "OH_PERSISTENCE_DIR"):
            self.assertTrue(env[key].startswith("/workspace/"), key)
            self.assertIn(env[key], owned, key)
        self.assertIn(os.path.dirname(self.manifest["bootstrap"]["done_file"]), owned)
        self.assertEqual(self.server["volumes"], ["coding-agent-workspace:/workspace"])
        self.assertEqual(self.boot["volumes"], ["coding-agent-workspace:/workspace"])
        self.assertEqual(owned[0], "/workspace")

    def test_secrets(self):
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        self.assertEqual(set(self.server["x-sealed-secrets"]), {"OH_SESSION_API_KEYS_0", "OH_SECRET_KEY"})
        self.assertEqual(set(self.boot["x-sealed-secrets"]), {"LITELLM_MASTER_KEY", "OH_SESSION_API_KEYS_0"})
        self.assertEqual(secrets["OH_SESSION_API_KEYS_0"]["generate"], "hex32")
        self.assertEqual(secrets["OH_SECRET_KEY"]["generate"], "hex32")
        self.assertNotIn("LITELLM_MASTER_KEY", self.server["x-sealed-secrets"])

    def test_telemetry_off(self):
        self.assertEqual(self.manifest["telemetry_off_env"], {
            "OH_TELEMETRY_EXPORTER": "none", "DO_NOT_TRACK": "1", "ANONYMIZED_TELEMETRY": "false",
            "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        })
        for svc in self.services.values():
            env = svc.get("environment") or {}
            for name in ("LMNR_PROJECT_API_KEY", "OTEL_ENDPOINT", "OH_TELEMETRY_POSTHOG_API_KEY", "LLM_BASE_URL"):
                self.assertNotIn(name, env)

    def test_route_metering_bootstrap(self):
        self.assertEqual(self.manifest["routes"], [{
            "name": "code", "service": "coding-agent-server", "internal_port": 8000,
            "path_or_host": "code", "auth": "gate",
        }])
        self.assertEqual(self.manifest["metering"], {"unit": "app_hour", "source": "heartbeat"})
        self.assertEqual(self.manifest["bootstrap"]["service"], "coding-agent-bootstrap")
        self.assertEqual(self.manifest["bootstrap"]["done_file"], self.boot["environment"]["SEALED_DONE_FILE"])
        self.assertIn(self.manifest["bootstrap"]["done_file"], " ".join(self.boot["healthcheck"]["test"]))
        self.assertEqual(self.boot["depends_on"], {"coding-agent-server": {"condition": "service_healthy"}})
        self.assertEqual(self.manifest["maintainer_share_bps"], 2000)

    def test_gateway_wiring(self):
        env = self.boot["environment"]
        names = gateway_model_names()
        self.assertEqual(env["SEALED_GATEWAY_URL"], "http://llm-gateway:4000")
        self.assertEqual(env["SEALED_MODEL_PRIMARY"], "relay/default")
        self.assertEqual(env["SEALED_MODEL_FALLBACK"], "local/qwen3-4b")
        self.assertIn(env["SEALED_MODEL_PRIMARY"], names)
        self.assertIn(env["SEALED_MODEL_FALLBACK"], names)
        for pattern in env["SEALED_LLM_KEY_MODELS"].split(","):
            self.assertIn(pattern, names)
        self.assertEqual(env["SEALED_AGENT_SERVER_URL"], "http://coding-agent-server:8000")

    def test_egress_closed(self):
        self.assertEqual(self.app["egress"]["default_allow"], [])
        self.assertTrue(self.app["egress"]["customer_additions_allowed"])

    def test_embedded_bootstrap_runs_standalone(self):
        """Run the exact script text from the fragment with python3 -I -c against fakes."""
        master, session = "sk-" + "d4" * 32, "sess-abc"
        with tempfile.TemporaryDirectory() as tmp:
            done = os.path.join(tmp, "bootstrap.done")
            with FakeGateway(master) as gw, FakeOpenHands(session, tmp) as oh:
                env = dict(self.boot["environment"])
                env.update({
                    "SEALED_GATEWAY_URL": gw.url, "SEALED_AGENT_SERVER_URL": oh.url, "SEALED_DONE_FILE": done,
                    "SEALED_BOOTSTRAP_IDLE": "0", "SEALED_POLL_INTERVAL_S": "0.05",
                    "LITELLM_MASTER_KEY": master, "OH_SESSION_API_KEYS_0": session, "PATH": os.environ["PATH"],
                    "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
                })
                proc = subprocess.run([sys.executable, *self.boot["entrypoint"][1:]], env=env,
                                      capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(oh.settings["agent_settings"]["llm"]["model"], "litellm_proxy/relay/default")
                self.assertNotIn(master, proc.stderr + proc.stdout)
            self.assertTrue(os.path.exists(done))


class OpenCodeFallbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = catalog_lint.load_app(FALLBACK_DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.server = cls.services["coding-agent-server"]
        cls.boot = cls.services["coding-agent-bootstrap"]
        cls.oc_config = json.loads(cls.server["environment"]["OPENCODE_CONFIG_CONTENT"])

    def test_lint_clean(self):
        self.assertEqual(catalog_lint.lint_app(FALLBACK_DIR, variant=True), [])

    def test_manifest_schema(self):
        errors = catalog_lint.schema_errors(self.manifest)
        if errors is None:
            self.skipTest("jsonschema not installed")
        self.assertEqual(errors, [])

    def test_compose_config(self):
        result = catalog_lint.compose_config(self.app["fragment_text"])
        if result is None:
            self.skipTest("docker CLI not installed")
        self.assertEqual(result[0], 0, result[1])

    def test_same_service_names_as_primary(self):
        primary = catalog_lint.load_app(APP_DIR)["fragment"]["services"]
        self.assertEqual(set(self.services), set(primary))
        self.assertEqual(self.manifest["id"], "coding-agent")
        self.assertEqual(self.manifest["routes"][0]["name"], "code")

    def test_scripts_embedded(self):
        self.assertEqual(self.boot["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "dropuid.py")))
        self.assertEqual(self.boot["command"][3], read(os.path.join(APP_DIR, "bootstrap", "seed.py")))
        self.assertEqual(self.boot["environment"]["SEALED_BOOTSTRAP_MODE"], "key-file")
        self.assertIn("/workspace/.sealed/llm-gateway-key", self.server["entrypoint"][3])
        self.assertEqual(self.boot["environment"]["SEALED_KEY_FILE"], "/workspace/.sealed/llm-gateway-key")

    def test_opencode_config_wired_to_gateway(self):
        cfg = self.oc_config
        self.assertIs(cfg["autoupdate"], False)
        self.assertEqual(cfg["share"], "disabled")
        self.assertEqual(cfg["enabled_providers"], ["litellm"])
        provider = cfg["provider"]["litellm"]
        self.assertEqual(provider["npm"], "@ai-sdk/openai-compatible")
        self.assertEqual(provider["options"], {"baseURL": "http://llm-gateway:4000/v1", "apiKey": "{env:LITELLM_API_KEY}"})
        names = gateway_model_names()
        for key, model in provider["models"].items():
            self.assertNotIn("/", key)
            self.assertIn(model["id"], names)
        self.assertEqual(cfg["model"], "litellm/relay-default")
        self.assertIn(cfg["small_model"].split("/", 1)[1], provider["models"])

    def test_disable_switches(self):
        env = self.server["environment"]
        for key, value in self.manifest["telemetry_off_env"].items():
            if key.startswith("OPENCODE_"):
                self.assertEqual(env[key], value)
        for key in ("OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_DISABLE_MODELS_FETCH", "OPENCODE_DISABLE_LSP_DOWNLOAD",
                    "OPENCODE_DISABLE_DEFAULT_PLUGINS"):
            self.assertEqual(env[key], "1")

    def test_auth_user_matches_healthcheck(self):
        user = self.server["environment"]["OPENCODE_SERVER_USERNAME"]
        self.assertIn(f"'{user}:' + p", self.server["healthcheck"]["test"][-1])
        self.assertIn("/run/sealed/secrets/coding-agent/OPENCODE_SERVER_PASSWORD", self.server["healthcheck"]["test"][-1])
        self.assertEqual(self.server["x-sealed-secrets"], ["OPENCODE_SERVER_PASSWORD"])
        self.assertEqual(self.server["command"], ["opencode", "serve", "--hostname", "0.0.0.0", "--port", "4096"])
        self.assertEqual(self.server["depends_on"], {"coding-agent-bootstrap": {"condition": "service_healthy"}})

    def test_dockerfile(self):
        _, stages = dockerfile_lint.stages(read(os.path.join(FALLBACK_DIR, "images", "opencode", "Dockerfile")))
        self.assertEqual(len(stages), 1)
        stage = stages[0]
        self.assertEqual(stage.base, OPENCODE_BASE)
        run = " ".join(stage.all("RUN"))
        self.assertIn("apk add --no-cache bash git python3", run)
        self.assertIn("adduser -D -u 10001", run)
        self.assertEqual(stage.all("USER"), ["10001:10001"])
        env = stage.env()
        for key in ("OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_DISABLE_MODELS_FETCH", "OPENCODE_DISABLE_LSP_DOWNLOAD",
                    "OPENCODE_DISABLE_DEFAULT_PLUGINS"):
            self.assertEqual(env[key], "1")
        self.assertEqual(stage.exec_form("ENTRYPOINT"), ["opencode"])

    def test_switch_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "catalog", "apps", "coding-agent")
            shutil.copytree(APP_DIR, copy, ignore=shutil.ignore_patterns("__pycache__"))
            script = os.path.join(copy, "fallback-opencode", "switch.sh")
            env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"])
            proc = subprocess.run(["bash", script], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            switched = catalog_lint.load_app(copy)
            self.assertEqual(switched["manifest"]["images"][0]["name"], "opencode")
            self.assertEqual(switched["fragment_text"], self.app["fragment_text"])
            self.assertTrue(os.path.exists(os.path.join(copy, "images", "opencode", "Dockerfile")))
            again = subprocess.run(["bash", script], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(again.returncode, 1)
            self.assertIn("already uses OpenCode", again.stderr)


if __name__ == "__main__":
    unittest.main()
