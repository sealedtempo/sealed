"""Packaging tests for coding-agent and its OpenCode fallback: fragments, manifests, egress, images.

The app directory holds either the OpenHands release (default) or, after
fallback-opencode/switch.sh, the OpenCode variant. Each test class checks the variant it is
about and skips itself when the app directory holds the other one, so the suite passes in
both states (test_switch_script runs it on a switched copy).
"""
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
from fakes import FakeLiteLLM, FakeOpenHands  # noqa: E402

AGENT_SERVER_DIGEST = "sha256:9e04bf35e5f44f987f2bd7bb82b8f967104def33183da85bd6e95c9eb34ddfb3"
OPENCODE_BASE = ("ghcr.io/anomalyco/opencode:1.19.5"
                 "@sha256:f4cfe16d91efbbfca01a51c44094fba4cf82e15c7fa17de5f11f9059699b1e6e")
NESTED = os.environ.get("SEALED_SWITCH_NESTED") == "1"


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


def gateway_app_key():
    entries = yaml.safe_load(read(os.path.join(GATEWAY_DIR, "images", "litellm", "app_keys.yaml")))["apps"]
    return next(e for e in entries if e["app"] == "coding-agent")


def app_variant():
    manifest = yaml.safe_load(read(os.path.join(APP_DIR, "manifest.yaml")))
    return manifest["images"][0]["name"]


class CommonChecks:
    """Checks that hold for every coding-agent variant."""

    DIR = APP_DIR
    VARIANT = False

    def test_lint_clean(self):
        self.assertEqual(catalog_lint.lint_app(self.DIR, variant=self.VARIANT), [])

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
        self.assertEqual(sorted(parsed["services"]), sorted(self.services))

    def test_never_holds_the_gateway_master_key(self):
        names = {s["name"] for s in self.manifest["secrets"]}
        self.assertNotIn("LITELLM_MASTER_KEY", names)
        self.assertNotIn("LITELLM_MASTER_KEY", self.app["fragment_text"])
        key = {s["name"]: s for s in self.manifest["secrets"]}["LLM_GATEWAY_KEY"]
        self.assertEqual(key["generate"], "none")
        self.assertIn(gateway_app_key()["secret"], key["description"])
        holders = [n for n, s in self.services.items() if "LLM_GATEWAY_KEY" in (s.get("x-sealed-secrets") or [])]
        self.assertTrue(holders)

    def test_gateway_key_scope(self):
        entry = gateway_app_key()
        self.assertEqual(entry["key_alias"], "coding-agent")
        names = gateway_model_names()
        for pattern in entry["models"]:
            self.assertIn(pattern, names)
            self.assertFalse(pattern.startswith(("byok/", "external/")))

    def test_egress_closed(self):
        self.assertEqual(self.app["egress"]["default_allow"], [])
        self.assertTrue(self.app["egress"]["customer_additions_allowed"])

    def test_route_and_metering(self):
        route = self.manifest["routes"][0]
        self.assertEqual((route["name"], route["service"], route["auth"]), ("code", "coding-agent-server", "gate"))
        self.assertEqual(self.manifest["primary_service"], "coding-agent-server")
        self.assertEqual(self.manifest["metering"], {"unit": "app_hour", "source": "heartbeat"})
        self.assertEqual(self.manifest["maintainer_share_bps"], 2000)


class OpenHandsPackagingTest(CommonChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if app_variant() != "openhands-agent-server":
            raise unittest.SkipTest("app directory holds the OpenCode variant")
        cls.app = catalog_lint.load_app(APP_DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.server = cls.services["coding-agent-server"]
        cls.boot = cls.services["coding-agent-bootstrap"]

    def test_fragments_up_to_date(self):
        self.assertEqual(load_tool().main(["--check"]), 0)

    def test_scripts_embedded_verbatim(self):
        self.assertEqual(self.server["entrypoint"][:3], ["/usr/local/bin/python3", "-I", "-c"])
        self.assertEqual(self.server["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "dropuid.py")))
        self.assertEqual(self.boot["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "dropuid.py")))
        self.assertEqual(self.boot["command"][:3], ["/usr/local/bin/python3", "-I", "-c"])
        self.assertEqual(self.boot["command"][3], read(os.path.join(APP_DIR, "bootstrap", "seed.py")))

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
        self.assertEqual(self.server["volumes"], ["coding-agent-workspace:/workspace"])
        self.assertEqual(owned[0], "/workspace")

    def test_bootstrap_state_is_out_of_the_agents_reach(self):
        done = self.manifest["bootstrap"]["done_file"]
        self.assertEqual(self.manifest["bootstrap"]["service"], "coding-agent-bootstrap")
        self.assertEqual(done, self.boot["environment"]["SEALED_DONE_FILE"])
        self.assertIn(done, " ".join(self.boot["healthcheck"]["test"]))
        # The done file is on a volume only the bootstrap job mounts (the composer keeps it on the
        # data disk), owned by a uid other than the agent's.
        self.assertEqual(self.boot["volumes"], ["coding-agent-bootstrap:/var/lib/sealed-bootstrap"])
        self.assertTrue(done.startswith("/var/lib/sealed-bootstrap/"))
        for name, svc in self.services.items():
            if name != "coding-agent-bootstrap":
                self.assertFalse([v for v in svc.get("volumes") or [] if v.startswith("coding-agent-bootstrap:")])
        self.assertEqual(self.boot["environment"]["SEALED_OWNED_DIRS"], "/var/lib/sealed-bootstrap")
        self.assertNotEqual(self.boot["environment"]["SEALED_RUN_AS"], self.server["environment"]["SEALED_RUN_AS"])
        self.assertTrue(self.boot["read_only"])
        self.assertEqual(self.boot["depends_on"], {"coding-agent-server": {"condition": "service_healthy"}})

    def test_secrets(self):
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        self.assertEqual(set(secrets), {"OH_SESSION_API_KEYS_0", "OH_SECRET_KEY", "LLM_GATEWAY_KEY"})
        self.assertEqual(set(self.server["x-sealed-secrets"]), {"OH_SESSION_API_KEYS_0", "OH_SECRET_KEY"})
        self.assertEqual(set(self.boot["x-sealed-secrets"]), {"LLM_GATEWAY_KEY", "OH_SESSION_API_KEYS_0"})
        self.assertEqual(secrets["OH_SESSION_API_KEYS_0"]["generate"], "hex32")
        self.assertEqual(secrets["OH_SECRET_KEY"]["generate"], "hex32")

    def test_telemetry_off(self):
        self.assertEqual(self.manifest["telemetry_off_env"], {
            "OH_TELEMETRY_EXPORTER": "none", "DO_NOT_TRACK": "1", "ANONYMIZED_TELEMETRY": "false",
            "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        })
        for svc in self.services.values():
            env = svc.get("environment") or {}
            for name in ("LMNR_PROJECT_API_KEY", "OTEL_ENDPOINT", "OH_TELEMETRY_POSTHOG_API_KEY", "LLM_BASE_URL"):
                self.assertNotIn(name, env)

    def test_gateway_wiring(self):
        env = self.boot["environment"]
        self.assertEqual(env["SEALED_GATEWAY_URL"], "http://llm-gateway:4000")
        self.assertEqual(env["SEALED_MODEL_DEFAULT"], "relay/default")
        self.assertIn(env["SEALED_MODEL_DEFAULT"], gateway_model_names())
        self.assertEqual(env["SEALED_AGENT_SERVER_URL"], "http://coding-agent-server:8000")
        self.assertNotIn("litellm_extra_body", read(os.path.join(APP_DIR, "bootstrap", "seed.py")))

    def test_embedded_bootstrap_runs_standalone(self):
        """Run the exact script text from the fragment with python3 -I -c against fakes."""
        master, key, session = "sk-" + "d4" * 32, "sk-" + "e5" * 32, "sess-abc"
        with tempfile.TemporaryDirectory() as tmp:
            done = os.path.join(tmp, "run", "bootstrap", "done")
            with FakeLiteLLM(master) as gw, FakeOpenHands(session, tmp) as oh:
                gw.add_key(key, key_alias="coding-agent", models=["relay/*", "local/*"])
                env = dict(self.boot["environment"])
                env.update({
                    "SEALED_GATEWAY_URL": gw.url, "SEALED_AGENT_SERVER_URL": oh.url, "SEALED_DONE_FILE": done,
                    "SEALED_BOOTSTRAP_IDLE": "0", "SEALED_POLL_INTERVAL_S": "0.05",
                    "LLM_GATEWAY_KEY": key, "OH_SESSION_API_KEYS_0": session, "PATH": os.environ["PATH"],
                    "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
                })
                proc = subprocess.run([sys.executable, *self.boot["command"][1:]], env=env,
                                      capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(oh.settings["agent_settings"]["llm"]["model"], "litellm_proxy/relay/default")
                self.assertEqual(oh.settings["agent_settings"]["llm"]["api_key"], key)
                self.assertNotIn(key, proc.stderr + proc.stdout)
            self.assertTrue(os.path.exists(done))


class OpenCodeChecks(CommonChecks):
    """The OpenCode variant, wherever it sits (fallback-opencode/ or, after the switch, the app dir)."""

    @classmethod
    def load(cls):
        cls.app = catalog_lint.load_app(cls.DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.server = cls.services["coding-agent-server"]
        cls.oc_config = json.loads(cls.server["environment"]["OPENCODE_CONFIG_CONTENT"])

    def test_single_service_with_the_primary_route(self):
        self.assertEqual(sorted(self.services), ["coding-agent-server"])
        self.assertNotIn("bootstrap", self.manifest)
        self.assertEqual(self.manifest["routes"][0]["internal_port"], 4096)
        self.assertEqual(self.manifest["healthcheck"]["http"], "/global/health")

    def test_scripts_embedded(self):
        self.assertEqual(self.server["entrypoint"][:3], ["/usr/bin/python3", "-I", "-c"])
        self.assertEqual(self.server["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "dropuid.py")))
        self.assertEqual(self.server["command"][:3], ["/usr/bin/python3", "-I", "-c"])
        self.assertEqual(self.server["command"][3], read(os.path.join(APP_DIR, "bootstrap", "authproxy.py")))

    def test_opencode_only_on_loopback_behind_the_proxy(self):
        args = self.server["command"][4:]
        sep = args.index("--")
        flags = dict(zip(args[:sep:2], args[1:sep:2]))
        child = args[sep + 1:]
        self.assertEqual(flags["--listen"], "0.0.0.0:%d" % self.manifest["routes"][0]["internal_port"])
        upstream_host, upstream_port = flags["--upstream"].rsplit(":", 1)
        self.assertEqual(upstream_host, "127.0.0.1")
        self.assertEqual(child[:2], ["opencode", "serve"])
        child_flags = dict(zip(child[2::2], child[3::2]))
        self.assertEqual(child_flags, {"--hostname": "127.0.0.1", "--port": upstream_port})
        self.assertNotEqual(upstream_port, "4096")

    def test_secrets(self):
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        self.assertEqual(set(secrets), {"LLM_GATEWAY_KEY", "CODE_SESSION_API_KEY", "OPENCODE_SERVER_PASSWORD"})
        self.assertEqual(set(self.server["x-sealed-secrets"]), set(secrets))
        self.assertEqual(secrets["CODE_SESSION_API_KEY"]["generate"], "hex32")
        # Generated for OpenCode alone, never the password gate's password.
        self.assertEqual(secrets["OPENCODE_SERVER_PASSWORD"]["generate"], "hex32")
        self.assertIn("never the password gate", secrets["OPENCODE_SERVER_PASSWORD"]["description"])
        self.assertFalse([n for n in secrets if n.startswith("GATE") or "GATE_PASSWORD" in n])

    def test_healthcheck_uses_the_public_health_path(self):
        probe = self.server["healthcheck"]["test"][-1]
        self.assertIn("http://127.0.0.1:4096/global/health", probe)
        self.assertNotIn("/run/sealed/secrets", probe)
        self.assertIn("ProxyHandler({})", probe)

    def test_opencode_config_wired_to_gateway(self):
        cfg = self.oc_config
        self.assertIs(cfg["autoupdate"], False)
        self.assertEqual(cfg["share"], "disabled")
        self.assertEqual(cfg["enabled_providers"], ["litellm"])
        provider = cfg["provider"]["litellm"]
        self.assertEqual(provider["npm"], "@ai-sdk/openai-compatible")
        self.assertEqual(provider["options"], {"baseURL": "http://llm-gateway:4000/v1", "apiKey": "{env:LLM_GATEWAY_KEY}"})
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
        owned = env["SEALED_OWNED_DIRS"].split(",")
        self.assertIn(self.server["working_dir"], owned)
        for key in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"):
            self.assertTrue(env[key].startswith("/workspace/.opencode/"), key)

    def test_dockerfile(self):
        _, stages = dockerfile_lint.stages(read(os.path.join(self.DIR, "images", "opencode", "Dockerfile")))
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
        self.assertIn("127.0.0.1", stage.exec_form("CMD"))  # never unauthenticated on the network by default


class OpenCodeFallbackTest(OpenCodeChecks, unittest.TestCase):
    DIR = FALLBACK_DIR
    VARIANT = True

    @classmethod
    def setUpClass(cls):
        cls.load()

    def test_primary_service_matches_openhands(self):
        primary = yaml.safe_load(read(os.path.join(APP_DIR, "manifest.yaml")))
        self.assertEqual(self.manifest["id"], "coding-agent")
        self.assertEqual(self.manifest["primary_service"], primary["primary_service"])
        self.assertEqual(self.manifest["routes"][0]["name"], primary["routes"][0]["name"])

    def test_switch_script(self):
        if NESTED:
            self.skipTest("already inside a switched copy")
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            copy = os.path.join(repo, "catalog", "apps", "coding-agent")
            ignore = shutil.ignore_patterns("__pycache__")
            shutil.copytree(APP_DIR, copy, ignore=ignore)
            shutil.copytree(GATEWAY_DIR, os.path.join(repo, "catalog", "apps", "llm-gateway"), ignore=ignore,
                            symlinks=True)
            shutil.copytree(os.path.dirname(catalog_lint.SCHEMA_PATH), os.path.join(repo, "catalog", "schema"))
            script = os.path.join(copy, "fallback-opencode", "switch.sh")
            env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"])
            proc = subprocess.run(["bash", script], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            switched = catalog_lint.load_app(copy)
            self.assertEqual(switched["manifest"]["images"][0]["name"], "opencode")
            self.assertEqual(switched["fragment_text"], self.app["fragment_text"])
            self.assertTrue(os.path.exists(os.path.join(copy, "images", "opencode", "Dockerfile")))
            self.assertEqual(read(os.path.join(copy, "README.md")), read(os.path.join(FALLBACK_DIR, "app-README.md")))
            # The documented procedure ends with "run the tests": they must pass on the switched app.
            suite = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", os.path.join(copy, "tests"),
                                    "-t", os.path.join(copy, "tests")], capture_output=True, text=True,
                                   env=dict(env, SEALED_SWITCH_NESTED="1"), timeout=600)
            self.assertEqual(suite.returncode, 0, suite.stderr[-4000:])
            self.assertIn("OK", suite.stderr.strip().splitlines()[-1])
            again = subprocess.run(["bash", script], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(again.returncode, 1)
            self.assertIn("already uses OpenCode", again.stderr)


class OpenCodeActiveTest(OpenCodeChecks, unittest.TestCase):
    """Runs only on a switched app directory."""

    DIR = APP_DIR

    @classmethod
    def setUpClass(cls):
        if app_variant() != "opencode":
            raise unittest.SkipTest("app directory holds the OpenHands release")
        cls.load()

    def test_fragments_up_to_date(self):
        self.assertEqual(load_tool().main(["--check"]), 0)

    def test_same_files_as_the_fallback(self):
        for name in ("manifest.yaml", "compose.fragment.yaml", "egress.yaml", "waivers.yaml"):
            self.assertEqual(read(os.path.join(APP_DIR, name)), read(os.path.join(FALLBACK_DIR, name)), name)


if __name__ == "__main__":
    unittest.main()
