"""Packaging tests for coding-agent and its OpenCode fallback: fragments, manifests, egress, images.

The app directory holds either the OpenHands release (default) or, after
fallback-opencode/switch.sh, the OpenCode variant. Each test class checks the variant it is
about and skips itself when the app directory holds the other one, so the suite passes in
both states (test_switch_script runs it on a switched copy). The catalog rules are checked by
the real composer (llm-gateway/tests/sealed_compose.py); these tests add what is specific to
this app.
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

import dockerfile_lint  # noqa: E402
import license_texts  # noqa: E402
import sealed_compose  # noqa: E402
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

    def test_never_holds_the_gateway_master_key(self):
        names = {s["name"] for s in self.manifest["secrets"]}
        self.assertNotIn("LITELLM_MASTER_KEY", names)
        self.assertNotIn("LITELLM_MASTER_KEY", self.app["fragment_text"])
        key = {s["name"]: s for s in self.manifest["secrets"]}["LLM_GATEWAY_KEY"]
        self.assertEqual(key["generate"], "none")
        self.assertIn(gateway_app_key()["secret"], key["description"])
        holders = [n for n, s in self.services.items() if "LLM_GATEWAY_KEY" in (s.get("x-sealed-secrets") or [])]
        self.assertTrue(holders)

    def test_gateway_key_refers_to_the_gateway_secret(self):
        """Integration brief item 6: sealed secrets copies the value instead of asking twice."""
        key = {s["name"]: s for s in self.manifest["secrets"]}["LLM_GATEWAY_KEY"]
        self.assertEqual(key["same_as"], "llm-gateway/" + gateway_app_key()["secret"])
        gateway = {s["name"]: s for s in sealed_compose.load_yaml(os.path.join(GATEWAY_DIR, "manifest.yaml"))["secrets"]}
        self.assertIn(gateway_app_key()["secret"], gateway)
        self.assertEqual([s for s in self.manifest["secrets"] if "same_as" in s], [key])
        # D-059: the gateway opts in to exactly this reference.
        self.assertEqual(gateway[gateway_app_key()["secret"]]["share_with"], [self.manifest["id"]])
        # Nothing in coding-agent is shared with another app.
        self.assertEqual([s["name"] for s in self.manifest["secrets"] if "share_with" in s], [])

    def test_no_service_starts_as_root(self):
        """Integration brief item 11: volume owners come from x-sealed-owner, not from a root start."""
        owners = {name: (spec or {}).get("x-sealed-owner") for name, spec in (self.app["fragment"].get("volumes") or {}).items()}
        for name, svc in self.services.items():
            user = svc.get("user", "")
            self.assertRegex(user, r"^[1-9][0-9]*:[1-9][0-9]*$", name)
            for mount in svc.get("volumes") or []:
                volume, target = mount.split(":")[:2]
                read_only = mount.endswith(":ro")
                if not read_only:
                    self.assertEqual(owners[volume], user, f"{name} writes {volume} as {user}")
        self.assertTrue(all(owners.values()), owners)
        self.assertNotIn("dropuid", self.app["fragment_text"])

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
        cls.app = sealed_compose.load_app(APP_DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.server = cls.services["coding-agent-server"]
        cls.boot = cls.services["coding-agent-bootstrap"]

    def test_fragments_up_to_date(self):
        self.assertEqual(load_tool().main(["--check"]), 0)

    def test_scripts_embedded_verbatim(self):
        self.assertEqual(self.server["entrypoint"][:3], ["/usr/local/bin/python3", "-I", "-c"])
        self.assertEqual(self.server["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "prepdirs.py")))
        self.assertEqual(self.server["command"][:3], ["tini", "--", "/usr/local/bin/openhands-agent-server"])
        self.assertEqual(self.boot["entrypoint"][:3], ["/usr/local/bin/python3", "-I", "-c"])
        self.assertEqual(self.boot["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "seed.py")))
        self.assertNotIn("command", self.boot)

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
        self.assertEqual(env["SEALED_RUN_AS"], self.server["user"])
        self.assertEqual(self.app["fragment"]["volumes"]["coding-agent-workspace"]["x-sealed-owner"], self.server["user"])
        self.assertNotIn("working_dir", self.server)  # the image's is /, outside the volume

    def test_bootstrap_state_is_out_of_the_agents_reach(self):
        done = self.manifest["bootstrap"]["done_file"]
        self.assertEqual(self.manifest["bootstrap"]["service"], "coding-agent-bootstrap")
        # Integration brief item 10: <volume>/<path> relative to /mnt/sealed-data/coding-agent/.
        self.assertEqual(done, "coding-agent-bootstrap/done")
        volume, rest = done.split("/", 1)
        self.assertEqual(self.boot["volumes"], [volume + ":/var/lib/sealed-bootstrap"])
        self.assertEqual(self.boot["environment"]["SEALED_DONE_FILE"], "/var/lib/sealed-bootstrap/" + rest)
        # The done file is on a volume only the bootstrap job mounts (the composer keeps it on the
        # data disk), owned by a uid other than the agent's.
        for name, svc in self.services.items():
            if name != "coding-agent-bootstrap":
                self.assertFalse([v for v in svc.get("volumes") or [] if v.startswith(volume + ":")])
        owners = self.app["fragment"]["volumes"]
        self.assertEqual(owners[volume]["x-sealed-owner"], self.boot["user"])
        self.assertNotEqual(self.boot["user"], self.server["user"])
        self.assertTrue(self.boot["read_only"])
        self.assertEqual(self.boot["depends_on"], {"coding-agent-server": {"condition": "service_healthy"}})
        # It exits once done (the composer gives it restart: on-failure), so it has no healthcheck.
        self.assertNotIn("healthcheck", self.boot)
        self.assertNotIn("signal.pause", read(os.path.join(APP_DIR, "bootstrap", "seed.py")))

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
                env = dict(self.boot["environment"])
                env.update({
                    "SEALED_GATEWAY_URL": gw.url, "SEALED_AGENT_SERVER_URL": oh.url, "SEALED_DONE_FILE": done,
                    "SEALED_POLL_INTERVAL_S": "0.05",
                    "LLM_GATEWAY_KEY": key, "OH_SESSION_API_KEYS_0": session, "PATH": os.environ["PATH"],
                    "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
                })
                # Exits by itself once done: restart on-failure must not see a running job forever.
                proc = subprocess.run([sys.executable, *self.boot["entrypoint"][1:]], env=env,
                                      capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(oh.settings["agent_settings"]["llm"]["model"], "litellm_proxy/relay/default")
                self.assertEqual(oh.settings["agent_settings"]["llm"]["api_key"], key)
                self.assertNotIn(key, proc.stderr + proc.stdout)
                self.assertEqual(gw.calls, [])  # the job is not on the network llm-gateway is on
            self.assertTrue(os.path.exists(done))


class OpenCodeChecks(CommonChecks):
    """The OpenCode variant, wherever it sits (fallback-opencode/ or, after the switch, the app dir)."""

    @classmethod
    def load(cls):
        cls.app = sealed_compose.load_app(cls.DIR)
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
        self.assertEqual(self.server["entrypoint"][3], read(os.path.join(APP_DIR, "bootstrap", "prepdirs.py")))
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
        # Docker would create a missing working_dir as root inside the volume, so the container
        # starts in the volume root and prepdirs.py changes to the project directory it created.
        self.assertEqual(self.server["working_dir"], "/workspace")
        self.assertEqual(owned[0], "/workspace")
        self.assertEqual(env["SEALED_WORKDIR"], "/workspace/project")
        self.assertIn(env["SEALED_WORKDIR"], owned)
        self.assertEqual(env["SEALED_RUN_AS"], self.server["user"])
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
            script = os.path.join(copy, "fallback-opencode", "switch.sh")
            # The copy has no composer source; the nested suite runs this checkout's composer on it.
            env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"],
                       SEALED_COMPOSER_DIR=sealed_compose.Composer().root)
            proc = subprocess.run(["bash", script], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            switched = sealed_compose.load_app(copy)
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


def envexec_secrets(service):
    """Secret names a composed service's envexec entrypoint exports (--secret / --optional-secret)."""
    entry = service["entrypoint"]
    sep = entry.index("--")
    return {entry[i + 1] for i in range(sep) if entry[i] in ("--secret", "--optional-secret")}


class ComposerChecks:
    """The real composer on a variant, composed together with llm-gateway (same_as needs it)."""

    DIR = APP_DIR
    WARNINGS = ("sbom-missing",)

    @classmethod
    def compose(cls):
        cls.composer = sealed_compose.composer_for(cls)
        cls.app = sealed_compose.load_app(cls.DIR)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.stack = cls.composer.compose([GATEWAY_DIR, cls.DIR], os.path.join(cls.tmp.name, "out"))
        cls.composed = cls.stack["compose"]["services"]
        cls.info = next(a for a in cls.stack["stack"]["apps"] if a["id"] == "coding-agent")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_lint_findings(self):
        findings = self.composer.lint([self.DIR])
        self.assertEqual(sealed_compose.unexpected(findings, warnings=self.WARNINGS), [])
        errors = [f for f in findings if f["severity"] == "error"]
        self.assertEqual(len(errors), len(sealed_compose.unbuilt_images(self.app["manifest"])), errors)

    def test_each_service_exports_only_its_declared_secrets(self):
        for name, svc in self.app["fragment"]["services"].items():
            self.assertEqual(envexec_secrets(self.composed[name]), set(svc.get("x-sealed-secrets") or []), name)

    def test_license_exclusions_are_matched_by_the_lint(self):
        """License audit F6: each exclusion catches what it names, in an SBOM, and nothing it should not."""
        sp = "/usr/local/lib/python3.13/site-packages"
        caught_files = [
            "/usr/lib/node_modules/@anthropic-ai/claude-agent-sdk/cli.js",
            "/opt/app/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude",
            f"{sp}/litellm_enterprise/__init__.py",
        ]
        if "/acp-node/" in self.app["manifest"]["license_exclusions"]:
            caught_files.append("/acp-node/node_modules/@zed-industries/claude-code-acp/dist/index.js")
        clean_files = [f"{sp}/litellm/__init__.py", f"{sp}/openhands/sdk/__init__.py", "/usr/local/bin/opencode",
                       "/usr/lib/node_modules/npm/package.json", "/opt/acp-nodes.txt"]
        caught_packages = ["@anthropic-ai/claude-agent-sdk", "litellm-enterprise"]
        clean_packages = ["litellm", "openhands-sdk", "@anthropic-ai/sdk", "opencode-ai"]
        image = self.app["manifest"]["images"][0]["name"]
        findings = self.composer.lint_with_sbom(self.DIR, image, caught_packages + clean_packages,
                                                caught_files + clean_files)
        hits = sealed_compose.excluded_hits(findings)
        for path in caught_files:
            self.assertIn(path, hits)
        for name in caught_packages:
            self.assertIn(name + "@1.0.0", hits)
        for entry in clean_files + [n + "@1.0.0" for n in clean_packages]:
            self.assertNotIn(entry, hits)
        used = set().union(*hits.values())
        for pattern in sealed_compose.exclusion_patterns(self.app["manifest"]):
            self.assertIn(pattern, used, f"license_exclusions entry {pattern!r} matches nothing")

    def test_services_run_as_their_fragment_users(self):
        for name, svc in self.app["fragment"]["services"].items():
            self.assertEqual(self.composed[name]["user"], svc["user"], name)

    def test_code_route_is_gated(self):
        site = sealed_compose.caddy_site(self.stack["caddyfile"], "code.34-1-2-3.sslip.io")
        self.assertIsNotNone(site)
        port = self.app["manifest"]["routes"][0]["internal_port"]
        self.assertIn(f"reverse_proxy coding-agent-server:{port}", site)
        if self.composer.brief:
            # Integration brief item 9: forward_auth to sealed-agent, no basic_auth in Caddy.
            self.assertIn("forward_auth sealed-agent:7070", site)
            self.assertIn("/v1/gate?route=code", site)
            self.assertNotIn("basic_auth", site)
        else:
            self.assertIn("basic_auth", site)

    def test_docker_compose_accepts_the_composed_document(self):
        result = sealed_compose.docker_compose_config(self.stack["compose_path"])
        if result is None:
            self.skipTest("docker CLI not installed")
        self.assertEqual(result[0], 0, result[1])

    def brief_only(self):
        if not self.composer.brief:
            self.skipTest(f"composer {self.composer.version} predates integration brief items 5 to 11 (1.2.0)")

    def test_secret_files_are_mounted_per_service(self):
        self.brief_only()
        root = "/run/sealed/secrets/coding-agent"
        for name, svc in self.app["fragment"]["services"].items():
            want = {f"{root}/{s}" for s in svc.get("x-sealed-secrets") or []}
            self.assertEqual(sealed_compose.secret_mounts(self.composed[name], "coding-agent"), want, name)

    def test_volume_owners_are_recorded_for_the_agent(self):
        self.brief_only()
        for name, spec in self.app["fragment"]["volumes"].items():
            entry = next(v for v in self.info["volumes"] if v["name"] == name)
            self.assertIn(spec["x-sealed-owner"], json.dumps(entry), name)

    def test_only_the_primary_service_reaches_other_apps(self):
        """D-041: the bootstrap job cannot reach llm-gateway, which is why seed.py never calls it."""
        self.brief_only()
        primary = self.app["manifest"]["primary_service"]
        for name in self.app["fragment"]["services"]:
            networks = set(self.composed[name]["networks"])
            self.assertIn("app-coding-agent", networks, name)
            self.assertEqual("apps" in networks, name == primary, name)
        self.assertIn("apps", self.composed["llm-gateway-litellm"]["networks"])

    def test_same_as_needs_llm_gateway_in_the_stack(self):
        self.brief_only()
        alone = self.composer.compose([self.DIR], os.path.join(self.tmp.name, "alone"), expect_ok=False)
        self.assertNotEqual(alone["status"], 0)
        self.assertIn("llm-gateway", alone["stderr"])

    def share_with_only(self):
        if not self.composer.share_with:
            self.skipTest(f"composer {self.composer.version} predates share_with (D-059)")

    def test_same_as_needs_the_gateway_to_share_the_key(self):
        """D-059: without share_with on APP_KEY_CODING_AGENT the composer refuses the reference."""
        self.share_with_only()
        scratch = os.path.join(self.tmp.name, "unshared")
        os.makedirs(scratch)
        gateway = sealed_compose.brief_compatible_copy(GATEWAY_DIR, scratch, brief=False, share_with=True)
        copied = sealed_compose.load_yaml(os.path.join(gateway, "manifest.yaml"))
        self.assertEqual([s["name"] for s in copied["secrets"] if "share_with" in s], [])
        refused = self.composer.compose([gateway, self.DIR], os.path.join(self.tmp.name, "unshared-out"),
                                        expect_ok=False)
        self.assertNotEqual(refused["status"], 0)
        self.assertIn("share_with", refused["stderr"])

    def test_the_gateway_master_key_cannot_be_referenced(self):
        self.share_with_only()
        scratch = os.path.join(self.tmp.name, "master")
        os.makedirs(scratch)
        app = sealed_compose.brief_compatible_copy(self.DIR, scratch, brief=False, share_with=False)
        manifest = sealed_compose.load_yaml(os.path.join(app, "manifest.yaml"))
        for secret in manifest["secrets"]:
            if secret.get("same_as"):
                secret["same_as"] = "llm-gateway/LITELLM_MASTER_KEY"
        with open(os.path.join(app, "manifest.yaml"), "w", encoding="utf-8") as handle:
            yaml.safe_dump(manifest, handle, sort_keys=False)
        refused = self.composer.compose([GATEWAY_DIR, app], os.path.join(self.tmp.name, "master-out"),
                                        expect_ok=False)
        self.assertNotEqual(refused["status"], 0)
        self.assertIn("LITELLM_MASTER_KEY", refused["stderr"])


class OpenHandsComposerTest(ComposerChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if app_variant() != "openhands-agent-server":
            raise unittest.SkipTest("app directory holds the OpenCode variant")
        cls.compose()

    def test_bootstrap_job(self):
        boot = self.composed["coding-agent-bootstrap"]
        self.assertEqual(boot["restart"], "on-failure")
        self.assertEqual(self.info["bootstrap"]["service"], "coding-agent-bootstrap")
        self.assertEqual(self.info["bootstrap"]["donePath"],
                         "/mnt/sealed-data/coding-agent/coding-agent-bootstrap/done")
        self.assertEqual(self.composed["coding-agent-server"]["restart"], "unless-stopped")


class OpenCodeFallbackComposerTest(ComposerChecks, unittest.TestCase):
    DIR = FALLBACK_DIR
    # The variant directory is not a release directory; the app's LICENSE-NOTICE covers OpenCode.
    WARNINGS = ("sbom-missing", "missing-file")

    @classmethod
    def setUpClass(cls):
        cls.compose()

    def test_starts_in_the_volume_root(self):
        self.assertEqual(self.composed["coding-agent-server"]["working_dir"], "/workspace")


class LicenseTextsTest(unittest.TestCase):
    """License audit F10: the MIT texts of OpenHands and of the OpenCode fallback, byte for byte.

    LICENSES/ belongs to the app directory, so both variants ship both texts (switch.sh leaves it).
    """

    EXPECTED = {
        "openhands-software-agent-sdk-v1.58.2-LICENSE": ("OpenHands/software-agent-sdk", "v1.58.2", "LICENSE"),
        "opencode-v1.19.5-LICENSE": ("anomalyco/opencode", "v1.19.5", "LICENSE"),
    }

    def test_texts_match_upstream(self):
        self.assertEqual(license_texts.problems(APP_DIR), [])

    def test_the_expected_texts_are_shipped_for_the_pinned_tags(self):
        texts = license_texts.notice_texts(read(os.path.join(APP_DIR, "LICENSE-NOTICE")))
        self.assertEqual({t.file: (t.repo, t.ref, t.path) for t in texts}, self.EXPECTED)
        for variant in (APP_DIR, FALLBACK_DIR):
            upstream = yaml.safe_load(read(os.path.join(variant, "manifest.yaml")))["upstream"]
            text = next(t for t in texts if "https://github.com/" + t.repo == upstream["repo"])
            self.assertEqual(text.ref, upstream["version"], variant)
            self.assertIn("MIT License", read(os.path.join(APP_DIR, "LICENSES", text.file)))


if __name__ == "__main__":
    unittest.main()
