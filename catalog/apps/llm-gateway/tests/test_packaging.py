"""Packaging tests for llm-gateway: manifest, fragment, egress, Dockerfiles and their consistency.

The catalog rules themselves are checked by the real composer (sealed_compose.py runs
`go run ./runtime/composer/cmd/sealed-compose lint` and `compose`); these tests add what is
specific to this app.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import dockerfile_lint  # noqa: E402
import license_texts  # noqa: E402
import sealed_compose  # noqa: E402

APP_DIR = os.path.normpath(os.path.join(HERE, ".."))
CATALOG_DIR = os.path.normpath(os.path.join(APP_DIR, ".."))
IMAGE_DIR = os.path.join(APP_DIR, "images", "litellm")
LITELLM_BASE = ("ghcr.io/berriai/litellm-database:v1.106.5"
                "@sha256:0d10536ce596ef74bf5bbd3244310bb11c2cadd8f92d2f22d587cc0b9fc16e01")
POSTGRES_DIGEST = "sha256:1beaa3084eee2676f20a9cd9928f0bf2c5bf674f8e49f81017912183d377c61c"


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class PackagingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = sealed_compose.load_app(APP_DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.providers = yaml.safe_load(read(os.path.join(IMAGE_DIR, "providers.yaml")))
        cls.config = yaml.safe_load(read(os.path.join(IMAGE_DIR, "config.yaml")))
        cls.dockerfile = read(os.path.join(IMAGE_DIR, "Dockerfile"))

    def test_service_names(self):
        self.assertEqual(sorted(self.services),
                         ["llm-gateway-db", "llm-gateway-keys", "llm-gateway-litellm", "llm-gateway-ollama"])

    def test_metering_and_payout(self):
        self.assertEqual(self.manifest["metering"], {"unit": "tokens", "source": "callback"})
        self.assertEqual(self.manifest["maintainer"]["payout_address"], "${MAINTAINER_DEFAULT_ADDRESS}")
        self.assertEqual(self.manifest["maintainer_share_bps"], 2000)

    def test_routes_and_health(self):
        self.assertEqual(self.manifest["routes"], [{
            "name": "gateway", "service": "llm-gateway-litellm", "internal_port": 4000,
            "path_or_host": "gateway", "auth": "bearer-passthrough",
        }])
        self.assertEqual(self.manifest["healthcheck"]["http"], "/health/liveliness")
        test = " ".join(self.services["llm-gateway-litellm"]["healthcheck"]["test"])
        self.assertIn("/health/liveliness", test)
        self.assertIn("ProxyHandler({})", test)

    def test_egress_is_closed_by_default(self):
        self.assertEqual(self.app["egress"]["default_allow"], [])
        self.assertTrue(self.app["egress"]["customer_additions_allowed"])

    def test_required_secrets(self):
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        self.assertEqual(secrets["LITELLM_MASTER_KEY"]["generate"], "sk-hex32")
        self.assertEqual(secrets["LITELLM_SALT_KEY"]["generate"], "sk-hex32")
        self.assertEqual(secrets["POSTGRES_PASSWORD"]["generate"], "hex32")
        self.assertEqual(secrets["OLLAMA_GATE_KEY"]["generate"], "hex32")
        for name in ("LITELLM_MASTER_KEY", "LITELLM_SALT_KEY", "POSTGRES_PASSWORD", "OLLAMA_GATE_KEY"):
            self.assertFalse(secrets[name].get("optional", False))
        # Nothing here refers to another app's secret; coding-agent's required LLM_GATEWAY_KEY refers
        # to APP_KEY_CODING_AGENT, so that one is required (and generated) too.
        self.assertFalse([s for s in secrets.values() if "same_as" in s])
        self.assertIn("same_as", secrets["APP_KEY_CODING_AGENT"]["description"])
        self.assertEqual(secrets["APP_KEY_CODING_AGENT"]["generate"], "sk-hex32")
        self.assertFalse(secrets["APP_KEY_CODING_AGENT"].get("optional", False))

    def test_only_app_keys_are_shared_and_only_with_their_app(self):
        """D-059: a secret can be referenced (same_as) only by the apps its share_with lists."""
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        self.assertEqual(secrets["APP_KEY_CODING_AGENT"]["share_with"], ["coding-agent"])
        app_keys = yaml.safe_load(read(os.path.join(IMAGE_DIR, "app_keys.yaml")))["apps"]
        shared = {name: s["share_with"] for name, s in secrets.items() if "share_with" in s}
        # Each virtual key the keys job provisions is shared with exactly the app it is for.
        self.assertEqual(shared, {e["secret"]: [e["app"]] for e in app_keys})
        for name in ("LITELLM_MASTER_KEY", "LITELLM_SALT_KEY", "POSTGRES_PASSWORD", "OLLAMA_GATE_KEY"):
            self.assertNotIn("share_with", secrets[name])
        self.assertIn("share_with", secrets["APP_KEY_CODING_AGENT"]["description"])

    def test_every_catalog_reference_to_this_app_is_opted_in(self):
        """Every same_as in the catalog that points here names a secret shared with that app."""
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        found = []
        for root, _dirs, files in os.walk(CATALOG_DIR):
            if "manifest.yaml" not in files or "node_modules" in root:
                continue
            manifest = yaml.safe_load(read(os.path.join(root, "manifest.yaml")))
            for secret in manifest.get("secrets") or []:
                ref = secret.get("same_as", "")
                if not ref.startswith("llm-gateway/"):
                    continue
                target = secrets.get(ref.split("/", 1)[1])
                found.append((manifest["id"], ref))
                self.assertIsNotNone(target, ref)
                self.assertIn(manifest["id"], target.get("share_with") or [], (root, ref))
        # coding-agent and its OpenCode variant both refer to APP_KEY_CODING_AGENT.
        self.assertEqual(sorted(found), [("coding-agent", "llm-gateway/APP_KEY_CODING_AGENT")] * 2)

    def test_provider_secrets_match_manifest_and_fragment(self):
        secrets = {s["name"]: s for s in self.manifest["secrets"]}
        wanted = set(self.services["llm-gateway-litellm"]["x-sealed-secrets"])
        names = [p["secret"] for f in ("byok", "external") for p in self.providers[f]]
        names += ["BYOK_ROUTES_ENABLED", "EXTERNAL_ROUTES_ENABLED"]
        for name in names:
            self.assertIn(name, secrets)
            self.assertTrue(secrets[name].get("optional"), name)
            self.assertEqual(secrets[name]["generate"], "none", name)
            self.assertIn(name, wanted)
        used = set()
        for svc in self.services.values():
            used |= set(svc.get("x-sealed-secrets") or [])
        self.assertEqual(used, set(secrets))
        for p in self.providers["external"] + self.providers["byok"]:
            self.assertIn("data leaves your cloud", secrets[p["secret"]]["description"])
        self.assertIn("not verify", secrets["BYOK_ROUTES_ENABLED"]["description"])

    def test_master_key_stays_in_the_gateway(self):
        holders = {n for n, svc in self.services.items() if "LITELLM_MASTER_KEY" in (svc.get("x-sealed-secrets") or [])}
        self.assertEqual(holders, {"llm-gateway-litellm", "llm-gateway-keys"})
        app_keys = yaml.safe_load(read(os.path.join(IMAGE_DIR, "app_keys.yaml")))["apps"]
        keys_svc = self.services["llm-gateway-keys"]
        for entry in app_keys:
            self.assertIn(entry["secret"], keys_svc["x-sealed-secrets"])
            self.assertNotIn(entry["secret"], self.services["llm-gateway-litellm"]["x-sealed-secrets"])
        self.assertEqual(keys_svc["environment"]["SEALED_GATEWAY_URL"], "http://llm-gateway-litellm:4000")
        self.assertEqual(keys_svc["depends_on"], {"llm-gateway-litellm": {"condition": "service_healthy"}})
        self.assertTrue(keys_svc["read_only"])
        self.assertNotEqual(keys_svc["user"].split(":")[0], "0")

    def test_config_targets_exist(self):
        bases = {m["litellm_params"].get("api_base") for m in self.config["model_list"]}
        self.assertEqual(bases, {"http://llm-gateway-ollama:11434", "http://sealed-mpp-payer:8090/v1"})
        self.assertIn("llm-gateway-ollama", self.services)
        names = [m["model_name"] for m in self.config["model_list"]]
        self.assertEqual(names, ["local/qwen3-4b", "local/*", "relay/default", "relay/*"])
        self.assertEqual(self.config["router_settings"]["fallbacks"], [{"relay/default": ["local/qwen3-4b"]}])
        self.assertEqual(self.services["llm-gateway-litellm"]["environment"]["SEALED_DB_HOST"], "llm-gateway-db")

    def test_usage_url_is_agent(self):
        env = self.services["llm-gateway-litellm"]["environment"]
        self.assertEqual(env["SEALED_USAGE_URL"], "http://sealed-agent:7070/v1/usage-events")

    def test_fragment_never_sets_forbidden_env(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("ep", os.path.join(IMAGE_DIR, "sealed_entrypoint.py"))
        ep = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ep)
        for name, svc in self.services.items():
            env = svc.get("environment") or {}
            self.assertFalse(set(env) & set(ep.FORBIDDEN_ENV), name)
            self.assertNotEqual(env.get("LITELLM_LOG", "").upper(), "DEBUG")
        self.assertFalse(set(self.manifest["telemetry_off_env"]) & set(ep.FORBIDDEN_ENV))

    def test_postgres_pin(self):
        images = {i["name"]: i for i in self.manifest["images"]}
        self.assertEqual(images["postgres"]["digest"], POSTGRES_DIGEST)
        self.assertEqual(images["postgres"]["source"], "docker.io/library/postgres:16.15")
        self.assertEqual(images["litellm"]["source"], "build:images/litellm")
        self.assertEqual(images["local-model"]["source"], "build:images/local-model")

    def test_build_sources_resolve_under_the_app(self):
        """build:<dir> is relative to the app directory (as the other catalog apps resolve it)."""
        for image in self.manifest["images"]:
            if image["source"].startswith("build:"):
                rel = image["source"][len("build:"):]
                self.assertTrue(os.path.isfile(os.path.join(APP_DIR, rel, "Dockerfile")), rel)
        target = os.path.realpath(os.path.join(APP_DIR, "images", "local-model"))
        self.assertEqual(target, os.path.realpath(os.path.join(sealed_compose.REPO_ROOT, "runtime", "images", "local-model")))

    def test_ollama_service_locked_down(self):
        svc = self.services["llm-gateway-ollama"]
        self.assertTrue(svc["read_only"])
        self.assertEqual(svc["user"], "10002:10002")
        self.assertEqual(svc["environment"]["HOME"], "/tmp/ollama")
        self.assertEqual(svc["entrypoint"], ["/usr/local/bin/sealed-ollama-gate"])
        command = svc["command"]
        sep = command.index("--")
        self.assertEqual(command[sep + 1:], ["/bin/ollama", "serve"])
        flags = dict(zip(command[:sep:2], command[1:sep:2]))
        self.assertEqual(flags, {"-listen": "0.0.0.0:11434", "-upstream": "127.0.0.1:11435",
                                 "-allow-peer": "llm-gateway-litellm", "-key-env": "OLLAMA_GATE_KEY"})
        self.assertIn("llm-gateway-litellm", self.services)
        self.assertEqual(svc["healthcheck"]["test"][1:], ["/usr/local/bin/sealed-ollama-gate", "probe",
                                                          "http://127.0.0.1:11434/healthz"])
        # Per-service secret mounts (integration brief item 5): Ollama gets its gate key and nothing else.
        self.assertEqual(svc["x-sealed-secrets"], ["OLLAMA_GATE_KEY"])
        self.assertIn("OLLAMA_GATE_KEY", self.services["llm-gateway-litellm"]["x-sealed-secrets"])
        holders = {n for n, s in self.services.items() if "OLLAMA_GATE_KEY" in (s.get("x-sealed-secrets") or [])}
        self.assertEqual(holders, {"llm-gateway-litellm", "llm-gateway-ollama"})
        local = [m for m in self.config["model_list"] if m["model_name"].startswith("local/")]
        self.assertEqual(len(local), 2)
        for entry in local:
            self.assertEqual(entry["litellm_params"]["api_base"], "http://llm-gateway-ollama:11434")
            self.assertEqual(entry["litellm_params"]["api_key"], "os.environ/OLLAMA_GATE_KEY")


def envexec_secrets(service):
    """Secret names a composed service's envexec entrypoint exports (--secret / --optional-secret)."""
    entry = service["entrypoint"]
    sep = entry.index("--")
    return {entry[i + 1] for i in range(sep) if entry[i] in ("--secret", "--optional-secret")}


class LicenseTextsTest(unittest.TestCase):
    """License audit F10: LICENSES/ holds the upstream texts byte for byte, as LICENSE-NOTICE says."""

    EXPECTED = {
        "litellm-v1.106.5-LICENSE": ("BerriAI/litellm", "v1.106.5", "LICENSE"),
        "ollama-v0.40.12-LICENSE": ("ollama/ollama", "v0.40.12", "LICENSE"),
        "go-1.27.3-LICENSE": ("golang/go", "go1.27.3", "LICENSE"),
        "go-1.27.3-PATENTS": ("golang/go", "go1.27.3", "PATENTS"),
        "postgresql-16.15-COPYRIGHT": ("postgres/postgres", "REL_16_15", "COPYRIGHT"),
    }

    def test_texts_match_upstream(self):
        self.assertEqual(license_texts.problems(APP_DIR), [])

    def test_the_expected_texts_are_shipped(self):
        texts = license_texts.notice_texts(read(os.path.join(APP_DIR, "LICENSE-NOTICE")))
        self.assertEqual({t.file: (t.repo, t.ref, t.path) for t in texts}, self.EXPECTED)
        manifest = yaml.safe_load(read(os.path.join(APP_DIR, "manifest.yaml")))
        litellm = next(t for t in texts if t.repo == "BerriAI/litellm")
        self.assertEqual("https://github.com/" + litellm.repo, manifest["upstream"]["repo"])
        self.assertEqual(litellm.ref, manifest["upstream"]["version"])
        self.assertIn("enterprise/", read(os.path.join(APP_DIR, "LICENSES", litellm.file)))
        # The Go texts are those of the toolchain that builds sealed-ollama-gate.
        gate = read(os.path.join(APP_DIR, "images", "local-model", "Dockerfile"))
        self.assertIn("ARG GO_BASE=golang:1.27.3-", gate)

    def test_the_check_catches_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = os.path.join(tmp, "app")
            os.makedirs(os.path.join(app, "LICENSES"))
            for name in ("LICENSE-NOTICE",):
                with open(os.path.join(app, name), "w", encoding="utf-8") as handle:
                    handle.write(read(os.path.join(APP_DIR, name)))
            for name in self.EXPECTED:
                with open(os.path.join(APP_DIR, "LICENSES", name), "rb") as src, \
                        open(os.path.join(app, "LICENSES", name), "wb") as dst:
                    dst.write(src.read())
            self.assertEqual(license_texts.problems(app), [])
            # One changed byte (a CRLF line ending counts), an unlisted file, a missing file.
            path = os.path.join(app, "LICENSES", "ollama-v0.40.12-LICENSE")
            with open(path, "rb") as handle:
                data = handle.read()
            with open(path, "wb") as handle:
                handle.write(data.replace(b"\n", b"\r\n", 1))
            with open(os.path.join(app, "LICENSES", "extra-LICENSE"), "w") as handle:
                handle.write("x")
            os.remove(os.path.join(app, "LICENSES", "go-1.27.3-PATENTS"))
            found = "\n".join(license_texts.problems(app))
            self.assertIn("ollama-v0.40.12-LICENSE: git blob", found)
            self.assertIn("extra-LICENSE is not named", found)
            self.assertIn("go-1.27.3-PATENTS is missing", found)

    def test_git_blob_hash_matches_git(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"hello\n")
        try:
            # `printf 'hello\n' | git hash-object --stdin`
            self.assertEqual(license_texts.git_blob_hash(handle.name), "ce013625030ba8dba906f756967f9e9ca394464a")
        finally:
            os.unlink(handle.name)


class ComposerTest(unittest.TestCase):
    """The real composer on this app: lint findings and the composed stack."""

    @classmethod
    def setUpClass(cls):
        cls.composer = sealed_compose.composer_for(cls)
        cls.app = sealed_compose.load_app(APP_DIR)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.stack = cls.composer.compose([APP_DIR], os.path.join(cls.tmp.name, "out"))
        cls.composed = cls.stack["compose"]["services"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_lint_only_blocks_on_the_unbuilt_images(self):
        findings = self.composer.lint([APP_DIR])
        self.assertEqual(sealed_compose.unexpected(findings), [])
        unbuilt = sorted(f["field"] for f in findings if f["code"] == "unbuilt-image")
        names = sealed_compose.unbuilt_images(self.app["manifest"])
        self.assertEqual(len(unbuilt), len(names), unbuilt)
        self.assertEqual(sorted(names), ["litellm", "local-model"])

    def test_composed_services(self):
        fragment = set(self.app["fragment"]["services"])
        self.assertTrue(fragment <= set(self.composed))
        self.assertIn("sealed-mpp-payer", self.composed)

    def test_each_service_exports_only_its_declared_secrets(self):
        for name, svc in self.app["fragment"]["services"].items():
            self.assertEqual(envexec_secrets(self.composed[name]), set(svc.get("x-sealed-secrets") or []), name)
        self.assertEqual(envexec_secrets(self.composed["llm-gateway-ollama"]), {"OLLAMA_GATE_KEY"})

    def test_secret_files_are_mounted_per_service(self):
        if not self.composer.brief:
            self.skipTest(f"composer {self.composer.version} mounts the whole app secret directory "
                          "(per-service mounts arrive with 1.2.0, integration brief item 5)")
        root = "/run/sealed/secrets/llm-gateway"
        for name, svc in self.app["fragment"]["services"].items():
            want = {f"{root}/{s}" for s in svc.get("x-sealed-secrets") or []}
            self.assertEqual(sealed_compose.secret_mounts(self.composed[name], "llm-gateway"), want, name)

    def test_only_the_gateway_itself_is_on_the_shared_network(self):
        """D-041: other apps reach llm-gateway-litellm only; Postgres, Ollama and the keys job stay private."""
        if not self.composer.brief:
            self.skipTest(f"composer {self.composer.version} has one shared network (per-app networks arrive with 1.2.0)")
        for name in self.app["fragment"]["services"]:
            networks = set(self.composed[name]["networks"])
            self.assertIn("app-llm-gateway", networks, name)
            self.assertEqual("apps" in networks, name == "llm-gateway-litellm", name)

    def test_gateway_route_passes_bearer_keys(self):
        site = sealed_compose.caddy_site(self.stack["caddyfile"], "gateway.34-1-2-3.sslip.io")
        self.assertIsNotNone(site)
        self.assertIn("reverse_proxy llm-gateway-litellm:4000", site)
        self.assertIn('header Authorization "Bearer *"', site)

    def test_docker_compose_accepts_the_composed_document(self):
        result = sealed_compose.docker_compose_config(self.stack["compose_path"])
        if result is None:
            self.skipTest("docker CLI not installed")
        self.assertEqual(result[0], 0, result[1])


class LitellmDockerfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read(os.path.join(IMAGE_DIR, "Dockerfile"))
        cls.args, cls.stages = dockerfile_lint.stages(cls.text)
        cls.final = cls.stages[-1]

    def test_base_pinned(self):
        self.assertEqual(self.stages[0].base, LITELLM_BASE)
        for stage in self.stages:
            if stage.base != "scratch" and stage.base not in {s.name for s in self.stages}:
                self.assertTrue(dockerfile_lint.is_digest_pinned(stage.base), stage.base)

    def test_enterprise_removed_and_checked(self):
        run = " ".join(self.stages[0].all("RUN"))
        self.assertIn("rm -rf /app/enterprise", run)
        self.assertIn('"$SP/litellm_enterprise"', run)
        self.assertIn("litellm_enterprise-*.dist-info", run)
        self.assertIn("find_spec('litellm_enterprise') is None", run)

    def test_flattened(self):
        self.assertEqual(self.final.base, "scratch")
        self.assertEqual(self.final.all("COPY"), ["--from=upstream / /"])
        self.assertEqual(len(self.stages), 2)

    def test_final_env_matches_telemetry_off_env(self):
        manifest = yaml.safe_load(read(os.path.join(APP_DIR, "manifest.yaml")))
        env = self.final.env()
        for key, value in manifest["telemetry_off_env"].items():
            if key.startswith(("LITELLM_", "HF_HUB_", "PRISMA_", "CHECKPOINT_", "DISABLE_ADMIN", "NO_")):
                self.assertEqual(env.get(key), value, key)
        self.assertEqual(env["LITELLM_LOG"], "ERROR")
        self.assertEqual(env["LITELLM_MODE"], "PRODUCTION")
        self.assertNotIn("LITELLM_LICENSE", env)

    def test_entrypoint_matches_fragment(self):
        fragment = yaml.safe_load(read(os.path.join(APP_DIR, "compose.fragment.yaml")))
        svc = fragment["services"]["llm-gateway-litellm"]
        self.assertEqual(self.final.exec_form("ENTRYPOINT"), svc["entrypoint"])

    def test_build_checks_the_relay_retry_guard(self):
        """D-067: the build checks the rendered relay/ routes and the pre-call hook against real LiteLLM."""
        run = " ".join(self.stages[0].all("RUN"))
        self.assertIn("p['max_retries'] == 0 and p['num_retries'] == 0", run)
        self.assertIn("cls.async_pre_call_hook is not CustomLogger.async_pre_call_hook", run)
        self.assertIn("inspect.signature(cls.async_pre_call_hook)", run)

    def test_build_context_files_exist(self):
        for arg in self.stages[0].all("COPY"):
            for name in arg.split()[:-1]:
                self.assertTrue(os.path.exists(os.path.join(IMAGE_DIR, name)), name)


if __name__ == "__main__":
    unittest.main()
