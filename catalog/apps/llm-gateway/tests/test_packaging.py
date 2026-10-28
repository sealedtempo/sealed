"""Packaging tests for llm-gateway: manifest, fragment, egress, Dockerfiles and their consistency."""
from __future__ import annotations

import os
import sys
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import catalog_lint  # noqa: E402
import dockerfile_lint  # noqa: E402

APP_DIR = os.path.normpath(os.path.join(HERE, ".."))
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
        cls.app = catalog_lint.load_app(APP_DIR)
        cls.manifest = cls.app["manifest"]
        cls.services = cls.app["fragment"]["services"]
        cls.providers = yaml.safe_load(read(os.path.join(IMAGE_DIR, "providers.yaml")))
        cls.config = yaml.safe_load(read(os.path.join(IMAGE_DIR, "config.yaml")))
        cls.dockerfile = read(os.path.join(IMAGE_DIR, "Dockerfile"))

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
        code, out = result
        self.assertEqual(code, 0, out)
        parsed = yaml.safe_load(out)
        self.assertEqual(sorted(parsed["services"]),
                         ["llm-gateway-db", "llm-gateway-keys", "llm-gateway-litellm", "llm-gateway-ollama"])
        self.assertIn("LITELLM_MASTER_KEY", parsed["services"]["llm-gateway-litellm"]["x-sealed-secrets"])
        self.assertEqual(parsed["services"]["llm-gateway-ollama"]["user"], "10002:10002")

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
        for name in ("LITELLM_MASTER_KEY", "LITELLM_SALT_KEY", "POSTGRES_PASSWORD"):
            self.assertFalse(secrets[name].get("optional", False))

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
        self.assertEqual(target, os.path.realpath(os.path.join(catalog_lint.REPO_ROOT, "runtime", "images", "local-model")))

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
                                 "-allow-peer": "llm-gateway-litellm"})
        self.assertIn("llm-gateway-litellm", self.services)
        self.assertEqual(svc["healthcheck"]["test"][1:], ["/usr/local/bin/sealed-ollama-gate", "probe",
                                                          "http://127.0.0.1:11434/healthz"])
        # Ollama holds no secret, so the app's secret directory is not mounted into it.
        self.assertNotIn("x-sealed-secrets", svc)
        local = [m for m in self.config["model_list"] if m["model_name"].startswith("local/")]
        for entry in local:
            self.assertEqual(entry["litellm_params"]["api_base"], "http://llm-gateway-ollama:11434")


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

    def test_build_context_files_exist(self):
        for arg in self.stages[0].all("COPY"):
            for name in arg.split()[:-1]:
                self.assertTrue(os.path.exists(os.path.join(IMAGE_DIR, name)), name)


if __name__ == "__main__":
    unittest.main()
