"""Negative tests for catalog_lint.py: each INTERFACES section 14 rule rejects a bad fragment."""
from __future__ import annotations

import os
import sys
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import catalog_lint  # noqa: E402
import dockerfile_lint  # noqa: E402

MANIFEST = {
    "id": "demo",
    "images": [{"name": "web", "source": "docker.io/x/web:1", "digest": "sha256:" + "1" * 64}],
    "secrets": [{"name": "API_KEY", "description": "x", "generate": "hex32"}],
}
GOOD = """
services:
  demo-web:
    image: "{{image:web}}"
    entrypoint: ["/bin/web"]
    command: ["--port", "80"]
    x-sealed-secrets: [API_KEY]
    environment: {MODE: prod}
    volumes: ["demo-data:/data"]
    depends_on: {demo-db: {condition: service_healthy}}
  demo-db:
    image: "{{image:web}}"
    entrypoint: ["/bin/db"]
volumes:
  demo-data: {}
"""


def lint(text, manifest=MANIFEST):
    return catalog_lint.lint_fragment("demo", manifest, yaml.safe_load(text), text)


def mutate(path, value):
    doc = yaml.safe_load(GOOD)
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return yaml.safe_dump(doc)


class FragmentRulesTest(unittest.TestCase):
    def test_good_fragment(self):
        self.assertEqual(lint(GOOD), [])

    def assertRejected(self, text, needle):
        errors = lint(text)
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_forbidden_keys(self):
        for key, value in (("ports", ["80:80"]), ("privileged", True), ("networks", ["apps"]),
                           ("cap_add", ["SYS_ADMIN"]), ("env_file", ["x.env"]), ("build", "."),
                           ("network_mode", "host"), ("secrets", ["x"]), ("extra_hosts", ["a:1.2.3.4"])):
            self.assertRejected(mutate(["services", "demo-web", key], value), f"{key}: key is not allowed")

    def test_top_level_keys(self):
        self.assertRejected(GOOD + "networks: {apps: {}}\n", "top-level key 'networks'")

    def test_service_prefix(self):
        doc = yaml.safe_load(GOOD)
        doc["services"]["web"] = doc["services"].pop("demo-web")
        doc["services"]["demo-db"]["depends_on"] = {"web": {"condition": "service_started"}}
        self.assertRejected(yaml.safe_dump(doc), "must start with demo-")

    def test_image_refs(self):
        self.assertRejected(mutate(["services", "demo-web", "image"], "nginx:latest"), "must be {{image:<name>}}")
        self.assertRejected(mutate(["services", "demo-web", "image"], "{{image:other}}"), "not listed in manifest images")

    def test_entrypoint_required(self):
        doc = yaml.safe_load(GOOD)
        del doc["services"]["demo-web"]["entrypoint"]
        self.assertRejected(yaml.safe_dump(doc), "explicit entrypoint required")

    def test_secrets(self):
        self.assertRejected(mutate(["services", "demo-web", "x-sealed-secrets"], ["NOPE"]), "not in manifest secrets")
        self.assertRejected(mutate(["services", "demo-web", "environment"], {"API_KEY": "leak"}),
                            "secrets must come from x-sealed-secrets")

    def test_volumes(self):
        self.assertRejected(mutate(["services", "demo-web", "volumes"], ["/var/run/docker.sock:/var/run/docker.sock"]),
                            "not a named volume")
        self.assertRejected(mutate(["services", "demo-web", "volumes"], ["other:/data"]), "not a named volume")
        self.assertRejected(mutate(["volumes"], {"data": {}, "demo-data": {}}), "volumes.data")

    def test_depends_on_other_app(self):
        self.assertRejected(mutate(["services", "demo-web", "depends_on"], {"llm-gateway-litellm": {}}),
                            "not a service of this app")

    def test_dollar_is_rejected(self):
        self.assertRejected(mutate(["services", "demo-web", "environment"], {"MODE": "x$y"}), "contains '$'")

    def test_non_string_env(self):
        self.assertRejected(mutate(["services", "demo-web", "environment"], {"N": 3}), "value must be a string")


class EgressRulesTest(unittest.TestCase):
    def test_good(self):
        self.assertEqual(catalog_lint.lint_egress({"version": 1, "default_allow": ["api.example.com:443", "*.x.io:443"],
                                                   "customer_additions_allowed": True, "notes": "why"}), [])

    def test_bad(self):
        errors = catalog_lint.lint_egress({"version": 2, "default_allow": ["https://x.com"],
                                           "customer_additions_allowed": "yes", "notes": ""})
        self.assertEqual(len(errors), 4, errors)
        self.assertTrue(catalog_lint.lint_egress({"version": 1}))


class SubstituteTest(unittest.TestCase):
    def test_dummy_digests_are_stable(self):
        a = catalog_lint.substitute_images('image: "{{image:web}}"')
        self.assertEqual(a, catalog_lint.substitute_images('image: "{{image:web}}"'))
        self.assertRegex(a, r"ghcr.io/sealed-dev/web@sha256:[0-9a-f]{64}")


class DockerfileReaderTest(unittest.TestCase):
    def test_stages_and_env(self):
        text = (
            "# syntax=docker/dockerfile:1.7\nARG BASE=img:1@sha256:" + "a" * 64 + "\n"
            "FROM --platform=linux/amd64 ${BASE} AS one\nRUN echo a \\\n    && echo b\nENV A=1 \\\n    B=two\n"
            "FROM scratch\nCOPY --from=one / /\nENTRYPOINT [\"/bin/x\", \"-y\"]\n"
        )
        args, stages = dockerfile_lint.stages(text)
        self.assertEqual(stages[0].base, "img:1@sha256:" + "a" * 64)
        self.assertEqual(stages[0].name, "one")
        self.assertEqual(stages[0].all("RUN"), ["echo a      && echo b"])
        self.assertEqual(stages[0].env(), {"A": "1", "B": "two"})
        self.assertEqual(stages[1].exec_form("ENTRYPOINT"), ["/bin/x", "-y"])
        self.assertTrue(dockerfile_lint.is_digest_pinned(stages[0].base))
        self.assertFalse(dockerfile_lint.is_digest_pinned("img:latest"))


if __name__ == "__main__":
    unittest.main()
