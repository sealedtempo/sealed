"""Tests for catalog_lint.py (standard library only): python3 -m unittest discover catalog/tools"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import catalog_lint  # noqa: E402

FIXTURES = os.path.join(catalog_lint.REPO_ROOT, "runtime", "composer", "testdata", "apps")

try:
    COMPOSER = catalog_lint.find_composer()
    SKIP = ""
except catalog_lint.ComposerUnavailable as exc:
    if os.environ.get("SEALED_REQUIRE_COMPOSER") == "1":
        raise
    COMPOSER, SKIP = None, str(exc)


@unittest.skipIf(SKIP, SKIP)
class ComposerLintTest(unittest.TestCase):
    def test_clean_fixtures(self) -> None:
        for app in ("notes", "llm-gateway", "inference-relay"):
            findings = catalog_lint.composer_lint(os.path.join(FIXTURES, app), require_sbom=True)
            self.assertEqual(catalog_lint.errors_of(findings), [], app)

    def test_errors_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = os.path.join(tmp, "notes")
            shutil.copytree(os.path.join(FIXTURES, "notes"), app)
            path = os.path.join(app, "compose.fragment.yaml")
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text.replace('    user: "1000"', "    privileged: true"))
            errors = catalog_lint.errors_of(catalog_lint.composer_lint(app))
            self.assertTrue(any(f["code"] == "fragment" and "privileged" in f["message"] for f in errors), errors)
            env = dict(os.environ, SEALED_COMPOSE_BIN=COMPOSER)
            cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog_lint.py")
            res = subprocess.run([sys.executable, cli, app], capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 1)
            self.assertIn("[fragment]", res.stdout)
            ok = subprocess.run([sys.executable, cli, os.path.join(FIXTURES, "notes")], capture_output=True, text=True, env=env)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)


if __name__ == "__main__":
    unittest.main()
