"""Tests for catalog_lint.py (standard library only): python3 -m unittest discover catalog/tools"""
from __future__ import annotations

import json
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

    def test_release_license_rules(self) -> None:
        # License audit F5 and F6, through the wrapper: no license metadata fails a release
        # unless a reviewed override covers it; license_exclusions globs match the file list.
        with tempfile.TemporaryDirectory() as tmp:
            app = os.path.join(tmp, "notes")
            shutil.copytree(os.path.join(FIXTURES, "notes"), app)
            manifest = os.path.join(app, "manifest.yaml")
            with open(manifest, encoding="utf-8") as fh:
                text = fh.read()
            with open(manifest, "w", encoding="utf-8") as fh:
                fh.write(text.replace("license_exclusions: []", 'license_exclusions: ["ms-playwright/chromium-*"]'))

            def pkg(name: str, version: str) -> dict:
                return {"SPDXID": "SPDXRef-" + name, "name": name, "versionInfo": version, "licenseConcluded": "NOASSERTION",
                        "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:npm/{name}@{version}"}]}

            sbom = {"spdxVersion": "SPDX-2.3", "name": "notes-web",
                    "packages": [pkg("pause-stream", "0.0.11"), pkg("left-pad", "1.3.0")],
                    "files": [{"SPDXID": "SPDXRef-f1", "fileName": "root/.cache/ms-playwright/chromium-1187/chrome-linux/chrome"},
                              {"SPDXID": "SPDXRef-f2", "fileName": "root/.cache/ms-playwright/firefox-1490/firefox/firefox"}]}
            with open(os.path.join(app, "sbom", "notes-web.spdx.json"), "w", encoding="utf-8") as fh:
                json.dump(sbom, fh)
            errors = catalog_lint.errors_of(catalog_lint.composer_lint(app, require_sbom=True))
            self.assertEqual([f["field"] for f in errors if f["code"] == "sbom-no-license"], ["left-pad@1.3.0"], errors)
            self.assertEqual([f["field"] for f in errors if f["code"] == "excluded-path"], ["/root/.cache/ms-playwright/chromium-1187/"], errors)
            self.assertFalse([f for f in catalog_lint.errors_of(catalog_lint.composer_lint(app)) if f["code"] == "sbom-no-license"])


def _tracked_files() -> list[str] | None:
    """The repository's tracked files, or None outside a git work tree (a source archive)."""
    git = shutil.which("git")
    if not git:
        return None
    res = subprocess.run([git, "-C", catalog_lint.REPO_ROOT, "ls-files", "-z"], capture_output=True, timeout=60)
    if res.returncode != 0:
        return None
    return [f for f in res.stdout.decode("utf-8", "surrogateescape").split("\0") if f]


class RepositoryHygieneTest(unittest.TestCase):
    """D-057 and D-069: build outputs never enter history. These tests write __pycache__ next to this file."""

    def test_no_python_bytecode_is_tracked(self) -> None:
        files = _tracked_files()
        if files is None:
            self.skipTest("not a git work tree")
        self.assertIn("catalog/tools/test_catalog_lint.py", files)
        bytecode = [f for f in files if "__pycache__/" in f or f.endswith((".pyc", ".pyo", ".pyd"))]
        self.assertEqual(bytecode, [], "untrack them with git rm --cached and keep __pycache__/ in .gitignore")

    def test_bytecode_here_is_ignored(self) -> None:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gitignore"), encoding="utf-8") as fh:
            self.assertIn("__pycache__/", fh.read().split())


if __name__ == "__main__":
    unittest.main()
