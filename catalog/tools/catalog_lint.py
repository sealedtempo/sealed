"""Shared catalog tooling for Python app suites (integration brief item 25).

A thin wrapper around the composer's lint command (runtime/composer/cmd/sealed-compose), which is
the only authority for the catalog rules; the Node twin is catalog-lint.mjs. Standard library only.

    python3 catalog/tools/catalog_lint.py [--json] [--require-sbom] <app dir>...

The binary comes from SEALED_COMPOSE_BIN, or is built once per process with `go build` from this
checkout (or SEALED_COMPOSER_DIR).
"""
from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
COMPOSER_MAIN = "runtime/composer/cmd/sealed-compose"

_built: Optional[str] = None


class ComposerUnavailable(RuntimeError):
    """Neither SEALED_COMPOSE_BIN nor Go with the composer sources is available."""


def find_composer() -> str:
    """Returns the path of a sealed-compose binary, building it if needed."""
    global _built
    env_bin = os.environ.get("SEALED_COMPOSE_BIN")
    if env_bin:
        if not os.path.exists(env_bin):
            raise ComposerUnavailable(f"SEALED_COMPOSE_BIN {env_bin} does not exist")
        return os.path.abspath(env_bin)
    if _built:
        return _built
    dirs = [d for d in (os.environ.get("SEALED_COMPOSER_DIR"), REPO_ROOT) if d]
    src = next((d for d in dirs if os.path.exists(os.path.join(d, COMPOSER_MAIN, "main.go"))), None)
    if src is None:
        raise ComposerUnavailable("composer sources not found (set SEALED_COMPOSE_BIN or SEALED_COMPOSER_DIR)")
    if shutil.which("go") is None:
        raise ComposerUnavailable("go is not installed")
    tmp = tempfile.mkdtemp(prefix="sealed-compose-")
    atexit.register(shutil.rmtree, tmp, True)
    out = os.path.join(tmp, "sealed-compose")
    res = subprocess.run(["go", "build", "-o", out, "./" + COMPOSER_MAIN], cwd=src, capture_output=True, text=True, timeout=600)
    if res.returncode != 0:
        raise RuntimeError("building sealed-compose failed: " + res.stderr)
    _built = out
    return out


def composer_lint(app_dirs: list[str] | str, require_sbom: bool = False, registry: Optional[str] = None) -> list[dict[str, Any]]:
    """sealed-compose lint --json: the findings whatever the exit code."""
    if isinstance(app_dirs, str):
        app_dirs = [app_dirs]
    args = [find_composer(), "lint", "--json"]
    if require_sbom:
        args.append("--require-sbom")
    if registry:
        args += ["--registry", registry]
    for d in app_dirs:
        args += ["--app-dir", os.path.abspath(d)]
    res = subprocess.run(args, cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("sealed-compose lint failed: " + res.stderr) from exc


def errors_of(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if f.get("severity") == "error"]


def format_finding(f: dict[str, Any]) -> str:
    loc = f.get("app", "")
    if f.get("file"):
        loc += "/" + f["file"]
    if f.get("field"):
        loc += " " + f["field"]
    return f"{f.get('severity')}: {loc} [{f.get('code')}] {f.get('message')}"


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    require_sbom = "--require-sbom" in argv
    dirs = [a for a in argv if not a.startswith("--")]
    if not dirs:
        print("usage: catalog_lint.py [--json] [--require-sbom] <app dir>...", file=sys.stderr)
        return 2
    try:
        findings = composer_lint(dirs, require_sbom=require_sbom)
    except ComposerUnavailable as exc:
        print(f"catalog_lint: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(format_finding(f))
    return 1 if errors_of(findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
