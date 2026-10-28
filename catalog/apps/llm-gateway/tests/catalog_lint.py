"""Local checks for a catalog app directory against INTERFACES sections 7 and 14.

Used by the unit tests of llm-gateway and coding-agent. It mirrors the composer's
fragment rules so packaging mistakes show up before CI. Requires PyYAML; jsonschema and
the docker CLI are optional (checks that need them report themselves as skipped).

    python catalog_lint.py <app dir> [<app dir> ...]
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Optional

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCHEMA_PATH = os.path.join(REPO_ROOT, "catalog", "schema", "manifest.schema.json")

ALLOWED_SERVICE_KEYS = {
    "image", "command", "entrypoint", "environment", "healthcheck", "depends_on", "volumes",
    "tmpfs", "user", "working_dir", "read_only", "stop_grace_period", "shm_size", "ulimits",
    "mem_limit", "cpus", "labels", "x-sealed-secrets",
}
IMAGE_REF = re.compile(r"^\{\{image:([a-z][a-z0-9-]*)\}\}$")
ZERO_DIGEST = "sha256:" + "0" * 64
HOST_PORT = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?:[0-9]{1,5}$")
DUMMY_REGISTRY = "ghcr.io/sealed-dev"


def load_yaml(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_app(app_dir: str, manifest_name: str = "manifest.yaml") -> dict[str, Any]:
    manifest = load_yaml(os.path.join(app_dir, manifest_name))
    fragment_path = os.path.join(app_dir, manifest.get("compose_fragment", "compose.fragment.yaml"))
    egress_path = os.path.join(app_dir, manifest.get("egress_policy", "egress.yaml"))
    with open(fragment_path, "r", encoding="utf-8") as handle:
        fragment_text = handle.read()
    return {
        "dir": app_dir,
        "manifest": manifest,
        "fragment_text": fragment_text,
        "fragment": yaml.safe_load(fragment_text),
        "egress": load_yaml(egress_path),
    }


def lint_fragment(app_id: str, manifest: dict[str, Any], fragment: Any, fragment_text: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(fragment, dict):
        return ["fragment: not a mapping"]
    for key in fragment:
        if key not in ("services", "volumes"):
            errors.append(f"fragment: top-level key {key!r} is not allowed")
    if "$" in fragment_text:
        errors.append("fragment: contains '$' (compose interpolation would change measured values)")

    services = fragment.get("services") or {}
    volumes = fragment.get("volumes") or {}
    image_names = {img["name"] for img in manifest.get("images", [])}
    secret_names = {s["name"] for s in manifest.get("secrets", [])}
    prefix = f"{app_id}-"

    for vol in volumes:
        if not str(vol).startswith(prefix):
            errors.append(f"volumes.{vol}: name must start with {prefix}")

    for name, svc in services.items():
        where = f"services.{name}"
        if not name.startswith(prefix):
            errors.append(f"{where}: service name must start with {prefix}")
        if not isinstance(svc, dict):
            errors.append(f"{where}: not a mapping")
            continue
        for key in svc:
            if key not in ALLOWED_SERVICE_KEYS:
                errors.append(f"{where}.{key}: key is not allowed")
        match = IMAGE_REF.match(str(svc.get("image", "")))
        if not match:
            errors.append(f"{where}.image: must be {{{{image:<name>}}}}")
        elif match.group(1) not in image_names:
            errors.append(f"{where}.image: {match.group(1)} is not listed in manifest images")
        if "entrypoint" not in svc:
            errors.append(f"{where}.entrypoint: explicit entrypoint required")
        elif not isinstance(svc["entrypoint"], list) or not svc["entrypoint"]:
            errors.append(f"{where}.entrypoint: must be a non-empty list")
        if "command" in svc and not isinstance(svc["command"], list):
            errors.append(f"{where}.command: must be a list")
        wanted = svc.get("x-sealed-secrets") or []
        for secret in wanted:
            if secret not in secret_names:
                errors.append(f"{where}.x-sealed-secrets: {secret} is not in manifest secrets")
        env = svc.get("environment") or {}
        if not isinstance(env, dict):
            errors.append(f"{where}.environment: must be a mapping")
            env = {}
        for key, value in env.items():
            if key in secret_names:
                errors.append(f"{where}.environment.{key}: secrets must come from x-sealed-secrets")
            if not isinstance(value, str):
                errors.append(f"{where}.environment.{key}: value must be a string")
        deps = svc.get("depends_on") or {}
        for dep in (deps if isinstance(deps, (list, dict)) else []):
            if dep not in services:
                errors.append(f"{where}.depends_on: {dep} is not a service of this app")
        for mount in svc.get("volumes") or []:
            if not isinstance(mount, str):
                errors.append(f"{where}.volumes: use short syntax name:/path")
                continue
            source = mount.split(":", 1)[0]
            if source.startswith(("/", ".", "~")) or source not in volumes:
                errors.append(f"{where}.volumes: {mount} is not a named volume of this app")
    return errors


def lint_manifest(app: dict[str, Any]) -> list[str]:
    manifest = app["manifest"]
    services = (app["fragment"] or {}).get("services") or {}
    errors: list[str] = []
    app_id = manifest.get("id", "")
    if os.path.basename(os.path.normpath(app["dir"])) != app_id and not app.get("variant"):
        errors.append(f"manifest.id {app_id!r} does not match the directory name")
    for field in ("primary_service",):
        if manifest.get(field) not in services:
            errors.append(f"manifest.{field}: {manifest.get(field)!r} is not a fragment service")
    for route in manifest.get("routes", []):
        if route.get("service") not in services:
            errors.append(f"manifest.routes[{route.get('name')}]: unknown service {route.get('service')!r}")
    if manifest.get("healthcheck", {}).get("service") not in services:
        errors.append("manifest.healthcheck.service is not a fragment service")
    boot = manifest.get("bootstrap")
    if boot and boot.get("service") not in services:
        errors.append("manifest.bootstrap.service is not a fragment service")
    for image in manifest.get("images", []):
        built = str(image.get("source", "")).startswith("build:")
        if built and image.get("digest") != ZERO_DIGEST:
            errors.append(f"images.{image['name']}: built images keep the zero digest until CI pins it (D-028)")
        if not built and image.get("digest") == ZERO_DIGEST:
            errors.append(f"images.{image['name']}: upstream images must be pinned by digest")
        if not built and "@" in str(image.get("source", "")):
            errors.append(f"images.{image['name']}: source is the upstream tag; the digest goes in digest")
    used = set()
    for svc in services.values():
        match = IMAGE_REF.match(str(svc.get("image", "")))
        if match:
            used.add(match.group(1))
    for image in manifest.get("images", []):
        if image["name"] not in used:
            errors.append(f"images.{image['name']}: not used by any service")
    if not manifest.get("telemetry_off_env"):
        errors.append("manifest.telemetry_off_env must not be empty")
    for key, value in (manifest.get("telemetry_off_env") or {}).items():
        if not isinstance(value, str):
            errors.append(f"telemetry_off_env.{key}: value must be a string")
    return errors


def lint_egress(egress: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(egress, dict):
        return ["egress: not a mapping"]
    if set(egress) != {"version", "default_allow", "customer_additions_allowed", "notes"}:
        errors.append(f"egress: keys must be version, default_allow, customer_additions_allowed, notes (got {sorted(egress)})")
    if egress.get("version") != 1:
        errors.append("egress.version must be 1")
    allow = egress.get("default_allow")
    if not isinstance(allow, list):
        errors.append("egress.default_allow must be a list")
    else:
        for entry in allow:
            if not isinstance(entry, str) or not HOST_PORT.match(entry):
                errors.append(f"egress.default_allow: {entry!r} is not host:port")
    if not isinstance(egress.get("customer_additions_allowed"), bool):
        errors.append("egress.customer_additions_allowed must be a boolean")
    if not isinstance(egress.get("notes"), str) or not egress.get("notes"):
        errors.append("egress.notes must be a non-empty string")
    return errors


def schema_errors(manifest: Any) -> Optional[list[str]]:
    """JSON Schema validation, or None when the jsonschema package is not installed."""
    try:
        import jsonschema
    except ImportError:
        return None
    with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
        schema = json.load(handle)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in validator.iter_errors(manifest)]


def substitute_images(fragment_text: str) -> str:
    def repl(match: re.Match) -> str:
        name = match.group(1)
        digest = hashlib.sha256(name.encode()).hexdigest()
        return f"{DUMMY_REGISTRY}/{name}@sha256:{digest}"

    return re.sub(r"\{\{image:([a-z][a-z0-9-]*)\}\}", repl, fragment_text)


def compose_config(fragment_text: str) -> Optional[tuple[int, str]]:
    """Run `docker compose config` (YAML output keeps x- keys) with dummy digests. None if docker is absent."""
    docker = shutil.which("docker")
    if docker is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "compose.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(substitute_images(fragment_text))
        proc = subprocess.run(
            [docker, "compose", "-p", "sealed-lint", "-f", path, "config"],
            capture_output=True, text=True, timeout=60,
        )
        return proc.returncode, proc.stdout if proc.returncode == 0 else proc.stderr


def lint_app(app_dir: str, manifest_name: str = "manifest.yaml", variant: bool = False) -> list[str]:
    app = load_app(app_dir, manifest_name)
    app["variant"] = variant
    manifest = app["manifest"]
    errors = lint_manifest(app)
    errors += lint_fragment(manifest.get("id", ""), manifest, app["fragment"], app["fragment_text"])
    errors += lint_egress(app["egress"])
    schema = schema_errors(manifest)
    if schema:
        errors += [f"schema: {e}" for e in schema]
    result = compose_config(app["fragment_text"])
    if result is not None and result[0] != 0:
        errors.append(f"docker compose config failed: {result[1].strip()}")
    return errors


def main(argv: list[str]) -> int:
    status = 0
    for app_dir in argv:
        errors = lint_app(app_dir)
        for err in errors:
            print(f"{app_dir}: {err}")
        status |= 1 if errors else 0
        if not errors:
            print(f"{app_dir}: ok")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
