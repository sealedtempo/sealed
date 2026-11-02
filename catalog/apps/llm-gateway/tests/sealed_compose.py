"""Runs the real composer for the catalog tests of llm-gateway and coding-agent.

The app-local copy of the catalog rules is gone (integration brief item 25): manifests,
fragments and egress policies are checked only by the composer's own lint,
`go run ./runtime/composer/cmd/sealed-compose lint`, and composed stacks come from
`sealed-compose compose`. Switch to catalog/tools/ once that shared tooling exists.

The apps already use the fields of integration brief items 5 to 11 (`secrets[].same_as`, the
`password` generator, `x-sealed-owner` on volumes), which composer 1.2.0 introduces. With an
older composer in the tree, `inputs()` hands the composer a copy of each app with exactly those
fields removed, so every other rule still runs; tests that need 1.2.0 behaviour check
`Composer.brief` and skip with the reason otherwise.

`secrets[].share_with` (D-059: the source secret's opt-in for `same_as`) is newer than 1.2.0. It
is detected from the composer's own manifest schema, not from the version: a composer whose
schema does not declare it gets a copy without it, and tests of its enforcement check
`Composer.share_with`.

The composer is looked up in SEALED_COMPOSER_DIR, then in this checkout. Without Go or the
composer source the tests skip, unless CI or SEALED_REQUIRE_COMPOSER=1 is set; then they fail.
Requires PyYAML.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from typing import Any, Optional

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
BRIEF_VERSION = (1, 2, 0)
ZERO_DIGEST = "sha256:" + "0" * 64
REGISTRY = "ghcr.io/sealedtempo"
CLI = "./runtime/composer/cmd/sealed-compose"
# Files the composer reads from an app directory (bundle.go CollectBundleFiles).
BUNDLE_FILES = ("manifest.yaml", "compose.fragment.yaml", "egress.yaml", "LICENSE-NOTICE", "README.md")


def load_yaml(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_app(app_dir: str) -> dict[str, Any]:
    """The app's manifest, fragment (parsed and as text) and egress policy."""
    manifest = load_yaml(os.path.join(app_dir, "manifest.yaml"))
    with open(os.path.join(app_dir, "compose.fragment.yaml"), "r", encoding="utf-8") as handle:
        fragment_text = handle.read()
    return {
        "dir": app_dir,
        "manifest": manifest,
        "fragment_text": fragment_text,
        "fragment": yaml.safe_load(fragment_text),
        "egress": load_yaml(os.path.join(app_dir, "egress.yaml")),
    }


def required() -> bool:
    return os.environ.get("SEALED_REQUIRE_COMPOSER") == "1" or bool(os.environ.get("CI"))


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


class Composer:
    def __init__(self, root: Optional[str] = None) -> None:
        self.root = os.path.abspath(root or os.environ.get("SEALED_COMPOSER_DIR") or REPO_ROOT)
        self.go = shutil.which("go")

    def unavailable(self) -> Optional[str]:
        if self.go is None:
            return "go is not installed"
        if not os.path.isfile(os.path.join(self.root, CLI, "main.go")):
            return f"composer source not found under {self.root} (set SEALED_COMPOSER_DIR)"
        return None

    @property
    def version(self) -> str:
        source_dir = os.path.join(self.root, "runtime", "composer")
        for name in sorted(os.listdir(source_dir)):
            if name.endswith(".go") and not name.endswith("_test.go"):
                with open(os.path.join(source_dir, name), encoding="utf-8") as handle:
                    match = re.search(r'^const Version = "([^"]+)"', handle.read(), re.M)
                if match:
                    return match.group(1)
        raise RuntimeError("cannot find const Version in runtime/composer")

    @property
    def brief(self) -> bool:
        """True when the composer implements integration brief items 5 to 11 (composer 1.2.0)."""
        return parse_version(self.version) >= BRIEF_VERSION

    @property
    def share_with(self) -> bool:
        """True when the composer's manifest schema declares secrets[].share_with (D-059)."""
        path = os.path.join(self.root, "catalog", "schema", "manifest.schema.json")
        try:
            with open(path, encoding="utf-8") as handle:
                schema = json.load(handle)
        except (OSError, ValueError):
            return False
        secret = (((schema.get("properties") or {}).get("secrets") or {}).get("items") or {})
        return "share_with" in (secret.get("properties") or {})

    def run(self, args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
        return subprocess.run([self.go, "run", CLI, *args], cwd=self.root, capture_output=True, text=True,
                              timeout=timeout)

    def inputs(self, app_dirs: list[str], scratch: str) -> list[str]:
        """The directories to hand to the composer: the apps themselves when the composer knows every
        field they use, otherwise copies without the fields it does not know (brief_compatible_copy)."""
        if self.brief and self.share_with:
            return [os.path.abspath(d) for d in app_dirs]
        return [brief_compatible_copy(d, scratch, brief=not self.brief, share_with=not self.share_with)
                for d in app_dirs]

    def lint(self, app_dirs: list[str]) -> list[dict[str, Any]]:
        """`sealed-compose lint --json` findings for the apps, whatever the exit code."""
        with tempfile.TemporaryDirectory() as scratch:
            args = ["lint", "--json"]
            for d in self.inputs(app_dirs, scratch):
                args += ["--app-dir", d]
            proc = self.run(args)
        try:
            return json.loads(proc.stdout)
        except ValueError:
            raise AssertionError(f"sealed-compose lint failed: {proc.stderr.strip()}") from None

    def lint_with_sbom(self, app_dir: str, image: str, packages: list[str], files: list[str]) -> list[dict[str, Any]]:
        """`sealed-compose lint --json` of a copy of the app carrying a made-up SPDX SBOM for one image
        (sbom/<image>.spdx.json): the given package names (license MIT) and file paths."""
        with tempfile.TemporaryDirectory() as scratch:
            copy = brief_compatible_copy(app_dir, scratch, brief=not self.brief, share_with=not self.share_with)
            os.makedirs(os.path.join(copy, "sbom"))
            doc = {
                "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": image,
                "packages": [{"name": n, "versionInfo": "1.0.0", "licenseConcluded": "MIT"} for n in packages],
                "files": [{"fileName": f} for f in files],
            }
            with open(os.path.join(copy, "sbom", image + ".spdx.json"), "w", encoding="utf-8") as handle:
                json.dump(doc, handle)
            proc = self.run(["lint", "--json", "--app-dir", copy])
        try:
            return json.loads(proc.stdout)
        except ValueError:
            raise AssertionError(f"sealed-compose lint failed: {proc.stderr.strip()}") from None

    def compose(self, app_dirs: list[str], out_dir: str, expect_ok: bool = True) -> dict[str, Any]:
        """`sealed-compose compose` of the apps with a sample config; the artifacts, parsed."""
        os.makedirs(out_dir, exist_ok=True)
        ids = [load_yaml(os.path.join(d, "manifest.yaml"))["id"] for d in app_dirs]
        config_path = os.path.join(out_dir, "input-config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(sample_config(ids, self.version, brief=self.brief), handle)
        scratch = os.path.join(out_dir, "apps")
        os.makedirs(scratch, exist_ok=True)
        args = ["compose", "--config", config_path, "--fill-release-ids", "--allow-missing-sbom",
                "--registry", REGISTRY, "--out", out_dir]
        for d in self.inputs(app_dirs, scratch):
            args += ["--app-dir", d]
        proc = self.run(args)
        if not expect_ok:
            return {"status": proc.returncode, "stderr": proc.stderr}
        if proc.returncode != 0:
            raise AssertionError(f"sealed-compose compose failed: {proc.stderr.strip()}")

        def read(name: str) -> str:
            with open(os.path.join(out_dir, name), encoding="utf-8") as handle:
                return handle.read()

        return {
            "status": 0,
            "caddyfile": read("Caddyfile"),
            "compose": json.loads(read("docker-compose.json")),
            "compose_path": os.path.join(out_dir, "docker-compose.json"),
            "stack": json.loads(read("stack.json")),
        }


def composer_for(test: Any) -> Composer:
    """The composer, or skip the test class (fail under CI or SEALED_REQUIRE_COMPOSER=1)."""
    composer = Composer()
    reason = composer.unavailable()
    if reason:
        if required():
            raise AssertionError("the real composer is required here: " + reason)
        raise unittest.SkipTest(reason)
    return composer


def brief_compatible_copy(app_dir: str, dest_root: str, brief: bool = True, share_with: bool = True) -> str:
    """Copy the composer's input files of an app, without the fields an older composer rejects.

    With brief: manifest `secrets[].same_as` and fragment `volumes.<name>.x-sealed-owner` are
    removed and `generate: password` becomes `generate: none` (composer 1.2.0 fields). With
    share_with: manifest `secrets[].share_with` is removed (D-059). Nothing else changes, so the
    older composer still checks every other rule on the real content.
    """
    manifest = load_yaml(os.path.join(app_dir, "manifest.yaml"))
    fragment = load_yaml(os.path.join(app_dir, "compose.fragment.yaml"))
    dest = os.path.join(dest_root, manifest["id"])
    if os.path.exists(dest):
        dest = tempfile.mkdtemp(prefix=manifest["id"] + "-", dir=dest_root)
        dest = os.path.join(dest, manifest["id"])
    os.makedirs(dest)
    for secret in manifest.get("secrets") or []:
        if share_with:
            secret.pop("share_with", None)
        if brief:
            secret.pop("same_as", None)
            if secret.get("generate") == "password":
                secret["generate"] = "none"
    for name, spec in list((fragment.get("volumes") or {}).items()):
        if brief and isinstance(spec, dict):
            spec.pop("x-sealed-owner", None)
            fragment["volumes"][name] = spec or {}
    with open(os.path.join(dest, "manifest.yaml"), "w", encoding="utf-8") as handle:
        yaml.safe_dump(manifest, handle, sort_keys=False, allow_unicode=True)
    if brief:
        with open(os.path.join(dest, "compose.fragment.yaml"), "w", encoding="utf-8") as handle:
            yaml.safe_dump(fragment, handle, sort_keys=False, allow_unicode=True, width=1 << 20)
    else:  # nothing to remove from the fragment: keep it byte for byte
        shutil.copyfile(os.path.join(app_dir, "compose.fragment.yaml"), os.path.join(dest, "compose.fragment.yaml"))
    for name in BUNDLE_FILES[2:]:
        if os.path.exists(os.path.join(app_dir, name)):
            shutil.copyfile(os.path.join(app_dir, name), os.path.join(dest, name))
    if os.path.isdir(os.path.join(app_dir, "LICENSES")):
        shutil.copytree(os.path.join(app_dir, "LICENSES"), os.path.join(dest, "LICENSES"))
    return dest


def unexpected(findings: list[dict[str, Any]], errors: tuple[str, ...] = ("unbuilt-image",),
               warnings: tuple[str, ...] = ("sbom-missing",)) -> list[str]:
    """Findings other than the allowed error and warning codes, as readable lines."""
    allowed = {"error": set(errors), "warning": set(warnings)}
    return [f"{f['severity']} {f.get('file', '')} {f.get('field', '')} [{f['code']}] {f['message']}"
            for f in findings if f["code"] not in allowed.get(f["severity"], set())]


def excluded_hits(findings: list[dict[str, Any]], files: list[str] | tuple[str, ...] = ()) -> dict[str, set[str]]:
    """excluded-path findings of `lint --json`: SBOM entry (package@version or file path) -> patterns.

    The lint (license audit F6 globs) reports a package by name@version, a matched file by its path, and
    the files under a matched directory once, by the directory ("/<dir>/", every pattern that matched
    it in the message). Each of `files` under a reported directory gets that directory's patterns."""
    hits: dict[str, set[str]] = {}
    for f in findings:
        if f["code"] == "excluded-path":
            m = re.search(r'excluded paths? ((?:"[^"]*"(?:, )?)+)', f["message"])
            patterns = set(re.findall(r'"([^"]*)"', m.group(1))) if m else {""}
            hits.setdefault(f.get("field", ""), set()).update(patterns)
    for path in files:
        for field, patterns in list(hits.items()):
            if field.endswith("/") and path.startswith(field):
                hits.setdefault(path, set()).update(patterns)
    return hits


def exclusion_patterns(manifest: dict[str, Any]) -> list[str]:
    """The manifest's license_exclusions an SBOM can match: all but the "<owner>/<repo>:<path>" notes."""
    return [p for p in manifest.get("license_exclusions") or [] if not re.match(r"^[\w.-]+/[\w.-]+:", p)]


def unbuilt_images(manifest: dict[str, Any]) -> list[str]:
    return [i["name"] for i in manifest["images"] if i["digest"] == ZERO_DIGEST]


def unbuilt_copy(app_dir: str, dest_root: str) -> str:
    """A copy of the app with every build-sourced image digest reset to the all-zero placeholder.

    After the release cut pins the real manifest, this restores the pre-release (unbuilt) state so a
    test can still prove the lint blocks on exactly the build images it is meant to."""
    dest = brief_compatible_copy(app_dir, dest_root, brief=False, share_with=False)
    manifest_path = os.path.join(dest, "manifest.yaml")
    manifest = load_yaml(manifest_path)
    for image in manifest.get("images") or []:
        if str(image.get("source", "")).startswith("build:"):
            image["digest"] = ZERO_DIGEST
    with open(manifest_path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(manifest, handle, sort_keys=False, allow_unicode=True)
    return dest


def sample_config(app_ids: list[str], version: str, brief: bool = True) -> dict[str, Any]:
    """A sealed-config/v1 document for a test stack (sslip hostnames on 34.1.2.3)."""
    def word(byte: str, count: int) -> str:
        return "0x" + byte * count

    config = {
        "schema": "sealed-config/v1",
        "chainId": 4217,
        "customer": word("0", 38) + "c1",
        "salt": word("5a", 32),
        "imageId": word("1d", 32),
        "composerVersion": version,
        "apps": [{"id": i, "releaseId": word("00", 32)} for i in sorted(app_ids)],
        "hostnames": {"scheme": "sslip", "ip": "34.1.2.3"},
        "egressAdditions": {},
        "allowedVpcRanges": [],
        "endpoints": {
            "keyBroker": "https://sealed-key-broker-xyz.a.run.app",
            "platformApi": "https://api.sealed.example",
            "tempoRpc": "https://rpc.tempo.xyz",
            # The relay is served on its deployment's attest host (D-045).
            "relay": "https://attest.relay.sealed.example",
            "relayAttest": "https://attest.relay.sealed.example/attest",
        },
        "contracts": {
            "platformRegistry": word("0", 38) + "e1",
            "appRegistry": word("0", 38) + "e2",
            "deploymentRegistry": word("0", 38) + "e3",
            "feeSplitter": word("0", 38) + "e4",
        },
        "feeToken": "0x20c000000000000000000000b9537d11c60e8b50",
        "settlement": {"mode": "access-key", "intervalMinutes": 60, "gracePeriodMinutes": 1440,
                       "spendLimitPerDay": "2000000"},
        "relayOwner": word("0", 38) + "b1",
    }
    if brief:
        config["debug"] = False  # integration brief item 13, composer 1.2.0
    return config


def caddy_site(caddyfile: str, host: str) -> Optional[str]:
    """The block of one site ("<host> {" to the "}" at column 0) in a rendered Caddyfile."""
    lines = caddyfile.split("\n")
    try:
        start = lines.index(host + " {")
    except ValueError:
        return None
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start:end + 1])


def secret_mounts(service: dict[str, Any], app_id: str) -> set[str]:
    """Targets of a composed service's mounts under /run/sealed/secrets/<app>."""
    root = f"/run/sealed/secrets/{app_id}"
    targets = set()
    for volume in service.get("volumes") or []:
        target = volume.get("target") if isinstance(volume, dict) else str(volume).split(":")[1]
        if target == root or str(target).startswith(root + "/"):
            targets.add(target)
    return targets


def docker_compose_config(path: str) -> Optional[tuple[int, str]]:
    """`docker compose config` on a composed document. None if the docker CLI is absent."""
    docker = shutil.which("docker")
    if docker is None:
        return None
    proc = subprocess.run([docker, "compose", "-p", "sealed-catalog-check", "-f", path, "config", "--quiet"],
                          capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stderr
