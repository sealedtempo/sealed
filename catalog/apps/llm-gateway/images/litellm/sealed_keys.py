"""Keys job of the Sealed llm-gateway (service llm-gateway-keys).

Provisions the LiteLLM virtual keys that other catalog apps use, so no other app ever
needs the gateway master key. For each entry of app_keys.yaml whose secret is set
(for example APP_KEY_CODING_AGENT), the key with exactly that value is made to exist
with the listed alias, models (llm_api key type) and rate limits:

- missing or deleted: any older key holding the alias is deleted, then
  POST /key/generate {"key": <value>, ...} creates it;
- active but drifted (models or limits changed): POST /key/update restores them;
- blocked or expired by an admin: left alone and reported;
- secret unset: the alias is deleted (reported as "unset"), so a removed app leaves no
  live key behind.

It repeats every SEALED_KEYS_INTERVAL_S seconds, so a reset gateway database heals by
itself. Keys are looked up by sha256 hash, never put in URLs, and never printed. The
status file (no secrets) feeds the service healthcheck.

Usage: sealed_keys.py [--once] [--check-config]
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional

import yaml

APP_ID = "llm-gateway"
ALIAS = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
SECRET_NAME = re.compile(r"^APP_KEY_[A-Z0-9_]+$")
LIMIT_FIELDS = ("rpm_limit", "tpm_limit", "max_parallel_requests")
FORBIDDEN_MODEL_PREFIXES = ("byok/", "external/")
KEY_TYPE = "llm_api"


class KeysError(Exception):
    """A configuration or gateway problem. Messages never contain key values."""


def log(message: str) -> None:
    print("llm-gateway-keys: " + message, file=sys.stderr, flush=True)


class AppKey:
    def __init__(self, entry: Mapping[str, Any]) -> None:
        self.app = str(entry.get("app") or "")
        self.secret = str(entry.get("secret") or "")
        self.alias = str(entry.get("key_alias") or "")
        self.models = list(entry.get("models") or [])
        self.limits = {f: entry[f] for f in LIMIT_FIELDS if entry.get(f) is not None}
        if not ALIAS.match(self.app) or not ALIAS.match(self.alias):
            raise KeysError(f"app_keys: bad app or key_alias in {self.app!r}")
        if not SECRET_NAME.match(self.secret):
            raise KeysError(f"app_keys: {self.alias}: secret must be APP_KEY_<NAME>")
        if not self.models or not all(isinstance(m, str) and m for m in self.models):
            raise KeysError(f"app_keys: {self.alias}: models must be a non-empty list of route names")
        for model in self.models:
            if model.startswith(FORBIDDEN_MODEL_PREFIXES) or model == "*":
                raise KeysError(f"app_keys: {self.alias}: {model} would let the app send data out of the VM")
        for name, value in self.limits.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise KeysError(f"app_keys: {self.alias}: {name} must be a positive integer")

    def desired(self) -> dict[str, Any]:
        return {"key_alias": self.alias, "models": list(self.models), **self.limits}

    def generate_body(self, value: str) -> dict[str, Any]:
        return {
            "key": value,
            **self.desired(),
            "key_type": KEY_TYPE,
            "metadata": {"sealed_app": self.app, "sealed_managed": True},
        }


def load_specs(path: str) -> list[AppKey]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    entries = data.get("apps") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise KeysError(f"{path}: expected a top-level 'apps' list")
    specs = [AppKey(e if isinstance(e, dict) else {}) for e in entries]
    for field in ("alias", "secret"):
        values = [getattr(s, field) for s in specs]
        if len(values) != len(set(values)):
            raise KeysError(f"{path}: duplicate {field}")
    return specs


class Secrets:
    """Env var (exported by envexec) first, then the secret file."""

    def __init__(self, env: Mapping[str, str], secret_dir: str) -> None:
        self.env = env
        self.dir = secret_dir

    def get(self, name: str) -> Optional[str]:
        value = self.env.get(name)
        if value is None or not value.strip():
            try:
                with open(os.path.join(self.dir, name), "r", encoding="utf-8") as handle:
                    value = handle.read()
            except (FileNotFoundError, IsADirectoryError, PermissionError):
                return None
        value = value.strip("\r\n")
        return value if value.strip() else None


def check_key_value(value: str, master: str) -> Optional[str]:
    """Why a key value is unusable, or None."""
    if not value.startswith("sk-") or len(value) < 35 or re.search(r"\s", value):
        return "must be sk- followed by at least 32 characters (generate: sk-hex32)"
    if value == master:
        return "must not equal LITELLM_MASTER_KEY"
    return None


def token_hash(value: str) -> str:
    """LiteLLM stores and looks keys up by sha256 hex of the raw key (hash_token)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Admin:
    """LiteLLM admin API with the master key. Never uses proxy env vars (the gateway is in the VM)."""

    def __init__(self, base_url: str, master_key: str, timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/")
        self.auth = {"Authorization": "Bearer " + master_key}
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, path: str, body: Any = None, auth: bool = True) -> tuple[int, Any]:
        headers = dict(self.auth) if auth else {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, _decode(response.read())
        except urllib.error.HTTPError as err:
            return err.code, _decode(err.read())

    def checked(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        status, payload = self.call(method, path, body)
        if status in (401, 403):
            raise KeysError(f"gateway rejected the master key on {path} (HTTP {status})")
        if status >= 500:
            raise KeysError(f"{path} failed (HTTP {status})")
        return status, payload

    def ready(self) -> bool:
        status, _ = self.call("GET", "/health/readiness", auth=False)
        return status == 200

    def key_info(self, hashed: str) -> Optional[dict[str, Any]]:
        status, payload = self.checked("GET", "/key/info?key=" + hashed)
        if status == 404:
            return None
        info = payload.get("info") if isinstance(payload, dict) else None
        if status != 200 or not isinstance(info, dict):
            raise KeysError(f"/key/info failed (HTTP {status})")
        return info

    def delete_alias(self, alias: str) -> None:
        # 4xx means no key holds the alias; LiteLLM 1.106.5 also answers 200 when none did.
        self.checked("POST", "/key/delete", {"key_aliases": [alias]})

    def generate(self, body: dict[str, Any]) -> None:
        status, payload = self.checked("POST", "/key/generate", body)
        if status >= 300 or not isinstance(payload, dict):
            raise KeysError(f"/key/generate for {body.get('key_alias')} failed (HTTP {status})")

    def update(self, hashed: str, fields: dict[str, Any]) -> None:
        status, _ = self.checked("POST", "/key/update", {"key": hashed, **fields})
        if status >= 300:
            raise KeysError(f"/key/update for {fields.get('key_alias')} failed (HTTP {status})")


def _decode(raw: bytes) -> Any:
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def drift(info: Mapping[str, Any], desired: Mapping[str, Any]) -> dict[str, Any]:
    """Fields of desired that the stored key does not match."""
    out: dict[str, Any] = {}
    for name, want in desired.items():
        have = info.get(name)
        if name == "models":
            if sorted(have or []) != sorted(want):
                out[name] = want
        elif have != want:
            out[name] = want
    return out


def reconcile_one(admin: Admin, spec: AppKey, value: Optional[str], master: str) -> str:
    if value is None:
        admin.delete_alias(spec.alias)
        return "unset"
    problem = check_key_value(value, master)
    if problem:
        raise KeysError(f"{spec.secret} {problem}")
    hashed = token_hash(value)
    info = admin.key_info(hashed)
    status = (info or {}).get("status", "active")
    if info is None or status == "deleted":
        admin.delete_alias(spec.alias)  # free the alias if an older key holds it
        admin.generate(spec.generate_body(value))
        return "created"
    if info.get("blocked") or status in ("revoked", "blocked", "expired"):
        return "left-" + str(status if status != "active" else "blocked")
    fields = drift(info, spec.desired())
    if fields:
        fields.setdefault("key_alias", spec.alias)
        admin.update(hashed, fields)
        return "updated"
    return "ok"


def reconcile(admin: Admin, specs: list[AppKey], secrets: Secrets, master: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for spec in specs:
        try:
            results[spec.alias] = reconcile_one(admin, spec, secrets.get(spec.secret), master)
        except (KeysError, OSError) as err:
            results[spec.alias] = "error: " + str(err)
    return results


def write_status(path: str, results: Mapping[str, str], now: float) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    ok = all(not r.startswith("error") for r in results.values())
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".status.")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"ok": ok, "at": int(now), "apps": dict(results)}, handle, sort_keys=True)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def wait_ready(admin: Admin, timeout: float, interval: float, sleep: Callable[[float], Any],
               clock: Callable[[], float]) -> None:
    deadline = clock() + timeout
    while True:
        try:
            if admin.ready():
                return
        except OSError:
            pass
        if clock() >= deadline:
            raise KeysError("timed out waiting for the gateway")
        sleep(interval)


class Settings:
    def __init__(self, env: Mapping[str, str]) -> None:
        self.secret_dir = env.get("SEALED_SECRETS_DIR", f"/run/sealed/secrets/{APP_ID}")
        self.gateway = env.get("SEALED_GATEWAY_URL", "http://llm-gateway-litellm:4000")
        self.specs_path = env.get("SEALED_APP_KEYS_FILE", "/etc/litellm/app_keys.yaml")
        self.status_path = env.get("SEALED_KEYS_STATUS_FILE", "/run/sealed-keys/status.json")
        self.interval = float(env.get("SEALED_KEYS_INTERVAL_S", "300"))
        self.retry = float(env.get("SEALED_KEYS_RETRY_S", "30"))
        self.wait_timeout = float(env.get("SEALED_KEYS_WAIT_TIMEOUT_S", "900"))
        self.poll = float(env.get("SEALED_KEYS_POLL_S", "3"))


def run_once(cfg: Settings, env: Mapping[str, str], sleep=time.sleep, clock=time.monotonic) -> dict[str, str]:
    specs = load_specs(cfg.specs_path)
    secrets = Secrets(env, cfg.secret_dir)
    master = secrets.get("LITELLM_MASTER_KEY")
    if master is None:
        raise KeysError("LITELLM_MASTER_KEY is missing")
    admin = Admin(cfg.gateway, master)
    wait_ready(admin, cfg.wait_timeout, cfg.poll, sleep, clock)
    results = reconcile(admin, specs, secrets, master)
    write_status(cfg.status_path, results, time.time())
    log(" ".join(f"{alias}={outcome}" for alias, outcome in sorted(results.items())) or "no app keys")
    return results


def main(argv: Optional[list[str]] = None, env: Optional[Mapping[str, str]] = None,
         sleep: Callable[[float], Any] = time.sleep) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ if env is None else env)
    cfg = Settings(env)
    if "--check-config" in args:
        try:
            specs = load_specs(cfg.specs_path)
        except (KeysError, OSError, yaml.YAMLError) as err:
            log("error: " + str(err))
            return 2
        log("config ok: " + ",".join(s.alias for s in specs))
        return 0
    once = "--once" in args
    while True:
        try:
            results = run_once(cfg, env, sleep)
            failed = any(r.startswith("error") for r in results.values())
        except (KeysError, OSError, yaml.YAMLError) as err:
            log("error: " + str(err))
            failed = True
            try:
                write_status(cfg.status_path, {"_job": "error: " + str(err)}, time.time())
            except OSError:
                pass
        if once:
            return 1 if failed else 0
        sleep(cfg.retry if failed else cfg.interval)


if __name__ == "__main__":
    sys.exit(main())
