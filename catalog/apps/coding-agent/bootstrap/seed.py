"""Sealed coding-agent bootstrap job (stdlib only; embedded verbatim in the compose fragment).

Runs once per data disk, before the code route opens:
1. waits for llm-gateway (GET /health/readiness) and, in openhands mode, for the agent server;
2. creates a LiteLLM virtual key for this app with the gateway master key (any older key with
   the same alias is deleted first, so a re-run rotates it);
3. picks the default model: the relay model if the gateway serves it, else the local model;
4. openhands mode: stores {model, base_url, api_key} through PATCH /api/settings;
   key-file mode (OpenCode fallback): writes the key to a 0600 file for the server to read;
5. writes the done file (no secrets in it) and then idles, so the composer's
   restart: unless-stopped policy does not loop the job.
Secret values are never printed.
"""
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request

LITELLM_PREFIX = "litellm_proxy/"


class BootstrapError(Exception):
    pass


def log(message):
    print("coding-agent-bootstrap: " + message, file=sys.stderr, flush=True)


class Config:
    def __init__(self, env):
        self.mode = env.get("SEALED_BOOTSTRAP_MODE", "openhands")
        if self.mode not in ("openhands", "key-file"):
            raise BootstrapError("SEALED_BOOTSTRAP_MODE must be openhands or key-file")
        self.gateway_url = env.get("SEALED_GATEWAY_URL", "http://llm-gateway:4000").rstrip("/")
        self.agent_url = env.get("SEALED_AGENT_SERVER_URL", "http://coding-agent-server:8000").rstrip("/")
        self.key_alias = env.get("SEALED_LLM_KEY_ALIAS", "coding-agent")
        self.key_models = [m.strip() for m in env.get("SEALED_LLM_KEY_MODELS", "relay/*,local/*").split(",") if m.strip()]
        self.primary = env.get("SEALED_MODEL_PRIMARY", "relay/default")
        self.fallback = env.get("SEALED_MODEL_FALLBACK", "local/qwen3-4b")
        self.done_file = env.get("SEALED_DONE_FILE", "/workspace/.sealed/bootstrap.done")
        self.key_file = env.get("SEALED_KEY_FILE", "/workspace/.sealed/llm-gateway-key")
        self.wait_timeout = float(env.get("SEALED_WAIT_TIMEOUT_S", "900"))
        self.poll_interval = float(env.get("SEALED_POLL_INTERVAL_S", "3"))
        self.idle = env.get("SEALED_BOOTSTRAP_IDLE", "1") == "1"
        self.master_key = (env.get("LITELLM_MASTER_KEY") or "").strip()
        self.session_key = (env.get("OH_SESSION_API_KEYS_0") or "").strip()
        if not self.master_key:
            raise BootstrapError("LITELLM_MASTER_KEY is not set (secret of this app)")
        if self.mode == "openhands" and not self.session_key:
            raise BootstrapError("OH_SESSION_API_KEYS_0 is not set (secret of this app)")


class Http:
    """JSON over HTTP that never uses proxy env vars (all targets are inside the VM)."""

    def __init__(self, timeout=10.0):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, url, body=None, headers=None):
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, _decode(response.read())
        except urllib.error.HTTPError as err:
            return err.code, _decode(err.read())


def _decode(raw):
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def wait_for(what, check, timeout, interval, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + timeout
    while True:
        try:
            if check():
                return
        except OSError:
            pass
        if clock() >= deadline:
            raise BootstrapError("timed out waiting for " + what)
        sleep(interval)


class Gateway:
    def __init__(self, http, base_url, master_key):
        self.http = http
        self.base = base_url
        self.auth = {"Authorization": "Bearer " + master_key}

    def ready(self):
        status, _ = self.http.call("GET", self.base + "/health/readiness")
        return status == 200

    def delete_alias(self, alias):
        status, _ = self.http.call("POST", self.base + "/key/delete", {"key_aliases": [alias]}, self.auth)
        if status in (401, 403):
            raise BootstrapError("gateway rejected the master key (HTTP " + str(status) + ")")
        return status < 300

    def generate_key(self, alias, models):
        body = {
            "key_alias": alias,
            "models": models,
            "key_type": "llm_api",
            "duration": None,
            "metadata": {"sealed_app": "coding-agent"},
        }
        status, payload = self.http.call("POST", self.base + "/key/generate", body, self.auth)
        key = payload.get("key") if isinstance(payload, dict) else None
        if status >= 300 or not isinstance(key, str) or not key.startswith("sk-"):
            raise BootstrapError("key generation failed (HTTP " + str(status) + ")")
        return key

    def model_names(self):
        status, payload = self.http.call("GET", self.base + "/v1/model/info", None, self.auth)
        if status != 200 or not isinstance(payload, dict):
            raise BootstrapError("could not list gateway models (HTTP " + str(status) + ")")
        return {m.get("model_name") for m in payload.get("data") or [] if isinstance(m, dict)}


class AgentServer:
    def __init__(self, http, base_url, session_key):
        self.http = http
        self.base = base_url
        self.auth = {"X-Session-API-Key": session_key}

    def ready(self):
        status, _ = self.http.call("GET", self.base + "/ready")
        return status == 200

    def patch_llm(self, llm):
        return self.http.call("PATCH", self.base + "/api/settings", {"agent_settings_diff": {"llm": llm}}, self.auth)


def choose_model(available, primary, fallback):
    if primary in available:
        return primary
    if fallback in available:
        return fallback
    raise BootstrapError("gateway serves neither " + primary + " nor " + fallback)


def llm_settings(cfg, model, key):
    llm = {
        "model": LITELLM_PREFIX + model,
        "base_url": cfg.gateway_url,
        "api_key": key,
        "usage_id": "coding-agent",
    }
    if model == cfg.primary and cfg.fallback and cfg.fallback != model:
        # Per-request fallback at the gateway when the relay refuses (attestation, spend limit).
        llm["litellm_extra_body"] = {"fallbacks": [cfg.fallback]}
    return llm


def seed_openhands(cfg, agent, model, key):
    llm = llm_settings(cfg, model, key)
    status, _ = agent.patch_llm(llm)
    if status == 422 and "litellm_extra_body" in llm:
        log("settings rejected litellm_extra_body; storing without gateway fallback")
        llm.pop("litellm_extra_body")
        status, _ = agent.patch_llm(llm)
    if status == 409:
        raise BootstrapError("agent settings are encrypted with a different OH_SECRET_KEY (HTTP 409)")
    if status >= 300:
        raise BootstrapError("PATCH /api/settings failed (HTTP " + str(status) + ")")


def write_private(path, text, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def run(cfg, http, sleep=time.sleep, clock=time.monotonic):
    if os.path.exists(cfg.done_file) and (cfg.mode != "key-file" or os.path.exists(cfg.key_file)):
        log("already bootstrapped (" + cfg.done_file + ")")
        return {"skipped": True}
    gateway = Gateway(http, cfg.gateway_url, cfg.master_key)
    log("waiting for llm-gateway at " + cfg.gateway_url)
    wait_for("llm-gateway", gateway.ready, cfg.wait_timeout, cfg.poll_interval, sleep, clock)
    agent = None
    if cfg.mode == "openhands":
        agent = AgentServer(http, cfg.agent_url, cfg.session_key)
        wait_for("agent server", agent.ready, cfg.wait_timeout, cfg.poll_interval, sleep, clock)

    gateway.delete_alias(cfg.key_alias)
    key = gateway.generate_key(cfg.key_alias, cfg.key_models)
    model = choose_model(gateway.model_names(), cfg.primary, cfg.fallback)
    if model != cfg.primary:
        log("relay model unavailable, using " + model)

    if agent is not None:
        seed_openhands(cfg, agent, model, key)
    else:
        write_private(cfg.key_file, key, 0o600)

    summary = {"mode": cfg.mode, "model": LITELLM_PREFIX + model, "key_alias": cfg.key_alias, "at": int(time.time())}
    write_private(cfg.done_file, json.dumps(summary, sort_keys=True) + "\n", 0o644)
    log("done: model " + summary["model"] + ", key alias " + cfg.key_alias)
    return summary


def idle_forever():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        signal.pause()


def main(env=None):
    try:
        cfg = Config(dict(os.environ if env is None else env))
        run(cfg, Http())
    except (BootstrapError, OSError) as err:
        log("error: " + str(err))
        return 1
    if cfg.idle:
        idle_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
