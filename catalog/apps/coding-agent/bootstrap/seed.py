"""Sealed coding-agent bootstrap job (stdlib only; embedded verbatim in the compose fragment).

Runs at every start of the stack (the composer gives the job restart: on-failure, so it is
retried until it succeeds and then stays exited), so a changed key or a reset agent store is
fixed by a restart. Its done file lives on the job's own volume, which the agent's container
does not mount; manifest bootstrap.done_file names it, and sealed-agent keeps the code route
closed (503 starting) until it exists:
1. waits for the agent server (GET /ready);
2. stores {model, base_url, api_key} through PATCH /api/settings. A litellm_proxy/ model the
   customer already chose on this gateway is kept; otherwise the default (relay/default) is
   used. When the relay fails, the gateway answers relay/default from the local model
   (router_settings.fallbacks), so no client-side fallback is needed;
3. writes the done file (no secrets in it) and exits 0.
The job never contacts llm-gateway itself: with per-app networks (D-041) only the primary
service, coding-agent-server, is on the shared apps network where llm-gateway is, and the job
is not. The key is LLM_GATEWAY_KEY, which refers to llm-gateway's APP_KEY_CODING_AGENT
(same_as), so it is the value llm-gateway's keys job provisions; this app never holds the
gateway master key. Secret values are never printed.
"""
import json
import os
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
        self.gateway_url = env.get("SEALED_GATEWAY_URL", "http://llm-gateway:4000").rstrip("/")
        self.agent_url = env.get("SEALED_AGENT_SERVER_URL", "http://coding-agent-server:8000").rstrip("/")
        self.model = env.get("SEALED_MODEL_DEFAULT", "relay/default")
        self.usage_id = env.get("SEALED_LLM_USAGE_ID", "coding-agent")
        self.done_file = env.get("SEALED_DONE_FILE", "/var/lib/sealed-bootstrap/done")
        self.wait_timeout = float(env.get("SEALED_WAIT_TIMEOUT_S", "900"))
        self.poll_interval = float(env.get("SEALED_POLL_INTERVAL_S", "3"))
        self.llm_key = (env.get("LLM_GATEWAY_KEY") or "").strip()
        self.session_key = (env.get("OH_SESSION_API_KEYS_0") or "").strip()
        if not self.llm_key:
            raise BootstrapError("LLM_GATEWAY_KEY is not set (secret of this app)")
        if not self.session_key:
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


class AgentServer:
    def __init__(self, http, base_url, session_key):
        self.http = http
        self.base = base_url
        self.auth = {"X-Session-API-Key": session_key}

    def ready(self):
        status, _ = self.http.call("GET", self.base + "/ready")
        return status == 200

    def stored_llm(self):
        status, payload = self.http.call("GET", self.base + "/api/settings", None, self.auth)
        if status == 409:
            raise BootstrapError("agent settings are encrypted with a different OH_SECRET_KEY (HTTP 409)")
        if status != 200 or not isinstance(payload, dict):
            raise BootstrapError("GET /api/settings failed (HTTP " + str(status) + ")")
        llm = (payload.get("agent_settings") or {}).get("llm")
        return llm if isinstance(llm, dict) else {}

    def patch_llm(self, llm):
        return self.http.call("PATCH", self.base + "/api/settings", {"agent_settings_diff": {"llm": llm}}, self.auth)


def choose_model(cfg, stored):
    """Keep a gateway model the customer chose earlier; otherwise use the default."""
    model = stored.get("model")
    if stored.get("base_url") == cfg.gateway_url and isinstance(model, str) and model.startswith(LITELLM_PREFIX):
        if len(model) > len(LITELLM_PREFIX):
            return model
    return LITELLM_PREFIX + cfg.model


def seed_openhands(cfg, agent, model):
    llm = {"model": model, "base_url": cfg.gateway_url, "api_key": cfg.llm_key, "usage_id": cfg.usage_id}
    status, _ = agent.patch_llm(llm)
    if status == 409:
        raise BootstrapError("agent settings are encrypted with a different OH_SECRET_KEY (HTTP 409)")
    if status >= 300:
        raise BootstrapError("PATCH /api/settings failed (HTTP " + str(status) + ")")


def write_done(path, summary):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, sort_keys=True) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def run(cfg, http, sleep=time.sleep, clock=time.monotonic):
    if os.path.exists(cfg.done_file):
        os.unlink(cfg.done_file)  # healthy only after this run succeeds
    agent = AgentServer(http, cfg.agent_url, cfg.session_key)
    log("waiting for the agent server at " + cfg.agent_url)
    wait_for("agent server", agent.ready, cfg.wait_timeout, cfg.poll_interval, sleep, clock)

    model = choose_model(cfg, agent.stored_llm())
    seed_openhands(cfg, agent, model)
    summary = {"model": model, "base_url": cfg.gateway_url, "at": int(time.time())}
    write_done(cfg.done_file, summary)
    log("done: model " + model)
    return summary


def main(env=None):
    try:
        cfg = Config(dict(os.environ if env is None else env))
        run(cfg, Http())
    except (BootstrapError, OSError) as err:
        log("error: " + str(err))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
