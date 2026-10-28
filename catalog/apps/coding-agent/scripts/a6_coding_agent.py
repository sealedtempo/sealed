#!/usr/bin/env python3
"""A6 acceptance helper for the coding-agent app (headless flow, docs/notes/openhands.md section 7).

Asks the coding agent to write calc.py and test_calc.py through the llm-gateway, waits for it to
finish, then checks independently that the file exists, that the test passes when we run it
ourselves, and that tokens were used. Prints a JSON summary on success, exits non-zero otherwise.

Gate: the code route sits behind Sealed's gate (Caddy forward_auth to sealed-agent). With
--gate-password the helper sends Basic auth (user sealed) once, keeps the sealed_gate cookie the
gate sets, and sends only the cookie afterwards, so the gate password crosses the wire once and the
agent never sees it. While the app's bootstrap is not done the gate answers 503 starting; the
helper waits up to --gate-wait seconds. A gate that sets no cookie gets Basic auth on every call.

OpenHands (default):
  a6-coding-agent.sh --url https://code.<ip-with-dashes>.sslip.io \
      --session-key "$CODING_AGENT_API_KEY" --gate-password "$SEALED_GATE_PASSWORD"
  The LLM settings (model, gateway URL, virtual key) are read from the agent's stored settings,
  which the bootstrap job seeded. Override with --model litellm_proxy/local/qwen3-4b or --llm-key.

OpenCode fallback (--session-key is its CODE_SESSION_API_KEY):
  a6-coding-agent.sh --target opencode --url https://code.<ip>.sslip.io --session-key "$K" --gate-password "$PW"

Token evidence: the agent's own usage counters must show tokens. With --gateway-admin-key (the
gateway master key) and --gateway-check-url https://gateway.<ip>.sslip.io, llm-gateway's spend
logs must also show tokens for this app's key since the run started; that corroboration is
required whenever the agent's counters have an unknown shape.

Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

TASK = (
    "In the current directory create calc.py containing def add(a, b): return a + b, and test_calc.py "
    "with a unittest.TestCase asserting add(2, 3) == 5. Then run: python3 -m unittest -v test_calc. "
    "Finish when the test passes."
)
TERMINAL = ("finished", "error", "stuck")
REDACTED = "**********"
TEST_COMMAND = "python3 -m unittest -v test_calc"
GATE_COOKIE = "sealed_gate"
GATE_REALM = 'realm="sealed"'
REDIRECTS = (301, 302, 303, 307, 308)
PROBE = {"openhands": "/ready", "opencode": "/global/health"}


class A6Error(Exception):
    pass


def log(message: str) -> None:
    print("a6: " + message, file=sys.stderr, flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects come back as responses, so a Set-Cookie on them is never lost."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def gate_refused(status: int, headers: Any) -> bool:
    return status == 401 and GATE_REALM in (headers.get("WWW-Authenticate") or "")


def origin(url: str) -> tuple[str, str]:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme, parts.netloc


class Gate:
    """Client side of Sealed's gate: Basic auth once, then the sealed_gate cookie."""

    def __init__(self, user: str, password: str, wait: float = 300.0, poll: float = 5.0,
                 sleep: Any = time.sleep, clock: Any = time.monotonic) -> None:
        self.basic = basic_auth(user, password)["Authorization"]
        self.cookie: Optional[str] = None
        self.basic_every_call = False
        self.logins = 0
        self.wait, self.poll, self.sleep, self.clock = wait, poll, sleep, clock

    def headers(self) -> dict[str, str]:
        if self.cookie:
            return {"Cookie": f"{GATE_COOKIE}={self.cookie}"}
        if self.basic_every_call:
            return {"Authorization": self.basic}
        return {}

    def observe(self, headers: Any) -> None:
        for value in headers.get_all("Set-Cookie") or []:
            name, _, rest = value.partition("=")
            if name.strip() == GATE_COOKIE:
                token = rest.split(";", 1)[0].strip()
                if token:
                    self.cookie = token

    def wait_started(self, attempt: Any, path: str, deadline: float) -> tuple[int, Any]:
        while True:
            status, headers = attempt()
            if status == 503 and self.clock() < deadline:
                log(f"waiting for the app to start (503 on {path})")
                self.sleep(self.poll)
                continue
            return status, headers

    def login(self, client: "Client", path: str) -> None:
        """Probe without credentials; if the gate asks, send Basic auth once and keep the cookie.

        The gate password is sent only to a route whose gate asks for it (401 with a Basic
        challenge), never to an ungated URL such as the in-VM address of the service.
        """
        self.logins += 1
        self.cookie = None
        self.basic_every_call = False
        deadline = self.clock() + self.wait

        def bare() -> tuple[int, Any]:
            status, headers, _ = client.send("GET", client.base + path, None, dict(client.headers))
            return status, headers

        def with_password() -> tuple[int, Any]:
            url = client.base + path
            status, headers, _ = client.send("GET", url, None, {**client.headers, "Authorization": self.basic})
            self.observe(headers)
            if status in REDIRECTS and self.cookie:
                url = urllib.parse.urljoin(url, headers.get("Location") or path)
                if origin(url) != origin(client.base):
                    raise A6Error("the gate redirected to another origin: " + origin(url)[1])
                status, headers, _ = client.send("GET", url, None, {**client.headers, **self.headers()})
                self.observe(headers)
            return status, headers

        status, headers = self.wait_started(bare, path, deadline)
        challenge = (headers.get("WWW-Authenticate") or "").lower()
        if status == 503:
            raise A6Error(f"the app did not start within {self.wait:g}s (HTTP 503 on {path})")
        if status != 401 or not challenge.startswith("basic"):
            log("gate: the route did not ask for the gate password, so it is not sent")
            return
        status, headers = self.wait_started(with_password, path, deadline)
        if status == 401:
            raise A6Error("the gate refused the gate password (HTTP 401); check --gate-password")
        if status == 503:
            raise A6Error(f"the app did not start within {self.wait:g}s (gate answered 503)")
        if self.cookie:
            log("gate: logged in once, using the sealed_gate cookie from now on")
        else:
            self.basic_every_call = True
            log("gate: no sealed_gate cookie was set; sending Basic auth on every call")


class Client:
    def __init__(self, base_url: str, headers: dict[str, str], timeout: float = 60.0,
                 context: Optional[ssl.SSLContext] = None, gate: Optional[Gate] = None) -> None:
        self.base = base_url.rstrip("/")
        self.headers = headers
        self.timeout = timeout
        self.gate = gate
        self.probe = "/"
        handlers: list[Any] = [NoRedirect()]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def send(self, method: str, url: str, data: Optional[bytes], headers: dict[str, str],
             timeout: Optional[float] = None) -> tuple[int, Any, bytes]:
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout or self.timeout) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers, err.read()
        except (urllib.error.URLError, OSError) as err:
            raise A6Error(f"{method} {urllib.parse.urlsplit(url).path}: {err}") from None

    def call(self, method: str, path: str, body: Any = None, query: Optional[dict[str, str]] = None,
             headers: Optional[dict[str, str]] = None, timeout: Optional[float] = None) -> tuple[int, Any]:
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        hdrs = dict(self.headers)
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        for attempt in (1, 2):
            sent = dict(hdrs, **(self.gate.headers() if self.gate else {}))
            status, rheaders, raw = self.send(method, url, data, sent, timeout)
            if self.gate is None:
                if gate_refused(status, rheaders):
                    raise A6Error(f"{method} {path}: the route is behind the Sealed gate; pass --gate-password")
                break
            self.gate.observe(rheaders)
            # A refused cookie (expired, or sealed-agent restarted with a new key): log in again
            # once. The gate stopped the request, so the app never saw it and a retry is safe.
            if attempt == 1 and self.gate.cookie and gate_refused(status, rheaders):
                log("gate: the sealed_gate cookie was refused, logging in again")
                self.gate.login(self, self.probe)
                continue
            break
        return status, _decode(raw)

    def ok(self, method: str, path: str, **kwargs: Any) -> Any:
        status, payload = self.call(method, path, **kwargs)
        if not 200 <= status < 300:
            detail = payload if isinstance(payload, str) else json.dumps(payload)
            raise A6Error(f"{method} {path}: HTTP {status}: {detail[:300]}")
        return payload


def _decode(raw: bytes) -> Any:
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def basic_auth(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": "Basic " + token}


def resolve_llm(client: Client, args: argparse.Namespace) -> dict[str, Any]:
    if args.llm_key:
        return {"model": args.model or "litellm_proxy/relay/default", "base_url": args.gateway_url,
                "api_key": args.llm_key}
    settings = client.ok("GET", "/api/settings", headers={"X-Expose-Secrets": "plaintext"})
    llm = dict(((settings or {}).get("agent_settings") or {}).get("llm") or {})
    key = llm.get("api_key")
    if not isinstance(key, str) or not key or key == REDACTED:
        raise A6Error("stored LLM settings have no usable api_key; did the bootstrap job run? (or pass --llm-key)")
    if not llm.get("model") or not llm.get("base_url"):
        raise A6Error("stored LLM settings are missing model or base_url")
    if args.model:
        llm["model"] = args.model
        llm.pop("litellm_extra_body", None)
    return llm


def total_prompt_tokens(info: dict[str, Any]) -> Optional[int]:
    metrics = ((info.get("stats") or {}).get("usage_to_metrics")) or {}
    values = metrics.values() if isinstance(metrics, dict) else metrics
    total, seen = 0, False
    for metric in values:
        usage = (metric or {}).get("accumulated_token_usage") or {}
        if "prompt_tokens" in usage:
            seen = True
            total += int(usage.get("prompt_tokens") or 0)
    if seen:
        return total
    return None if not values else -1


def parse_time(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def row_tokens(row: dict[str, Any]) -> int:
    total = row.get("total_tokens")
    if isinstance(total, int) and total > 0:
        return total
    return sum(v for v in (row.get("prompt_tokens"), row.get("completion_tokens")) if isinstance(v, int) and v > 0)


def gateway_tokens(args: argparse.Namespace, llm_key: Optional[str], since: float) -> Optional[int]:
    """Tokens llm-gateway logged for this app's key since `since`, or None without --gateway-admin-key."""
    if not args.gateway_admin_key:
        return None
    context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else None
    gateway = Client(args.gateway_check_url or args.gateway_url,
                     {"Authorization": "Bearer " + args.gateway_admin_key}, context=context)
    query = {"api_key": hashlib.sha256(llm_key.encode("utf-8")).hexdigest()} if llm_key else None
    rows = gateway.ok("GET", "/spend/logs", query=query)
    if not isinstance(rows, list):
        raise A6Error("unexpected /spend/logs response from llm-gateway")
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if not llm_key and (row.get("metadata") or {}).get("user_api_key_alias") != args.key_alias:
            continue
        started = parse_time(row.get("startTime"))
        if started is not None and started >= since - 5:
            total += row_tokens(row)
    return total


def require_tokens(agent_tokens: Optional[int], gateway: Optional[int], source: str) -> None:
    if gateway is not None and gateway <= 0:
        raise A6Error(f"llm-gateway logged no tokens for {source} since the run started")
    if agent_tokens is None or agent_tokens == 0:
        if gateway is None:
            raise A6Error(f"{source} recorded no LLM usage")
        return
    if agent_tokens < 0 and gateway is None:
        raise A6Error(f"{source} usage has an unknown shape; pass --gateway-admin-key (and "
                      "--gateway-check-url) so llm-gateway can corroborate the token use")


def openhands(client: Client, args: argparse.Namespace) -> dict[str, Any]:
    started = time.time()
    client.ok("GET", "/ready")
    llm = resolve_llm(client, args)
    llm.setdefault("usage_id", "coding-agent-a6")
    workdir = f"{args.workspace.rstrip('/')}/a6-{int(time.time())}"
    client.ok("POST", "/api/file/create_directory", query={"path": workdir})
    body = {
        "agent": {"kind": "Agent", "llm": llm, "tools": [{"name": "terminal"}, {"name": "file_editor"}]},
        "workspace": {"working_dir": workdir},
        "max_iterations": args.max_iterations,
        "autotitle": False,
        "initial_message": {"role": "user", "run": True, "content": [{"type": "text", "text": TASK}]},
    }
    created = client.ok("POST", "/api/conversations", body=body)
    cid = created.get("id") if isinstance(created, dict) else None
    if not cid:
        raise A6Error("conversation create returned no id")
    log(f"conversation {cid} started in {workdir} with model {llm['model']}")

    status = "running"
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        info = client.ok("GET", f"/api/conversations/{cid}")
        status = str(info.get("execution_status", ""))
        if status in TERMINAL:
            break
        time.sleep(args.poll)
    if status != "finished":
        raise A6Error(f"agent did not finish (last status {status!r})")

    content = client.ok("GET", "/api/file/download", query={"path": f"{workdir}/calc.py"})
    if "def add" not in (content if isinstance(content, str) else json.dumps(content)):
        raise A6Error("calc.py does not define add")
    result = client.ok("POST", "/api/bash/execute_bash_command",
                       body={"command": TEST_COMMAND, "cwd": workdir, "timeout": 120}, timeout=180)
    if not isinstance(result, dict) or result.get("exit_code") != 0:
        raise A6Error(f"independent test run failed: {json.dumps(result)[:500]}")

    info = client.ok("GET", f"/api/conversations/{cid}")
    tokens = total_prompt_tokens(info)
    if tokens is None or tokens == 0:
        raise A6Error("conversation recorded no LLM usage")
    gateway = gateway_tokens(args, llm.get("api_key"), started)
    require_tokens(tokens, gateway, "the conversation")
    if not args.keep:
        client.call("DELETE", f"/api/conversations/{cid}")
    return {"target": "openhands", "conversation": cid, "workdir": workdir, "model": llm["model"],
            "prompt_tokens": tokens if tokens >= 0 else None, "gateway_tokens": gateway, "test_exit_code": 0}


def shell_exit(result: Any) -> Optional[int]:
    parts = result.get("parts") if isinstance(result, dict) else None
    exits = []
    for part in parts or []:
        if isinstance(part, dict) and part.get("type") == "tool":
            meta = ((part.get("state") or {}).get("metadata")) or {}
            if "exit" in meta:
                exits.append(meta["exit"])
    return exits[-1] if exits else None


def message_tokens(reply: Any) -> Optional[int]:
    """input + output tokens of an OpenCode assistant message, or None if it has no counters."""
    info = reply.get("info") if isinstance(reply, dict) else None
    tokens = info.get("tokens") if isinstance(info, dict) else None
    if not isinstance(tokens, dict):
        return None
    return sum(v for v in (tokens.get("input"), tokens.get("output")) if isinstance(v, int) and v > 0)


def opencode(client: Client, args: argparse.Namespace) -> dict[str, Any]:
    started = time.time()
    health = client.ok("GET", "/global/health")
    if not (isinstance(health, dict) and health.get("healthy")):
        raise A6Error("OpenCode is not healthy")
    query = {"directory": args.workspace}
    sub = f"a6-{int(time.time())}"
    session = client.ok("POST", "/session", body={"title": "a6"}, query=query)
    sid = session.get("id") if isinstance(session, dict) else None
    if not sid:
        raise A6Error("session create returned no id")
    model = args.model or "relay-default"
    text = (f"Create {sub}/calc.py with def add(a, b): return a + b and {sub}/test_calc.py (unittest, "
            f"asserts add(2, 3) == 5). Run: cd {sub} && {TEST_COMMAND}")
    log(f"session {sid} started with model litellm/{model}")
    reply = client.ok("POST", f"/session/{sid}/message", query=query, timeout=args.timeout, body={
        "model": {"providerID": "litellm", "modelID": model}, "agent": "build",
        "parts": [{"type": "text", "text": text}],
    })
    tokens = message_tokens(reply)
    content = client.ok("GET", "/file/content", query={"path": f"{sub}/calc.py", **query})
    if "def add" not in str((content or {}).get("content", "") if isinstance(content, dict) else content):
        raise A6Error("calc.py does not define add")
    result = client.ok("POST", f"/session/{sid}/shell", query=query, timeout=180,
                       body={"agent": "build", "command": f"cd {sub} && {TEST_COMMAND}"})
    code = shell_exit(result)
    if code != 0:
        raise A6Error(f"independent test run failed (exit {code})")
    gateway = gateway_tokens(args, args.llm_key, started)
    require_tokens(tokens, gateway, "the OpenCode reply")
    if not args.keep:
        client.call("DELETE", f"/session/{sid}", query=query)
    return {"target": "opencode", "session": sid, "workdir": f"{args.workspace}/{sub}", "model": model,
            "tokens": tokens, "gateway_tokens": gateway, "test_exit_code": 0}


def parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    env = os.environ
    p = argparse.ArgumentParser(description="A6 acceptance check for the coding-agent app")
    p.add_argument("--target", choices=("openhands", "opencode"), default=env.get("A6_TARGET", "openhands"))
    p.add_argument("--url", default=env.get("A6_URL"), help="code route or http://coding-agent-server:8000")
    p.add_argument("--session-key", default=env.get("CODING_AGENT_API_KEY"),
                   help="X-Session-API-Key: OH_SESSION_API_KEYS_0 (OpenHands) or CODE_SESSION_API_KEY (OpenCode)")
    p.add_argument("--gate-user", default=env.get("SEALED_GATE_USER", "sealed"))
    p.add_argument("--gate-password", default=env.get("SEALED_GATE_PASSWORD"),
                   help="gate password: sent once as Basic auth, then the sealed_gate cookie is used")
    p.add_argument("--gate-wait", type=float, default=float(env.get("A6_GATE_WAIT_S", "300")),
                   help="seconds to wait while the gate answers 503 (app bootstrap not done)")
    p.add_argument("--llm-key", default=env.get("CODING_AGENT_LLM_KEY"), help="LiteLLM virtual key override")
    p.add_argument("--model", default=env.get("A6_MODEL"), help="model override, e.g. litellm_proxy/local/qwen3-4b")
    p.add_argument("--gateway-url", default=env.get("A6_GATEWAY_URL", "http://llm-gateway:4000"),
                   help="gateway URL as the agent sees it (base_url with --llm-key)")
    p.add_argument("--gateway-check-url", default=env.get("A6_GATEWAY_CHECK_URL"),
                   help="gateway URL reachable from here for the spend-log check (default --gateway-url)")
    p.add_argument("--gateway-admin-key", default=env.get("A6_GATEWAY_MASTER_KEY"),
                   help="gateway master key; enables the spend-log corroboration")
    p.add_argument("--key-alias", default=env.get("A6_KEY_ALIAS", "coding-agent"),
                   help="gateway key alias of the app (spend logs, when the key itself is unknown)")
    p.add_argument("--workspace", default=None, help="parent dir for the test files")
    p.add_argument("--timeout", type=float, default=float(env.get("A6_TIMEOUT_S", "900")))
    p.add_argument("--poll", type=float, default=float(env.get("A6_POLL_S", "5")))
    p.add_argument("--max-iterations", type=int, default=40)
    p.add_argument("--ca-file", default=env.get("A6_CA_FILE"))
    p.add_argument("--keep", action="store_true", help="keep the conversation or session afterwards")
    args = p.parse_args(argv)
    if not args.url:
        p.error("--url (or A6_URL) is required")
    if not args.session_key:
        p.error("--session-key (or CODING_AGENT_API_KEY) is required")
    if args.workspace is None:
        args.workspace = "/workspace/project"
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    headers = {"X-Session-API-Key": args.session_key}
    context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else None
    gate = None
    if args.gate_password:
        gate = Gate(args.gate_user, args.gate_password, wait=args.gate_wait, poll=min(args.poll, 5.0))
    client = Client(args.url, headers, context=context, gate=gate)
    client.probe = PROBE[args.target]
    try:
        if gate is not None:
            gate.login(client, client.probe)
        summary = (openhands if args.target == "openhands" else opencode)(client, args)
    except A6Error as err:
        log("FAIL: " + str(err))
        return 1
    print(json.dumps({"ok": True, **summary}, sort_keys=True))
    log("A6 coding-agent OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
