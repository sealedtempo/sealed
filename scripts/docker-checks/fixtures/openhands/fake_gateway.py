"""Fake llm-gateway for `scripts/docker-checks/run.sh --openhands` (a test double, never shipped).

It stands in for llm-gateway-litellm at its composed addresses (alias llm-gateway on the apps network,
port 4000) and speaks just enough of the LiteLLM proxy API for the OpenHands agent-server and the A6
helper (catalog/apps/coding-agent/scripts/a6_coding_agent.py):

- POST /chat/completions and /v1/chat/completions: a scripted model. When the request offers tools it
  answers with tool calls, decided from the conversation so far: a terminal command that writes
  calc.py and test_calc.py in the current directory, then one that runs the test, then finish.
  stream: true is answered as server-sent events.
- GET /v1/model/info and /model/info: one model, relay/default, with function calling.
- GET /spend/logs: one row per chat call, for the A6 helper's --gateway-admin-key corroboration.
- GET /health/liveliness and /health/readiness: 200.
- GET /dc/stats: request counts for run.sh (no secrets in it).

LLM calls must carry "Authorization: Bearer <key>" with the key in DC_APP_KEY_FILE (llm-gateway's
APP_KEY_CODING_AGENT, which coding-agent's LLM_GATEWAY_KEY refers to); /spend/logs needs the key in
DC_MASTER_KEY_FILE (LITELLM_MASTER_KEY). A wrong or missing key gets 401 and is counted. Secret values
are never printed. Standard library only; runs with the agent-server image's python3.
"""
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "relay/default"
WRITE_FILES = (
    "printf 'def add(a, b):\\n    return a + b\\n' > calc.py && "
    "printf 'import unittest\\n\\nfrom calc import add\\n\\n\\nclass TestAdd(unittest.TestCase):\\n"
    "    def test_add(self):\\n        self.assertEqual(add(2, 3), 5)\\n' > test_calc.py && pwd && ls"
)
RUN_TEST = "python3 -m unittest -v test_calc"
TERMINAL_NAMES = ("terminal", "execute_bash", "bash")

LOCK = threading.Lock()
STATS = {"chat": 0, "chat_stream": 0, "model_info": 0, "spend_logs": 0, "unauthorized": {},
         "prompt_tokens": 0, "completion_tokens": 0, "steps": {}, "paths": {}, "models": [],
         "tools_offered": [], "last_tool_results": []}
SPEND = []


def log(msg):
    print("fake-gateway: " + msg, file=sys.stdout, flush=True)


def read_key(env):
    path = os.environ.get(env, "")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


APP_KEY = read_key("DC_APP_KEY_FILE")
MASTER_KEY = read_key("DC_MASTER_KEY_FILE")


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return ""


def resolve(schema, root):
    """Follow a local $ref and take the first non-null anyOf/oneOf branch."""
    for _ in range(8):
        if not isinstance(schema, dict):
            return {}
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            node = root
            for part in ref[2:].split("/"):
                node = node.get(part, {}) if isinstance(node, dict) else {}
            schema = node
            continue
        for key in ("anyOf", "oneOf"):
            branches = [b for b in schema.get(key, []) if isinstance(b, dict) and b.get("type") != "null"]
            if branches:
                schema = branches[0]
                break
        else:
            return schema
    return schema


def fill_args(params, given):
    """Arguments for a tool call: the given ones plus a value for every other required parameter."""
    args = dict(given)
    props = params.get("properties", {}) if isinstance(params, dict) else {}
    for name in params.get("required", []) if isinstance(params, dict) else []:
        if name in args:
            continue
        prop = resolve(props.get(name, {}), params)
        enum = prop.get("enum")
        if enum:
            args[name] = "LOW" if "LOW" in enum else enum[0]
        elif prop.get("type") == "boolean":
            args[name] = False
        elif prop.get("type") in ("integer", "number"):
            args[name] = prop.get("default", 60)
        elif prop.get("type") == "array":
            args[name] = []
        elif prop.get("type") == "object":
            args[name] = {}
        else:
            args[name] = "docker-checks scripted step"
    return args


def tool_params(tools, name):
    for tool in tools:
        fn = tool.get("function", {}) if isinstance(tool, dict) else {}
        if fn.get("name") == name:
            return fn.get("parameters") or {}
    return None


def decide(body):
    """Return (step, message) for the next assistant turn."""
    messages = body.get("messages") or []
    tools = body.get("tools") or []
    names = [t.get("function", {}).get("name") for t in tools if isinstance(t, dict)]
    results = [text_of(m.get("content")) for m in messages if isinstance(m, dict) and m.get("role") == "tool"]
    with LOCK:
        STATS["tools_offered"] = sorted(n for n in names if n)
        STATS["last_tool_results"] = [r[-300:] for r in results[-3:]]
    terminal = next((n for n in TERMINAL_NAMES if n in names), None)
    if not tools or terminal is None:
        return "text", {"role": "assistant", "content": "Done."}
    if len(results) == 0:
        step, name, given = "write", terminal, {"command": WRITE_FILES}
    elif len(results) == 1:
        step, name, given = "test", terminal, {"command": RUN_TEST}
    elif "finish" in names:
        step, name, given = "finish", "finish", {"message": "calc.py and test_calc.py are written and the test passes."}
    else:
        return "text", {"role": "assistant", "content": "calc.py and test_calc.py are written and the test passes."}
    args = fill_args(tool_params(tools, name) or {}, given)
    call = {"id": "call_dc_%d_%s" % (int(time.time() * 1000), step), "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}
    return step, {"role": "assistant", "content": None, "tool_calls": [call]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def bearer(self):
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return (self.headers.get("x-litellm-api-key") or self.headers.get("api-key") or "").strip()

    def count_path(self):
        path = self.path.split("?", 1)[0]
        with LOCK:
            STATS["paths"][self.command + " " + path] = STATS["paths"].get(self.command + " " + path, 0) + 1
        return path

    def authorized(self, want):
        if want and self.bearer() == want:
            return True
        what = self.command + " " + self.path.split("?", 1)[0]
        with LOCK:
            STATS["unauthorized"][what] = STATS["unauthorized"].get(what, 0) + 1
        # Header names only, never values.
        log("401 for %s (%s; headers: %s)" % (what, "wrong key" if self.bearer() else "no key",
                                             ", ".join(sorted(k.lower() for k in self.headers.keys()))))
        self.send_json(401, {"error": {"message": "Authentication Error, invalid key", "type": "auth_error"}})
        return False

    def do_GET(self):
        path = self.count_path()
        if path in ("/health/liveliness", "/health/readiness", "/health"):
            return self.send_json(200, {"status": "healthy"})
        if path == "/dc/stats":
            with LOCK:
                return self.send_json(200, STATS)
        if path in ("/v1/model/info", "/model/info", "/model_group/info"):
            if not self.authorized(APP_KEY):
                return None
            with LOCK:
                STATS["model_info"] += 1
            info = {"max_input_tokens": 131072, "max_output_tokens": 8192, "max_tokens": 8192,
                    "input_cost_per_token": 0.0, "output_cost_per_token": 0.0, "mode": "chat",
                    "supports_function_calling": True, "supports_vision": False}
            return self.send_json(200, {"data": [{"model_name": MODEL, "litellm_params": {"model": MODEL},
                                                  "model_info": dict(info, id="dc-relay-default")}]})
        if path == "/spend/logs":
            if not self.authorized(MASTER_KEY):
                return None
            query = dict(p.split("=", 1) for p in self.path.split("?", 1)[1].split("&") if "=" in p) if "?" in self.path else {}
            with LOCK:
                STATS["spend_logs"] += 1
                rows = [r for r in SPEND if not query.get("api_key") or r["api_key"] == query["api_key"]]
            return self.send_json(200, rows)
        if path in ("/v1/models", "/models"):
            if not self.authorized(APP_KEY):
                return None
            return self.send_json(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})
        log("404 for GET " + path)
        return self.send_json(404, {"error": {"message": "not found in the fake gateway"}})

    def do_POST(self):
        path = self.count_path()
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if path not in ("/chat/completions", "/v1/chat/completions"):
            log("404 for POST " + path)
            return self.send_json(404, {"error": {"message": "not found in the fake gateway"}})
        if not self.authorized(APP_KEY):
            return None
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self.send_json(400, {"error": {"message": "invalid JSON"}})
        step, message = decide(body)
        prompt = max(1, len(raw) // 4)
        completion = max(1, len(json.dumps(message)) // 4)
        model = str(body.get("model") or MODEL)
        stream = bool(body.get("stream"))
        with LOCK:
            STATS["chat"] += 1
            n = STATS["chat"]
            STATS["chat_stream"] += 1 if stream else 0
            STATS["prompt_tokens"] += prompt
            STATS["completion_tokens"] += completion
            STATS["steps"][step] = STATS["steps"].get(step, 0) + 1
            if model not in STATS["models"]:
                STATS["models"].append(model)
            SPEND.append({"request_id": "dc-%d" % n, "api_key": hashlib.sha256(APP_KEY.encode()).hexdigest(),
                          "startTime": now_iso(), "endTime": now_iso(), "model": model,
                          "prompt_tokens": prompt, "completion_tokens": completion,
                          "total_tokens": prompt + completion, "metadata": {"user_api_key_alias": "coding-agent"}})
        log("chat %d: model %s, %d messages, %d tools, step %s%s" % (
            n, model, len(body.get("messages") or []), len(body.get("tools") or []), step,
            " (stream)" if stream else ""))
        usage = {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}
        finish = "tool_calls" if message.get("tool_calls") else "stop"
        cid, created = "chatcmpl-dc-%d" % n, int(time.time())
        if not stream:
            return self.send_json(200, {"id": cid, "object": "chat.completion", "created": created, "model": model,
                                        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                                        "usage": usage})
        delta = {"role": "assistant", "content": message.get("content")}
        if message.get("tool_calls"):
            delta["tool_calls"] = [dict(c, index=i) for i, c in enumerate(message["tool_calls"])]
        chunks = [
            {"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}]},
            {"choices": [], "usage": usage},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for chunk in chunks:
            chunk.update({"id": cid, "object": "chat.completion.chunk", "created": created, "model": model})
            self.wfile.write(b"data: " + json.dumps(chunk).encode("utf-8") + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True
        return None


def main():
    if not APP_KEY or not MASTER_KEY:
        log("DC_APP_KEY_FILE and DC_MASTER_KEY_FILE must name non-empty files")
        return 1
    port = int(os.environ.get("DC_PORT", "4000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    log("listening on :%d" % port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
