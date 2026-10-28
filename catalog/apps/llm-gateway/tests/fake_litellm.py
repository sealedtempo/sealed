"""In-process fake of the LiteLLM proxy endpoints used by the keys job, the coding-agent bootstrap
and the A6 helper. Behavior follows the LiteLLM 1.106.5 source (key_management_endpoints.py,
spend_management_endpoints.py): keys are stored and looked up by sha256 of the raw key, custom
key values must start with sk- and be at least 16 characters, aliases are unique among live keys,
deleted keys stay readable through /key/info with status "deleted", and /spend/logs filters by
the hashed key.
"""
from __future__ import annotations

import fnmatch
import hashlib
import http.server
import json
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

ROUTES = ("local/qwen3-4b", "local/*", "relay/default", "relay/*")


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest() if value.startswith("sk-") else value


class FakeLiteLLM:
    def __init__(self, master_key: str, routes=ROUTES, not_ready_polls: int = 0) -> None:
        self.master_key = master_key
        self.routes = list(routes)
        self.not_ready_polls = not_ready_polls
        self.keys: dict[str, dict[str, Any]] = {}
        self.deleted: dict[str, dict[str, Any]] = {}
        self.spend_logs: list[dict[str, Any]] = []
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []
        self.lock = threading.Lock()
        self.counter = 0
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    # Test helpers ---------------------------------------------------------------------------
    def by_alias(self, alias: str) -> dict[str, Any] | None:
        return next((k for k in self.keys.values() if k.get("key_alias") == alias), None)

    def add_key(self, raw: str, **fields) -> dict[str, Any]:
        record = {"token": hash_token(raw), "key_alias": None, "models": [], "metadata": {},
                  "blocked": None, "key_type": "default", **fields}
        self.keys[record["token"]] = record
        return record

    def reset_database(self) -> None:
        self.keys.clear()
        self.deleted.clear()

    def record_usage(self, raw_key: str, prompt: int, completion: int, at: float | None = None) -> None:
        record = self.keys[hash_token(raw_key)]
        start = datetime.fromtimestamp(at if at is not None else time.time(), tz=timezone.utc)
        self.spend_logs.append({
            "request_id": "chatcmpl-%d" % len(self.spend_logs), "api_key": record["token"],
            "startTime": start.isoformat().replace("+00:00", "Z"), "total_tokens": prompt + completion,
            "prompt_tokens": prompt, "completion_tokens": completion, "spend": 0.0,
            "metadata": {"user_api_key_alias": record.get("key_alias")},
        })

    def paths(self, method: str | None = None) -> list[str]:
        return [p for m, p, _, _ in self.calls if method is None or m == method]

    # Routing ---------------------------------------------------------------------------------
    def caller(self, headers: dict[str, str]) -> tuple[str, dict[str, Any] | None]:
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return "none", None
        token = auth[len("Bearer "):]
        if token == self.master_key:
            return "admin", None
        record = self.keys.get(hash_token(token))
        if record is None or record.get("blocked"):
            return "none", None
        return "key", record

    def route(self, method: str, path: str, query: dict[str, str], body: Any, headers: dict[str, str]):
        if method == "GET" and path == "/health/readiness":
            if self.not_ready_polls > 0:
                self.not_ready_polls -= 1
                return 503, {"status": "unhealthy", "db": "Not connected"}
            return 200, {"status": "healthy", "db": "connected"}
        role, record = self.caller(headers)
        if role == "none":
            return 401, {"error": {"message": "Authentication Error, Invalid proxy server token passed"}}
        if method == "GET" and path == "/v1/models":
            allowed = record["models"] if record else ["*"]
            names = [r for r in self.routes if any(fnmatch.fnmatchcase(r, p) or r == p for p in allowed)]
            return 200, {"object": "list", "data": [{"id": n, "object": "model"} for n in names]}
        if role != "admin":
            return 401, {"error": {"message": "Only proxy admins can use this route"}}
        if method == "GET" and path == "/key/info":
            token = hash_token(query.get("key", ""))
            if token in self.keys:
                return 200, {"key": query["key"], "info": self.view(self.keys[token], "active")}
            if token in self.deleted:
                return 200, {"key": query["key"], "info": self.view(self.deleted[token], "deleted")}
            return 404, {"error": {"message": "Key not found in database"}}
        if method == "POST" and path == "/key/generate":
            return self.generate(body)
        if method == "POST" and path == "/key/update":
            token = hash_token(body.get("key", ""))
            if token not in self.keys:
                return 404, {"error": {"message": "key not found"}}
            alias = body.get("key_alias")
            if alias and any(k.get("key_alias") == alias for t, k in self.keys.items() if t != token):
                return 400, {"error": {"message": "Unique key aliases across all keys are required"}}
            self.keys[token].update({k: v for k, v in body.items() if k != "key"})
            return 200, {"key": token}
        if method == "POST" and path == "/key/delete":
            aliases = set(body.get("key_aliases") or [])
            for token in [t for t, k in self.keys.items() if k.get("key_alias") in aliases]:
                self.deleted[token] = self.keys.pop(token)
            return 200, {"deleted_keys": sorted(aliases)}
        if method == "GET" and path == "/spend/logs":
            rows = self.spend_logs
            if "api_key" in query:
                rows = [r for r in rows if r["api_key"] == hash_token(query["api_key"])]
            return 200, sorted(rows, key=lambda r: r["startTime"], reverse=True)
        return 404, {"detail": "Not Found"}

    def view(self, record: dict[str, Any], status: str) -> dict[str, Any]:
        info = {k: v for k, v in record.items() if k != "token"}
        info["status"] = "revoked" if record.get("blocked") and status == "active" else status
        return info

    def generate(self, body: dict[str, Any]):
        key = body.get("key")
        alias = body.get("key_alias")
        if alias and self.by_alias(alias):
            return 400, {"error": {"message": f"Key with alias '{alias}' already exists."}}
        if key is not None and not key.startswith("sk-"):
            return 400, {"error": {"message": "Invalid key format. LiteLLM Virtual Key must start with 'sk-'."}}
        if key is not None and len(key) < 16:
            return 400, {"error": {"message": "Invalid key format. LiteLLM Virtual Key must be at least 16 characters long."}}
        if key is None:
            self.counter += 1
            key = "sk-generated-%04d" % self.counter
        token = hash_token(key)
        if token in self.keys:
            return 500, {"error": {"message": "Unique constraint failed on the fields: (`token`)"}}
        self.deleted.pop(token, None)
        fields = {k: v for k, v in body.items() if k != "key"}
        self.add_key(key, **fields)
        return 200, {"key": key, "key_alias": alias, "token_id": token}

    def _handler(self):
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parsed.query))
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None
                headers = {k.lower(): v for k, v in self.headers.items()}
                with fake.lock:
                    fake.calls.append((self.command, self.path, body, headers))
                    status, payload = fake.route(self.command, parsed.path, query, body, headers)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _serve

            def log_message(self, *args):
                pass

        return Handler
