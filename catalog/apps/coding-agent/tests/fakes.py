"""In-process fake servers for coding-agent tests: OpenHands agent-server and OpenCode.

They implement only the endpoints the bootstrap job and the A6 helper use, with the auth and
status codes documented in docs/notes/openhands.md. Files the fake agents "write" land in a real
temp directory, and test commands really run there. The LiteLLM fake is shared with llm-gateway
(catalog/apps/llm-gateway/tests/fake_litellm.py), so the gateway's keys job and this app's
bootstrap are tested against the same gateway.
"""
from __future__ import annotations

import base64
import http.server
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import urllib.parse
from typing import Any, Callable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "llm-gateway", "tests"))
from fake_litellm import FakeLiteLLM  # noqa: E402,F401


class FakeServer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []
        self.lock = threading.Lock()
        handler = self._handler_class()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
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

    def paths(self, method: str | None = None) -> list[str]:
        return [p for m, p, _, _ in self.calls if method is None or m == method]

    def route(self, method: str, path: str, query: dict[str, str], body: Any, headers: dict[str, str]) -> tuple[int, Any]:
        raise NotImplementedError

    def _handler_class(self):
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parsed.query))
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                body: Any = None
                if raw:
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        body = raw.decode("utf-8", "replace")
                headers = {k.lower(): v for k, v in self.headers.items()}
                with server.lock:
                    server.calls.append((self.command, parsed.path, body, headers))
                status, payload = server.route(self.command, parsed.path, query, body, headers)
                if isinstance(payload, (dict, list)):
                    data = json.dumps(payload).encode()
                    ctype = "application/json"
                else:
                    data = str(payload if payload is not None else "").encode()
                    ctype = "text/plain"
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_HEAD = do_POST = do_PATCH = do_DELETE = do_PUT = _serve

            def log_message(self, *args):
                pass

        return Handler


class FakeOpenHands(FakeServer):
    """agent-server subset with a fake agent that writes the A6 files when a conversation runs."""

    def __init__(self, session_key: str, root: str, running_polls: int = 2, final_status: str = "finished",
                 settings_status: int | None = None, agent_writes: Callable[[str], None] | None = None,
                 record_tokens: bool | str = True, not_ready_polls: int = 0) -> None:
        super().__init__()
        self.session_key = session_key
        self.root = root
        self.running_polls = running_polls
        self.final_status = final_status
        self.settings_status = settings_status
        self.agent_writes = agent_writes or write_good_files
        self.record_tokens = record_tokens
        self.not_ready_polls = not_ready_polls
        self.settings: dict[str, Any] = {"agent_settings": {"llm": {}}}
        self.conversations: dict[str, dict[str, Any]] = {}

    def local(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def route(self, method, path, query, body, headers):
        if path == "/ready":
            if self.not_ready_polls > 0:
                self.not_ready_polls -= 1
                return 503, {"status": "initializing"}
            return 200, {"status": "ready"}
        if not path.startswith("/api/"):
            return 404, {"detail": "Not Found"}
        if headers.get("x-session-api-key") != self.session_key:
            return 401, {"detail": "Unauthorized"}
        if path == "/api/settings" and method == "PATCH":
            if self.settings_status:
                return self.settings_status, {"detail": "settings error"}
            llm = (body.get("agent_settings_diff") or {}).get("llm") or {}
            self.settings["agent_settings"]["llm"].update(llm)
            return 200, self.view_settings(False)
        if path == "/api/settings" and method == "GET":
            return 200, self.view_settings(headers.get("x-expose-secrets") == "plaintext")
        if path == "/api/file/create_directory" and method == "POST":
            os.makedirs(self.local(query["path"]), exist_ok=True)
            return 200, {"success": True}
        if path == "/api/file/download" and method == "GET":
            try:
                with open(self.local(query["path"])) as handle:
                    return 200, handle.read()
            except FileNotFoundError:
                return 404, {"detail": "File not found"}
        if path == "/api/bash/execute_bash_command" and method == "POST":
            proc = subprocess.run(body["command"].replace("python3", shlex.quote(sys.executable)), shell=True,
                                  cwd=self.local(body["cwd"]), capture_output=True, text=True, timeout=60)
            return 200, {"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
        if path == "/api/conversations" and method == "POST":
            cid = "conv-%d" % (len(self.conversations) + 1)
            self.conversations[cid] = {"body": body, "polls": 0}
            return 201, {"id": cid, "execution_status": "running"}
        match = re.fullmatch(r"/api/conversations/([^/]+)", path)
        if match and method == "GET":
            conv = self.conversations.get(match.group(1))
            if conv is None:
                return 404, {"detail": "not found"}
            conv["polls"] += 1
            status = "running"
            if conv["polls"] > self.running_polls:
                status = self.final_status
                if status == "finished" and not conv.get("written"):
                    self.agent_writes(self.local(conv["body"]["workspace"]["working_dir"]))
                    conv["written"] = True
            usage = {"accumulated_token_usage": {"prompt_tokens": 321, "completion_tokens": 45}}
            if self.record_tokens == "unknown-shape":
                usage = {"accumulated_cost": 0.0}
            stats = {"usage_to_metrics": {"coding-agent-a6": usage} if self.record_tokens else {}}
            return 200, {"id": match.group(1), "execution_status": status, "stats": stats}
        if match and method == "DELETE":
            self.conversations.pop(match.group(1), None)
            return 200, {"success": True}
        return 404, {"detail": "Not Found"}

    def view_settings(self, plaintext: bool) -> dict[str, Any]:
        llm = dict(self.settings["agent_settings"]["llm"])
        is_set = bool(llm.get("api_key"))
        if "api_key" in llm and not plaintext:
            llm["api_key"] = "**********"
        return {"agent_settings": {"llm": llm}, "llm_api_key_is_set": is_set}


def write_good_files(directory: str) -> None:
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "calc.py"), "w") as handle:
        handle.write("def add(a, b):\n    return a + b\n")
    with open(os.path.join(directory, "test_calc.py"), "w") as handle:
        handle.write("import unittest\nfrom calc import add\n\n\nclass T(unittest.TestCase):\n"
                     "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n\n\n"
                     "if __name__ == '__main__':\n    unittest.main()\n")


def write_broken_files(directory: str) -> None:
    write_good_files(directory)
    with open(os.path.join(directory, "calc.py"), "w") as handle:
        handle.write("def add(a, b):\n    return a - b\n")


class FakeOpenCode(FakeServer):
    """OpenCode server subset with HTTP basic auth on every route."""

    def __init__(self, user: str, password: str, root: str, exit_override: int | None = None,
                 record_tokens: bool = True, on_message: Callable[[], None] | None = None) -> None:
        super().__init__()
        self.expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.root = root
        self.exit_override = exit_override
        self.record_tokens = record_tokens
        self.on_message = on_message
        self.sessions: dict[str, Any] = {}

    def local(self, directory: str, rel: str = "") -> str:
        return os.path.join(self.root, directory.lstrip("/"), rel)

    def route(self, method, path, query, body, headers):
        if headers.get("authorization") != self.expected:
            return 401, "Unauthorized"
        directory = query.get("directory", "/workspace")
        if path == "/global/health" and method in ("GET", "HEAD"):
            return 200, {"healthy": True, "version": "1.19.5"}
        if path == "/session" and method == "POST":
            sid = "ses_%d" % (len(self.sessions) + 1)
            self.sessions[sid] = body
            os.makedirs(self.local(directory), exist_ok=True)
            return 200, {"id": sid, "title": body.get("title")}
        match = re.fullmatch(r"/session/([^/]+)/(message|shell)", path)
        if match and method == "POST":
            if match.group(2) == "message":
                sub = re.search(r"Create (a6-\d+)/calc.py", body["parts"][0]["text"]).group(1)
                write_good_files(self.local(directory, sub))
                if self.on_message:
                    self.on_message()
                info = {"role": "assistant"}
                if self.record_tokens:
                    info["tokens"] = {"input": 1200, "output": 80, "reasoning": 0, "cache": {"read": 0, "write": 0}}
                return 200, {"info": info, "parts": [{"type": "text", "text": "done"}]}
            proc = subprocess.run(body["command"].replace("python3", shlex.quote(sys.executable)), shell=True,
                                  cwd=self.local(directory), capture_output=True, text=True, timeout=60)
            code = proc.returncode if self.exit_override is None else self.exit_override
            return 200, {"info": {}, "parts": [{"type": "tool", "state": {"status": "completed",
                                                                           "metadata": {"exit": code}}}]}
        if path == "/file/content":
            try:
                with open(self.local(directory, query["path"])) as handle:
                    return 200, {"type": "text", "content": handle.read()}
            except FileNotFoundError:
                return 404, {"error": "not found"}
        if re.fullmatch(r"/session/[^/]+", path) and method == "DELETE":
            return 200, True
        return 404, "Not Found"
