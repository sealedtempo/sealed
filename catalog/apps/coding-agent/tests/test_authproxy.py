"""Tests for bootstrap/authproxy.py (OpenCode session-key gate) over real sockets."""
from __future__ import annotations

import base64
import http.client
import http.server
import importlib.util
import io
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from unittest import mock

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
APP_DIR = os.path.normpath(os.path.join(HERE, ".."))

from fakes import FakeOpenCode  # noqa: E402

PROXY_PATH = os.path.join(APP_DIR, "bootstrap", "authproxy.py")
spec = importlib.util.spec_from_file_location("authproxy", PROXY_PATH)
authproxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authproxy)

SESSION = "code-session-key-0123456789abcdef"
PASSWORD = "opencode-password-fedcba9876543210"


class Proxy:
    """authproxy in-process on an ephemeral port in front of an upstream."""

    def __init__(self, upstream_port, session=SESSION, password=PASSWORD):
        settings = authproxy.Settings(("127.0.0.1", upstream_port), session, "opencode", password)
        self.server = authproxy.make_server(("127.0.0.1", 0), settings)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def port(self):
        return self.server.server_address[1]

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            conn.close()


class StreamingUpstream:
    """Upstream that answers /event with an SSE stream paused between two events."""

    def __init__(self):
        self.release = threading.Event()
        self.seen = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                outer.seen.append(dict(self.headers.items()))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for event in (b"data: server.connected\n\n", b"data: session.idle\n\n"):
                    self.wfile.write(b"%x\r\n" % len(event) + event + b"\r\n")
                    self.wfile.flush()
                    outer.release.wait(5)
                self.wfile.write(b"0\r\n\r\n")

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                outer.seen.append({"body": body, **dict(self.headers.items())})
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.httpd.shutdown()
        self.httpd.server_close()


class AuthProxyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def key(self, **extra):
        return {"X-Session-API-Key": SESSION, **extra}

    def test_health_is_public_and_reaches_opencode_with_its_password(self):
        with FakeOpenCode("opencode", PASSWORD, self.tmp.name) as oc, Proxy(oc.httpd.server_port) as proxy:
            status, body, _ = proxy.request("GET", "/global/health")
            self.assertEqual(status, 200, body)
            self.assertTrue(json.loads(body)["healthy"])
            status, body, _ = proxy.request("HEAD", "/global/health")
            self.assertEqual((status, body), (200, b""))

    def test_session_key_required(self):
        with FakeOpenCode("opencode", PASSWORD, self.tmp.name) as oc, Proxy(oc.httpd.server_port) as proxy:
            for headers in ({}, {"X-Session-API-Key": "wrong"}, {"X-Session-API-Key": SESSION[:-1]},
                            {"Authorization": "Basic " + base64.b64encode(f"opencode:{PASSWORD}".encode()).decode()}):
                status, _, _ = proxy.request("POST", "/session?directory=/workspace", b"{}", headers)
                self.assertEqual(status, 401, headers)
            self.assertEqual(oc.calls, [])

    def test_forwards_with_opencode_auth_only(self):
        with FakeOpenCode("opencode", PASSWORD, self.tmp.name) as oc, Proxy(oc.httpd.server_port) as proxy:
            status, body, _ = proxy.request("POST", "/session?directory=/workspace", b'{"title":"t"}',
                                            self.key(Authorization="Basic c2VhbGVkOmdhdGVwdw==",
                                                     **{"Content-Type": "application/json"}))
            self.assertEqual(status, 200, body)
            headers = oc.calls[0][3]
            self.assertEqual(headers["authorization"],
                             "Basic " + base64.b64encode(f"opencode:{PASSWORD}".encode()).decode())
            self.assertNotIn("x-session-api-key", headers)
            self.assertEqual(oc.calls[0][2], {"title": "t"})

    def test_self_update_and_upgrades_refused(self):
        with FakeOpenCode("opencode", PASSWORD, self.tmp.name) as oc, Proxy(oc.httpd.server_port) as proxy:
            self.assertEqual(proxy.request("POST", "/global/upgrade", b"{}", self.key())[0], 403)
            self.assertEqual(proxy.request("POST", "/global/upgrade?x=1", b"{}", self.key())[0], 403)
            status, _, _ = proxy.request("GET", "/pty/1/connect", None,
                                         self.key(Upgrade="websocket", Connection="Upgrade"))
            self.assertEqual(status, 501)
            self.assertEqual(oc.calls, [])

    def test_streams_server_sent_events(self):
        upstream = StreamingUpstream()
        try:
            with Proxy(upstream.httpd.server_port) as proxy:
                sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                sock.sendall(("GET /event HTTP/1.1\r\nHost: x\r\nX-Session-API-Key: " + SESSION +
                              "\r\n\r\n").encode())
                received = b""
                deadline = time.monotonic() + 5
                while b"server.connected" not in received and time.monotonic() < deadline:
                    received += sock.recv(4096)
                self.assertIn(b"server.connected", received)
                self.assertNotIn(b"session.idle", received)  # still paused upstream: not buffered
                self.assertIn(b"Transfer-Encoding: chunked", received)
                upstream.release.set()
                while not received.endswith(b"0\r\n\r\n") and time.monotonic() < deadline:
                    received += sock.recv(4096)
                self.assertIn(b"session.idle", received)
                sock.close()
        finally:
            upstream.close()

    def test_chunked_request_bodies_and_size_limit(self):
        upstream = StreamingUpstream()
        try:
            with Proxy(upstream.httpd.server_port) as proxy:
                sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                sock.sendall(("POST /session/1/message HTTP/1.1\r\nHost: x\r\nX-Session-API-Key: " + SESSION +
                              "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                              "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").encode())
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                sock.close()
                self.assertTrue(data.startswith(b"HTTP/1.1 200"), data)
                self.assertTrue(data.endswith(b"hello world"))
                self.assertEqual(upstream.seen[-1]["body"], b"hello world")
                self.assertEqual(upstream.seen[-1]["Content-Length"], "11")
                with mock.patch.object(authproxy, "MAX_BODY", 4):
                    self.assertEqual(proxy.request("POST", "/x", b"too large", self.key())[0], 413)
        finally:
            upstream.close()

    def test_upstream_down(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with Proxy(port) as proxy:
            self.assertEqual(proxy.request("GET", "/global/health")[0], 502)

    def test_argument_and_secret_errors(self):
        env = {"CODE_SESSION_API_KEY": SESSION, "OPENCODE_SERVER_PASSWORD": PASSWORD}
        bad = [
            ["--listen", "127.0.0.1:0", "--upstream", "10.0.0.5:4097", "--", "opencode"],
            ["--listen", "127.0.0.1:0", "--", ],
            ["--listen", "127.0.0.1:0", "opencode"],
            ["--bogus", "1", "--", "opencode"],
            ["--listen", "nope", "--", "opencode"],
        ]
        with redirect_stderr(io.StringIO()):
            for argv in bad:
                self.assertEqual(authproxy.main(argv, env=env, popen=self.fail), 2, argv)
            for broken in ({"OPENCODE_SERVER_PASSWORD": PASSWORD}, {"CODE_SESSION_API_KEY": SESSION},
                           {"CODE_SESSION_API_KEY": "short", "OPENCODE_SERVER_PASSWORD": PASSWORD}):
                self.assertEqual(authproxy.main(["--listen", "127.0.0.1:0", "--", "opencode"], env=broken,
                                                popen=self.fail), 2)

    def test_source_is_embeddable(self):
        with open(PROXY_PATH) as handle:
            text = handle.read()
        self.assertNotIn("$", text)
        self.assertNotIn("\t", text)


class EmbeddedProxyProcessTest(unittest.TestCase):
    """The exact proxy text from the OpenCode fragment, run with python3 -I -c, supervising a child."""

    def test_runs_child_without_session_key_and_forwards_sigterm(self):
        fragment_path = os.path.join(APP_DIR, "fallback-opencode", "compose.fragment.yaml")
        with open(fragment_path, encoding="utf-8") as handle:
            server = yaml.safe_load(handle)["services"]["coding-agent-server"]
        script = server["command"][3]
        with tempfile.TemporaryDirectory() as tmp, FakeOpenCode("opencode", PASSWORD, tmp) as oc:
            env_file = os.path.join(tmp, "child-env.json")
            child = [sys.executable, "-c",
                     "import json, os, sys, time; json.dump(dict(os.environ), open(sys.argv[1], 'w')); time.sleep(60)",
                     env_file]
            env = {"PATH": os.environ["PATH"], "CODE_SESSION_API_KEY": SESSION,
                   "OPENCODE_SERVER_PASSWORD": PASSWORD, "OPENCODE_SERVER_USERNAME": "opencode",
                   "LLM_GATEWAY_KEY": "sk-" + "e5" * 32}
            proc = subprocess.Popen([sys.executable, "-I", "-c", script, "--listen", "127.0.0.1:0",
                                     "--upstream", "127.0.0.1:%d" % oc.httpd.server_port, "--", *child],
                                    env=env, stderr=subprocess.PIPE, text=True)
            try:
                line = proc.stderr.readline()
                match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
                self.assertIsNotNone(match, line)
                port = int(match.group(1))
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("POST", "/session?directory=/workspace", body=b"{}",
                             headers={"X-Session-API-Key": SESSION, "Content-Type": "application/json"})
                self.assertEqual(conn.getresponse().status, 200)
                conn.close()
                deadline = time.monotonic() + 5
                while not os.path.exists(env_file) and time.monotonic() < deadline:
                    time.sleep(0.02)
                time.sleep(0.1)
                with open(env_file) as handle:
                    child_env = json.load(handle)
                self.assertNotIn("CODE_SESSION_API_KEY", child_env)
                self.assertEqual(child_env["OPENCODE_SERVER_PASSWORD"], PASSWORD)
                self.assertIn("LLM_GATEWAY_KEY", child_env)
                proc.send_signal(signal.SIGTERM)
                self.assertEqual(proc.wait(10), 128 + signal.SIGTERM)
                rest = proc.stderr.read()
                for secret in (SESSION, PASSWORD):
                    self.assertNotIn(secret, line + rest)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
