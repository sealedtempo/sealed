"""A stand-in for Sealed's gate on a route: Caddy forward_auth to sealed-agent /v1/gate.

Integration brief item 9 (D-044): a request passes when it carries a valid sealed_gate cookie, or
Basic auth with user sealed and the gate password. A Basic success sets sealed_gate (HttpOnly,
Secure, SameSite=Lax, Path=/, 12 h). Anything else gets 401 with WWW-Authenticate: Basic
realm="sealed". With the cookie, the client's own Authorization header reaches the app
untouched; the gate's own Basic credentials never do. Until the app's bootstrap is done the
gate answers 503 starting.

How the cookie reaches the client is the composer's choice, so both shapes are modelled:
mode "proxy" adds Set-Cookie to the app's response, mode "redirect" answers a Basic success
with 302 back to the same URL plus Set-Cookie. Mode "basic" is the older Caddy basic_auth gate
(no cookie, Authorization stripped on every request).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import http.server
import os
import threading
import urllib.parse
from typing import Optional

COOKIE = "sealed_gate"
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
              "transfer-encoding", "upgrade", "host", "content-length"}


class FakeGate:
    def __init__(self, upstream_url: str, password: str, mode: str = "proxy", starting: int = 0) -> None:
        if mode not in ("proxy", "redirect", "basic"):
            raise ValueError(mode)
        self.upstream = urllib.parse.urlsplit(upstream_url)
        self.basic = "Basic " + base64.b64encode(f"sealed:{password}".encode()).decode()
        self.mode = mode
        self.starting = starting
        self.key = os.urandom(32)
        self.session = os.urandom(16).hex()
        self.basic_checks = 0
        self.cookie_passes = 0
        self.refusals = 0
        self.lock = threading.Lock()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def token(self) -> str:
        mac = hmac.new(self.key, ("sealed-gate/" + self.session).encode(), hashlib.sha256).hexdigest()
        return self.session + "." + mac

    def rotate(self) -> None:
        """A new per-boot key: every cookie issued so far stops working (sealed-agent restart)."""
        self.key = os.urandom(32)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _decide(self, headers) -> tuple[str, Optional[str]]:
        """("starting"|"cookie"|"basic"|"refuse", cookie to set)."""
        with self.lock:
            if self.starting > 0:
                self.starting -= 1
                return "starting", None
            cookies = [c.strip() for v in headers.get_all("Cookie") or [] for c in v.split(";")]
            if self.mode != "basic" and f"{COOKIE}={self.token()}" in cookies:
                self.cookie_passes += 1
                return "cookie", None
            if hmac.compare_digest((headers.get("Authorization") or "").encode(), self.basic.encode()):
                self.basic_checks += 1
                return "basic", None if self.mode == "basic" else self.token()
            self.refusals += 1
            return "refuse", None

    def _handler(self):
        gate = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def reply(self, status, text, extra=None):
                body = text.encode()
                self.send_response(status)
                for key, value in (extra or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def handle_any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                decision, cookie = gate._decide(self.headers)
                if decision == "starting":
                    return self.reply(503, "starting")
                if decision == "refuse":
                    return self.reply(401, "Unauthorized", {"WWW-Authenticate": 'Basic realm="sealed"'})
                set_cookie = None
                if cookie:
                    set_cookie = f"{COOKIE}={cookie}; Max-Age=43200; Path=/; Secure; HttpOnly; SameSite=Lax"
                if set_cookie and gate.mode == "redirect":
                    return self.reply(302, "", {"Location": self.path, "Set-Cookie": set_cookie})
                headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
                if decision == "basic":
                    headers.pop("Authorization", None)  # the gate's own credentials stop here
                conn = http.client.HTTPConnection(gate.upstream.hostname, gate.upstream.port, timeout=60)
                try:
                    conn.request(self.command, self.path, body=body, headers=headers)
                    response = conn.getresponse()
                    data = response.read()
                    self.send_response(response.status, response.reason)
                    for key, value in response.getheaders():
                        if key.lower() not in HOP_BY_HOP:
                            self.send_header(key, value)
                    if set_cookie:
                        self.send_header("Set-Cookie", set_cookie)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                finally:
                    conn.close()

            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any

        return Handler
