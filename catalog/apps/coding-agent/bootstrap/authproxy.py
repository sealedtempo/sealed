"""Session-key gate in front of OpenCode in the same container (stdlib only; embedded verbatim
in the OpenCode fallback fragment).

Caddy's password gate consumes the Authorization header, so OpenCode's own HTTP Basic auth
cannot be used through the code route, and the gate password must never be handed to the
agent. This proxy runs OpenCode on loopback (argv after --) and serves its API on the
container port:
- every request needs X-Session-API-Key: <CODE_SESSION_API_KEY>, except GET or HEAD of
  /global/health (healthchecks);
- requests reach OpenCode with Authorization: Basic <OPENCODE_SERVER_USERNAME>:
  <OPENCODE_SERVER_PASSWORD>, a password generated for OpenCode alone; any client
  Authorization header is dropped;
- /global/upgrade (self-update) is refused, and so are WebSocket upgrades;
- responses stream, so Server-Sent Events (/event) work.
CODE_SESSION_API_KEY is removed from OpenCode's environment. Paths and bodies are never logged.

  authproxy.py --listen 0.0.0.0:4096 --upstream 127.0.0.1:4097 -- opencode serve --port 4097
"""
import base64
import hmac
import http.client
import http.server
import os
import signal
import subprocess
import sys
import threading

SESSION_KEY_ENV = "CODE_SESSION_API_KEY"
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
              "te", "trailer", "trailers", "transfer-encoding", "upgrade"}
DROP_FROM_CLIENT = HOP_BY_HOP | {"authorization", "x-session-api-key", "host", "content-length"}
PUBLIC = {("GET", "/global/health"), ("HEAD", "/global/health")}
DENIED_PREFIXES = ("/global/upgrade",)
MAX_BODY = 64 * 1024 * 1024
MIN_SECRET_LEN = 16


class ProxyError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def log(message):
    print("authproxy: " + message, file=sys.stderr, flush=True)


def host_port(text):
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise ValueError("expected host:port, got " + repr(text))
    return host, int(port)


def parse_args(argv):
    if "--" not in argv:
        raise ValueError("usage: authproxy.py --listen HOST:PORT --upstream HOST:PORT -- <opencode command>")
    sep = argv.index("--")
    flags, child = argv[:sep], argv[sep + 1:]
    values = {"--listen": "0.0.0.0:4096", "--upstream": "127.0.0.1:4097"}
    i = 0
    while i < len(flags):
        if flags[i] not in values or i + 1 >= len(flags):
            raise ValueError("unknown or incomplete flag " + repr(flags[i]))
        values[flags[i]] = flags[i + 1]
        i += 2
    upstream = host_port(values["--upstream"])
    if upstream[0] not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("--upstream must be loopback, so OpenCode is never reachable directly")
    if not child:
        raise ValueError("missing OpenCode command after --")
    return host_port(values["--listen"]), upstream, child


class Settings:
    def __init__(self, upstream, session_key, user, password):
        if len(session_key) < MIN_SECRET_LEN:
            raise ValueError(SESSION_KEY_ENV + " is missing or shorter than 16 characters")
        if len(password) < MIN_SECRET_LEN:
            raise ValueError("OPENCODE_SERVER_PASSWORD is missing or shorter than 16 characters")
        self.upstream = upstream
        self.session_key = session_key.encode("utf-8")
        token = base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")
        self.upstream_auth = "Basic " + token

    @classmethod
    def from_env(cls, env, upstream):
        return cls(upstream, (env.get(SESSION_KEY_ENV) or "").strip(),
                   env.get("OPENCODE_SERVER_USERNAME") or "opencode",
                   (env.get("OPENCODE_SERVER_PASSWORD") or "").strip())


def make_handler(settings):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "sealed-authproxy"
        sys_version = ""

        def log_message(self, *args):
            pass

        def reply(self, status, text):
            body = (text + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def authorized(self, path):
            if (self.command, path) in PUBLIC:
                return True
            supplied = (self.headers.get("X-Session-API-Key") or "").encode("utf-8")
            return hmac.compare_digest(supplied, settings.session_key)

        def read_body(self):
            encoding = (self.headers.get("Transfer-Encoding") or "").strip().lower()
            if encoding:
                if encoding != "chunked":
                    raise ProxyError(501, "unsupported transfer encoding")
                return self.read_chunked()
            length = self.headers.get("Content-Length")
            if length is None:
                return None
            try:
                size = int(length)
            except ValueError:
                raise ProxyError(400, "bad Content-Length")
            if size < 0 or size > MAX_BODY:
                raise ProxyError(413, "request body too large")
            return self.rfile.read(size)

        def read_chunked(self):
            chunks, total = [], 0
            while True:
                line = self.rfile.readline(1024)
                try:
                    size = int(line.split(b";")[0].strip(), 16)
                except ValueError:
                    raise ProxyError(400, "bad chunked body")
                if size == 0:
                    while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                        pass
                    return b"".join(chunks)
                total += size
                if total > MAX_BODY:
                    raise ProxyError(413, "request body too large")
                chunks.append(self.rfile.read(size))
                self.rfile.readline(1024)

        def forward_headers(self, body):
            named = {t.strip().lower() for t in (self.headers.get("Connection") or "").split(",")}
            headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_FROM_CLIENT | named}
            headers["Host"] = settings.upstream[0] + ":" + str(settings.upstream[1])
            headers["Authorization"] = settings.upstream_auth
            if body is not None:
                headers["Content-Length"] = str(len(body))
            return headers

        def handle_any(self):
            if not self.path.startswith("/"):
                self.close_connection = True
                return self.reply(400, "bad request target")
            path = self.path.split("?", 1)[0]
            if not self.authorized(path):
                return self.reply(401, "missing or wrong X-Session-API-Key")
            if path.startswith(DENIED_PREFIXES):
                return self.reply(403, "not allowed through the Sealed code route")
            if self.headers.get("Upgrade"):
                self.close_connection = True
                return self.reply(501, "connection upgrades are not proxied")
            try:
                body = self.read_body()
            except ProxyError as err:
                self.close_connection = True
                return self.reply(err.status, str(err))
            conn = http.client.HTTPConnection(settings.upstream[0], settings.upstream[1])
            try:
                try:
                    conn.request(self.command, self.path, body=body, headers=self.forward_headers(body))
                    response = conn.getresponse()
                except OSError:
                    self.close_connection = True
                    return self.reply(502, "OpenCode is not reachable")
                self.relay(response)
            except OSError:
                self.close_connection = True  # client went away mid-stream
            finally:
                conn.close()

        def relay(self, response):
            length = response.getheader("Content-Length")
            no_body = self.command == "HEAD" or response.status in (204, 304) or response.status < 200
            self.send_response_only(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                    self.send_header(key, value)
            if no_body or length is not None:
                if length is not None:
                    self.send_header("Content-Length", length)
                self.end_headers()
                while not no_body:
                    data = response.read(65536)
                    if not data:
                        break
                    self.wfile.write(data)
            else:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                while True:
                    data = response.read1(65536)
                    if not data:
                        break
                    self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = handle_any

    return Handler


def make_server(listen, settings):
    server = http.server.ThreadingHTTPServer(listen, make_handler(settings))
    server.daemon_threads = True
    return server


def main(argv=None, env=None, popen=subprocess.Popen):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ if env is None else env)
    try:
        listen, upstream, child = parse_args(argv)
        settings = Settings.from_env(env, upstream)
        server = make_server(listen, settings)
    except (ValueError, OSError) as err:
        log("error: " + str(err))
        return 2
    child_env = {k: v for k, v in env.items() if k != SESSION_KEY_ENV}
    try:
        proc = popen(child, env=child_env)
    except OSError as err:
        server.server_close()
        log("error: cannot start " + child[0] + ": " + str(err))
        return 1
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda signum, _frame: proc.send_signal(signum))
    host, port = server.server_address[:2]
    log("listening on " + host + ":" + str(port) + ", OpenCode on " + upstream[0] + ":" + str(upstream[1]))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    code = proc.wait()
    server.shutdown()
    server.server_close()
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
