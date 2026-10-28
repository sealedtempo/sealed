// Stand-in for the Caddy site the composer renders for a gated route, in both shapes:
// - "forward_auth" (D-044, brief item 9): Caddy asks sealed-agent /v1/gate. A valid sealed_gate
//   cookie or Basic auth for user "sealed" passes; a Basic success also sets the cookie. The
//   request reaches the app with every header untouched, Authorization included. Until the
//   app's bootstrap is done the agent answers 503 "starting".
// - "basic_auth" (the composer before item 9): Caddy basic_auth, Authorization stripped.
// catalog.test.mjs checks the Caddyfile the real composer renders for crm against these shapes.

import { createHmac, randomBytes } from "node:crypto";
import { request as httpRequest, createServer } from "node:http";

export const GATE_USER = "sealed";
export const COOKIE = "sealed_gate";

export function createFakeGate({ upstream, mode = "forward_auth", password, ready = () => true }) {
  const target = new URL(upstream);
  const expected = `Basic ${Buffer.from(`${GATE_USER}:${password}`).toString("base64")}`;
  const key = randomBytes(32);
  const session = createHmac("sha256", key).update("session").digest("hex");
  const seen = [];

  const hasCookie = (req) =>
    (req.headers.cookie ?? "").split(";").some((c) => c.trim() === `${COOKIE}=${session}`);

  const server = createServer((req, res) => {
    const headers = { ...req.headers, host: target.host };
    const extra = {};
    if (mode === "forward_auth") {
      if (!ready()) {
        seen.push({ method: req.method, path: req.url, outcome: "starting" });
        res.writeHead(503, { "content-type": "text/plain" });
        return res.end("starting");
      }
      if (hasCookie(req)) {
        seen.push({ method: req.method, path: req.url, outcome: "cookie" });
      } else if (req.headers.authorization === expected) {
        seen.push({ method: req.method, path: req.url, outcome: "basic" });
        extra["set-cookie"] = `${COOKIE}=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`;
      } else {
        seen.push({ method: req.method, path: req.url, outcome: "refused" });
        res.writeHead(401, { "www-authenticate": 'Basic realm="sealed"' });
        return res.end();
      }
    } else {
      if (req.headers.authorization !== expected) {
        seen.push({ method: req.method, path: req.url, outcome: "refused" });
        res.writeHead(401, { "www-authenticate": 'Basic realm="restricted"' });
        return res.end();
      }
      delete headers.authorization;
      seen.push({ method: req.method, path: req.url, outcome: "basic" });
    }
    const upstreamReq = httpRequest(
      { host: target.hostname, port: target.port, method: req.method, path: req.url, headers },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode, { ...upstreamRes.headers, ...extra });
        upstreamRes.pipe(res);
      },
    );
    upstreamReq.on("error", () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(upstreamReq);
  });

  return {
    seen,
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      return `http://127.0.0.1:${server.address().port}`;
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
