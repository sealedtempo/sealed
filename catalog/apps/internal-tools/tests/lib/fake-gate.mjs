// A stand-in for Sealed's gate on a route: Caddy forward_auth to sealed-agent /v1/gate.
//
// Integration brief item 9 (D-044): a request passes with a valid sealed_gate cookie, or with
// Basic auth for user sealed and the gate password. A Basic success sets sealed_gate (HttpOnly,
// Secure, SameSite=Lax, Path=/, 12 h). Anything else gets 401 with WWW-Authenticate: Basic
// realm="sealed". With the cookie the client's own Authorization header reaches the app
// untouched; the gate's own Basic credentials never do. Until the app's bootstrap is done the
// gate answers 503 starting.
//
// How the cookie reaches the client is the composer's choice, so both shapes are modelled:
// mode "proxy" adds Set-Cookie to the app's response, mode "redirect" answers a Basic success
// with 302 back to the same URL plus Set-Cookie. Mode "basic" is the older Caddy basic_auth gate
// (no cookie).

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";

const COOKIE = "sealed_gate";
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host"]);

export function createFakeGate(upstreamUrl, password, { mode = "proxy", starting = 0 } = {}) {
  if (!["proxy", "redirect", "basic"].includes(mode)) throw new Error(`unknown mode ${mode}`);
  const upstream = new URL(upstreamUrl);
  const basic = Buffer.from(`Basic ${Buffer.from(`sealed:${password}`).toString("base64")}`);
  let key = randomBytes(32);
  const session = randomBytes(16).toString("hex");
  const stats = { basicChecks: 0, cookiePasses: 0, refusals: 0, starting, upstreamHeaders: [] };
  const token = () => `${session}.${createHmac("sha256", key).update(`sealed-gate/${session}`).digest("hex")}`;

  const decide = (req) => {
    if (stats.starting > 0) {
      stats.starting--;
      return ["starting"];
    }
    const cookies = (req.headers.cookie ?? "").split(";").map((c) => c.trim());
    if (mode !== "basic" && cookies.includes(`${COOKIE}=${token()}`)) {
      stats.cookiePasses++;
      return ["cookie"];
    }
    const auth = Buffer.from(req.headers.authorization ?? "");
    if (auth.length === basic.length && timingSafeEqual(auth, basic)) {
      stats.basicChecks++;
      return ["basic", mode === "basic" ? undefined : token()];
    }
    stats.refusals++;
    return ["refuse"];
  };

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const [decision, cookie] = decide(req);
    if (decision === "starting") return res.writeHead(503, { "content-type": "text/plain" }).end("starting");
    if (decision === "refuse") {
      return res.writeHead(401, { "www-authenticate": 'Basic realm="sealed"', "content-type": "text/plain" }).end("Unauthorized");
    }
    const setCookie = cookie && `${COOKIE}=${cookie}; Max-Age=43200; Path=/; Secure; HttpOnly; SameSite=Lax`;
    if (setCookie && mode === "redirect") return res.writeHead(302, { location: req.url, "set-cookie": setCookie }).end();
    const headers = Object.fromEntries(Object.entries(req.headers).filter(([k]) => !HOP_BY_HOP.has(k)));
    if (decision === "basic") delete headers.authorization; // the gate's own credentials stop here
    stats.upstreamHeaders.push({ path: req.url, headers });
    const body = Buffer.concat(chunks);
    const up = httpRequest({ host: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers: { ...headers, "content-length": body.length } }, (upRes) => {
      const out = Object.fromEntries(Object.entries(upRes.headers).filter(([k]) => !HOP_BY_HOP.has(k)));
      if (setCookie) out["set-cookie"] = [...[out["set-cookie"] ?? []].flat(), setCookie];
      res.writeHead(upRes.statusCode, out);
      upRes.pipe(res);
    });
    up.on("error", () => res.writeHead(502).end());
    up.end(body);
  });

  return {
    stats,
    rotate() {
      key = randomBytes(32);
    },
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      return `http://127.0.0.1:${server.address().port}`;
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
