// Stand-in for the Caddy site the composer renders for one route (runtime/caddy/Caddyfile.tmpl):
// - "gate": basic_auth (user "sealed") in front, Authorization stripped before proxying;
// - "bearer-passthrough": requests whose Authorization starts with "Bearer " go to the app
//   unchanged, everything else is handled like "gate";
// - "public": no gate.
// catalog.test.mjs checks the Caddyfile the real composer renders for crm against these shapes.

import { request as httpRequest, createServer } from "node:http";

export const GATE_USER = "sealed";

export function createFakeGate({ upstream, mode, password }) {
  const target = new URL(upstream);
  const expected = `Basic ${Buffer.from(`${GATE_USER}:${password}`).toString("base64")}`;
  const seen = [];

  const server = createServer((req, res) => {
    const auth = req.headers.authorization ?? "";
    const bearer = mode === "bearer-passthrough" && auth.startsWith("Bearer ");
    const headers = { ...req.headers, host: target.host };
    if (mode !== "public" && !bearer) {
      if (auth !== expected) {
        seen.push({ method: req.method, path: req.url, outcome: "refused" });
        res.writeHead(401, { "www-authenticate": 'Basic realm="restricted"' });
        return res.end();
      }
      delete headers.authorization;
    }
    seen.push({ method: req.method, path: req.url, outcome: bearer ? "passthrough" : "gated" });
    const upstreamReq = httpRequest(
      { host: target.hostname, port: target.port, method: req.method, path: req.url, headers },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
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
