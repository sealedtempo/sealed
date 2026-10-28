// The attest host's TLS front, standing in for Caddy's public `attest` route: HTTPS with a self-signed certificate
// for the stack's attest hostname, proxying GET /attest to the agent. The agent host reads the certificate's key
// the way it reads Caddy's (a TLS handshake, ServedCertSource), so the live quote binds the key a verifier is
// served on this very connection (INTERFACES 3, live attest).
import { mkdirSync, readFileSync } from "node:fs";
import { request } from "node:http";
import { createServer, type Server } from "node:https";
import { join } from "node:path";
import type { Supervisor } from "./procs.ts";

export interface AttestFront {
  url: string;
  certPem: string;
  /** The agent's local API the front forwards to (changes when the agent restarts on another port). */
  target: { port: number };
  close(): Promise<void>;
}

/** A self-signed P-256 certificate for `hostname` (openssl, one day). */
export async function selfSignedCert(sup: Supervisor, dir: string, hostname: string): Promise<{ key: string; cert: string }> {
  mkdirSync(dir, { recursive: true });
  const key = join(dir, "attest-key.pem");
  const cert = join(dir, "attest-cert.pem");
  await sup.runOk("openssl-attest-cert", "openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", `/CN=${hostname}`, "-addext", `subjectAltName=DNS:${hostname}`, "-keyout", key, "-out", cert,
  ]);
  return { key: readFileSync(key, "utf8"), cert: readFileSync(cert, "utf8") };
}

export async function startAttestFront(o: { port: number; key: string; cert: string; agentPort: number; caddyIp: string; peerHeader: string }): Promise<AttestFront> {
  const target = { port: o.agentPort };
  const srv: Server = createServer({ key: o.key, cert: o.cert }, (req, res) => {
    const path = req.url ?? "/";
    if (req.method !== "GET" || !path.startsWith("/attest")) {
      res.writeHead(404).end();
      return;
    }
    // As Caddy: the agent sees the request from Caddy's address with the client in X-Forwarded-For.
    const up = request(
      { host: "127.0.0.1", port: target.port, path, method: "GET", headers: { [o.peerHeader]: o.caddyIp, "x-forwarded-for": req.socket.remoteAddress ?? "" } },
      (r) => {
        res.writeHead(r.statusCode ?? 502, { "content-type": r.headers["content-type"] ?? "application/json" });
        r.pipe(res);
      },
    );
    up.on("error", () => res.writeHead(502).end());
    up.end();
  });
  await new Promise<void>((ok, fail) => {
    srv.once("error", fail);
    srv.listen(o.port, "127.0.0.1", () => ok());
  });
  return {
    url: `https://127.0.0.1:${o.port}/attest`,
    certPem: o.cert,
    target,
    close: () =>
      new Promise<void>((r) => {
        srv.close(() => r());
        srv.closeAllConnections();
      }),
  };
}
