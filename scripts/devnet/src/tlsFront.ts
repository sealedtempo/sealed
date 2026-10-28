// HTTPS fronts for the endpoints the measured config names. Composer 1.3.0 (ws/harden-composer, review C-4)
// accepts only https URLs for endpoints.keyBroker, endpoints.platformApi and endpoints.tempoRpc, as a real
// deployment has them. The devnet's key broker, platform api and anvil speak plain HTTP on loopback, so each gets a
// front here: HTTPS with one run-local self-signed certificate for the three *.devnet.test names, forwarding every
// request unchanged to the component. Only the agent host trusts that certificate (NODE_EXTRA_CA_CERTS), the way an
// agent in a VM trusts the public CAs that sign the real endpoints.
import { mkdirSync, readFileSync } from "node:fs";
import { type IncomingHttpHeaders, request } from "node:http";
import { createServer, type Server } from "node:https";
import { join } from "node:path";
import type { Supervisor } from "./procs.ts";

/** The names the config gives the three endpoints; the agent host resolves them to 127.0.0.1 (net.ts). */
export const ENDPOINT_HOSTS = { keyBroker: "key-broker.devnet.test", platformApi: "api.devnet.test", tempoRpc: "rpc.devnet.test" } as const;

export type EndpointName = keyof typeof ENDPOINT_HOSTS;

/** The config's endpoints.keyBroker, platformApi and tempoRpc: https URLs of the fronts on the given ports. */
export function endpointUrls(ports: Record<EndpointName, number>): Record<EndpointName, string> {
  const out = {} as Record<EndpointName, string>;
  for (const k of Object.keys(ENDPOINT_HOSTS) as EndpointName[]) out[k] = `https://${ENDPOINT_HOSTS[k]}:${ports[k]}`;
  return out;
}

export interface EndpointCert {
  key: string;
  cert: string;
  /** The certificate as a PEM file, for NODE_EXTRA_CA_CERTS. */
  certFile: string;
}

/** A self-signed P-256 certificate (openssl, one day) whose subjectAltName lists every name in `hostnames`. */
export async function endpointCert(sup: Supervisor, dir: string, hostnames: readonly string[]): Promise<EndpointCert> {
  if (hostnames.length === 0) throw new Error("endpointCert: no hostnames");
  mkdirSync(dir, { recursive: true });
  const key = join(dir, "endpoints-key.pem");
  const cert = join(dir, "endpoints-cert.pem");
  await sup.runOk("openssl-endpoints-cert", "openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", `/CN=${hostnames[0]}`, "-addext", `subjectAltName=${hostnames.map((h) => `DNS:${h}`).join(",")}`,
    "-keyout", key, "-out", cert,
  ]);
  return { key: readFileSync(key, "utf8"), cert: readFileSync(cert, "utf8"), certFile: cert };
}

export interface TlsFront {
  /** https://<hostname>:<port>, the URL a config names. */
  url: string;
  port: number;
  close(): Promise<void>;
}

// Hop-by-hop headers (RFC 9110 7.6.1) belong to one connection; node:http frames each side itself.
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer"]);

function forwardable(h: IncomingHttpHeaders): IncomingHttpHeaders {
  return Object.fromEntries(Object.entries(h).filter(([k]) => !HOP_BY_HOP.has(k.toLowerCase())));
}

/** HTTPS on 127.0.0.1:`port` for `hostname`, forwarding method, path, headers and body to http://127.0.0.1:`targetPort`. */
export async function startTlsFront(o: { hostname: string; port: number; targetPort: number; key: string; cert: string }): Promise<TlsFront> {
  const srv: Server = createServer({ key: o.key, cert: o.cert }, (req, res) => {
    const up = request({ host: "127.0.0.1", port: o.targetPort, method: req.method, path: req.url, headers: forwardable(req.headers) }, (r) => {
      res.writeHead(r.statusCode ?? 502, forwardable(r.headers));
      r.pipe(res);
    });
    up.on("error", (err) => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end(`devnet tls front for ${o.hostname}: ${err.message}`);
    });
    req.pipe(up);
  });
  await new Promise<void>((ok, fail) => {
    srv.once("error", fail);
    srv.listen(o.port, "127.0.0.1", () => ok());
  });
  return {
    url: `https://${o.hostname}:${o.port}`,
    port: o.port,
    close: () =>
      new Promise<void>((r) => {
        srv.close(() => r());
        srv.closeAllConnections();
      }),
  };
}
