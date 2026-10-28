import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { freePorts } from "../src/net.ts";
import { Supervisor } from "../src/procs.ts";
import { ENDPOINT_HOSTS, type EndpointCert, endpointCert, endpointUrls, startTlsFront, type TlsFront } from "../src/tlsFront.ts";

const dir = mkdtempSync(join(tmpdir(), "devnet-tls-"));
const NAMES = Object.values(ENDPOINT_HOSTS);
let cert: EndpointCert;
let upstream: Server;
let front: TlsFront;

// The component behind the front: echoes what it received, with its own status and header.
beforeAll(async () => {
  cert = await endpointCert(new Supervisor(join(dir, "logs")), join(dir, "cert"), NAMES);
  upstream = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString()));
    req.on("end", () => {
      res.writeHead(201, { "content-type": "application/json", "x-upstream": "yes" });
      res.end(JSON.stringify({ method: req.method, url: req.url, body, auth: req.headers.authorization ?? null }));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  const [port] = await freePorts(1);
  front = await startTlsFront({ hostname: "api.devnet.test", port: port as number, targetPort: (upstream.address() as { port: number }).port, ...cert });
});

afterAll(async () => {
  await front?.close();
  await new Promise<void>((r) => (upstream ? upstream.close(() => r()) : r()));
  rmSync(dir, { recursive: true, force: true });
});

function viaFront(o: { ca?: string; servername: string; body: string }): Promise<{ status: number; headers: Record<string, unknown>; text: string }> {
  return new Promise((ok, fail) => {
    const req = request(
      { host: "127.0.0.1", port: front.port, servername: o.servername, method: "POST", path: "/v1/release?x=1", ca: o.ca, headers: { authorization: "Bearer t", "content-type": "application/json" } },
      (res) => {
        let text = "";
        res.on("data", (c: Buffer) => (text += c.toString()));
        res.on("end", () => ok({ status: res.statusCode ?? 0, headers: res.headers, text }));
      },
    );
    req.on("error", fail);
    req.end(o.body);
  });
}

describe("https fronts for the config's endpoints (composer 1.3.0 accepts only https endpoints)", () => {
  it("the config names every endpoint by an https URL on a devnet host", () => {
    const urls = endpointUrls({ keyBroker: 7001, platformApi: 7002, tempoRpc: 7003 });
    expect(urls).toEqual({ keyBroker: "https://key-broker.devnet.test:7001", platformApi: "https://api.devnet.test:7002", tempoRpc: "https://rpc.devnet.test:7003" });
    for (const u of Object.values(urls)) expect(new URL(u).protocol).toBe("https:");
  });

  it("one certificate names every devnet endpoint host", () => {
    const x = new X509Certificate(cert.cert);
    for (const n of NAMES) expect(x.checkHost(n)).toBe(n);
    expect(front.url).toBe(`https://api.devnet.test:${front.port}`);
  });

  it("forwards method, path, headers and body, and passes the component's answer back", async () => {
    const body = JSON.stringify({ quote: "0x00", big: "a".repeat(200_000) });
    const r = await viaFront({ ca: cert.cert, servername: "api.devnet.test", body });
    expect(r.status).toBe(201);
    expect(r.headers["x-upstream"]).toBe("yes");
    const echoed = JSON.parse(r.text) as { method: string; url: string; body: string; auth: string };
    expect(echoed).toEqual({ method: "POST", url: "/v1/release?x=1", body, auth: "Bearer t" });
  });

  it("a client that does not trust the run's certificate is refused", async () => {
    await expect(viaFront({ servername: "api.devnet.test", body: "{}" })).rejects.toThrow(/self[- ]signed|unable to verify|certificate/i);
  });

  it("the agent host reaches it by name with NODE_EXTRA_CA_CERTS and the devnet resolver, as fetch does in the agent", async () => {
    const net = fileURLToPath(new URL("../src/net.ts", import.meta.url));
    const script = join(dir, "client.mjs");
    writeFileSync(
      script,
      `const { installDevnetResolver } = await import(${JSON.stringify(net)});\n` +
        `installDevnetResolver();\n` +
        `const r = await fetch(${JSON.stringify(`${front.url}/v1/nonce`)}, { method: "POST", body: "hello" });\n` +
        `console.log(r.status, await r.text());\n`,
    );
    const { stdout } = await promisify(execFile)(process.execPath, [script], { env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: cert.certFile } });
    expect(stdout).toMatch(/^201 /);
    expect(JSON.parse(stdout.slice(4)) as { url: string; body: string }).toMatchObject({ url: "/v1/nonce", body: "hello" });
  });
});
