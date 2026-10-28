import { readFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import tls from "node:tls";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { servedCertificate, ServedCertSource, spkiSha256 } from "../src/tls.js";
import { selfSignedCert } from "./helpers/selfSigned.js";

const fixtures = join(import.meta.dirname, "fixtures");
const fx = JSON.parse(await readFile(join(fixtures, "attest.json"), "utf8"));
const served = { host: "attest.34-1-2-3.sslip.io", ...selfSignedCert("attest.34-1-2-3.sslip.io") };

describe("tlsPubKeyHash", () => {
  it("is sha256 of the DER SubjectPublicKeyInfo", async () => {
    expect(spkiSha256(await readFile(join(fixtures, "attest.crt")))).toBe(fx.spkiSha256);
    expect(spkiSha256(served.cert)).toBe(served.spkiSha256);
  });

  describe("from the certificate Caddy serves for the attest host", () => {
    let server: tls.Server;
    let port: number;
    const sni: string[] = [];
    beforeAll(async () => {
      const ctx = tls.createSecureContext({ key: served.key, cert: served.cert });
      server = tls.createServer({ SNICallback: (name, cb) => (sni.push(name), cb(null, ctx)) }, (s) => s.end());
      server.on("tlsClientError", () => undefined);
      await new Promise<void>((ok) => server.listen(0, "127.0.0.1", () => ok()));
      port = (server.address() as AddressInfo).port;
    });
    afterAll(() => new Promise<void>((ok) => server.close(() => ok())));

    it("hashes the served leaf certificate, sent with the attest host as SNI, and caches it", async () => {
      let now = 0;
      const src = new ServedCertSource({ host: "127.0.0.1", port }, served.host, 60_000, () => now);
      expect(await src.tlsPubKeyHash()).toBe(served.spkiSha256);
      expect(sni).toEqual([served.host]);
      now = 30_000;
      expect(await src.tlsPubKeyHash()).toBe(served.spkiSha256);
      expect(sni.length).toBe(1);
      now = 61_000;
      await src.tlsPubKeyHash();
      expect(sni.length).toBe(2);
    });

    it("is undefined while nothing is served (Caddy down or no certificate yet)", async () => {
      const closed = tls.createServer({});
      await new Promise<void>((ok) => closed.listen(0, "127.0.0.1", () => ok()));
      const deadPort = (closed.address() as AddressInfo).port;
      await new Promise<void>((ok) => closed.close(() => ok()));
      expect(await servedCertificate({ host: "127.0.0.1", port: deadPort }, served.host)).toBeUndefined();
      expect(await new ServedCertSource({ host: "127.0.0.1", port: deadPort }, served.host).tlsPubKeyHash()).toBeUndefined();
    });
  });
});
