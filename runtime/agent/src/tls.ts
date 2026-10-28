// tlsPubKeyHash = sha256(DER SubjectPublicKeyInfo of the serving TLS cert) (INTERFACES 3). The agent
// takes the certificate from a TLS handshake with Caddy on its fixed apps-network IP, using the attest
// hostname as SNI: that is exactly what a verifier connecting to the attest host is served, and it
// needs no access to Caddy's root-only certificate storage.
import { X509Certificate } from "node:crypto";
import tls from "node:tls";
import { bytesToHex, type Hex, sha256Hex } from "@sealed/core";

export function spkiSha256(cert: string | Buffer): Hex {
  const der = new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" });
  return sha256Hex(new Uint8Array(der));
}

export interface TlsKeySource {
  /** undefined while no certificate is being served yet. */
  tlsPubKeyHash(): Promise<Hex | undefined>;
}

/** DER of the leaf certificate served at host:port for `servername`, or undefined if the handshake fails. */
export function servedCertificate(target: { host: string; port: number }, servername: string, timeoutMs = 5000): Promise<Buffer | undefined> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: Buffer | undefined) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(v);
    };
    // The chain is not validated here: the verifier compares the served key with the quote.
    const socket = tls.connect({ host: target.host, port: target.port, servername, rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] }, () => {
      const raw = socket.getPeerCertificate(false)?.raw;
      finish(raw && raw.length > 0 ? raw : undefined);
    });
    socket.setTimeout(timeoutMs, () => finish(undefined));
    socket.on("error", () => finish(undefined));
  });
}

export class ServedCertSource implements TlsKeySource {
  private cache?: { at: number; hash: Hex };
  constructor(
    private readonly target: { host: string; port: number },
    private readonly servername: string,
    private readonly ttlMs = 60_000,
    private readonly now: () => number = Date.now,
  ) {}

  async tlsPubKeyHash(): Promise<Hex | undefined> {
    if (this.cache && this.now() - this.cache.at < this.ttlMs) return this.cache.hash;
    const der = await servedCertificate(this.target, this.servername);
    if (!der) return undefined;
    const hash = spkiSha256(der);
    this.cache = { at: this.now(), hash };
    return hash;
  }
}

export const fixedTlsKey = (hash: Hex | Uint8Array): TlsKeySource => ({
  tlsPubKeyHash: async () => (typeof hash === "string" ? hash : bytesToHex(hash)),
});
