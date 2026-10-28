// tlsPubKeyHash = sha256(DER SubjectPublicKeyInfo of the certificate Caddy serves for the attest
// host). Caddy's data volume is mounted read-only into the agent.
import { X509Certificate } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { bytesToHex, type Hex, sha256Hex } from "@sealed/core";

export function spkiSha256(certPem: string | Buffer): Hex {
  const cert = new X509Certificate(certPem);
  const der = cert.publicKey.export({ type: "spki", format: "der" });
  return sha256Hex(new Uint8Array(der));
}

/** Locates <dataDir>/caddy/certificates/<issuer>/<host>/<host>.crt (newest if several issuers). */
export async function findCaddyCert(caddyDataDir: string, host: string): Promise<string | undefined> {
  const base = join(caddyDataDir, "caddy", "certificates");
  let issuers: string[];
  try {
    issuers = await readdir(base);
  } catch {
    return undefined;
  }
  let best: { path: string; mtime: number } | undefined;
  for (const issuer of issuers) {
    const path = join(base, issuer, host, `${host}.crt`);
    try {
      const s = await stat(path);
      if (!best || s.mtimeMs > best.mtime) best = { path, mtime: s.mtimeMs };
    } catch {
      // not issued by this issuer
    }
  }
  return best?.path;
}

export interface TlsKeySource {
  /** undefined while the certificate has not been issued yet. */
  tlsPubKeyHash(): Promise<Hex | undefined>;
}

export class CaddyCertSource implements TlsKeySource {
  private cache?: { path: string; mtime: number; hash: Hex };
  constructor(
    private readonly caddyDataDir: string,
    private readonly host: string | undefined,
  ) {}

  async tlsPubKeyHash(): Promise<Hex | undefined> {
    if (!this.host) return undefined;
    const path = await findCaddyCert(this.caddyDataDir, this.host);
    if (!path) return undefined;
    const { mtimeMs } = await stat(path);
    if (this.cache && this.cache.path === path && this.cache.mtime === mtimeMs) return this.cache.hash;
    const hash = spkiSha256(await readFile(path));
    this.cache = { path, mtime: mtimeMs, hash };
    return hash;
  }
}

export const fixedTlsKey = (hash: Hex | Uint8Array): TlsKeySource => ({
  tlsPubKeyHash: async () => (typeof hash === "string" ? hash : bytesToHex(hash)),
});
