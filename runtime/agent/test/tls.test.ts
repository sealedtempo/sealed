import { cp, mkdir, mkdtemp, readFile, rm, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CaddyCertSource, findCaddyCert, spkiSha256 } from "../src/tls.js";

const fx = JSON.parse(await readFile(join(import.meta.dirname, "fixtures/attest.json"), "utf8"));
const certPath = join(import.meta.dirname, "fixtures/attest.crt");

describe("tlsPubKeyHash", () => {
  it("is sha256 of the DER SubjectPublicKeyInfo", async () => {
    expect(spkiSha256(await readFile(certPath))).toBe(fx.spkiSha256);
  });
  it("finds Caddy's certificate for the attest host", async () => {
    const data = await mkdtemp(join(tmpdir(), "caddy-data-"));
    try {
      const src = new CaddyCertSource(data, fx.host);
      expect(await src.tlsPubKeyHash()).toBeUndefined();
      const dir = join(data, "caddy", "certificates", "acme-v02.api.letsencrypt.org-directory", fx.host);
      await mkdir(dir, { recursive: true });
      await cp(certPath, join(dir, `${fx.host}.crt`));
      expect(await findCaddyCert(data, fx.host)).toBe(join(dir, `${fx.host}.crt`));
      expect(await src.tlsPubKeyHash()).toBe(fx.spkiSha256);
      await utimes(join(dir, `${fx.host}.crt`), new Date(), new Date(Date.now() + 1000));
      expect(await src.tlsPubKeyHash()).toBe(fx.spkiSha256);
      expect(await new CaddyCertSource(data, undefined).tlsPubKeyHash()).toBeUndefined();
    } finally {
      await rm(data, { recursive: true, force: true });
    }
  });
});
