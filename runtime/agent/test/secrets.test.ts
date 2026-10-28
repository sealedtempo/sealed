import { mkdir, mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type SecretsLayout, SecretsTargetError, TMPFS_MAGIC, writePayerSecrets, writeReadyFlag, writeSecrets } from "../src/secrets.js";

const owners = new Set(["crm", "_gate"]);

describe("tmpfs secrets (INTERFACES 14-15)", () => {
  let dir: string;
  let layout: SecretsLayout;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-secrets-"));
    layout = { secretsDir: join(dir, "secrets"), readyDir: join(dir, "ready"), requireTmpfs: false };
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("writes one file per secret per app and removes stale ones", async () => {
    await writeSecrets(layout, { crm: { APP_SECRET: "s1", OLD: "x" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$abc" } }, owners);
    expect(await readFile(join(layout.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("s1");
    expect(await readFile(join(layout.secretsDir, "_gate", "GATE_PASSWORD_BCRYPT"), "utf8")).toBe("$2a$14$abc");
    expect((await stat(join(layout.secretsDir, "crm", "APP_SECRET"))).mode & 0o777).toBe(0o444);
    await writeSecrets(layout, { crm: { APP_SECRET: "s2" } }, owners);
    expect(await readdir(join(layout.secretsDir, "crm"))).toEqual(["APP_SECRET"]);
    expect(await readFile(join(layout.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("s2");
  });

  it("rejects path-like owners and names, the reserved payer directory and owners outside the stack", async () => {
    await expect(writeSecrets(layout, { "../x": { A: "1" } }, owners)).rejects.toThrow("invalid secret owner");
    await expect(writeSecrets(layout, { crm: { "../A": "1" } }, owners)).rejects.toThrow("invalid secret name");
    await expect(writeSecrets(layout, { "sealed-mpp-payer": { ENCLAVE_KEY: "0x1" } }, new Set(["sealed-mpp-payer"]))).rejects.toThrow("invalid secret owner");
    await expect(writeSecrets(layout, { scraper: { KEY: "1" } }, owners)).rejects.toThrow("invalid secret owner");
    // Nothing is written when any owner is refused.
    await expect(writeSecrets(layout, { crm: { APP_SECRET: "s" }, ghost: { A: "1" } }, owners)).rejects.toThrow();
    await expect(stat(join(layout.secretsDir, "crm"))).rejects.toThrow();
  });

  // Review finding: the enclave key was written wherever the directory pointed, also onto a disk-backed layer.
  it("in production refuses to write into a directory that is not a tmpfs mount", async () => {
    const tmpfsDirs = new Set<string>();
    const prod: SecretsLayout = { ...layout, requireTmpfs: true, fsType: async (p) => {
      await stat(p);
      return tmpfsDirs.has(p) ? TMPFS_MAGIC : 0xef53;
    } };
    await expect(writeSecrets(prod, { crm: { APP_SECRET: "s" } }, owners)).rejects.toThrow(SecretsTargetError);
    await mkdir(join(layout.secretsDir, "crm"), { recursive: true });
    await expect(writeSecrets(prod, { crm: { APP_SECRET: "s" } }, owners)).rejects.toThrow("not on tmpfs (f_type 0xef53)");
    await expect(writePayerSecrets(prod, "0xkey", "1")).rejects.toThrow(SecretsTargetError);
    expect(await readdir(join(layout.secretsDir, "crm"))).toEqual([]);
    tmpfsDirs.add(join(layout.secretsDir, "crm"));
    await writeSecrets(prod, { crm: { APP_SECRET: "s" }, _gate: {} }, owners);
    expect(await readFile(join(layout.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("s");
  });

  it("writes the payer key and limit, then the ready marker inside the shared ready directory", async () => {
    await writePayerSecrets(layout, "0xkey", "2000000");
    expect(await readFile(join(layout.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8")).toBe("0xkey");
    expect(await readFile(join(layout.secretsDir, "sealed-mpp-payer", "SPEND_LIMIT_PER_DAY"), "utf8")).toBe("2000000");
    await mkdir(layout.readyDir); // the composer's sealed-ready volume is a directory
    await writeReadyFlag(layout, 123);
    expect(await readFile(join(layout.readyDir, "ok"), "utf8")).toBe("123\n");
    expect(await readdir(layout.readyDir)).toEqual(["ok"]);
    await writeReadyFlag(layout, 124);
    expect(await readFile(join(layout.readyDir, "ok"), "utf8")).toBe("124\n");
  });
});
