import { mkdir, mkdtemp, readdir, readFile, rm, stat, symlink } from "node:fs/promises";
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

  // Composer 1.2 binds the host's /run/sealed/secrets (a tmpfs) into the agent, with no owner
  // directories in it (review finding: they were never created, so the boot failed closed).
  it("in production creates owner directories on a tmpfs secrets root and refuses symlinked ones", async () => {
    const prod: SecretsLayout = { ...layout, requireTmpfs: true, fsType: async (p) => {
      await stat(p);
      return p === layout.secretsDir || p.startsWith(`${layout.secretsDir}/`) ? TMPFS_MAGIC : 0xef53;
    } };
    await mkdir(layout.secretsDir, { recursive: true });
    await writeSecrets(prod, { crm: { APP_SECRET: "s" } }, owners);
    await writePayerSecrets(prod, "0xkey", "1");
    expect(await readFile(join(layout.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("s");
    expect((await stat(join(layout.secretsDir, "crm"))).mode & 0o777).toBe(0o755);
    expect(await readFile(join(layout.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8")).toBe("0xkey");
    await mkdir(join(dir, "elsewhere"));
    await symlink(join(dir, "elsewhere"), join(layout.secretsDir, "_gate"));
    await expect(writeSecrets(prod, { _gate: { GATE_PASSWORD_BCRYPT: "$2a$" } }, owners)).rejects.toThrow("is not a directory");
    expect(await readdir(join(dir, "elsewhere"))).toEqual([]);
  });

  it("with the stack's secretFiles writes exactly those files, placeholders included", async () => {
    const files = new Map([["crm", new Set(["APP_SECRET", "SMTP_PASSWORD"])]]);
    const isOptional = (o: string, n: string) => o === "crm" && n === "SMTP_PASSWORD";
    const r = await writeSecrets(layout, { crm: { APP_SECRET: "s1", UNUSED: "u" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$" } }, owners, { files, isOptional });
    expect(r).toEqual({ placeholders: ["crm/SMTP_PASSWORD"], missing: [], skipped: ["_gate", "crm"] });
    expect((await readdir(join(layout.secretsDir, "crm"))).sort()).toEqual(["APP_SECRET", "SMTP_PASSWORD"]);
    await expect(stat(join(layout.secretsDir, "_gate"))).rejects.toThrow();
    const r2 = await writeSecrets(layout, {}, owners, { files: new Map([["crm", new Set(["DB_PASSWORD"])]]) });
    expect(r2.missing).toEqual(["crm/DB_PASSWORD"]);
  });

  // D-042 (composer 1.2): a service mounts each declared secret as its own file, and Docker cannot
  // start a container whose mount source is missing.
  it("writes an empty placeholder for an optional secret mounted alone, and reports a missing required one", async () => {
    const individually = new Map([["crm", new Set(["APP_SECRET", "SMTP_PASSWORD", "DB_PASSWORD"])]]);
    const isOptional = (o: string, n: string) => o === "crm" && n === "SMTP_PASSWORD";
    const r = await writeSecrets(layout, { crm: { APP_SECRET: "s1" } }, owners, { individually, isOptional });
    expect(r).toEqual({ placeholders: ["crm/SMTP_PASSWORD"], missing: ["crm/DB_PASSWORD"], skipped: [] });
    expect(await readFile(join(layout.secretsDir, "crm", "SMTP_PASSWORD"), "utf8")).toBe("");
    expect((await readdir(join(layout.secretsDir, "crm"))).sort()).toEqual(["APP_SECRET", "SMTP_PASSWORD"]);
    // Released later: the placeholder becomes the value; an owner with nothing released still gets its placeholders.
    await writeSecrets(layout, { crm: { APP_SECRET: "s1", SMTP_PASSWORD: "smtp" } }, owners, { individually, isOptional });
    expect(await readFile(join(layout.secretsDir, "crm", "SMTP_PASSWORD"), "utf8")).toBe("smtp");
    await rm(join(layout.secretsDir, "crm"), { recursive: true });
    const r2 = await writeSecrets(layout, {}, owners, { individually, isOptional });
    expect(r2.placeholders).toEqual(["crm/SMTP_PASSWORD"]);
  });

  it("validates but does not write owners whose directory the compose does not mount into the agent", async () => {
    const r = await writeSecrets(layout, { crm: { APP_SECRET: "s" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$" } }, owners, { onDisk: new Set(["crm"]) });
    expect(r.skipped).toEqual(["_gate"]);
    await expect(stat(join(layout.secretsDir, "_gate"))).rejects.toThrow();
    await expect(writeSecrets(layout, { ghost: { A: "1" } }, owners, { onDisk: new Set(["crm"]) })).rejects.toThrow("invalid secret owner");
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
