import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { writePayerSecrets, writeReadyFlag, writeSecrets } from "../src/secrets.js";

describe("tmpfs secrets (INTERFACES 14-15)", () => {
  let dir: string;
  let layout: { secretsDir: string; readyFile: string };
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-secrets-"));
    layout = { secretsDir: join(dir, "secrets"), readyFile: join(dir, "ready") };
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("writes one file per secret per app and removes stale ones", async () => {
    await writeSecrets(layout, { crm: { APP_SECRET: "s1", OLD: "x" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$abc" } });
    expect(await readFile(join(layout.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("s1");
    expect(await readFile(join(layout.secretsDir, "_gate", "GATE_PASSWORD_BCRYPT"), "utf8")).toBe("$2a$14$abc");
    expect((await stat(join(layout.secretsDir, "crm", "APP_SECRET"))).mode & 0o777).toBe(0o444);
    await writeSecrets(layout, { crm: { APP_SECRET: "s2" } });
    expect(await readdir(join(layout.secretsDir, "crm"))).toEqual(["APP_SECRET"]);
    expect(await readFile(join(layout.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("s2");
  });

  it("rejects path-like owners and names, and the reserved payer directory", async () => {
    await expect(writeSecrets(layout, { "../x": { A: "1" } })).rejects.toThrow("invalid secret owner");
    await expect(writeSecrets(layout, { crm: { "../A": "1" } })).rejects.toThrow("invalid secret name");
    await expect(writeSecrets(layout, { "sealed-mpp-payer": { ENCLAVE_KEY: "0x1" } })).rejects.toThrow("invalid secret owner");
  });

  it("writes the payer key and limit, then the ready flag", async () => {
    await writePayerSecrets(layout, "0xkey", "2000000");
    expect(await readFile(join(layout.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8")).toBe("0xkey");
    expect(await readFile(join(layout.secretsDir, "sealed-mpp-payer", "SPEND_LIMIT_PER_DAY"), "utf8")).toBe("2000000");
    await writeFile(join(dir, "unrelated"), "");
    await writeReadyFlag(layout, 123);
    expect(await readFile(layout.readyFile, "utf8")).toBe("123\n");
  });
});
