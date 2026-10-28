// bcrypt for the password gate, checked against golang.org/x/crypto/bcrypt (the vectors in
// fixtures/bcrypt-go-vectors.jsonl and, when Go is installed, fresh ones) and the classic OpenWall
// crypt_blowfish vectors.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BcryptWorker, bcryptHash, bcryptVerify, GateBusyError, parseBcrypt, piHex } from "../src/gate/bcrypt.js";

const repo = join(import.meta.dirname, "../../..");
const vectors = (await readFile(join(import.meta.dirname, "fixtures/bcrypt-go-vectors.jsonl"), "utf8"))
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l) as { password: string; cost: number; hash: string });
const pw = (hex: string) => Buffer.from(hex, "hex");
const text = (s: string) => Buffer.from(s, "utf8");

function goAvailable(): boolean {
  try {
    execFileSync("go", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("bcrypt (gate password, D-044)", () => {
  it("derives the Blowfish constants from pi", () => {
    // The first words of P and of each S-box as published with Blowfish.
    const hex = piHex(1042 * 8);
    expect(hex.slice(0, 16)).toBe("243f6a8885a308d3");
    expect(hex.slice(8 * 18, 8 * 19)).toBe("d1310ba6");
    expect(hex.slice(-8)).toBe("3ac372e6");
  });

  it("matches golang.org/x/crypto/bcrypt on the committed vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(20);
    for (const v of vectors) {
      const h = parseBcrypt(v.hash);
      expect(h, v.hash).toBeDefined();
      expect(bcryptHash(pw(v.password), h!.salt, v.cost, "a")).toBe(v.hash);
      expect(bcryptVerify(pw(v.password), v.hash)).toBe(true);
      const wrong = Buffer.concat([pw(v.password), text("x")]);
      if (pw(v.password).length < 72) expect(bcryptVerify(wrong, v.hash)).toBe(false);
    }
  });

  it("matches the OpenWall crypt_blowfish vectors", () => {
    expect(bcryptVerify(text("U*U"), "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")).toBe(true);
    expect(bcryptVerify(text("U*U*"), "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK")).toBe(true);
    expect(bcryptVerify(text("U*U*U"), "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a")).toBe(true);
    expect(bcryptVerify(text(""), "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy")).toBe(true);
    expect(bcryptVerify(text("U*U"), "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK")).toBe(false);
  });

  it("treats $2a$, $2b$ and $2y$ alike and uses only 72 bytes of the password", () => {
    const v = vectors.find((x) => x.password === "ab".repeat(71)) as (typeof vectors)[number];
    expect(bcryptVerify(pw(v.password), v.hash.replace("$2a$", "$2b$"))).toBe(true);
    expect(bcryptVerify(pw(v.password), v.hash.replace("$2a$", "$2y$"))).toBe(true);
    const long = vectors.find((x) => x.password === "cd".repeat(72)) as (typeof vectors)[number];
    expect(bcryptVerify(pw(long.password), long.hash)).toBe(true);
    // Standard bcrypt would accept any longer password with the same first 72 bytes; the gate refuses them.
    expect(bcryptVerify(pw(`${long.password}cd`), long.hash)).toBe(false);
  });

  it("rejects malformed hashes and costs that would stall the gate", () => {
    for (const bad of ["", "$2x$04$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "$2a$03$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "$2a$05$CCCC", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOe!"]) {
      expect(parseBcrypt(bad)).toBeUndefined();
      expect(() => bcryptVerify(text("x"), bad)).toThrow("not a bcrypt hash");
    }
    expect(() => bcryptVerify(text("x"), "$2a$21$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")).toThrow("above 20");
  });

  it.runIf(goAvailable())("matches Go on fresh random passwords and salts", () => {
    const input = Array.from({ length: 6 }, (_, i) => `4 ${randomBytes(1 + ((i * 13) % 70)).toString("hex")}`).join("\n");
    const out = execFileSync("go", ["run", "./runtime/agent/test/tools/bcrypt-vectors.go"], { cwd: repo, input, encoding: "utf8" });
    for (const line of out.trim().split("\n")) {
      const v = JSON.parse(line) as { password: string; cost: number; hash: string };
      expect(bcryptHash(pw(v.password), parseBcrypt(v.hash)!.salt, v.cost, "a")).toBe(v.hash);
    }
  }, 120_000);

  describe("worker", () => {
    const worker = new BcryptWorker({ maxPending: 2 });
    afterAll(() => worker.close());
    const v = vectors.find((x) => x.cost === 5) as (typeof vectors)[number];

    it("verifies off the event loop", async () => {
      expect(await worker.verify(pw(v.password), v.hash)).toBe(true);
      expect(await worker.verify(text("nope"), v.hash)).toBe(false);
      await expect(worker.verify(text("x"), "not-a-hash")).rejects.toThrow("not a bcrypt hash");
    });

    it("bounds the number of checks in flight", async () => {
      const a = worker.verify(text("1"), v.hash);
      const b = worker.verify(text("2"), v.hash);
      await expect(worker.verify(text("3"), v.hash)).rejects.toThrow(GateBusyError);
      expect(await Promise.all([a, b])).toEqual([false, false]);
    });
  });
});
