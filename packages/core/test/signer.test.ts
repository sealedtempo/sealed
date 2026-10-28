import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { deriveEnclavePrivateKey, enclaveSignerAddress, recoverCjsonBodySigner, signCjsonBody } from "../src/signer.js";

const seed = `0x${"42".repeat(32)}` as const;

describe("enclave signer derivation", () => {
  it("is deterministic and seed-specific", () => {
    const k1 = deriveEnclavePrivateKey(seed);
    expect(deriveEnclavePrivateKey(seed)).toBe(k1);
    expect(deriveEnclavePrivateKey(`0x${"43".repeat(32)}`)).not.toBe(k1);
    expect(enclaveSignerAddress(seed)).toBe(privateKeyToAccount(k1).address.toLowerCase());
  });
  it("matches the documented HKDF construction", async () => {
    const { hkdfSync } = await import("node:crypto");
    const okm = Buffer.from(hkdfSync("sha256", Buffer.from("42".repeat(32), "hex"), "sealed/enclave-signer/v1", Buffer.from([0]), 32));
    expect(deriveEnclavePrivateKey(seed)).toBe(`0x${okm.toString("hex")}`);
  });
  // Frozen: the key fixes the access-key id and FeeSplitter's enclaveSigner across reboots, so any
  // change to the derivation strands every deployment (spec gap in INTERFACES 9, pinned here).
  it("keeps the frozen vector", () => {
    expect(deriveEnclavePrivateKey(seed)).toBe("0x4d4d5af101bb41b2efc70a1a4178de19427df499354dd41b26e9280041758307");
    expect(enclaveSignerAddress(seed)).toBe("0x0a8814ee1725ee6cc3bdb23d7c82b869ac0a4092");
  });
  it("rejects seeds of the wrong size", () => {
    expect(() => deriveEnclavePrivateKey("0x1234")).toThrow("32 bytes");
  });
});

describe("EIP-191 over CJSON bodies", () => {
  it("signs canonical bytes, so key order does not matter", async () => {
    const key = deriveEnclavePrivateKey(seed);
    const sig = await signCjsonBody({ b: 1, a: { y: 2, x: 1 } }, key);
    expect(await recoverCjsonBodySigner({ a: { x: 1, y: 2 }, b: 1 }, sig)).toBe(enclaveSignerAddress(seed));
    expect(await recoverCjsonBodySigner({ a: { x: 1, y: 3 }, b: 1 }, sig)).not.toBe(enclaveSignerAddress(seed));
  });
});
