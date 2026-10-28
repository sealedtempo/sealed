import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bytesToBareHex, concatBytes, hexToBytes, utf8 } from "../src/hex.js";
import {
  deriveKeyPair,
  generateKeyPair,
  KB_RELEASE_INFO,
  open,
  openKbRelease,
  seal,
  sealKbRelease,
} from "../src/hpke.js";

const vector = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures/hpke-vector.json"), "utf8"));
const dec = (u: Uint8Array) => new TextDecoder().decode(u);

describe("HPKE X25519 / HKDF-SHA256 / AES-256-GCM", () => {
  it("round trips with info and aad", async () => {
    const kp = await generateKeyPair();
    expect(kp.publicKey.length).toBe(32);
    const wire = await seal(kp.publicKey, utf8("hello"), { info: "i", aad: utf8("a") });
    expect(wire.length).toBe(32 + 5 + 16);
    expect(dec(await open(kp.privateKey, wire, { info: "i", aad: utf8("a") }))).toBe("hello");
  });
  it("fails on wrong aad, wrong info or a flipped bit", async () => {
    const kp = await generateKeyPair();
    const wire = await seal(kp.publicKey, utf8("secret"), { info: KB_RELEASE_INFO, aad: utf8("n1") });
    await expect(open(kp.privateKey, wire, { info: KB_RELEASE_INFO, aad: utf8("n2") })).rejects.toThrow();
    await expect(open(kp.privateKey, wire, { info: "other", aad: utf8("n1") })).rejects.toThrow();
    const flipped = wire.slice();
    flipped[40] = (flipped[40] as number) ^ 1;
    await expect(open(kp.privateKey, flipped, { info: KB_RELEASE_INFO, aad: utf8("n1") })).rejects.toThrow();
  });
  it("reproduces the fixed vector (deterministic ephemeral key)", async () => {
    const kp = await deriveKeyPair(hexToBytes(vector.ikm));
    expect(bytesToBareHex(kp.publicKey)).toBe(vector.recipientPublicKey);
    const wire = await seal(kp.publicKey, utf8(vector.tsPlaintext), { info: vector.info, aad: hexToBytes(vector.aad) }, hexToBytes(vector.ephemeralIkm));
    expect(bytesToBareHex(wire)).toBe(vector.tsWire);
  });
  it("opens a ciphertext sealed by Go crypto/hpke", async () => {
    const kp = await deriveKeyPair(hexToBytes(vector.ikm));
    const pt = await open(kp.privateKey, hexToBytes(vector.goWire), { info: vector.info, aad: hexToBytes(vector.aad) });
    expect(dec(pt)).toBe(vector.goPlaintext);
  });
  it("key broker release helpers accept bare and enc-prefixed ciphertexts", async () => {
    const kp = await generateKeyPair();
    const nonce = hexToBytes(`0x${"cd".repeat(32)}`);
    const { enc, ciphertext } = await sealKbRelease(kp.publicKey, nonce, utf8('{"x":1}'));
    expect(dec(await openKbRelease(kp.privateKey, nonce, enc, ciphertext))).toBe('{"x":1}');
    expect(dec(await openKbRelease(kp.privateKey, nonce, enc, concatBytes(enc, ciphertext)))).toBe('{"x":1}');
    await expect(openKbRelease(kp.privateKey, hexToBytes(`0x${"ce".repeat(32)}`), enc, ciphertext)).rejects.toThrow();
  });
});
