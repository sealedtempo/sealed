// TDX report_data constructions (INTERFACES section 3): sha256(tag || fields) followed by 32 zero bytes.
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, type Hex, hexToBytes, utf8 } from "./hex.js";

export const KB_RELEASE_TAG = "sealed/kb-release/v1";
export const EVIDENCE_TAG = "sealed/evidence/v1";
export const ATTEST_TAG = "sealed/attest/v1";

function build(tag: string, fields: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(64);
  out.set(sha256(concatBytes(utf8(tag), ...fields)), 0);
  return out;
}

type Bytes = Hex | Uint8Array;
const b = (v: Bytes, len: number): Uint8Array => {
  const bytes = typeof v === "string" ? hexToBytes(v) : v;
  if (bytes.length !== len) throw new Error(`report_data field: expected ${len} bytes, got ${bytes.length}`);
  return bytes;
};

/** sha256("sealed/kb-release/v1" || nonce[32] || ephemeralPub[32]) || 0^32 */
export function kbReleaseReportData(nonce: Bytes, ephemeralPub: Bytes): Uint8Array {
  return build(KB_RELEASE_TAG, [b(nonce, 32), b(ephemeralPub, 32)]);
}

/** uint64 big-endian (INTERFACES: integers in byte strings are big-endian). */
export function uint64be(value: number | bigint): Uint8Array {
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("uint64: not a safe integer");
  const v = BigInt(value);
  if (v < 0n || v >= 1n << 64n) throw new Error("uint64: out of range");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, false);
  return out;
}

/**
 * sha256("sealed/evidence/v1" || stackHash[32] || configHash[32] || enclaveSigner[20] || nonce2[32] ||
 * uint64be(attestedAt)) || 0^32. D-047: the quote binds the bundle's attestedAt, so the oracle's
 * freshness window holds for the quote itself and not only for a field next to it.
 */
export function evidenceReportData(
  stackHash: Bytes,
  configHash: Bytes,
  enclaveSigner: Bytes,
  nonce2: Bytes,
  attestedAt: number | bigint,
): Uint8Array {
  return build(EVIDENCE_TAG, [b(stackHash, 32), b(configHash, 32), b(enclaveSigner, 20), b(nonce2, 32), uint64be(attestedAt)]);
}

/** sha256("sealed/attest/v1" || nonce[32] || tlsPubKeyHash[32] || enclaveSigner[20]) || 0^32 */
export function attestReportData(nonce: Bytes, tlsPubKeyHash: Bytes, enclaveSigner: Bytes): Uint8Array {
  return build(ATTEST_TAG, [b(nonce, 32), b(tlsPubKeyHash, 32), b(enclaveSigner, 20)]);
}

export function reportDataHex(rd: Uint8Array): Hex {
  return bytesToHex(rd);
}
