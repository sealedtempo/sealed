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

/** sha256("sealed/evidence/v1" || stackHash[32] || configHash[32] || enclaveSigner[20] || nonce2[32]) || 0^32 */
export function evidenceReportData(stackHash: Bytes, configHash: Bytes, enclaveSigner: Bytes, nonce2: Bytes): Uint8Array {
  return build(EVIDENCE_TAG, [b(stackHash, 32), b(configHash, 32), b(enclaveSigner, 20), b(nonce2, 32)]);
}

/** sha256("sealed/attest/v1" || nonce[32] || tlsPubKeyHash[32] || enclaveSigner[20]) || 0^32 */
export function attestReportData(nonce: Bytes, tlsPubKeyHash: Bytes, enclaveSigner: Bytes): Uint8Array {
  return build(ATTEST_TAG, [b(nonce, 32), b(tlsPubKeyHash, 32), b(enclaveSigner, 20)]);
}

export function reportDataHex(rd: Uint8Array): Hex {
  return bytesToHex(rd);
}
