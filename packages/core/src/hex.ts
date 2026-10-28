export type Hex = `0x${string}`;
export type Address = `0x${string}`;

const HEX_RE = /^[0-9a-fA-F]*$/;

/** Decodes a hex string (with or without 0x). Throws on odd length or non-hex characters. */
export function hexToBytes(hex: string, expectedLength?: number): Uint8Array {
  const body = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (body.length % 2 !== 0 || !HEX_RE.test(body)) throw new Error("invalid hex string");
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(body.slice(2 * i, 2 * i + 2), 16);
  if (expectedLength !== undefined && out.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${out.length}`);
  }
  return out;
}

/** Lowercase 0x-prefixed hex. */
export function bytesToHex(bytes: Uint8Array): Hex {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s as Hex;
}

/** Lowercase hex without the 0x prefix (the dstack wire format). */
export function bytesToBareHex(bytes: Uint8Array): string {
  return bytesToHex(bytes).slice(2);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** True for a 0x-prefixed hex string of exactly `bytes` bytes. */
export function isHexOfLength(value: unknown, bytes: number): value is Hex {
  return typeof value === "string" && new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value);
}

/** Normalizes 0x hex to lowercase (INTERFACES: lowercase hex in JSON and hashes). */
export function lowerHex<T extends string>(value: T): T {
  return value.toLowerCase() as T;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}
