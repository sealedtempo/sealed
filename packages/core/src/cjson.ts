// Canonical JSON (INTERFACES section 1): RFC 8785 restricted to ASCII keys sorted by byte order,
// integers within the safe range, no floats, minimal string escaping, no whitespace.
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, type Hex, utf8 } from "./hex.js";

export type CJSONValue = null | boolean | number | string | CJSONValue[] | { [key: string]: CJSONValue };

export class CJSONError extends Error {
  constructor(message: string) {
    super(`cjson: ${message}`);
    this.name = "CJSONError";
  }
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

// ---------------------------------------------------------------------------------------------
// Strict parser. JSON.parse cannot report floats written as integers-with-exponent, duplicate
// keys or out-of-range integers, so CJSON input goes through this one.
// ---------------------------------------------------------------------------------------------

class Parser {
  private pos = 0;
  constructor(private readonly text: string) {}

  parse(): CJSONValue {
    this.ws();
    const v = this.value();
    this.ws();
    if (this.pos !== this.text.length) this.fail("trailing characters");
    return v;
  }

  private fail(what: string): never {
    throw new CJSONError(`invalid JSON: ${what} at offset ${this.pos}`);
  }

  private ws(): void {
    while (this.pos < this.text.length) {
      const c = this.text.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else break;
    }
  }

  private value(): CJSONValue {
    const c = this.text[this.pos];
    if (c === undefined) this.fail("unexpected end");
    if (c === "{") return this.object();
    if (c === "[") return this.array();
    if (c === '"') return this.string();
    if (c === "-" || (c >= "0" && c <= "9")) return this.number();
    if (this.text.startsWith("true", this.pos)) return this.literal("true", true);
    if (this.text.startsWith("false", this.pos)) return this.literal("false", false);
    if (this.text.startsWith("null", this.pos)) return this.literal("null", null);
    this.fail(`unexpected character ${JSON.stringify(c)}`);
  }

  private literal<T>(word: string, v: T): T {
    this.pos += word.length;
    return v;
  }

  private object(): { [key: string]: CJSONValue } {
    this.pos++;
    const out: { [key: string]: CJSONValue } = Object.create(null);
    const seen = new Set<string>();
    this.ws();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return { ...out };
    }
    for (;;) {
      this.ws();
      if (this.text[this.pos] !== '"') this.fail("expected object key");
      const key = this.string();
      if (!isAscii(key)) throw new CJSONError(`non-ASCII key ${JSON.stringify(key)}`);
      if (seen.has(key)) throw new CJSONError(`duplicate key ${JSON.stringify(key)}`);
      seen.add(key);
      this.ws();
      if (this.text[this.pos] !== ":") this.fail("expected ':'");
      this.pos++;
      this.ws();
      out[key] = this.value();
      this.ws();
      const c = this.text[this.pos];
      if (c === ",") {
        this.pos++;
        continue;
      }
      if (c === "}") {
        this.pos++;
        return { ...out };
      }
      this.fail("expected ',' or '}'");
    }
  }

  private array(): CJSONValue[] {
    this.pos++;
    const out: CJSONValue[] = [];
    this.ws();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      this.ws();
      const c = this.text[this.pos];
      if (c === ",") {
        this.pos++;
        continue;
      }
      if (c === "]") {
        this.pos++;
        return out;
      }
      this.fail("expected ',' or ']'");
    }
  }

  private number(): number {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.pos));
    if (!m) this.fail("bad number");
    this.pos += m[0].length;
    if (m[2] !== undefined || m[3] !== undefined) throw new CJSONError(`float not allowed: ${m[0]}`);
    const big = BigInt(m[0]);
    if (big > MAX_SAFE || big < -MAX_SAFE) throw new CJSONError(`integer out of range: ${m[0]}`);
    const n = Number(big);
    return n === 0 ? 0 : n; // folds -0
  }

  private string(): string {
    this.pos++;
    let out = "";
    for (;;) {
      const c = this.text[this.pos];
      if (c === undefined) this.fail("unterminated string");
      const code = c.charCodeAt(0);
      if (c === '"') {
        this.pos++;
        break;
      }
      if (code < 0x20) this.fail("raw control character in string");
      if (c === "\\") {
        const e = this.text[this.pos + 1];
        this.pos += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = this.text.slice(this.pos, this.pos + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
            this.pos += 4;
            out += String.fromCharCode(Number.parseInt(hex, 16));
            break;
          }
          default:
            this.fail("bad escape");
        }
        continue;
      }
      out += c;
      this.pos++;
    }
    if (!isWellFormed(out)) throw new CJSONError("invalid JSON: lone surrogate in string");
    return out;
  }
}

function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) return false;
  return true;
}

/** Parses JSON text under the CJSON rules (no floats, safe integers, unique ASCII keys). */
export function parseCJSON(text: string): CJSONValue {
  return new Parser(text).parse();
}

// ---------------------------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------------------------

function encodeString(s: string): string {
  if (!isWellFormed(s)) throw new CJSONError("lone surrogate in string");
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    const code = s.charCodeAt(i);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code < 0x20) {
      if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else out += `\\u00${code.toString(16).padStart(2, "0")}`;
    } else out += ch;
  }
  return `${out}"`;
}

function encode(v: unknown, path: string): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return encodeString(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new CJSONError(`float not allowed at ${path}`);
    if (!Number.isSafeInteger(v)) throw new CJSONError(`integer out of range at ${path}`);
    return String(v === 0 ? 0 : v);
  }
  if (typeof v === "bigint") {
    if (v > MAX_SAFE || v < -MAX_SAFE) throw new CJSONError(`integer out of range at ${path}`);
    return v.toString();
  }
  if (Array.isArray(v)) {
    return `[${v
      .map((item, i) => {
        if (item === undefined) throw new CJSONError(`undefined at ${path}[${i}]`);
        return encode(item, `${path}[${i}]`);
      })
      .join(",")}]`;
  }
  if (typeof v === "object") {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new CJSONError(`unsupported object at ${path}`);
    const entries = Object.entries(v as Record<string, unknown>).filter(([, val]) => val !== undefined);
    for (const [k] of entries) if (!isAscii(k)) throw new CJSONError(`non-ASCII key ${JSON.stringify(k)} at ${path}`);
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, val]) => `${encodeString(k)}:${encode(val, `${path}.${k}`)}`).join(",")}}`;
  }
  throw new CJSONError(`unsupported value of type ${typeof v} at ${path}`);
}

/**
 * Canonical JSON text of a value. Object properties whose value is undefined are omitted (like
 * JSON.stringify); everything else that has no CJSON form throws.
 */
export function canonicalize(value: unknown): string {
  return encode(value, "$");
}

/** Re-canonicalizes JSON text (parse strictly, then encode). */
export function canonicalizeText(text: string): string {
  return canonicalize(parseCJSON(text));
}

export function cjsonBytes(value: unknown): Uint8Array {
  return utf8(canonicalize(value));
}

/** sha256 over the CJSON bytes, as 0x hex. */
export function cjsonSha256(value: unknown): Hex {
  return bytesToHex(sha256(cjsonBytes(value)));
}
