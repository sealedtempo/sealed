import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CJSONError, canonicalize, canonicalizeText, cjsonSha256, parseCJSON } from "../src/cjson.js";

interface Vector {
  in: string;
  out?: string;
  error?: string;
}
const vectorsPath = join(import.meta.dirname, "../../../runtime/composer/testdata/cjson/vectors.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as Vector[];

describe("CJSON shared vectors (runtime/composer/testdata/cjson)", () => {
  it("has vectors", () => expect(vectors.length).toBeGreaterThan(10));
  for (const v of vectors) {
    it(`${v.error ? "rejects" : "canonicalizes"} ${v.in.slice(0, 50)}`, () => {
      if (v.error !== undefined) {
        expect(() => canonicalizeText(v.in)).toThrow(CJSONError);
        expect(() => canonicalizeText(v.in)).toThrow(v.error);
      } else {
        expect(canonicalizeText(v.in)).toBe(v.out);
        // idempotent
        expect(canonicalizeText(v.out as string)).toBe(v.out);
      }
    });
  }
});

describe("CJSON encoder", () => {
  it("sorts keys by byte order and drops undefined properties", () => {
    expect(canonicalize({ b: 1, a: { d: undefined, c: [true, null] } })).toBe('{"a":{"c":[true,null]},"b":1}');
  });
  it("escapes only quote, backslash and control characters", () => {
    expect(canonicalize("a\u0000\u001f\u007f<>&/é")).toBe('"a\\u0000\\u001f\u007f<>&/é"');
    expect(canonicalize("\b\f\n\r\t")).toBe('"\\b\\f\\n\\r\\t"');
  });
  it("rejects floats, unsafe integers, NaN and non-plain objects", () => {
    expect(() => canonicalize({ x: 1.5 })).toThrow("float");
    expect(() => canonicalize(2 ** 53)).toThrow("integer out of range");
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize(new Date(0))).toThrow("unsupported object");
    expect(() => canonicalize([undefined])).toThrow("undefined");
    expect(() => canonicalize({ "ké": 1 })).toThrow("non-ASCII key");
    expect(() => canonicalize("\ud800")).toThrow("lone surrogate");
  });
  it("accepts safe bigints and folds -0", () => {
    expect(canonicalize({ n: 12n, z: -0 })).toBe('{"n":12,"z":0}');
    expect(() => canonicalize(2n ** 53n)).toThrow("integer out of range");
  });
  it("matches JSON.stringify for plain sorted data", () => {
    const value = { a: [1, 2, { b: "x\ny" }], c: "☃" };
    expect(canonicalize(value)).toBe(JSON.stringify(value));
  });
  it("hashes the canonical bytes", () => {
    // sha256('{"a":1}')
    expect(cjsonSha256({ a: 1 })).toBe("0x015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862");
  });
});

describe("CJSON parser", () => {
  it("rejects lone surrogates, raw control characters and trailing data", () => {
    expect(() => parseCJSON('"\\ud800"')).toThrow("lone surrogate");
    expect(() => parseCJSON('"a\u0001"')).toThrow("invalid JSON");
    expect(() => parseCJSON("{} x")).toThrow("invalid JSON");
    expect(() => parseCJSON("01")).toThrow("invalid JSON");
  });
  it("parses __proto__ as a plain key", () => {
    expect(canonicalizeText('{"__proto__":1}')).toBe('{"__proto__":1}');
  });
});
