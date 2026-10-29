// The TypeScript side of the config parity table (runtime/composer/testdata/config-parity.json): sealedConfigSchema,
// through parseSealedConfig as composer.ParseConfig takes text, accepts and refuses each case as the Go composer does
// (TestConfigParity), and a valid case's output hashes to the composer's configHash. The format is described in
// runtime/composer/config_parity_test.go.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { cjsonSha256 } from "../src/cjson.js";
import { parseSealedConfig, SealedConfigError } from "../src/types/config.js";

interface ParityCase {
  name: string;
  set?: Record<string, unknown>;
  delete?: string[];
  raw?: string;
  pad?: number;
  valid: boolean;
  tsValid?: boolean;
  why?: string;
  field?: string;
  configHash?: string;
}

const table = JSON.parse(readFileSync(new URL("../../../runtime/composer/testdata/config-parity.json", import.meta.url), "utf8")) as {
  base: Record<string, unknown>;
  cases: ParityCase[];
};

function expandGen(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(expandGen);
  if (v === null || typeof v !== "object") return v;
  const o = v as Record<string, unknown>;
  if (!("$gen" in o)) return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, expandGen(x)]));
  const fill = (s: string, i: number) => s.replaceAll("{ii}", String(i).padStart(2, "0")).replaceAll("{i}", String(i));
  return Array.from({ length: o.count as number }, (_, i) =>
    typeof o.$gen === "string" ? fill(o.$gen, i) : Object.fromEntries(Object.entries(o.$gen as Record<string, string>).map(([k, x]) => [k, fill(x, i)])),
  );
}

function setPath(root: unknown, path: string, val: unknown, del: boolean): void {
  const segs = path.split(".");
  let cur = root;
  for (const [i, seg] of segs.entries()) {
    const last = i === segs.length - 1;
    if (Array.isArray(cur)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length || del) throw new Error(`${path}: bad index ${seg}`);
      if (last) cur[idx] = val;
      else cur = cur[idx];
    } else if (cur !== null && typeof cur === "object") {
      const o = cur as Record<string, unknown>;
      if (last) {
        if (del) delete o[seg];
        else o[seg] = val;
      } else if (seg in o) cur = o[seg];
      else throw new Error(`${path}: no ${seg}`);
    } else throw new Error(`${path}: ${seg} is not inside an object or list`);
  }
}

function documentOf(c: ParityCase): string {
  let text: string;
  if (c.raw !== undefined) text = c.raw;
  else {
    const doc = structuredClone(table.base);
    for (const p of Object.keys(c.set ?? {}).sort()) setPath(doc, p, expandGen(structuredClone((c.set as Record<string, unknown>)[p])), false);
    for (const p of c.delete ?? []) setPath(doc, p, undefined, true);
    text = JSON.stringify(doc);
  }
  if (c.pad !== undefined) {
    const n = Buffer.byteLength(text);
    if (n > c.pad) throw new Error(`${c.name}: ${n} bytes, more than pad ${c.pad}`);
    text += " ".repeat(c.pad - n);
  }
  return text;
}

describe("sealed-config/v1 parity with the Go composer", () => {
  it("the table is the composer's (enough cases of both kinds, names unique)", () => {
    expect(new Set(table.cases.map((c) => c.name)).size).toBe(table.cases.length);
    expect(table.cases.filter((c) => c.valid).length).toBeGreaterThanOrEqual(40);
    expect(table.cases.filter((c) => !c.valid).length).toBeGreaterThanOrEqual(100);
    for (const c of table.cases) if (c.tsValid !== undefined) expect(c.why, c.name).toBeTruthy();
  });

  for (const c of table.cases) {
    const expected = c.tsValid ?? c.valid;
    it(`${expected ? "accepts" : "refuses"} ${c.name}`, () => {
      const text = documentOf(c);
      let out: unknown;
      let err: unknown;
      try {
        out = parseSealedConfig(text);
      } catch (e) {
        err = e;
      }
      if (expected) {
        expect(err, String(err)).toBeUndefined();
        // Only cases the composer accepts carry its configHash; the output is its normalized form.
        if (c.valid) expect(cjsonSha256(out)).toBe(c.configHash);
        return;
      }
      expect(err, "accepted").toBeInstanceOf(SealedConfigError);
      if (c.field) {
        const e = err as SealedConfigError;
        expect(e.field?.startsWith(c.field) || e.message.includes(c.field), `${e.message} does not name ${c.field}`).toBe(true);
      }
    });
  }
});
