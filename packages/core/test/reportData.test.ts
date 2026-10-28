import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { attestReportData, evidenceReportData, kbReleaseReportData } from "../src/reportData.js";

const h = (...parts: (string | Buffer)[]) => {
  const c = createHash("sha256");
  for (const p of parts) c.update(p);
  return Buffer.concat([c.digest(), Buffer.alloc(32)]);
};
const b = (hex: string) => Buffer.from(hex, "hex");

describe("report_data constructions (INTERFACES 3)", () => {
  const nonce = "aa".repeat(32);
  it("key release", () => {
    const pub = "bb".repeat(32);
    expect(Buffer.from(kbReleaseReportData(`0x${nonce}`, `0x${pub}`))).toEqual(h("sealed/kb-release/v1", b(nonce), b(pub)));
  });
  it("evidence", () => {
    const [stack, config, signer, nonce2] = ["01".repeat(32), "02".repeat(32), "03".repeat(20), "04".repeat(32)];
    expect(Buffer.from(evidenceReportData(`0x${stack}`, `0x${config}`, `0x${signer}`, `0x${nonce2}`))).toEqual(
      h("sealed/evidence/v1", b(stack), b(config), b(signer), b(nonce2)),
    );
  });
  it("live attest", () => {
    const [tls, signer] = ["05".repeat(32), "06".repeat(20)];
    const rd = attestReportData(`0x${nonce}`, `0x${tls}`, `0x${signer}`);
    expect(rd.length).toBe(64);
    expect(Buffer.from(rd)).toEqual(h("sealed/attest/v1", b(nonce), b(tls), b(signer)));
  });
  it("tags separate the domains", () => {
    const x = `0x${"07".repeat(32)}` as const;
    expect(Buffer.from(kbReleaseReportData(x, x))).not.toEqual(Buffer.from(attestReportData(x, x, `0x${"07".repeat(20)}`)));
  });
  it("rejects wrong field lengths", () => {
    expect(() => kbReleaseReportData("0x00", `0x${"00".repeat(32)}`)).toThrow("expected 32 bytes");
  });
});
