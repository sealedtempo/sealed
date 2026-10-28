import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { attestReportData, evidenceReportData, kbReleaseReportData, uint64be } from "../src/reportData.js";

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
  it("evidence binds attestedAt as uint64 big-endian (D-047)", () => {
    const [stack, config, signer, nonce2] = ["01".repeat(32), "02".repeat(32), "03".repeat(20), "04".repeat(32)];
    const at = 1_730_000_000;
    const rd = evidenceReportData(`0x${stack}`, `0x${config}`, `0x${signer}`, `0x${nonce2}`, at);
    expect(Buffer.from(rd)).toEqual(h("sealed/evidence/v1", b(stack), b(config), b(signer), b(nonce2), b("00000000671db480")));
    // Frozen vector, shared with the Go verifier (computed independently with Python hashlib).
    expect(Buffer.from(rd).toString("hex")).toBe(`ecf4a53654152e242b80948f7c0657f5821a0406eb2a8291c5c0927696178ed3${"00".repeat(32)}`);
    expect(Buffer.from(evidenceReportData(`0x${stack}`, `0x${config}`, `0x${signer}`, `0x${nonce2}`, 2n ** 64n - 1n)).toString("hex")).toBe(
      `90e000a209152fb1c079fa4633dbb9f07e6df44ba27bcbc7357ed94e4d77e806${"00".repeat(32)}`,
    );
    // A different attestedAt gives a different quote binding.
    expect(Buffer.from(evidenceReportData(`0x${stack}`, `0x${config}`, `0x${signer}`, `0x${nonce2}`, at + 1))).not.toEqual(Buffer.from(rd));
  });
  it("uint64be rejects values outside uint64", () => {
    expect(Buffer.from(uint64be(1)).toString("hex")).toBe("0000000000000001");
    expect(() => uint64be(-1)).toThrow("out of range");
    expect(() => uint64be(2n ** 64n)).toThrow("out of range");
    expect(() => uint64be(1.5)).toThrow("safe integer");
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
