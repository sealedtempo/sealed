import { describe, expect, it } from "vitest";
import {
  canonicalize,
  deriveEnclavePrivateKey,
  enclaveSignerAddress,
  type Hex,
  periodsOverlap,
  recoverCjsonBodySigner,
  signUsageReportsRead,
  storedUsageReportSchema,
  usageReportsPageSchema,
  usageReportsReadMessage,
} from "../src/index.js";

const seed = `0x${"07".repeat(32)}` as Hex;
const deploymentId = `0x${"DE".repeat(32)}` as Hex;

describe("D-062 signed read of the stored usage reports", () => {
  it("signs the CJSON of {at, deploymentId, purpose} the api recovers (API_CONTRACT 7)", async () => {
    const msg = usageReportsReadMessage(deploymentId, 1_800_000_000);
    expect(canonicalize(msg)).toBe(`{"at":1800000000,"deploymentId":"0x${"de".repeat(32)}","purpose":"sealed/usage-reports/v1"}`);
    const h = await signUsageReportsRead(deploymentId, 1_800_000_000, deriveEnclavePrivateKey(seed));
    expect(h["x-sealed-at"]).toBe("1800000000");
    expect(await recoverCjsonBodySigner(usageReportsReadMessage(deploymentId.toLowerCase() as Hex, 1_800_000_000), h["x-sealed-signature"])).toBe(enclaveSignerAddress(seed));
  });

  it("treats shared boundaries as consecutive, anything else as overlap", () => {
    const p = (periodStart: number, periodEnd: number) => ({ periodStart, periodEnd });
    expect(periodsOverlap(p(0, 10), p(10, 20))).toBe(false);
    expect(periodsOverlap(p(10, 20), p(0, 10))).toBe(false);
    expect(periodsOverlap(p(0, 10), p(9, 20))).toBe(true);
    expect(periodsOverlap(p(0, 30), p(10, 20))).toBe(true);
    expect(periodsOverlap(p(10, 20), p(10, 20))).toBe(true);
  });

  it("parses the listing's page shape", () => {
    const entry = {
      usageHash: `0x${"ab".repeat(32)}`,
      periodStart: 1,
      periodEnd: 2,
      report: { deploymentId: `0x${"de".repeat(32)}`, periodStart: 1, periodEnd: 2, items: [{ appId: `0x${"01".repeat(32)}`, unit: 1, quantity: "10", fee: "2" }] },
      signature: `0x${"11".repeat(65)}`,
      receivedAt: 3,
    };
    expect(storedUsageReportSchema.parse(entry)).toEqual(entry);
    expect(usageReportsPageSchema.parse({ deploymentId: entry.report.deploymentId, reports: [entry], next: `1:0x${"ab".repeat(32)}` }).next).toBe(`1:0x${"ab".repeat(32)}`);
    expect(usageReportsPageSchema.safeParse({ deploymentId: entry.report.deploymentId, reports: [], next: "x" }).success).toBe(false);
  });
});
