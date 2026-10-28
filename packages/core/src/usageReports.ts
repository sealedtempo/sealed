// D-062: the enclave signer reads back the usage reports the platform stores for its deployment, so the
// agent can rebuild its paid ledger after the host rolls the data disk back. The read is signed
// (API_CONTRACT 7): EIP-191 personal_sign over the CJSON of {at, deploymentId, purpose}, sent as the
// x-sealed-at and x-sealed-signature headers.
import type { Hex } from "./hex.js";
import { signCjsonBody } from "./signer.js";

export const USAGE_REPORTS_PURPOSE = "sealed/usage-reports/v1";
/** The api accepts a signed read whose `at` is within this many seconds of its clock. */
export const USAGE_REPORTS_READ_WINDOW_SECONDS = 300;

/** The message an enclave signer signs to read its own deployment's stored reports. */
export function usageReportsReadMessage(deploymentId: Hex, at: number) {
  return { at, deploymentId: deploymentId.toLowerCase(), purpose: USAGE_REPORTS_PURPOSE };
}

/** Headers of a signed read of the stored reports. */
export async function signUsageReportsRead(deploymentId: Hex, at: number, enclaveKey: Hex): Promise<{ "x-sealed-at": string; "x-sealed-signature": Hex }> {
  return { "x-sealed-at": String(at), "x-sealed-signature": await signCjsonBody(usageReportsReadMessage(deploymentId, at), enclaveKey) };
}

/** Whether two report periods overlap. Consecutive periods may share their boundary (D-062, API_CONTRACT 15). */
export function periodsOverlap(a: { periodStart: number | bigint; periodEnd: number | bigint }, b: { periodStart: number | bigint; periodEnd: number | bigint }): boolean {
  return BigInt(a.periodStart) < BigInt(b.periodEnd) && BigInt(b.periodStart) < BigInt(a.periodEnd);
}
