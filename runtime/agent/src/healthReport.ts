// Content-free signed health reports (INTERFACES 10, property P5): app states, egress counters
// from sealed-egress and payment status. Signed by the enclave signer (EIP-191 over CJSON body).
//
// D-065: an app can modulate counts (how often it is blocked, how much it spends through the payer) to pass
// a few bits per report to the platform. Every count and amount the platform cannot read exactly elsewhere
// is rounded down to two significant figures before signing. Sent as they are: timestamps, limits, and
// totals the platform already holds exactly (signed usage reports, onchain fees and key limits).
import { type Hex, roundDownSignificant, roundDownSignificantDecimal, signCjsonBody } from "@sealed/core";
import type { PlatformClient } from "./evidence.js";
import { localJson, parseEndpoint } from "./http.js";
import type { AppStatus } from "./metering/appHealth.js";

export interface EgressStats {
  since?: string | number;
  allowed: Record<string, number>;
  blocked: Record<string, number>;
}

export type EgressStatsSource = () => Promise<EgressStats | undefined>;

export function httpEgressStats(url: string): EgressStatsSource {
  const u = new URL(url);
  const ep = parseEndpoint(u.origin);
  return async () => {
    try {
      const s = await localJson<EgressStats>(ep, `${u.pathname}${u.search}`, { timeoutMs: 5000 });
      return { since: s.since, allowed: counts(s.allowed), blocked: counts(s.blocked) };
    } catch {
      return undefined;
    }
  };
}

/** Per-destination counters are app-chosen names: only well-formed host:port keys, at most this many (largest first). */
export const MAX_EGRESS_KEYS = 50;
/** The platform refuses a report with more payment fields (API_CONTRACT 15). */
export const MAX_PAYMENT_KEYS = 64;
const HOST_PORT_RE = /^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*:[0-9]{1,5}$/;

/** Well-formed egress counts, rounded (D-065) before the largest are picked, so the pick says nothing finer. */
export function counts(v: unknown): Record<string, number> {
  const entries: [string, number][] = [];
  if (v && typeof v === "object") {
    for (const [k, n] of Object.entries(v as Record<string, unknown>)) {
      if (typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && k.length <= 260 && HOST_PORT_RE.test(k)) entries.push([k, roundDownSignificant(n)]);
    }
  }
  entries.sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  return Object.fromEntries(entries.slice(0, MAX_EGRESS_KEYS));
}

export interface HealthInputs {
  at: number;
  apps: Record<string, AppStatus>;
  egress?: EgressStats;
  payments: Record<string, string | number | boolean | null>;
}

/** Payment fields sent exactly: timestamps, limits, and totals the platform holds exactly elsewhere. */
export const EXACT_PAYMENT_FIELDS: ReadonlySet<string> = new Set([
  "failingSince",
  "deferredSince",
  "lastPaidAt",
  "lastAttemptAt",
  // The signed usage reports the platform stores carry every fee exactly.
  "metered",
  "unpaid",
  "budget_limit",
  // Settlement transactions and the access key's limit are public onchain.
  "budget_fees",
  "budget_onchainRemaining",
  "budget_onchainReadAt",
  "budget_windowEnd",
  "mpp_limit",
  "mpp_budget",
  "mpp_relayCheckedAt",
  "mpp_sentAt",
  "ledger_verifiedAt",
  "ledger_signedThrough",
]);

/** D-065: every other count (a number) or amount (a decimal string) rounded down to two significant figures. */
export function roundPayments(p: Record<string, string | number | boolean | null>): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  for (const [k, v] of Object.entries(p)) {
    if (Object.keys(out).length >= MAX_PAYMENT_KEYS) break;
    if (EXACT_PAYMENT_FIELDS.has(k)) out[k] = v;
    else if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) out[k] = roundDownSignificant(v);
    else if (typeof v === "string" && /^[0-9]{1,78}$/.test(v)) out[k] = roundDownSignificantDecimal(v);
    else out[k] = v;
  }
  return out;
}

export function healthBody(i: HealthInputs) {
  return {
    at: i.at,
    apps: i.apps,
    egress: i.egress
      ? { ...(i.egress.since !== undefined ? { since: i.egress.since } : {}), allowed: counts(i.egress.allowed), blocked: counts(i.egress.blocked) }
      : { allowed: {}, blocked: {} },
    payments: roundPayments(i.payments),
  };
}

export async function sendHealthReport(platform: PlatformClient, deploymentId: Hex, enclaveKey: Hex, inputs: HealthInputs) {
  const body = healthBody(inputs);
  const signature = await signCjsonBody(body, enclaveKey);
  const answer = await platform.postHealth({ deploymentId, signature, body });
  // API_CONTRACT 15: `reattest: true` while the customer's re-attest request is not answered by newer evidence (D-068).
  const reattest = (answer as { reattest?: unknown } | null | undefined)?.reattest === true;
  return { deploymentId, signature, body, reattest };
}
