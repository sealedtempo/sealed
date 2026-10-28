// Spend counters from sealed-mpp-payer (POST /v1/spend). The body is the payer's SpendReport as
// runtime/mpp-payer builds it (spend-reporter.ts): {source, mode, currency, counters{...}, relay{...},
// sentAt}. The counters go to the platform in signed health reports, flattened as `mpp_<counter>`, so
// only a fixed set of numeric counters and booleans is kept: anything else (free text, extra keys,
// other callers) would be a channel out of the VM (property P5).
//
// Also the bodies of POST /v1/spend/reserve {amount} and /release {reservationId, used} (D-048).
import { z } from "zod";

const decimal = z.string().regex(/^[0-9]{1,30}$/);
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
/** A base-unit amount as a decimal string, or a safe integer. */
const amount = z.union([decimal, count]).transform((v) => BigInt(v));

/** Fields that are read but never forwarded: only their type and size are checked. */
const dropped = z.string().max(80);

const spendReportSchema = z.object({
  source: dropped.optional(),
  mode: dropped.optional(),
  currency: address.optional(),
  counters: z
    .object({
      day: z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/),
      limit: decimal,
      budget: decimal,
      debited: decimal,
      remaining: decimal,
      charges: count,
      chargeAmount: decimal,
      deposits: count,
      depositAmount: decimal,
      topUps: count,
      topUpAmount: decimal,
      refunded: decimal,
      refused: count,
      sessionAuthorized: decimal,
    })
    .partial(),
  relay: z
    .object({ attested: z.boolean(), checkedAt: count, stackHash: dropped, sessionsAvailable: z.boolean() })
    .partial()
    .optional(),
  sentAt: count.optional(),
});

export type SpendCounters = Record<string, string | number | boolean>;

export interface SpendReport {
  counters: SpendCounters;
  /** The payer's token, when it says (must be the deployment's fee token). */
  currency?: string;
}

/** The flat `mpp_*` counters of a valid report, or undefined. Unknown keys are dropped. */
export function parseSpendReport(body: unknown): SpendReport | undefined {
  const r = spendReportSchema.safeParse(body);
  if (!r.success) return undefined;
  const out: SpendCounters = {};
  for (const [k, v] of Object.entries(r.data.counters)) if (v !== undefined) out[`mpp_${k}`] = v;
  const relay = r.data.relay;
  if (relay?.attested !== undefined) out.mpp_relayAttested = relay.attested;
  if (relay?.checkedAt !== undefined) out.mpp_relayCheckedAt = relay.checkedAt;
  if (relay?.sessionsAvailable !== undefined) out.mpp_sessionsAvailable = relay.sessionsAvailable;
  if (r.data.sentAt !== undefined) out.mpp_sentAt = r.data.sentAt;
  return { counters: out, ...(r.data.currency ? { currency: r.data.currency.toLowerCase() } : {}) };
}

export const reserveRequestSchema = z.object({ amount, currency: address.optional() }).strict();
export const releaseRequestSchema = z.object({ reservationId: z.string().regex(/^0x[0-9a-f]{32}$/), used: amount }).strict();
