// Spend counters from sealed-mpp-payer (POST /v1/spend, the payer's SpendReport). They go to the
// platform in signed health reports, so only a fixed set of numeric counters is kept: anything else
// (free text, extra keys, other callers) would be a channel out of the VM (property P5).
import { z } from "zod";

const decimal = z.string().regex(/^[0-9]{1,30}$/);
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

const spendReportSchema = z.object({
  counters: z
    .object({
      day: z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/),
      limit: decimal,
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
  relay: z.object({ attested: z.boolean(), checkedAt: count, sessionsAvailable: z.boolean() }).partial().optional(),
  sentAt: count.optional(),
});

export type SpendCounters = Record<string, string | number | boolean>;

/** Returns the flat `mpp_*` counters of a valid report, or undefined. Unknown keys are dropped. */
export function parseSpendReport(body: unknown): SpendCounters | undefined {
  const r = spendReportSchema.safeParse(body);
  if (!r.success) return undefined;
  const out: SpendCounters = {};
  for (const [k, v] of Object.entries(r.data.counters)) if (v !== undefined) out[`mpp_${k}`] = v;
  const relay = r.data.relay;
  if (relay?.attested !== undefined) out.mpp_relayAttested = relay.attested;
  if (relay?.checkedAt !== undefined) out.mpp_relayCheckedAt = relay.checkedAt;
  if (relay?.sessionsAvailable !== undefined) out.mpp_sessionsAvailable = relay.sessionsAvailable;
  if (r.data.sentAt !== undefined) out.mpp_sentAt = r.data.sentAt;
  return out;
}
