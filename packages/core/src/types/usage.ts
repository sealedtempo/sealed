// Usage reports and health reports as sent to the platform API (INTERFACES 4.2, 10, 11).
import { z } from "zod";
import { bytes32, decimalString, hexString, slug, uint64 } from "./common.js";

export const usageItemJsonSchema = z.object({
  appId: bytes32,
  unit: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  quantity: decimalString,
  fee: decimalString,
});

export const usageReportJsonSchema = z.object({
  deploymentId: bytes32,
  periodStart: uint64,
  periodEnd: uint64,
  items: z.array(usageItemJsonSchema),
});

export const usageSubmissionSchema = z.object({ report: usageReportJsonSchema, signature: hexString });

/**
 * One stored report of GET /v1/deployments/:id/usage-reports (API_CONTRACT 7, D-062): the report exactly as the
 * agent sent it, with the platform's own key and receive time. Readers check the signature themselves.
 */
export const storedUsageReportSchema = z.object({
  usageHash: bytes32,
  periodStart: uint64,
  periodEnd: uint64,
  report: usageReportJsonSchema,
  signature: hexString,
  receivedAt: uint64,
});
export type StoredUsageReport = z.infer<typeof storedUsageReportSchema>;

/** A page of stored reports in period order; `next` is the `after` cursor of the next page, null on the last. */
export const usageReportsPageSchema = z.object({
  deploymentId: bytes32,
  reports: z.array(storedUsageReportSchema),
  next: z.string().regex(/^[0-9]{1,20}:0x[0-9a-f]{64}$/).nullable(),
});
export type UsageReportsPage = z.infer<typeof usageReportsPageSchema>;

/** POST /v1/usage-events body from apps (agent local API). */
export const usageEventSchema = z.object({
  app: slug,
  unit: z.enum(["tokens", "pages", "app_hour"]),
  quantity: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  /** Optional idempotency key (for example LiteLLM's litellm_call_id). */
  id: z.string().max(200).optional(),
  meta: z.record(z.string(), z.unknown()).optional(),
});
export type UsageEvent = z.infer<typeof usageEventSchema>;

export const healthBodySchema = z
  .object({
    at: uint64,
    apps: z.record(z.string(), z.enum(["healthy", "unhealthy", "unknown"])),
    egress: z.object({
      since: z.union([z.number(), z.string()]).optional(),
      allowed: z.record(z.string(), z.number().int().nonnegative()),
      blocked: z.record(z.string(), z.number().int().nonnegative()),
    }),
    payments: z.record(z.string(), z.unknown()),
  })
  .loose();
export type HealthBody = z.infer<typeof healthBodySchema>;

export const healthSubmissionSchema = z.object({ deploymentId: bytes32, signature: hexString, body: healthBodySchema });

