// sealed-evidence/v1 (INTERFACES section 8).
import { z } from "zod";
import { address, bytes32, hexString, uint64 } from "./common.js";
import { sealedConfigSchema } from "./config.js";

export const eventLogEntrySchema = z
  .object({
    imr: z.number().int().min(0).max(3),
    event_type: z.number().int().nonnegative(),
    digest: z.string(),
    event: z.string(),
    event_payload: z.string(),
  })
  .loose();

export type EventLogEntry = z.infer<typeof eventLogEntrySchema>;

export const evidenceBundleSchema = z
  .object({
    schema: z.literal("sealed-evidence/v1"),
    chainId: z.number().int().positive(),
    contracts: z.object({ platformRegistry: address, appRegistry: address, deploymentRegistry: address }).loose(),
    deploymentId: bytes32,
    customer: address,
    imageId: bytes32,
    releaseIds: z.array(bytes32),
    config: sealedConfigSchema,
    configHash: bytes32,
    appCompose: z.string().min(1),
    stackHash: bytes32,
    enclaveSigner: address,
    nonce2: bytes32,
    attestedAt: uint64,
    quote: hexString,
    quoteHash: bytes32,
    eventLog: z.array(eventLogEntrySchema),
    eventLogHash: bytes32,
    runtime: z.enum(["dstack", "fallback"]),
    record: z.object({ txHash: bytes32, method: z.number().int() }).optional(),
  })
  .loose();

export type EvidenceBundle = z.infer<typeof evidenceBundleSchema>;
