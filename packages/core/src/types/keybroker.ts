// Key broker API (INTERFACES section 9).
import { z } from "zod";
import { bytes32, hexBytes, hexString, uint64 } from "./common.js";
import { eventLogEntrySchema } from "./evidence.js";

export const nonceResponseSchema = z.object({ nonce: bytes32, expiresAt: uint64 });

export const releaseRequestSchema = z.object({
  nonce: bytes32,
  ephemeralPub: bytes32,
  quote: hexString,
  eventLog: z.array(eventLogEntrySchema),
  config: z.record(z.string(), z.unknown()),
  appCompose: z.string(),
  releaseIds: z.array(bytes32),
  imageId: bytes32,
});
export type ReleaseRequest = z.infer<typeof releaseRequestSchema>;

export const releaseResponseSchema = z.object({
  stackHash: bytes32,
  deploymentId: bytes32,
  enc: hexBytes(32),
  ciphertext: hexString,
});
export type ReleaseResponse = z.infer<typeof releaseResponseSchema>;

export const DENIAL_REASONS = [
  "bad_nonce",
  "quote_invalid",
  "tcb_status",
  "report_data_mismatch",
  "image_not_approved",
  "image_debug",
  "measurements_mismatch",
  "rtmr3_replay",
  "compose_mismatch",
  "bundle_hash_mismatch",
  "customer_mismatch",
  "stack_not_approved",
] as const;

export const denialSchema = z.object({ decision: z.literal("denied"), reason: z.string(), detail: z.string().optional() });

// As the composer's manifest rules (catalog/schema/manifest.schema.json, manifest.go): a secret name is at most 128
// characters (MaxSecretNameLen; envexec refuses longer ones), and its owner is an app id or the password gate.
const secretName = z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/);
const secretOwner = z.string().regex(/^(_gate|[a-z][a-z0-9-]{1,30}[a-z0-9])$/);

export const releasePlaintextSchema = z.object({
  secrets: z.record(secretOwner, z.record(secretName, z.string())),
  diskKey: bytes32,
  signerSeed: bytes32,
});
export type ReleasePlaintext = z.infer<typeof releasePlaintextSchema>;
