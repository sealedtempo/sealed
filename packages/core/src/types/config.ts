// sealed-config/v1 (INTERFACES section 5). Public, measured, never holds secrets.
import { z } from "zod";
import { address, bytes32, decimalString, slug } from "./common.js";

const url = z.string().url();
const hostPort = z.string().regex(/^(\*\.)?[A-Za-z0-9.-]+:[0-9]{1,5}$/, "expected host:port");

export const hostnamesSchema = z.discriminatedUnion("scheme", [
  z.object({ scheme: z.literal("sslip"), ip: z.ipv4() }).loose(),
  z.object({ scheme: z.literal("custom"), ip: z.ipv4().optional(), domains: z.record(z.string(), z.string()) }).loose(),
]);

export const settlementSchema = z.object({
  mode: z.enum(["access-key", "enclave-account"]),
  intervalMinutes: z.number().int().positive(),
  gracePeriodMinutes: z.number().int().positive(),
  spendLimitPerDay: decimalString,
});

export const sealedConfigSchema = z
  .object({
    schema: z.literal("sealed-config/v1"),
    chainId: z.number().int().positive(),
    customer: address,
    salt: bytes32,
    imageId: bytes32,
    composerVersion: z.string().min(1),
    apps: z
      .array(z.object({ id: slug, releaseId: bytes32 }).loose())
      .refine((apps) => apps.every((a, i) => i === 0 || (apps[i - 1] as { id: string }).id < a.id), {
        message: "apps must be sorted by id and unique",
      }),
    hostnames: hostnamesSchema,
    egressAdditions: z.record(z.string(), z.array(hostPort)).default({}),
    allowedVpcRanges: z.array(z.string()).default([]),
    endpoints: z
      .object({
        keyBroker: url,
        platformApi: url,
        tempoRpc: url,
        relay: url.optional(),
        relayAttest: url.optional(),
      })
      .loose(),
    contracts: z
      .object({ platformRegistry: address, appRegistry: address, deploymentRegistry: address, feeSplitter: address })
      .loose(),
    feeToken: address,
    settlement: settlementSchema,
    relayOwner: address.optional(),
  })
  .loose();

export type SealedConfig = z.infer<typeof sealedConfigSchema>;

/** The hostname Caddy serves a route on (sslip: <route>.<ip-with-dashes>.sslip.io). */
export function routeHostname(config: Pick<SealedConfig, "hostnames">, route: string): string | undefined {
  const h = config.hostnames;
  if (h.scheme === "sslip") return `${route}.${h.ip.replaceAll(".", "-")}.sslip.io`;
  return h.domains[route];
}
