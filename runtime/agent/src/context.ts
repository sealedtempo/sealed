// The deployment context: measured public config, the booted app-compose and derived ids.
import { readFile } from "node:fs/promises";
import {
  type Address,
  type CJSONValue,
  configHash as computeConfigHash,
  deploymentId as computeDeploymentId,
  type Defaults,
  type FeeSchedule,
  feeScheduleFromDefaults,
  type Hex,
  parseCJSON,
  type SealedConfig,
  sealedConfigSchema,
  stackHash as computeStackHash,
} from "@sealed/core";
import { z } from "zod";

export interface AppMeta {
  id: string;
  releaseId: Hex;
  metering?: { unit: "tokens" | "pages" | "app_hour"; source: "callback" | "heartbeat" };
  healthcheck?: string;
}

export interface DeploymentContext {
  config: SealedConfig;
  /** The config exactly as measured (hash input, sent to the broker and in evidence). */
  configJson: Record<string, CJSONValue>;
  configHash: Hex;
  appCompose: string;
  stackHash: Hex;
  deploymentId: Hex;
  customer: Address;
  releaseIds: Hex[];
  imageId: Hex;
  apps: AppMeta[];
  defaults: Defaults;
  schedule: FeeSchedule;
}

export async function readPublicConfig(path: string): Promise<{ config: SealedConfig; json: Record<string, CJSONValue> }> {
  const json = parseCJSON(await readFile(path, "utf8"));
  if (json === null || typeof json !== "object" || Array.isArray(json)) throw new Error("config must be a JSON object");
  const parsed = sealedConfigSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`invalid public config: ${issue?.path.join(".")}: ${issue?.message}`);
  }
  return { config: parsed.data, json };
}

const appsMetaSchema = z.object({
  schema: z.literal("sealed-agent-apps/v1"),
  apps: z.record(
    z.string(),
    z.object({
      metering: z.object({ unit: z.enum(["tokens", "pages", "app_hour"]), source: z.enum(["callback", "heartbeat"]) }).optional(),
      healthcheck: z.string().url().optional(),
    }),
  ),
});

/** Optional per-app metering and health metadata (rendered by the composer from the manifests). */
export async function readAppsMeta(path: string): Promise<z.infer<typeof appsMetaSchema> | undefined> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  return appsMetaSchema.parse(parseCJSON(text));
}

export function buildContext(input: {
  config: SealedConfig;
  configJson: Record<string, CJSONValue>;
  appCompose: string;
  defaults: Defaults;
  appsMeta?: z.infer<typeof appsMetaSchema>;
}): DeploymentContext {
  const { config } = input;
  const stack = computeStackHash(input.appCompose);
  const apps: AppMeta[] = config.apps.map((a) => ({
    id: a.id,
    releaseId: a.releaseId.toLowerCase() as Hex,
    ...input.appsMeta?.apps[a.id],
  }));
  return {
    config,
    configJson: input.configJson,
    configHash: computeConfigHash(input.configJson),
    appCompose: input.appCompose,
    stackHash: stack,
    deploymentId: computeDeploymentId(config.customer as Address, stack, config.salt as Hex),
    customer: config.customer.toLowerCase() as Address,
    releaseIds: apps.map((a) => a.releaseId),
    imageId: config.imageId.toLowerCase() as Hex,
    apps,
    defaults: input.defaults,
    schedule: feeScheduleFromDefaults(input.defaults),
  };
}
