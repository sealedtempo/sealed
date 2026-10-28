// The deployment context: measured public config, the booted app-compose, the composer's stack
// facts and the ids derived from them.
import { readFile } from "node:fs/promises";
import {
  type Address,
  appId as computeAppId,
  canonicalize,
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
import {
  CADDY_SERVICE,
  COMPOSE_CONFIGS,
  healthcheckUrl,
  measuredConfigs,
  PAYER_SERVICE,
  parseStackInfo,
  requireMeasured,
  type StackInfo,
} from "./stack.js";

export interface AppMeta {
  id: string;
  appId: Hex;
  releaseId: Hex;
  metering: { unit: "tokens" | "pages" | "app_hour"; source: "callback" | "heartbeat" };
  /** http://<service ip>:<port><path>; undefined when the manifest names no reachable port. */
  healthcheck?: string;
  /** Fixed apps-network IPs of the app's services: the only callers allowed to post its usage. */
  serviceIps: string[];
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
  stack: StackInfo;
  /** The two measured Caddyfiles the payment-needed switch loads. */
  caddyfiles: { normal: string; paymentNeeded: string };
  caddyIp: string;
  /** sealed-mpp-payer's IP; undefined when the stack has no payer (no llm-gateway). */
  payerIp?: string;
  defaults: Defaults;
  schedule: FeeSchedule;
}

export async function readPublicConfig(path: string): Promise<{ config: SealedConfig; json: Record<string, CJSONValue> }> {
  return parsePublicConfig(await readFile(path, "utf8"));
}

export function parsePublicConfig(text: string): { config: SealedConfig; json: Record<string, CJSONValue> } {
  const json = parseCJSON(text);
  if (json === null || typeof json !== "object" || Array.isArray(json)) throw new Error("config must be a JSON object");
  const parsed = sealedConfigSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`invalid public config: ${issue?.path.join(".")}: ${issue?.message}`);
  }
  return { config: parsed.data, json };
}

/** Optional cross-check: a file the composer mounts must hold exactly the measured bytes. */
export async function checkMountedCopy(path: string | undefined, measured: string, what: string): Promise<void> {
  if (!path) return;
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (text !== measured) throw new Error(`${what} at ${path} differs from the measured copy in app-compose.json`);
}

export function buildContext(input: {
  config: SealedConfig;
  configJson: Record<string, CJSONValue>;
  appCompose: string;
  defaults: Defaults;
}): DeploymentContext {
  const { config } = input;
  const measured = measuredConfigs(input.appCompose);
  if (canonicalize(parseCJSON(requireMeasured(measured, COMPOSE_CONFIGS.config))) !== canonicalize(input.configJson)) {
    throw new Error("the public config file differs from the measured sealed-config in app-compose.json");
  }
  const stack = parseStackInfo(requireMeasured(measured, COMPOSE_CONFIGS.stack));
  if (stack.apps.map((a) => a.id).join(",") !== config.apps.map((a) => a.id).join(",")) {
    throw new Error("sealed-stack apps differ from the config apps");
  }
  const apps: AppMeta[] = config.apps.map((a, i) => {
    const s = stack.apps[i] as StackInfo["apps"][number];
    const releaseId = a.releaseId.toLowerCase() as Hex;
    const appId = computeAppId(a.id);
    if (s.releaseId !== releaseId || s.appId !== appId) throw new Error(`sealed-stack ids for ${a.id} differ from the config`);
    const healthcheck = healthcheckUrl(s);
    if (s.metering.source === "heartbeat" && !healthcheck) throw new Error(`${a.id} meters by heartbeat but has no healthcheck port`);
    return { id: a.id, appId, releaseId, metering: s.metering, healthcheck, serviceIps: s.services.map((x) => x.ip) };
  });
  const caddyIp = stack.sidecars[CADDY_SERVICE];
  if (!caddyIp) throw new Error("sealed-stack has no caddy sidecar");
  const stackHash = computeStackHash(input.appCompose);
  return {
    config,
    configJson: input.configJson,
    configHash: computeConfigHash(input.configJson),
    appCompose: input.appCompose,
    stackHash,
    deploymentId: computeDeploymentId(config.customer as Address, stackHash, config.salt as Hex),
    customer: config.customer.toLowerCase() as Address,
    releaseIds: apps.map((a) => a.releaseId),
    imageId: config.imageId.toLowerCase() as Hex,
    apps,
    stack,
    caddyfiles: {
      normal: requireMeasured(measured, COMPOSE_CONFIGS.caddyfile),
      paymentNeeded: requireMeasured(measured, COMPOSE_CONFIGS.caddyfilePaymentNeeded),
    },
    caddyIp,
    payerIp: stack.sidecars[PAYER_SERVICE],
    defaults: input.defaults,
    schedule: feeScheduleFromDefaults(input.defaults),
  };
}
