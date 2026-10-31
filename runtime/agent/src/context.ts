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
  parseSealedConfig,
  type SealedConfig,
  SealedConfigError,
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
  /** Every fixed IP of the app's services (on each network they join): the only callers allowed to post its usage. */
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

export async function readPublicConfig(path: string, o: { devSim?: boolean } = {}): Promise<{ config: SealedConfig; json: Record<string, CJSONValue> }> {
  return parsePublicConfig(await readFile(path, "utf8"), o);
}

/**
 * The public config by the composer's rules (@sealed/core parseSealedConfig, the twin of composer.ParseConfig): the
 * agent accepts exactly the configs the composer composes. With devSim (SEALED_DEV_SIM=1, local tests only) the
 * endpoints may be plain http on loopback.
 */
export function parsePublicConfig(text: string, o: { devSim?: boolean } = {}): { config: SealedConfig; json: Record<string, CJSONValue> } {
  let config: SealedConfig;
  try {
    config = parseSealedConfig(text, { devSim: o.devSim === true });
  } catch (err) {
    if (err instanceof SealedConfigError) throw new Error(`invalid public config: ${err.message}`);
    throw err;
  }
  return { config, json: parseCJSON(text) as Record<string, CJSONValue> };
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/**
 * Review C-4 (the agent's side): over plain http the agent cannot tell who answers, so anyone on the path could
 * hand it chosen secrets for its ephemeral HPKE key (a known disk key on a fresh deployment) or read the relay's
 * traffic. Every endpoint must be https, except a loopback endpoint (local tests) and dev sim mode. parsePublicConfig
 * already refuses http and loopback endpoints outside dev sim mode, as the composer does; this stays as a second check.
 */
export function requireHttpsEndpoints(endpoints: Record<string, unknown>, devSim: boolean): void {
  if (devSim) return;
  for (const [name, raw] of Object.entries(endpoints)) {
    if (typeof raw !== "string") continue;
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw new Error(`config endpoints.${name} is not a URL`);
    }
    if (u.protocol === "https:") continue;
    if (u.protocol === "http:" && LOOPBACK_HOSTS.has(u.hostname)) continue;
    throw new Error(`config endpoints.${name} must be https (got ${u.protocol}//${u.host})`);
  }
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
    return { id: a.id, appId, releaseId, metering: s.metering, healthcheck, serviceIps: [...new Set(s.services.flatMap((x) => x.ips))] };
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
