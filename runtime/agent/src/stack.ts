// What the composer tells the agent about the stack (sealed-stack/v1, INTERFACES 14) and the other
// measured inline configs. All of them are read from the booted app-compose.json, whose sha256 is the
// stackHash bound in every quote, so nothing here comes from an unmeasured file.
import { z } from "zod";

/** Inline compose `configs` the composer writes (runtime/composer, composedoc.go). */
export const COMPOSE_CONFIGS = {
  config: "sealed-config",
  stack: "sealed-stack",
  caddyfile: "sealed-caddyfile",
  caddyfilePaymentNeeded: "sealed-caddyfile-payment-needed",
} as const;

/** Host path the composer binds app volumes from; the agent sees it at SEALED_DATA_DIR. */
export const COMPOSE_DATA_ROOT = "/mnt/sealed-data";
export const PAYER_SERVICE = "sealed-mpp-payer";
export const CADDY_SERVICE = "caddy";

const ipv4 = z.string().regex(/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/, "IPv4 address");
const hex32 = z.string().regex(/^0x[0-9a-f]{64}$/);

const stackAppSchema = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9-]*$/),
    appId: hex32,
    releaseId: hex32,
    version: z.string(),
    primaryService: z.string(),
    services: z.array(z.object({ name: z.string(), ip: ipv4, primary: z.boolean() })).min(1),
    secrets: z.array(z.object({ name: z.string(), optional: z.boolean() })),
    metering: z.object({ unit: z.enum(["tokens", "pages", "app_hour"]), source: z.enum(["callback", "heartbeat"]) }),
    healthcheck: z.object({ service: z.string(), port: z.number().int().min(0).max(65535), path: z.string() }),
  })
  .loose();

export const stackInfoSchema = z
  .object({
    schema: z.literal("sealed-stack/v1"),
    composerVersion: z.string(),
    apps: z.array(stackAppSchema),
    sidecars: z.record(z.string(), ipv4),
    attestHost: z.string().min(1),
    caddy: z.object({ adminSocket: z.string(), caddyfile: z.string(), caddyfilePaymentNeeded: z.string() }).loose(),
  })
  .loose();

export type StackInfo = z.infer<typeof stackInfoSchema>;
export type StackApp = z.infer<typeof stackAppSchema>;

/**
 * The inline `configs.<name>.content` strings of the composed document. The composer doubles every
 * `$` so docker compose interpolation reproduces the measured text; this undoes that.
 */
export function measuredConfigs(appCompose: string): Record<string, string> {
  const outer = JSON.parse(appCompose) as { docker_compose_file?: unknown };
  if (typeof outer.docker_compose_file !== "string") throw new Error("app-compose.json has no docker_compose_file");
  const compose = JSON.parse(outer.docker_compose_file) as { configs?: Record<string, { content?: unknown }> };
  const out: Record<string, string> = {};
  for (const [name, c] of Object.entries(compose.configs ?? {})) {
    if (typeof c?.content === "string") out[name] = c.content.replaceAll("$$", "$");
  }
  return out;
}

export function requireMeasured(configs: Record<string, string>, name: string): string {
  const v = configs[name];
  if (v === undefined) throw new Error(`app-compose.json has no measured config ${name}`);
  return v;
}

export function parseStackInfo(text: string): StackInfo {
  const parsed = stackInfoSchema.safeParse(JSON.parse(text));
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`invalid sealed-stack/v1: ${issue?.path.join(".")}: ${issue?.message}`);
  }
  return parsed.data;
}

/** The agent's probe URL for an app's manifest healthcheck: the service's fixed IP, never a DNS name. */
export function healthcheckUrl(app: StackApp): string | undefined {
  const { service, port, path } = app.healthcheck;
  if (port === 0) return undefined;
  const svc = app.services.find((s) => s.name === service);
  if (!svc) throw new Error(`stack: ${app.id} healthcheck names unknown service ${service}`);
  const p = path.startsWith("/") ? path : `/${path}`;
  return `http://${svc.ip}:${port}${p}`;
}

/** Normalizes a socket peer address ("::ffff:172.30.0.16" -> "172.30.0.16"). */
export function normalizePeer(address: string | undefined): string {
  if (!address) return "";
  return address.startsWith("::ffff:") ? address.slice(7) : address;
}
