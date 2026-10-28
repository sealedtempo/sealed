// Content-free signed health reports (INTERFACES 10, property P5): app states, egress counters
// from sealed-egress and payment status. Signed by the enclave signer (EIP-191 over CJSON body).
import { type Hex, signCjsonBody } from "@sealed/core";
import type { PlatformClient } from "./evidence.js";
import { localJson, parseEndpoint } from "./http.js";
import type { AppStatus } from "./metering/appHealth.js";

export interface EgressStats {
  since?: string | number;
  allowed: Record<string, number>;
  blocked: Record<string, number>;
}

export type EgressStatsSource = () => Promise<EgressStats | undefined>;

export function httpEgressStats(url: string): EgressStatsSource {
  const u = new URL(url);
  const ep = parseEndpoint(u.origin);
  return async () => {
    try {
      const s = await localJson<EgressStats>(ep, `${u.pathname}${u.search}`, { timeoutMs: 5000 });
      return { since: s.since, allowed: counts(s.allowed), blocked: counts(s.blocked) };
    } catch {
      return undefined;
    }
  };
}

/** Per-destination counters are app-chosen names: only well-formed host:port keys, at most this many (largest first). */
export const MAX_EGRESS_KEYS = 50;
const HOST_PORT_RE = /^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*:[0-9]{1,5}$/;

export function counts(v: unknown): Record<string, number> {
  const entries: [string, number][] = [];
  if (v && typeof v === "object") {
    for (const [k, n] of Object.entries(v as Record<string, unknown>)) {
      if (typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && k.length <= 260 && HOST_PORT_RE.test(k)) entries.push([k, n]);
    }
  }
  entries.sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  return Object.fromEntries(entries.slice(0, MAX_EGRESS_KEYS));
}

export interface HealthInputs {
  at: number;
  apps: Record<string, AppStatus>;
  egress?: EgressStats;
  payments: Record<string, string | number | boolean | null>;
}

export function healthBody(i: HealthInputs) {
  return {
    at: i.at,
    apps: i.apps,
    egress: i.egress
      ? { ...(i.egress.since !== undefined ? { since: i.egress.since } : {}), allowed: counts(i.egress.allowed), blocked: counts(i.egress.blocked) }
      : { allowed: {}, blocked: {} },
    payments: i.payments,
  };
}

export async function sendHealthReport(platform: PlatformClient, deploymentId: Hex, enclaveKey: Hex, inputs: HealthInputs) {
  const body = healthBody(inputs);
  const signature = await signCjsonBody(body, enclaveKey);
  await platform.postHealth({ deploymentId, signature, body });
  return { deploymentId, signature, body };
}
