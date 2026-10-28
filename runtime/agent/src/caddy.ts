// Payment-needed switch through Caddy's admin API on a unix socket shared only with the agent
// (INTERFACES 14). App routes get a static 402 page; the attest route and data stay untouched.
// The original config is saved first so it can be restored exactly.
import { type Endpoint, HttpError, localJson, localRequest } from "./http.js";

export interface CaddyAdmin {
  getConfig(): Promise<unknown>;
  load(config: unknown): Promise<void>;
}

export class SocketCaddyAdmin implements CaddyAdmin {
  constructor(private readonly endpoint: Endpoint) {}
  async getConfig(): Promise<unknown> {
    return localJson(this.endpoint, "/config/", { timeoutMs: 10_000 });
  }
  async load(config: unknown): Promise<void> {
    const res = await localRequest(this.endpoint, "/load", { body: config, timeoutMs: 30_000 });
    if (res.status < 200 || res.status >= 300) throw new HttpError(res.status, res.body.slice(0, 1000), "caddy /load");
  }
}

export const PAYMENT_NEEDED_ID = "sealed-payment-needed";

export const PAYMENT_NEEDED_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Payment needed</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1f2937;line-height:1.5}h1{font-size:1.5rem}</style>
</head><body>
<h1>Payment needed</h1>
<p>This deployment could not pay its usage fees for longer than the grace period, so its apps are paused.</p>
<p>Your data is intact and stays on your encrypted disk. Apps come back automatically after the next successful payment.</p>
<p>If you own this deployment, check the spending limit and the balance of your account in the Sealed console.</p>
</body></html>
`;

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

function routeHosts(route: Json): string[] {
  const match = Array.isArray(route.match) ? route.match : [];
  return match.flatMap((m) => (isObj(m) && Array.isArray(m.host) ? (m.host as unknown[]).filter((h): h is string => typeof h === "string") : []));
}

/** True when the config already serves the payment-needed page. */
export function isPaymentNeededConfig(config: unknown): boolean {
  return JSON.stringify(config ?? null).includes(`"@id":"${PAYMENT_NEEDED_ID}`);
}

/**
 * Returns a copy of the Caddy JSON config where every top-level HTTP route whose host matcher
 * names one of `appHosts` responds with the payment-needed page. Routes for other hosts
 * (attest) are left as they are.
 */
export function paymentNeededConfig(config: unknown, appHosts: string[]): unknown {
  const copy = structuredClone(config) as Json;
  const hosts = new Set(appHosts.map((h) => h.toLowerCase()));
  const servers = (copy.apps as Json | undefined)?.http as Json | undefined;
  const serverMap = isObj(servers?.servers) ? (servers.servers as Json) : {};
  let n = 0;
  for (const server of Object.values(serverMap)) {
    if (!isObj(server) || !Array.isArray(server.routes)) continue;
    server.routes = server.routes.map((route: unknown) => {
      if (!isObj(route)) return route;
      const rh = routeHosts(route).map((h) => h.toLowerCase());
      if (!rh.some((h) => hosts.has(h))) return route;
      return {
        "@id": `${PAYMENT_NEEDED_ID}-${n++}`,
        match: route.match,
        handle: [
          {
            handler: "static_response",
            status_code: 402,
            headers: { "Content-Type": ["text/html; charset=utf-8"], "Cache-Control": ["no-store"] },
            body: PAYMENT_NEEDED_HTML,
          },
        ],
        terminal: true,
      };
    });
  }
  return copy;
}

export interface GateStore {
  getOriginal(): unknown;
  setOriginal(config: unknown): Promise<void>;
}

export class PaymentGate {
  constructor(
    private readonly admin: CaddyAdmin,
    private readonly appHosts: string[],
    private readonly store: GateStore,
  ) {}

  /** Switches app routes to the payment-needed page (idempotent; re-applies after a Caddy restart). */
  async enable(): Promise<void> {
    const current = await this.admin.getConfig();
    if (isPaymentNeededConfig(current)) return;
    await this.store.setOriginal(current);
    await this.admin.load(paymentNeededConfig(current, this.appHosts));
  }

  /** Restores the saved config. */
  async disable(): Promise<void> {
    const original = this.store.getOriginal();
    const current = await this.admin.getConfig();
    if (!isPaymentNeededConfig(current)) {
      // Caddy restarted from its measured Caddyfile in the meantime: nothing to restore.
      if (original !== undefined) await this.store.setOriginal(undefined);
      return;
    }
    if (original === undefined) throw new Error("no saved Caddy config to restore");
    await this.admin.load(original);
    await this.store.setOriginal(undefined);
  }
}
