// Payment-needed switch (INTERFACES 14): Caddy's admin API on the unix socket shared only with the
// agent. The agent only ever loads one of the two measured Caddyfiles from app-compose
// (`POST /load`, Content-Type text/caddyfile), so the switch cannot serve anything the customer did
// not approve. Caddy skips a reload when the adapted config is unchanged, so re-applying is cheap and
// also covers a Caddy restart (which comes back with the normal file).
//
// Caddy creates the socket with mode 0660 in the sealed-caddy-admin tmpfs (owner 10001:10001,
// setgid, brief item 15), so the agent connects to it directly after dropping to 10001:10001.
import { type Endpoint, HttpError, localRequest } from "./http.js";

export type CaddyVariant = "normal" | "payment-needed";

export interface CaddyFiles {
  normal: string;
  paymentNeeded: string;
}

export interface CaddySwitch {
  apply(variant: CaddyVariant): Promise<void>;
}

export async function loadCaddyfile(endpoint: Endpoint, caddyfile: string): Promise<void> {
  const res = await localRequest(endpoint, "/load", { body: caddyfile, headers: { "content-type": "text/caddyfile" }, timeoutMs: 30_000 });
  if (res.status < 200 || res.status >= 300) throw new HttpError(res.status, res.body.slice(0, 1000), "caddy /load");
}

/** Talks to the admin socket from the agent process. */
export class DirectCaddySwitch implements CaddySwitch {
  constructor(
    private readonly endpoint: Endpoint,
    private readonly files: CaddyFiles,
  ) {}
  apply(variant: CaddyVariant): Promise<void> {
    return loadCaddyfile(this.endpoint, variant === "normal" ? this.files.normal : this.files.paymentNeeded);
  }
}
