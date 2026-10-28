// Payment-needed switch (INTERFACES 14): Caddy's admin API on the unix socket shared only with the
// agent. The agent only ever loads one of the two measured Caddyfiles from app-compose
// (`POST /load`, Content-Type text/caddyfile), so the switch cannot serve anything the customer did
// not approve. Caddy skips a reload when the adapted config is unchanged, so re-applying is cheap and
// also covers a Caddy restart (which comes back with the normal file).
//
// Caddy creates the socket with mode 0660 in the sealed-caddy-admin tmpfs (owner 10001:10001,
// setgid 2770, brief item 15), so the agent connects to it directly after dropping to 10001:10001 and
// keeps no root process (review ws-int-agent 9). A stack whose socket the run-as user cannot reach
// (composer 1.1 made it root-only) fails the boot instead of getting a root helper.
import { stat } from "node:fs/promises";
import { dirname } from "node:path";
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

/** Who a process runs as after dropping root (setgroups([]): no supplementary groups). */
export interface RunAsIds {
  uid: number;
  gid: number;
}

interface Perm {
  uid: number;
  gid: number;
  mode: number;
}

/** Whether `who` holds permission `bits` (r=4, w=2, x=1) on a file with this owner and mode. */
function allowed(who: RunAsIds, p: Perm, bits: number): boolean {
  if (who.uid === p.uid) return ((p.mode >> 6) & bits) === bits;
  if (who.gid === p.gid) return ((p.mode >> 3) & bits) === bits;
  return (p.mode & bits) === bits;
}

/**
 * Whether `who` can connect to Caddy's admin socket as sealed-stack/v1 describes it (composer 1.2 and later:
 * write permission on the socket from `adminSocketMode` and `adminSocketOwner`) inside `dir` (search
 * permission). A stack without those facts (composer 1.1, a root-only socket) is not reachable.
 */
export function canReachAdminSocket(who: RunAsIds, socket: { adminSocketMode?: string; adminSocketOwner?: string }, dir: Perm | undefined): boolean {
  if (!socket.adminSocketMode || !socket.adminSocketOwner || !dir) return false;
  const [uid, gid] = socket.adminSocketOwner.split(":").map(Number) as [number, number];
  return allowed(who, { uid, gid, mode: Number.parseInt(socket.adminSocketMode, 8) }, 2) && allowed(who, dir, 1);
}

/** canReachAdminSocket with the socket directory as it is on disk now (it is a volume, so it exists before Caddy starts). */
export async function adminSocketReachable(who: RunAsIds, socketPath: string, socket: { adminSocketMode?: string; adminSocketOwner?: string }): Promise<boolean> {
  const dir = await stat(dirname(socketPath)).then(
    (st) => ({ uid: st.uid, gid: st.gid, mode: st.mode & 0o7777 }),
    () => undefined,
  );
  return canReachAdminSocket(who, socket, dir);
}
