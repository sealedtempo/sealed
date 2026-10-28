// Payment-needed switch (INTERFACES 14): Caddy's admin API on the unix socket shared only with the
// agent. The agent only ever loads one of the two measured Caddyfiles from app-compose
// (`POST /load`, Content-Type text/caddyfile), so the switch cannot serve anything the customer did
// not approve. Caddy skips a reload when the adapted config is unchanged, so re-applying is cheap and
// also covers a Caddy restart (which comes back with the normal file).
//
// Composer 1.2 makes the admin socket 0660 with group 10001 in a 2770 tmpfs volume owned by 10001:10001,
// which the agent's run-as user reaches directly, so the agent loads the Caddyfiles itself and keeps no
// root process (review ws-int-agent 9). With composer 1.1 the socket is root-only (tmpfs mode 0750) and
// the agent drops root after boot, so the loads go through a small helper process forked while still
// root (caddyHelper.ts) that accepts nothing but the two variant names.
import { type ChildProcess, fork } from "node:child_process";
import { existsSync } from "node:fs";
import { stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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

/** Talks to the admin socket from this process (used when the agent keeps the uid that can reach it). */
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
 * Whether `who` can connect to Caddy's admin socket as sealed-stack/v1 describes it (composer 1.2: write
 * permission on the socket from `adminSocketMode` and `adminSocketOwner`) inside `dir` (search permission). A
 * stack without those facts (composer 1.1, a root-only socket) needs the helper.
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

export function caddyHelperPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const js = join(here, "caddyHelper.js");
  return existsSync(js) ? js : join(here, "caddyHelper.ts");
}

interface HelperReply {
  id: number;
  ok: boolean;
  error?: string;
}

/**
 * The privileged helper as seen from the agent. Start it before dropping privileges; it keeps the
 * root uid and does only `POST /load` of the measured files given at start.
 */
export class HelperCaddySwitch implements CaddySwitch {
  private readonly child: ChildProcess;
  private nextId = 1;
  private readonly pending = new Map<number, { ok: () => void; fail: (e: Error) => void }>();
  private lost?: Error;

  constructor(socket: string, files: CaddyFiles, opts: { onLost?: (err: Error) => void; helperPath?: string } = {}) {
    // execArgv: [] so the helper never inherits the agent's own node flags (an inspector, loaders).
    this.child = fork(opts.helperPath ?? caddyHelperPath(), [], { stdio: ["ignore", "inherit", "inherit", "ipc"], serialization: "json", execArgv: [] });
    this.child.on("message", (m: HelperReply) => {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (m.ok) p.ok();
      else p.fail(new Error(`caddy helper: ${m.error ?? "failed"}`));
    });
    this.child.on("exit", (code, signal) => {
      this.lost = new Error(`caddy helper exited (${code ?? signal})`);
      for (const p of this.pending.values()) p.fail(this.lost);
      this.pending.clear();
      opts.onLost?.(this.lost);
    });
    this.child.send({ init: { socket, normal: files.normal, paymentNeeded: files.paymentNeeded } });
  }

  apply(variant: CaddyVariant): Promise<void> {
    if (this.lost) return Promise.reject(this.lost);
    const id = this.nextId++;
    return new Promise((ok, fail) => {
      this.pending.set(id, { ok, fail });
      this.child.send({ id, variant });
    });
  }

  /** Stops the helper without reporting it as lost. */
  close(): void {
    this.child.removeAllListeners("exit");
    this.lost = new Error("caddy helper closed");
    this.child.kill();
  }
}
