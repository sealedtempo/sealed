// After the steps that need root (LUKS, mount, volume ownership, tmpfs secrets), the agent drops
// to an unprivileged user for its long-running work (API, metering, payments).
import { chown, readdir } from "node:fs/promises";
import { join } from "node:path";
import type { Logger } from "./log.js";

export interface RunAs {
  uid: number;
  gid: number;
}

export function parseRunAs(spec: string | undefined): RunAs | undefined {
  if (!spec) return undefined;
  const m = /^(\d+)(?::(\d+))?$/.exec(spec.trim());
  if (!m) throw new Error(`SEALED_RUN_AS must be uid[:gid], got ${JSON.stringify(spec)}`);
  const uid = Number(m[1]);
  if (uid === 0) throw new Error("SEALED_RUN_AS must not be root");
  return { uid, gid: m[2] !== undefined ? Number(m[2]) : uid };
}

async function chownTree(path: string, who: RunAs): Promise<void> {
  await chown(path, who.uid, who.gid);
  for (const entry of await readdir(path, { withFileTypes: true }).catch(() => [])) {
    const p = join(path, entry.name);
    if (entry.isDirectory()) await chownTree(p, who);
    else await chown(p, who.uid, who.gid);
  }
}

/** Hands `ownedDirs` to the target user and switches uid/gid. No-op when not running as root. */
export async function dropPrivileges(who: RunAs | undefined, ownedDirs: string[], log: Logger): Promise<boolean> {
  if (!who || process.getuid?.() !== 0) return false;
  for (const d of ownedDirs) await chownTree(d, who);
  process.setgroups?.([]);
  process.setgid?.(who.gid);
  process.setuid?.(who.uid);
  log.info("dropped root privileges", { uid: who.uid, gid: who.gid });
  return true;
}
