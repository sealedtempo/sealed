// Per-app volume directories on the data disk. The composer turns each named volume into a bind
// mount of /mnt/sealed-data/<appId>/<volume> (host path); the agent sees that tree at its data mount
// and creates the directories, owned by the service's user, before apps start.
import { chown, mkdir } from "node:fs/promises";
import { isAbsolute, join, normalize, relative } from "node:path";
import { parseCJSON } from "@sealed/core";

export interface VolumeDir {
  path: string;
  uid?: number;
  gid?: number;
}

interface ComposeService {
  user?: string;
  volumes?: (string | { type?: string; source?: string })[];
}

function parseUser(user: string | undefined): { uid?: number; gid?: number } {
  const m = /^(\d+)(?::(\d+))?$/.exec(user ?? "");
  if (!m) return {};
  return { uid: Number(m[1]), gid: m[2] !== undefined ? Number(m[2]) : Number(m[1]) };
}

/**
 * Bind-mount sources under `composeRoot` (the host data root named in the compose), from the
 * app-compose's docker_compose_file, as paths under `mountAt` (where the agent sees that root).
 */
export function volumeDirsFromAppCompose(appCompose: string, composeRoot: string, mountAt = composeRoot): VolumeDir[] {
  const outer = JSON.parse(appCompose) as { docker_compose_file?: unknown };
  if (typeof outer.docker_compose_file !== "string") return [];
  let compose: { services?: Record<string, ComposeService> };
  try {
    compose = parseCJSON(outer.docker_compose_file) as typeof compose;
  } catch {
    return [];
  }
  const root = normalize(composeRoot);
  const dirs = new Map<string, VolumeDir>();
  for (const svc of Object.values(compose.services ?? {})) {
    const owner = parseUser(svc.user);
    for (const v of svc.volumes ?? []) {
      const source = typeof v === "string" ? v.split(":")[0] : v.type === "bind" || v.type === undefined ? v.source : undefined;
      if (!source || !isAbsolute(source)) continue;
      const rel = relative(root, normalize(source));
      if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) continue;
      const path = join(mountAt, rel);
      const prev = dirs.get(path);
      dirs.set(path, { path, ...(prev?.uid !== undefined ? { uid: prev.uid, gid: prev.gid } : owner) });
    }
  }
  return [...dirs.values()].sort((a, b) => a.path.localeCompare(b.path));
}

export async function createVolumeDirs(dirs: VolumeDir[], opts: { chown?: boolean } = {}): Promise<void> {
  for (const d of dirs) {
    await mkdir(d.path, { recursive: true, mode: 0o755 });
    if (opts.chown !== false && d.uid !== undefined && process.getuid?.() === 0) {
      await chown(d.path, d.uid, d.gid ?? d.uid);
    }
  }
}
