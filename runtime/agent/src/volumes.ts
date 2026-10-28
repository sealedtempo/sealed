// Per-app volume directories on the data disk (brief item 11). The composer turns each named volume
// into a bind mount of /mnt/sealed-data/<appId>/<volume> with create_host_path: false, so Docker
// never creates them: the agent does, after unlocking the disk and before the ready flag opens the
// gate envexec waits for. sealed-stack/v1 names every bind source (`dataDirs`) and the owner a
// manifest declares for a volume (`apps[].volumes[].owner`, from `x-sealed-owner`). The agent sees
// the data root at SEALED_DATA_DIR.
import { chown as fsChown, lstat, mkdir } from "node:fs/promises";
import { isAbsolute, join, normalize, relative } from "node:path";
import { parseCJSON } from "@sealed/core";
import { COMPOSE_DATA_ROOT, type StackInfo } from "./stack.js";

export interface VolumeDir {
  path: string;
  uid?: number;
  gid?: number;
  /**
   * The owner is declared by the manifest (`x-sealed-owner`), so it is enforced on every boot. An
   * owner guessed from a service's `user` is applied only when the directory is created, so an app
   * that hands its directory to another user (postgres does) keeps it.
   */
  declared?: boolean;
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

/** `rel` of a path strictly below `root`, or undefined for the root itself, escapes and relative paths. */
function below(root: string, path: string): string | undefined {
  if (!isAbsolute(path)) return undefined;
  const rel = relative(normalize(root), normalize(path));
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return undefined;
  return rel;
}

/**
 * Bind-mount sources under `composeRoot` (the host data root named in the compose), from the
 * app-compose's docker_compose_file, as paths under `mountAt` (where the agent sees that root). The
 * owner is a guess from the first service with a numeric `user` that mounts the directory.
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
  const dirs = new Map<string, VolumeDir>();
  for (const svc of Object.values(compose.services ?? {})) {
    const owner = parseUser(svc.user);
    for (const v of svc.volumes ?? []) {
      const source = typeof v === "string" ? v.split(":")[0] : v.type === "bind" || v.type === undefined ? v.source : undefined;
      const rel = source ? below(composeRoot, source) : undefined;
      if (rel === undefined) continue;
      const path = join(mountAt, rel);
      const prev = dirs.get(path);
      dirs.set(path, { path, ...(prev?.uid !== undefined ? { uid: prev.uid, gid: prev.gid } : owner) });
    }
  }
  return [...dirs.values()].sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Every data directory the stack binds: the compose's bind sources plus sealed-stack/v1 `dataDirs`,
 * with the owners the manifests declare. Paths outside the data root are refused.
 */
export function volumeDirsFromStack(stack: StackInfo, appCompose: string, mountAt: string): VolumeDir[] {
  const root = stack.dataRoot ?? COMPOSE_DATA_ROOT;
  const dirs = new Map<string, VolumeDir>();
  for (const d of volumeDirsFromAppCompose(appCompose, root, mountAt)) dirs.set(d.path, d);
  for (const p of stack.dataDirs ?? []) {
    const rel = below(root, p);
    if (rel === undefined) throw new Error(`sealed-stack dataDirs entry ${p} is not below ${root}`);
    const path = join(mountAt, rel);
    if (!dirs.has(path)) dirs.set(path, { path });
  }
  for (const app of stack.apps) {
    for (const v of app.volumes) {
      const rel = below(root, v.path);
      if (rel === undefined || !rel.startsWith(`${app.id}/`)) throw new Error(`sealed-stack volume ${app.id}/${v.name} has path ${v.path} outside ${root}/${app.id}`);
      if (!v.owner) continue;
      const [uid, gid] = v.owner.split(":").map(Number) as [number, number];
      const path = join(mountAt, rel);
      dirs.set(path, { path, uid, gid, declared: true });
    }
  }
  return [...dirs.values()].sort((a, b) => a.path.localeCompare(b.path));
}

export interface CreateVolumeDirsOptions {
  /** Set false to never chown (default: chown when running as root). */
  chown?: boolean;
  /** chown implementation (tests record calls; production uses fs.chown when root). */
  chownFn?: (path: string, uid: number, gid: number) => Promise<void>;
}

/** Creates the directories and applies their owners. A symlink or a non-directory in their place is an error. */
export async function createVolumeDirs(dirs: VolumeDir[], opts: CreateVolumeDirsOptions = {}): Promise<void> {
  const chownFn = opts.chownFn ?? (process.getuid?.() === 0 ? fsChown : undefined);
  for (const d of dirs) {
    let existed = false;
    try {
      const st = await lstat(d.path);
      if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${d.path} exists and is not a directory`);
      existed = true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    if (!existed) await mkdir(d.path, { recursive: true, mode: 0o755 });
    if (opts.chown === false || !chownFn || d.uid === undefined) continue;
    if (d.declared || !existed) await chownFn(d.path, d.uid, d.gid ?? d.uid);
  }
}
