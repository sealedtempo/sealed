// Boot step 3 (spec 5.6, INTERFACES 14-15): app secrets as files on tmpfs, the payer key for
// sealed-mpp-payer, then the ready flag. From composer 1.2 (D-042) the agent binds the host's
// /run/sealed/secrets (on the CVM's /run tmpfs) and creates the owner directories itself; each app
// service binds exactly the files it declares. A secret is never written to a directory that is not
// tmpfs, so it cannot land on a disk-backed layer.
import { lstat, mkdir, open, readdir, rename, rm, statfs } from "node:fs/promises";
import { join } from "node:path";

export const PAYER_DIR = "sealed-mpp-payer";
export const READY_MARKER = "ok";
export const TMPFS_MAGIC = 0x01021994;
const OWNER_RE = /^(_gate|[a-z][a-z0-9-]*)$/;
const NAME_RE = /^[A-Z][A-Z0-9_]*$/;

export interface SecretsLayout {
  secretsDir: string;
  readyDir: string;
  /** Production: every secrets directory must already be a tmpfs mount. Dev sim mode creates plain directories. */
  requireTmpfs: boolean;
  /** statfs f_type of a path (tests substitute it). */
  fsType?: (path: string) => Promise<number>;
}

export class SecretsTargetError extends Error {}

const defaultFsType = async (path: string) => (await statfs(path)).type;

async function requireTmpfs(layout: SecretsLayout, dir: string): Promise<void> {
  let type: number;
  try {
    type = await (layout.fsType ?? defaultFsType)(dir);
  } catch (err) {
    throw new SecretsTargetError(`${dir} is not a mounted tmpfs (${(err as NodeJS.ErrnoException).code ?? "error"})`);
  }
  if (type !== TMPFS_MAGIC) throw new SecretsTargetError(`${dir} is not on tmpfs (f_type 0x${type.toString(16)}); refusing to write secrets there`);
}

/**
 * Makes `<secretsDir>/<owner>` ready for secret files. An existing owner directory must be a real
 * directory (not a symlink) on tmpfs. A missing one is created (0755) only when the secrets root is
 * itself on tmpfs (composer 1.2 binds the host's /run/sealed/secrets), and is checked again after.
 */
async function prepareDir(layout: SecretsLayout, dir: string): Promise<void> {
  if (!layout.requireTmpfs) {
    await mkdir(dir, { recursive: true, mode: 0o755 });
    return;
  }
  let exists = true;
  try {
    const st = await lstat(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new SecretsTargetError(`${dir} is not a directory; refusing to write secrets there`);
  } catch (err) {
    if (err instanceof SecretsTargetError || (err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    exists = false;
  }
  if (!exists) {
    await requireTmpfs(layout, layout.secretsDir);
    await mkdir(dir, { mode: 0o755 });
  }
  await requireTmpfs(layout, dir);
}

/** Writes via a temp file in the same directory and renames it into place. */
async function atomicWrite(path: string, data: string, mode: number): Promise<void> {
  const tmp = `${path}.tmp-${process.pid}`;
  const fh = await open(tmp, "w", mode);
  try {
    await fh.writeFile(data);
    await fh.chmod(mode);
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
}

export interface WriteSecretsOptions {
  /**
   * owner -> the exact files to write (sealed-stack/v1 `secretFiles`, composer 1.2). When set, only
   * these files are written: released values, empty placeholders for optional secrets that were not
   * released. Released secrets outside it are not written, since no container binds them (the gate
   * hash stays in the agent's memory).
   */
  files?: ReadonlyMap<string, ReadonlySet<string>>;
  /**
   * owner -> names that some service mounts as a single file (composer 1.2, D-042). Docker cannot
   * start a container whose mount source is missing, so each of these must exist.
   */
  individually?: ReadonlyMap<string, ReadonlySet<string>>;
  /** Whether `<owner>/<name>` is an optional secret (sealed-stack/v1 apps[].secrets). */
  isOptional?: (owner: string, name: string) => boolean;
  /**
   * Owners whose secrets directory the compose mounts into the agent. Released secrets of any other
   * owner are validated but not written: no container could read them.
   */
  onDisk?: ReadonlySet<string>;
}

export interface WriteSecretsResult {
  /** `<owner>/<NAME>` of optional secrets that were not released and are mounted alone: written empty. */
  placeholders: string[];
  /** `<owner>/<NAME>` of required secrets that are mounted alone but were not released. */
  missing: string[];
  /** Owners with released secrets that were not written because the agent has no directory for them. */
  skipped: string[];
}

/**
 * Writes /run/sealed/secrets/<owner>/<NAME> for every released secret and removes files that are no
 * longer released. Owners must be apps of the stack or `_gate`. Files are 0444: each owner directory
 * is a tmpfs mounted read-only into that owner's services only (or, from composer 1.2, one file per
 * declared secret), and app containers run as arbitrary users. An optional secret that was not
 * released but is mounted as a single file gets an empty placeholder so its service can start; a
 * missing required one is reported, and that service fails to start rather than run without it.
 */
export async function writeSecrets(
  layout: SecretsLayout,
  secrets: Record<string, Record<string, string>>,
  allowedOwners: ReadonlySet<string>,
  opts: WriteSecretsOptions = {},
): Promise<WriteSecretsResult> {
  const individually = opts.files ?? opts.individually ?? new Map<string, ReadonlySet<string>>();
  const valid = (owner: string) => OWNER_RE.test(owner) && owner !== PAYER_DIR && allowedOwners.has(owner);
  for (const [owner, values] of Object.entries(secrets)) {
    if (!valid(owner)) throw new Error(`invalid secret owner ${JSON.stringify(owner)}`);
    for (const name of Object.keys(values)) if (!NAME_RE.test(name)) throw new Error(`invalid secret name for ${owner}`);
  }
  const result: WriteSecretsResult = { placeholders: [], missing: [], skipped: [] };
  const owners = new Set([...Object.keys(secrets), ...[...individually.keys()].filter((o) => o !== PAYER_DIR)]);
  for (const owner of [...owners].sort()) {
    if (!valid(owner)) throw new Error(`invalid secret owner ${JSON.stringify(owner)}`);
    if ((opts.onDisk && !opts.onDisk.has(owner)) || (opts.files && !opts.files.has(owner))) {
      if (Object.keys(secrets[owner] ?? {}).length > 0) result.skipped.push(owner);
      continue;
    }
    const wanted = opts.files?.get(owner);
    const values = Object.fromEntries(Object.entries(secrets[owner] ?? {}).filter(([name]) => !wanted || wanted.has(name)));
    if (wanted && Object.keys(values).length < Object.keys(secrets[owner] ?? {}).length) result.skipped.push(owner);
    const keep = new Set(Object.keys(values));
    const placeholders: string[] = [];
    for (const name of [...(individually.get(owner) ?? [])].sort()) {
      if (keep.has(name)) continue;
      if (!NAME_RE.test(name)) throw new Error(`invalid secret name for ${owner}`);
      if (opts.isOptional?.(owner, name)) placeholders.push(name);
      else result.missing.push(`${owner}/${name}`);
    }
    if (keep.size === 0 && placeholders.length === 0) continue;
    const dir = join(layout.secretsDir, owner);
    await prepareDir(layout, dir);
    for (const [name, value] of Object.entries(values)) await atomicWrite(join(dir, name), value, 0o444);
    for (const name of placeholders) {
      await atomicWrite(join(dir, name), "", 0o444);
      keep.add(name);
      result.placeholders.push(`${owner}/${name}`);
    }
    for (const existing of await readdir(dir)) {
      if (!keep.has(existing)) await rm(join(dir, existing), { force: true });
    }
  }
  return result;
}

/** /run/sealed/secrets/sealed-mpp-payer/{ENCLAVE_KEY,SPEND_LIMIT_PER_DAY} (INTERFACES 15). Only for stacks with the payer. */
export async function writePayerSecrets(layout: SecretsLayout, enclaveKey: string, spendLimitPerDay: string): Promise<void> {
  const dir = join(layout.secretsDir, PAYER_DIR);
  await prepareDir(layout, dir);
  await atomicWrite(join(dir, "ENCLAVE_KEY"), enclaveKey, 0o444);
  await atomicWrite(join(dir, "SPEND_LIMIT_PER_DAY"), spendLimitPerDay, 0o444);
}

/** Creates `<readyDir>/ok`, which envexec waits for before starting any app (the shared sealed-ready volume). */
export async function writeReadyFlag(layout: SecretsLayout, at: number): Promise<void> {
  await mkdir(layout.readyDir, { recursive: true, mode: 0o755 });
  await atomicWrite(join(layout.readyDir, READY_MARKER), `${at}\n`, 0o444);
}
