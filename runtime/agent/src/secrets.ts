// Boot step 3 (spec 5.6, INTERFACES 14-15): app secrets as files on tmpfs, the payer key for
// sealed-mpp-payer, then the ready flag. Each owner directory is its own tmpfs volume, mounted into
// that app only; a secret is never written to a directory that is not tmpfs, so it cannot land on
// the container's disk-backed writable layer.
import { mkdir, open, readdir, rename, rm, statfs } from "node:fs/promises";
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

async function prepareDir(layout: SecretsLayout, dir: string): Promise<void> {
  if (!layout.requireTmpfs) {
    await mkdir(dir, { recursive: true, mode: 0o755 });
    return;
  }
  let type: number;
  try {
    type = await (layout.fsType ?? defaultFsType)(dir);
  } catch (err) {
    throw new SecretsTargetError(`${dir} is not a mounted tmpfs (${(err as NodeJS.ErrnoException).code ?? "error"})`);
  }
  if (type !== TMPFS_MAGIC) throw new SecretsTargetError(`${dir} is not on tmpfs (f_type 0x${type.toString(16)}); refusing to write secrets there`);
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

/**
 * Writes /run/sealed/secrets/<owner>/<NAME> for every released secret and removes files that are no
 * longer released. Owners must be apps of the stack or `_gate`. Files are 0444: each directory is
 * mounted read-only into its own app only, and app containers run as arbitrary users.
 */
export async function writeSecrets(layout: SecretsLayout, secrets: Record<string, Record<string, string>>, allowedOwners: ReadonlySet<string>): Promise<void> {
  for (const [owner, values] of Object.entries(secrets)) {
    if (!OWNER_RE.test(owner) || owner === PAYER_DIR || !allowedOwners.has(owner)) throw new Error(`invalid secret owner ${JSON.stringify(owner)}`);
    for (const name of Object.keys(values)) if (!NAME_RE.test(name)) throw new Error(`invalid secret name for ${owner}`);
  }
  for (const [owner, values] of Object.entries(secrets)) {
    if (Object.keys(values).length === 0) continue;
    const dir = join(layout.secretsDir, owner);
    await prepareDir(layout, dir);
    for (const [name, value] of Object.entries(values)) await atomicWrite(join(dir, name), value, 0o444);
    for (const existing of await readdir(dir)) {
      if (!(existing in values)) await rm(join(dir, existing), { force: true });
    }
  }
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
