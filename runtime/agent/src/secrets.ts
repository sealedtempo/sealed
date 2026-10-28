// Boot step 3 (spec 5.6, INTERFACES 14-15): app secrets as files on tmpfs, the payer key for
// sealed-mpp-payer, then the ready flag. Each app directory only ever holds that app's secrets.
import { mkdir, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const PAYER_DIR = "sealed-mpp-payer";
const OWNER_RE = /^(_gate|[a-z][a-z0-9-]*)$/;
const NAME_RE = /^[A-Z][A-Z0-9_]*$/;

export interface SecretsLayout {
  secretsDir: string;
  readyFile: string;
}

async function atomicWrite(path: string, data: string, mode: number): Promise<void> {
  const tmp = `${path}.tmp-${process.pid}`;
  await writeFile(tmp, data, { mode });
  await rename(tmp, path);
}

/**
 * Writes /run/sealed/secrets/<app>/<NAME> for every released secret and removes files that are no
 * longer released. Files are 0444: each app sees only its own directory (a separate read-only
 * mount), and app containers run as arbitrary users.
 */
export async function writeSecrets(layout: SecretsLayout, secrets: Record<string, Record<string, string>>): Promise<void> {
  await mkdir(layout.secretsDir, { recursive: true, mode: 0o755 });
  for (const [owner, values] of Object.entries(secrets)) {
    if (!OWNER_RE.test(owner) || owner === PAYER_DIR) throw new Error(`invalid secret owner ${JSON.stringify(owner)}`);
    const dir = join(layout.secretsDir, owner);
    await mkdir(dir, { recursive: true, mode: 0o755 });
    for (const [name, value] of Object.entries(values)) {
      if (!NAME_RE.test(name)) throw new Error(`invalid secret name for ${owner}`);
      await atomicWrite(join(dir, name), value, 0o444);
    }
    for (const existing of await readdir(dir)) {
      if (!(existing in values)) await rm(join(dir, existing), { force: true });
    }
  }
}

/** /run/sealed/secrets/sealed-mpp-payer/{ENCLAVE_KEY,SPEND_LIMIT_PER_DAY} (INTERFACES 15). */
export async function writePayerSecrets(layout: SecretsLayout, enclaveKey: string, spendLimitPerDay: string): Promise<void> {
  const dir = join(layout.secretsDir, PAYER_DIR);
  await mkdir(dir, { recursive: true, mode: 0o755 });
  await atomicWrite(join(dir, "ENCLAVE_KEY"), enclaveKey, 0o444);
  await atomicWrite(join(dir, "SPEND_LIMIT_PER_DAY"), spendLimitPerDay, 0o444);
}

export async function writeReadyFlag(layout: SecretsLayout, at: number): Promise<void> {
  await mkdir(dirname(layout.readyFile), { recursive: true });
  await atomicWrite(layout.readyFile, `${at}\n`, 0o444);
}

export async function clearReadyFlag(layout: SecretsLayout): Promise<void> {
  await rm(layout.readyFile, { force: true });
}
