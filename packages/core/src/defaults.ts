// Loader for config/defaults.yaml (spec 2.4). Values are public. `test_overrides` replaces the
// matching top-level keys when test mode is on (option or SEALED_TEST_OVERRIDES=1).
import { parse as parseYaml } from "yaml";
import { z } from "zod";

const usd = z.number().nonnegative();

export const defaultsSchema = z
  .object({
    codename: z.string(),
    fees_usd: z.object({
      gateway_per_1m_tokens: usd,
      scraper_per_1k_pages: usd,
      app_hour: z.record(z.string(), usd),
    }),
    maintainer_share_bps: z.number().int().min(0).max(10_000),
    relay_markup_bps: z.number().int().min(0),
    spend_limit_per_day_usd: usd,
    grace_period_minutes: z.number().int().positive(),
    settlement_interval_minutes: z.number().int().positive(),
    fee_splitter_caps_usd: z.object({ per_payment: usd, per_deployment_per_day: usd }),
    test_overrides: z.record(z.string(), z.unknown()).optional(),
    chain: z
      .object({
        chain_id: z.number().int().positive(),
        public_rpc_url: z.string(),
        fee_token: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
        fee_token_decimals: z.number().int().min(0).max(36),
      })
      .loose(),
  })
  .loose();

export type Defaults = z.infer<typeof defaultsSchema>;

export interface LoadDefaultsOptions {
  /** Apply `test_overrides`. Defaults to process.env.SEALED_TEST_OVERRIDES === "1". */
  testOverrides?: boolean;
}

function envTestOverrides(): boolean {
  return typeof process !== "undefined" && process.env?.SEALED_TEST_OVERRIDES === "1";
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function deepMerge(base: Record<string, unknown>, over: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(over)) {
    const prev = out[k];
    out[k] = isPlainObject(prev) && isPlainObject(v) ? deepMerge(prev, v) : v;
  }
  return out;
}

/** Parses defaults.yaml text. Throws with the failing field on schema errors. */
export function parseDefaults(text: string, opts: LoadDefaultsOptions = {}): Defaults {
  const raw = parseYaml(text) as unknown;
  if (!isPlainObject(raw)) throw new Error("defaults.yaml: top level must be a mapping");
  const useOverrides = opts.testOverrides ?? envTestOverrides();
  const merged = useOverrides && isPlainObject(raw.test_overrides) ? deepMerge(raw, raw.test_overrides) : raw;
  const parsed = defaultsSchema.safeParse(merged);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`defaults.yaml: ${issue?.path.join(".") ?? "?"}: ${issue?.message ?? "invalid"}`);
  }
  return parsed.data;
}

/**
 * Reads defaults.yaml from `path`, or SEALED_DEFAULTS_PATH, or the first config/defaults.yaml found
 * walking up from the current directory. Node only.
 */
export async function loadDefaults(path?: string, opts: LoadDefaultsOptions = {}): Promise<Defaults> {
  const fs = await import("node:fs/promises");
  const nodePath = await import("node:path");
  const file = path ?? process.env.SEALED_DEFAULTS_PATH ?? (await findUp(fs, nodePath));
  return parseDefaults(await fs.readFile(file, "utf8"), opts);
}

async function findUp(fs: typeof import("node:fs/promises"), nodePath: typeof import("node:path")): Promise<string> {
  let dir = process.cwd();
  for (;;) {
    const candidate = nodePath.join(dir, "config", "defaults.yaml");
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      const parent = nodePath.dirname(dir);
      if (parent === dir) throw new Error("config/defaults.yaml not found (set SEALED_DEFAULTS_PATH)");
      dir = parent;
    }
  }
}

/**
 * Converts a USD amount from defaults.yaml to FEE_TOKEN base units exactly. Rejects values with
 * more fractional digits than the token has.
 */
export function usdToUnits(amount: number | string, decimals: number): bigint {
  const text = typeof amount === "number" ? numberToPlainString(amount) : amount.trim();
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m) throw new Error(`invalid USD amount ${JSON.stringify(amount)}`);
  const whole = m[1] as string;
  const frac = (m[2] ?? "").replace(/0+$/, "");
  if (frac.length > decimals) throw new Error(`USD amount ${text} has more than ${decimals} decimals`);
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, "0") || "0");
}

function numberToPlainString(n: number): string {
  if (!Number.isFinite(n) || n < 0) throw new Error(`invalid USD amount ${n}`);
  // Shortest round-trip form; expand exponents so 1e-7 is caught as too precise.
  const s = String(n);
  if (!/e/i.test(s)) return s;
  return n.toFixed(20).replace(/0+$/, "").replace(/\.$/, "");
}

export interface SettlementDefaults {
  intervalMinutes: number;
  gracePeriodMinutes: number;
  spendLimitPerDay: bigint;
  perPaymentCap: bigint;
  perDeploymentDailyCap: bigint;
  maintainerShareBps: number;
}

export function settlementDefaults(d: Defaults): SettlementDefaults {
  const dec = d.chain.fee_token_decimals;
  return {
    intervalMinutes: d.settlement_interval_minutes,
    gracePeriodMinutes: d.grace_period_minutes,
    spendLimitPerDay: usdToUnits(d.spend_limit_per_day_usd, dec),
    perPaymentCap: usdToUnits(d.fee_splitter_caps_usd.per_payment, dec),
    perDeploymentDailyCap: usdToUnits(d.fee_splitter_caps_usd.per_deployment_per_day, dec),
    maintainerShareBps: d.maintainer_share_bps,
  };
}
