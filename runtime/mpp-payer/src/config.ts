import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

export const PATHUSD = '0x20c0000000000000000000000000000000000000' as const
export const ESCROW_PRECOMPILE = '0x4d50500000000000000000000000000000000000' as const
export const DEFAULT_SECRETS_DIR = '/run/sealed/secrets/sealed-mpp-payer'
export const DEFAULT_CONFIG_PATH = '/etc/sealed/config.json'
/** In the payer image's writable layer, which survives container restarts. */
export const DEFAULT_SPEND_STATE_FILE = '/var/lib/sealed-mpp-payer/spend-state.json'

export type SettlementMode = 'access-key' | 'enclave-account'

export type PayerConfig = {
  port: number
  chainId: number
  allowedChainIds: number[]
  customer: `0x${string}`
  mode: SettlementMode
  enclaveKey: `0x${string}`
  currency: `0x${string}`
  spendLimitPerDay: bigint
  /** Cap on one channel's deposit and every voucher in it, in base units. */
  maxDeposit: bigint
  /** Cap on one per-request charge, in base units. */
  maxCharge: bigint
  relayUrl: string
  relayAttestUrl: string
  relayOwner: `0x${string}`
  /** Optional pin of the relay payee; it must equal TREASURY_ADDRESS in the attested relay compose. */
  relayPayee?: `0x${string}`
  rpcUrl: string
  verifierdUrl: string
  agentUrl: string
  attestIntervalSeconds: number
  allowedCallers: string[]
  reportIntervalSeconds: number
  /** Where the day's debits are kept so a restart does not reset the budget. */
  spendStateFile: string
}

type PublicConfig = {
  schema?: string
  chainId?: number
  customer?: string
  feeToken?: string
  endpoints?: { relay?: string; relayAttest?: string; tempoRpc?: string }
  settlement?: { mode?: string; spendLimitPerDay?: string }
  relayOwner?: string
}

function address(value: unknown, name: string): `0x${string}` {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error(`${name} must be a 20-byte hex address`)
  return value.toLowerCase() as `0x${string}`
}

function baseUnits(value: string, name: string): bigint {
  const v = value.trim()
  if (!/^\d+$/.test(v)) throw new Error(`${name} must be an integer amount in base units`)
  return BigInt(v)
}

function intEnv(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name]
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`)
  return value
}

/** A payer secret from the tmpfs sealed-agent writes (section 15); env is accepted for local runs. */
export function readPayerSecret(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const fromEnv = env[name]?.trim()
  if (fromEnv) return fromEnv
  const path = join(env.SEALED_SECRETS_DIR ?? DEFAULT_SECRETS_DIR, name)
  if (!existsSync(path)) return undefined
  return readFileSync(path, 'utf8').trim() || undefined
}

function httpsUrl(value: unknown, name: string): URL {
  if (typeof value !== 'string') throw new Error(`config ${name} missing`)
  const parsed = new URL(value)
  if (parsed.protocol !== 'https:') throw new Error(`config ${name} must be https (the relay's TLS key is attested)`)
  return parsed
}

/**
 * The relay's chat endpoint must be served on the attested origin: the live attestation binds
 * the TLS key of the relayAttest connection, and every relay request is pinned to that key, so
 * both endpoints must be one host and port (one certificate).
 */
export function relayEndpoints(relay: unknown, relayAttest: unknown): { relayUrl: string; relayAttestUrl: string } {
  const r = httpsUrl(relay, 'endpoints.relay')
  const a = httpsUrl(relayAttest, 'endpoints.relayAttest')
  if (r.origin !== a.origin)
    throw new Error(
      `endpoints.relay (${r.origin}) and endpoints.relayAttest (${a.origin}) must share one origin: relay requests are pinned to the attested TLS key`,
    )
  return { relayUrl: `${r.origin}${r.pathname.replace(/\/+$/, '')}`, relayAttestUrl: a.toString() }
}

export function loadPayerConfig(env: NodeJS.ProcessEnv = process.env): PayerConfig {
  const path = env.SEALED_CONFIG_FILE ?? env.SEALED_CONFIG_PATH ?? DEFAULT_CONFIG_PATH
  const pub = JSON.parse(readFileSync(path, 'utf8')) as PublicConfig
  if (pub.schema !== undefined && pub.schema !== 'sealed-config/v1') throw new Error(`unexpected config schema ${pub.schema}`)
  const chainId = pub.chainId ?? 4217
  const allowedChainIds = (env.ALLOWED_CHAIN_IDS ?? '4217')
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isSafeInteger(n) && n > 0)
  if (!allowedChainIds.includes(chainId)) throw new Error(`chain ${chainId} is not allowed (allowed: ${allowedChainIds.join(', ')})`)

  const key = readPayerSecret('ENCLAVE_KEY', env)
  if (!key || !/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error('ENCLAVE_KEY missing or not a 32-byte hex key')
  const limitRaw = readPayerSecret('SPEND_LIMIT_PER_DAY', env) ?? pub.settlement?.spendLimitPerDay
  if (!limitRaw) throw new Error('SPEND_LIMIT_PER_DAY missing')
  const spendLimitPerDay = baseUnits(limitRaw, 'SPEND_LIMIT_PER_DAY')

  const mode = (pub.settlement?.mode ?? 'access-key') as SettlementMode
  if (mode !== 'access-key' && mode !== 'enclave-account') throw new Error(`unknown settlement mode ${mode}`)

  const defaultDeposit = spendLimitPerDay / 4n > 500_000n ? 500_000n : spendLimitPerDay / 4n
  if (env.RELAY_SPEND_SHARE_BPS !== undefined && env.RELAY_SPEND_SHARE_BPS !== '')
    throw new Error('RELAY_SPEND_SHARE_BPS was removed: the payer draws from sealed-agent\'s shared daily budget (D-048)')
  const { relayUrl, relayAttestUrl } = relayEndpoints(pub.endpoints?.relay, pub.endpoints?.relayAttest)
  return {
    port: intEnv(env, 'PORT', 8090),
    chainId,
    allowedChainIds,
    customer: address(pub.customer, 'customer'),
    mode,
    enclaveKey: key as `0x${string}`,
    currency: address(pub.feeToken ?? PATHUSD, 'feeToken'),
    spendLimitPerDay,
    maxDeposit: env.MAX_DEPOSIT ? baseUnits(env.MAX_DEPOSIT, 'MAX_DEPOSIT') : defaultDeposit,
    maxCharge: env.MAX_CHARGE ? baseUnits(env.MAX_CHARGE, 'MAX_CHARGE') : 50_000n,
    relayUrl,
    relayAttestUrl,
    relayOwner: address(pub.relayOwner, 'relayOwner'),
    relayPayee: env.RELAY_PAYEE ? address(env.RELAY_PAYEE, 'RELAY_PAYEE') : undefined,
    rpcUrl: pub.endpoints?.tempoRpc ?? 'https://rpc.tempo.xyz',
    verifierdUrl: (env.SEALED_VERIFIERD_URL ?? env.VERIFIERD_URL ?? 'http://sealed-verifierd:8088').replace(/\/+$/, ''),
    agentUrl: (env.SEALED_AGENT_URL ?? env.AGENT_URL ?? 'http://sealed-agent:7070').replace(/\/+$/, ''),
    attestIntervalSeconds: intEnv(env, 'ATTEST_INTERVAL_SECONDS', 900),
    allowedCallers: (env.ALLOWED_CALLERS ?? 'llm-gateway')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    reportIntervalSeconds: intEnv(env, 'SPEND_REPORT_INTERVAL_SECONDS', 60),
    spendStateFile: env.SPEND_STATE_FILE ?? DEFAULT_SPEND_STATE_FILE,
  }
}
