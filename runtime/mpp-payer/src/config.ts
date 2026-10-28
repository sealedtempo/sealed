import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

export const PATHUSD = '0x20c0000000000000000000000000000000000000' as const
export const ESCROW_PRECOMPILE = '0x4d50500000000000000000000000000000000000' as const
export const DEFAULT_SECRETS_DIR = '/run/sealed/secrets/sealed-mpp-payer'
export const DEFAULT_CONFIG_PATH = '/etc/sealed/config.json'

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
  /** Pinned relay payee; when unset it is taken from the attested relay compose. */
  relayPayee?: `0x${string}`
  rpcUrl: string
  verifierdUrl: string
  agentUrl: string
  attestIntervalSeconds: number
  allowedCallers: string[]
  reportIntervalSeconds: number
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

function url(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new Error(`config ${name} missing`)
  const parsed = new URL(value)
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1')
    throw new Error(`config ${name} must be https`)
  return value.replace(/\/+$/, '')
}

export function loadPayerConfig(env: NodeJS.ProcessEnv = process.env): PayerConfig {
  const path = env.SEALED_CONFIG_PATH ?? DEFAULT_CONFIG_PATH
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
    relayUrl: url(pub.endpoints?.relay, 'endpoints.relay'),
    relayAttestUrl: url(pub.endpoints?.relayAttest, 'endpoints.relayAttest'),
    relayOwner: address(pub.relayOwner, 'relayOwner'),
    relayPayee: env.RELAY_PAYEE ? address(env.RELAY_PAYEE, 'RELAY_PAYEE') : undefined,
    rpcUrl: pub.endpoints?.tempoRpc ?? 'https://rpc.tempo.xyz',
    verifierdUrl: (env.VERIFIERD_URL ?? 'http://sealed-verifierd:8088').replace(/\/+$/, ''),
    agentUrl: (env.AGENT_URL ?? 'http://sealed-agent:7070').replace(/\/+$/, ''),
    attestIntervalSeconds: intEnv(env, 'ATTEST_INTERVAL_SECONDS', 900),
    allowedCallers: (env.ALLOWED_CALLERS ?? 'llm-gateway')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    reportIntervalSeconds: intEnv(env, 'SPEND_REPORT_INTERVAL_SECONDS', 60),
  }
}
