import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/** pathUSD; local Tempo nodes fund it. Mainnet's FEE_TOKEN is USDC.e (D-035), read from config.feeToken. */
export const PATHUSD = '0x20c0000000000000000000000000000000000000' as const
export const ESCROW_PRECOMPILE = '0x4d50500000000000000000000000000000000000' as const
export const DEFAULT_SECRETS_DIR = '/run/sealed/secrets/sealed-mpp-payer'
export const DEFAULT_CONFIG_PATH = '/etc/sealed/config.json'
/**
 * The payer's state directory: the day's debits, the channel journal and the stored session
 * channel. In the image's writable layer it survives container restarts; a persistent mount
 * here (composer interface change) also keeps it across image updates and VM replacement.
 */
export const DEFAULT_STATE_DIR = '/var/lib/sealed-mpp-payer'
export const DEFAULT_SPEND_STATE_FILE = `${DEFAULT_STATE_DIR}/spend-state.json`
/**
 * The payer needs this long after SIGTERM: in-flight payments (mppx's server waits up to 30 s
 * for a transaction) and the cooperative close of the session channel (the relay waits up to
 * 30 s for its close transaction). The composer's stop_grace_period must be at least
 * SHUTDOWN_SECONDS + 5 (D-067: at least 45 s).
 */
export const SHUTDOWN_SECONDS = 38

export type SettlementMode = 'access-key' | 'enclave-account'

export type PayerConfig = {
  port: number
  chainId: number
  allowedChainIds: number[]
  customer: `0x${string}`
  mode: SettlementMode
  enclaveKey: `0x${string}`
  /** FEE_TOKEN from the public config (feeToken): the only token the payer pays the relay in. */
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
  /** STATE_DIR: made private (0700, this process's user) at boot, see state-dir.ts. */
  stateDir: string
  /** Where the day's debits are kept so a restart does not reset the budget. */
  spendStateFile: string
  /** The channel journal (recovery of orphaned deposits). */
  channelJournalFile: string
  /** mppx's stored session channel (resumed after a restart). */
  sessionStoreFile: string
  /** Rotate a channel once less than this is left below maxDeposit, base units. */
  rotateHeadroom: bigint
  recoveryIntervalSeconds: number
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
 * The relay's chat endpoint is served on the attested origin (D-045): the live attestation binds
 * the TLS key of the relayAttest connection, and every relay request is pinned to that key, so
 * endpoints.relay must be exactly the origin of endpoints.relayAttest (one host and port, one
 * certificate). The relay route's path prefix (/v1/) is served there next to /attest.
 */
export function relayEndpoints(relay: unknown, relayAttest: unknown): { relayUrl: string; relayAttestUrl: string } {
  const r = httpsUrl(relay, 'endpoints.relay')
  const a = httpsUrl(relayAttest, 'endpoints.relayAttest')
  if (r.origin !== a.origin)
    throw new Error(
      `endpoints.relay (${r.origin}) and endpoints.relayAttest (${a.origin}) must share one origin: relay requests are pinned to the attested TLS key`,
    )
  if (r.pathname.replace(/\/+$/, '') !== '' || r.search !== '' || r.hash !== '')
    throw new Error(`endpoints.relay must be the relay's attest origin ${a.origin} without a path (its /v1/ route is served there)`)
  return { relayUrl: r.origin, relayAttestUrl: a.toString() }
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
  if (typeof pub.feeToken !== 'string') throw new Error('config feeToken missing: the payer pays the relay only in FEE_TOKEN')
  const { relayUrl, relayAttestUrl } = relayEndpoints(pub.endpoints?.relay, pub.endpoints?.relayAttest)
  const stateDir = env.STATE_DIR ?? DEFAULT_STATE_DIR
  const maxCharge = env.MAX_CHARGE ? baseUnits(env.MAX_CHARGE, 'MAX_CHARGE') : 50_000n
  const maxDeposit = env.MAX_DEPOSIT ? baseUnits(env.MAX_DEPOSIT, 'MAX_DEPOSIT') : defaultDeposit
  // A channel is rotated once less than one charge is left; never more than a quarter of it.
  const rotateHeadroom = env.ROTATE_HEADROOM ? baseUnits(env.ROTATE_HEADROOM, 'ROTATE_HEADROOM') : maxCharge < maxDeposit / 4n ? maxCharge : maxDeposit / 4n
  if (maxDeposit > 0n && rotateHeadroom >= maxDeposit) throw new Error('ROTATE_HEADROOM must be below MAX_DEPOSIT')
  return {
    port: intEnv(env, 'PORT', 8090),
    chainId,
    allowedChainIds,
    customer: address(pub.customer, 'customer'),
    mode,
    enclaveKey: key as `0x${string}`,
    currency: address(pub.feeToken, 'feeToken'),
    spendLimitPerDay,
    maxDeposit,
    maxCharge,
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
    stateDir,
    spendStateFile: env.SPEND_STATE_FILE ?? join(stateDir, 'spend-state.json'),
    channelJournalFile: join(stateDir, 'channels.json'),
    sessionStoreFile: join(stateDir, 'session-store.json'),
    rotateHeadroom,
    recoveryIntervalSeconds: intEnv(env, 'RECOVERY_INTERVAL_SECONDS', 60),
  }
}
