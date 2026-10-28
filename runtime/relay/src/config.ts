import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { PROVIDERS, type ProviderId } from './prices.js'

export const PATHUSD = '0x20c0000000000000000000000000000000000000' as const
export const DEFAULT_SECRETS_DIR = '/run/sealed/secrets/inference-relay'

/** Env var holding each provider's API key; the same name is the secret's name in the manifest. */
export const PROVIDER_KEY_ENV: Record<ProviderId, string> = {
  tinfoil: 'TINFOIL_API_KEY',
  phala: 'PHALA_API_KEY',
  nearai: 'NEARAI_API_KEY',
  privatemode: 'PRIVATEMODE_API_KEY',
}

/** A secret from env (envexec exports them) or its tmpfs file; undefined when absent or empty. */
export function readSecret(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const fromEnv = env[name]?.trim()
  if (fromEnv) return fromEnv
  const path = join(env.SEALED_SECRETS_DIR ?? DEFAULT_SECRETS_DIR, name)
  if (!existsSync(path)) return undefined
  const value = readFileSync(path, 'utf8').trim()
  return value || undefined
}

export function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim()
  if (!value) throw new Error(`missing required setting ${name}`)
  return value
}

function intEnv(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name]
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value)) throw new Error(`${name} must be an integer`)
  return value
}

function address(value: string, name: string): `0x${string}` {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error(`${name} must be a 20-byte hex address`)
  return value.toLowerCase() as `0x${string}`
}

export function databaseUrl(env: NodeJS.ProcessEnv): string {
  if (env.DATABASE_URL) return env.DATABASE_URL
  const password = readSecret('DATABASE_PASSWORD', env)
  if (!password) throw new Error('missing DATABASE_URL or DATABASE_PASSWORD')
  const host = env.DATABASE_HOST ?? 'inference-relay-db'
  const port = env.DATABASE_PORT ?? '5432'
  const user = env.DATABASE_USER ?? 'relay'
  const name = env.DATABASE_NAME ?? 'relay'
  return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${encodeURIComponent(name)}`
}

export type RelayConfig = {
  port: number
  realm: string
  secretKey: string
  recipient: `0x${string}`
  settlerKey?: `0x${string}`
  rpcUrl: string
  chainId: number
  currency: `0x${string}`
  markupBps: number
  pricesPath: string
  litellmUrl: string
  litellmKey: string
  databaseUrl: string
  batchTokens: number
  suggestedDeposit: string
  settleAmount: string
  settleIntervalMs: number
  superviseSeconds: number
  usageUrl: string
  providers: { provider: ProviderId; enabled: boolean; statusUrl: string; kind: 'sidecar' | 'probe' }[]
}

const here = dirname(fileURLToPath(import.meta.url))

export function loadRelayConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const secretKey = readSecret('MPP_SECRET_KEY', env)
  if (!secretKey || Buffer.byteLength(secretKey, 'utf8') < 32) throw new Error('MPP_SECRET_KEY must be at least 32 bytes')
  const litellmKey = readSecret('LITELLM_MASTER_KEY', env)
  if (!litellmKey) throw new Error('missing LITELLM_MASTER_KEY')
  const rawSettler = readSecret('RELAY_SETTLER_KEY', env)
  const settler = rawSettler && !rawSettler.startsWith('0x') ? `0x${rawSettler}` : rawSettler
  if (settler && !/^0x[0-9a-fA-F]{64}$/.test(settler)) throw new Error('RELAY_SETTLER_KEY must be a 32-byte hex key')
  const providers = PROVIDERS.map((provider) => {
    const probe = provider === 'privatemode'
    const host = `inference-relay-${provider}`
    const statusUrl =
      env[`${provider.toUpperCase()}_STATUS_URL`] ?? (probe ? `http://${host}:8080/v1/models` : `http://${host}:8100/v1/status`)
    return {
      provider,
      enabled: readSecret(PROVIDER_KEY_ENV[provider], env) !== undefined,
      statusUrl,
      kind: probe ? ('probe' as const) : ('sidecar' as const),
    }
  })
  return {
    port: intEnv(env, 'PORT', 8080),
    realm: requireEnv(env, 'MPP_REALM'),
    secretKey,
    recipient: address(requireEnv(env, 'TREASURY_ADDRESS'), 'TREASURY_ADDRESS'),
    settlerKey: settler as `0x${string}` | undefined,
    rpcUrl: env.TEMPO_RPC_URL ?? 'https://rpc.tempo.xyz',
    chainId: intEnv(env, 'TEMPO_CHAIN_ID', 4217),
    currency: address(env.FEE_TOKEN_ADDRESS ?? PATHUSD, 'FEE_TOKEN_ADDRESS'),
    markupBps: intEnv(env, 'RELAY_MARKUP_BPS', 500),
    pricesPath: env.RELAY_PRICES_PATH ?? join(here, '..', 'config', 'prices.json'),
    litellmUrl: env.LITELLM_URL ?? 'http://inference-relay-litellm:4000/v1',
    litellmKey,
    databaseUrl: databaseUrl(env),
    batchTokens: intEnv(env, 'SESSION_BATCH_TOKENS', 32),
    suggestedDeposit: env.SESSION_SUGGESTED_DEPOSIT ?? '0.5',
    settleAmount: env.SETTLE_EVERY_AMOUNT ?? '1',
    settleIntervalMs: intEnv(env, 'SETTLE_INTERVAL_MS', 5 * 60_000),
    superviseSeconds: intEnv(env, 'SUPERVISE_INTERVAL_SECONDS', 60),
    usageUrl: env.SEALED_USAGE_URL ?? 'http://sealed-agent:7070/v1/usage-events',
    providers,
  }
}
