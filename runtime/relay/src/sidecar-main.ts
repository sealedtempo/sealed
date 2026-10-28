import { serve } from '@hono/node-server'
import { PROVIDER_KEY_ENV, readSecret } from './config.js'
import { PROVIDERS, type ProviderId } from './prices.js'
import { nearAiVerifier } from './providers/nearai.js'
import { phalaVerifier } from './providers/phala.js'
import { ProviderSidecar } from './providers/sidecar.js'
import { tinfoilVerifier } from './providers/tinfoil.js'
import type { ProviderVerifier } from './providers/types.js'

const log = (line: string) => console.log(JSON.stringify({ t: new Date().toISOString(), event: 'sidecar', line }))

function list(value: string | undefined): string[] {
  return (value ?? '').split(',').map((s) => s.trim()).filter(Boolean)
}

/**
 * Builds the verifier for one provider, or undefined when its API key is not configured. Code
 * identity comes from reviewed allowlists in the measured fragment, one per provider: Tinfoil
 * pins its Sigstore release, Phala and NEAR AI pin compose hashes (and NEAR AI its OS image).
 * ALLOW_UNPINNED_PROVIDER_CODE=1 accepts empty lists (development only; never set in the fragment).
 */
export function verifierFor(provider: ProviderId, env: NodeJS.ProcessEnv = process.env): ProviderVerifier | undefined {
  const apiKey = readSecret(PROVIDER_KEY_ENV[provider], env)
  if (!apiKey) return undefined
  const allowUnpinned = env.ALLOW_UNPINNED_PROVIDER_CODE === '1'
  switch (provider) {
    case 'tinfoil':
      return tinfoilVerifier({ enclaveURL: env.TINFOIL_ENCLAVE_URL, configRepo: env.TINFOIL_CONFIG_REPO })
    case 'phala':
      return phalaVerifier({ baseURL: env.PHALA_BASE_URL, acceptedComposeHashes: list(env.PHALA_ACCEPTED_COMPOSE_HASHES), allowUnpinned })
    case 'nearai':
      return nearAiVerifier({
        baseURL: env.NEARAI_BASE_URL,
        apiKey,
        acceptedComposeHashes: list(env.NEARAI_ACCEPTED_COMPOSE_HASHES),
        acceptedOsMeasurements: list(env.NEARAI_ACCEPTED_OS_MEASUREMENTS),
        allowUnpinned,
      })
  }
}

function main(): void {
  const provider = (process.argv[2] ?? process.env.PROVIDER) as ProviderId
  if (!(PROVIDERS as readonly string[]).includes(provider))
    throw new Error(`usage: sidecar-main <tinfoil|phala|nearai>, got ${String(provider)}`)
  const sidecar = new ProviderSidecar(verifierFor(provider), {
    provider,
    refreshSeconds: Number(process.env.REVERIFY_SECONDS ?? 600),
    log,
  })
  sidecar.start()
  const port = Number(process.env.PORT ?? 8100)
  serve({ fetch: sidecar.app().fetch, port, hostname: '0.0.0.0' })
  log(`${provider} sidecar listening on ${port}`)
  const stop = () => void sidecar.stop().finally(() => process.exit(0))
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], 'file:').href) main()
