import { spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import YAML from 'yaml'
import { PROVIDER_KEY_ENV } from '../src/config.js'
import { loadPriceTable } from '../src/prices.js'

const require = createRequire(import.meta.url)
const Ajv2020 = require('ajv/dist/2020').default
const addFormats = require('ajv-formats').default

const repo = join(import.meta.dirname, '../../..')
const app = join(repo, 'catalog/apps/inference-relay')
const read = (p: string) => readFileSync(join(app, p), 'utf8')
const manifest = YAML.parse(read('manifest.yaml'))
const fragmentText = read('compose.fragment.yaml')
const fragment = YAML.parse(fragmentText)
const egress = YAML.parse(read('egress.yaml'))
const litellm = YAML.parse(read('images/litellm-relay/config.yaml'))
const defaults = YAML.parse(readFileSync(join(repo, 'config/defaults.yaml'), 'utf8'))
const deployments = JSON.parse(readFileSync(join(repo, 'contracts/deployments/tempo-mainnet.json'), 'utf8'))
const schema = JSON.parse(readFileSync(join(repo, 'catalog/schema/manifest.schema.json'), 'utf8'))

/**
 * Brief item 12 adds `on_attest_host` to manifest routes; the composer side (schema, lint,
 * Caddyfile) is ws/int-composer's. Until the tree's schema knows the field, the schema test adds
 * it to a copy and the lint test lints a copy of this app without it, so everything else is still
 * checked by the real schema and the real composer. Once the composer lands both run unchanged.
 */
const composerKnowsAttestHost = 'on_attest_host' in (schema.properties.routes.items.properties ?? {})

const ALLOWED_SERVICE_KEYS = new Set([
  'image', 'command', 'entrypoint', 'environment', 'healthcheck', 'depends_on', 'volumes', 'tmpfs', 'user',
  'working_dir', 'read_only', 'stop_grace_period', 'shm_size', 'ulimits', 'mem_limit', 'cpus', 'labels', 'x-sealed-secrets',
])

describe('catalog/apps/inference-relay', () => {
  it('manifest validates against catalog/schema/manifest.schema.json', () => {
    const tree = structuredClone(schema)
    if (!composerKnowsAttestHost) tree.properties.routes.items.properties.on_attest_host = { type: 'boolean' }
    const ajv = new Ajv2020({ allErrors: true, strict: true })
    addFormats(ajv)
    const validate = ajv.compile(tree)
    const ok = validate(manifest)
    expect(validate.errors ?? []).toEqual([])
    expect(ok).toBe(true)
    expect(manifest).toMatchObject({ id: 'inference-relay', category: 'ai', metering: { unit: 'tokens', source: 'callback' } })
  })

  it('serves the relay route on the attest host: /v1/ next to /attest, one origin and certificate (D-045)', () => {
    expect(manifest.routes).toEqual([
      { name: 'relay', service: 'inference-relay-front', internal_port: 8080, path_or_host: '/v1', auth: 'public', on_attest_host: true },
    ])
  })

  it('fragment follows the composer rules (INTERFACES section 14)', () => {
    expect(Object.keys(fragment).sort()).toEqual(['services', 'volumes'])
    const images = new Set(manifest.images.map((i: { name: string }) => i.name))
    const secrets = new Set(manifest.secrets.map((s: { name: string }) => s.name))
    for (const [name, service] of Object.entries<Record<string, any>>(fragment.services)) {
      expect(name.startsWith('inference-relay-')).toBe(true)
      for (const key of Object.keys(service)) expect(ALLOWED_SERVICE_KEYS.has(key), `${name}.${key}`).toBe(true)
      const image = /^\{\{image:([a-z][a-z0-9-]*)\}\}$/.exec(service.image)
      expect(image, `${name}.image`).not.toBeNull()
      expect(images.has(image![1])).toBe(true)
      expect(Array.isArray(service.entrypoint), `${name} needs an explicit entrypoint`).toBe(true)
      for (const s of service['x-sealed-secrets'] ?? []) expect(secrets.has(s), `${name} secret ${s}`).toBe(true)
      for (const v of service.volumes ?? []) expect(String(v).split(':')[0]).toMatch(/^inference-relay-/)
      for (const dep of Object.keys(service.depends_on ?? {})) expect(dep in fragment.services).toBe(true)
      for (const value of Object.values(service.environment ?? {})) expect(String(value)).not.toMatch(/sk-[0-9a-f]{8}|PRIVATE KEY|BEGIN /)
    }
    for (const image of manifest.images) {
      if (String(image.source).startsWith('build:')) expect(image.digest).toBe(`sha256:${'0'.repeat(64)}`)
      else expect(image.digest).not.toBe(`sha256:${'0'.repeat(64)}`)
    }
    expect(Object.keys(fragment.volumes)).toEqual(['inference-relay-pgdata'])
    expect(manifest.primary_service in fragment.services).toBe(true)
  })

  it('has no variable interpolation: the composer rejects any $ that is not $$ (the host env is not measured)', () => {
    const lines = fragmentText.split('\n').filter((line) => !line.trimStart().startsWith('#'))
    for (const line of lines) expect(line.replaceAll('$$', ''), line).not.toContain('$')
  })

  it('pins the payee to the deployed treasury, the currency to FEE_TOKEN and the markup to config/defaults.yaml', () => {
    const env = fragment.services['inference-relay-front'].environment
    // A literal (measured, read by every payer), lowercase, equal to the treasury FeeSplitter was deployed with.
    expect(env.TREASURY_ADDRESS).toBe('0x755a1e289503c7109d01a74ed253ba0f724ca3eb')
    expect(env.TREASURY_ADDRESS).toBe(deployments.config.treasury.toLowerCase())
    // FEE_TOKEN from config: USDC.e on mainnet (D-035); the price table is denominated in it too.
    expect(env.FEE_TOKEN_ADDRESS).toBe(defaults.chain.fee_token)
    expect(env.FEE_TOKEN_ADDRESS).toBe('0x20c000000000000000000000b9537d11c60e8b50')
    expect(env.FEE_TOKEN_ADDRESS).toBe(deployments.config.feeToken.toLowerCase())
    expect(loadPriceTable(join(repo, 'runtime/relay/config/prices.json'), 500).currency).toBe(env.FEE_TOKEN_ADDRESS)
    expect(Number(env.TEMPO_CHAIN_ID)).toBe(defaults.chain.chain_id)
    expect(Number(env.RELAY_MARKUP_BPS)).toBe(defaults.relay_markup_bps)
  })

  it('keeps provider code identity fail-closed: per-provider allowlists, never the development flag', () => {
    expect(fragmentText).not.toContain('ALLOW_UNPINNED_PROVIDER_CODE')
    expect(fragmentText).not.toMatch(/^\s+ACCEPTED_COMPOSE_HASHES:/m)
    const env = (name: string) => fragment.services[name].environment
    expect(env('inference-relay-phala')).toHaveProperty('PHALA_ACCEPTED_COMPOSE_HASHES')
    expect(env('inference-relay-nearai')).toHaveProperty('NEARAI_ACCEPTED_COMPOSE_HASHES')
    expect(env('inference-relay-nearai')).toHaveProperty('NEARAI_ACCEPTED_OS_MEASUREMENTS')
  })

  it('ships no Privatemode service, image, secret, model or egress host (D-055)', () => {
    const text = JSON.stringify({ manifest, fragment, litellm, egress })
    expect(text.toLowerCase()).not.toContain('privatemode')
    expect(text).not.toContain('confidential.cloud')
  })

  it('the example environment lists exactly the relay providers it reads a key for (D-055: no Privatemode)', () => {
    const example = readFileSync(join(repo, '.env.example'), 'utf8')
    const keys = [...example.matchAll(/^([A-Z0-9_]+_API_KEY)=/gm)].map((m) => m[1]).sort()
    expect(keys).toEqual(Object.values(PROVIDER_KEY_ENV).sort())
  })

  // Runs the real composer lint once runtime/composer is in this tree (after ws/composer merges).
  const composerCli = join(repo, 'runtime/composer/cmd/sealed-compose')
  const haveGo = spawnSync('go', ['version']).status === 0
  it.skipIf(!existsSync(composerCli) || !haveGo)('passes the composer catalog lint except for release-time digests and SBOMs', () => {
    let appDir = join(repo, 'catalog/apps/inference-relay')
    let scratch: string | undefined
    if (!composerKnowsAttestHost) {
      scratch = mkdtempSync(join(tmpdir(), 'relay-lint-'))
      appDir = join(scratch, 'inference-relay')
      cpSync(join(repo, 'catalog/apps/inference-relay'), appDir, { recursive: true })
      const text = readFileSync(join(appDir, 'manifest.yaml'), 'utf8')
      const without = text.replace(/^ {4}on_attest_host: true\n/m, '')
      expect(without).not.toBe(text)
      writeFileSync(join(appDir, 'manifest.yaml'), without)
    }
    try {
      const run = spawnSync('go', ['run', './runtime/composer/cmd/sealed-compose', 'lint', '--app-dir', appDir], { cwd: repo, encoding: 'utf8' })
      const errors = `${run.stdout}\n${run.stderr}`.split('\n').filter((l) => l.startsWith('error:'))
      expect(errors.filter((l) => !l.includes('[unbuilt-image]'))).toEqual([])
      expect(run.error).toBeUndefined()
    } finally {
      if (scratch) rmSync(scratch, { recursive: true, force: true })
    }
  }, 120_000)

  it('LiteLLM routes every priced model to its attested upstream with the right key', () => {
    const prices = loadPriceTable(join(repo, 'runtime/relay/config/prices.json'), 500)
    const byName = new Map(litellm.model_list.map((m: any) => [m.model_name, m.litellm_params]))
    expect(byName.size).toBe(prices.models.length)
    for (const m of prices.models) {
      const params = byName.get(m.id) as Record<string, string>
      expect(params, m.id).toBeDefined()
      expect(params.model).toBe(`openai/${m.upstreamModel}`)
      expect(params.api_base).toBe(`http://inference-relay-${m.provider}:8100/v1`)
      expect(params.api_key).toBe(`os.environ/${PROVIDER_KEY_ENV[m.provider]}`)
    }
    expect(litellm.general_settings.master_key).toBe('os.environ/LITELLM_MASTER_KEY')
    for (const banned of ['enable_jwt_auth', 'allowed_routes', 'allowed_ips', 'enforced_params', 'database_url'])
      expect(JSON.stringify(litellm)).not.toContain(banned)
  })

  it('egress allows only provider, Intel PCS and Tempo RPC hosts', () => {
    expect(egress.version).toBe(1)
    expect(egress.customer_additions_allowed).toBe(false)
    for (const entry of egress.default_allow) expect(entry).toMatch(/^[a-z0-9.-]+\.[a-z]{2,}:443$/)
    expect(egress.default_allow).toContain('rpc.tempo.xyz:443')
    expect(egress.default_allow).toContain('api.trustedservices.intel.com:443')
  })
})
