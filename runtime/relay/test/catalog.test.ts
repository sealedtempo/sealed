import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
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

const ALLOWED_SERVICE_KEYS = new Set([
  'image', 'command', 'entrypoint', 'environment', 'healthcheck', 'depends_on', 'volumes', 'tmpfs', 'user',
  'working_dir', 'read_only', 'stop_grace_period', 'shm_size', 'ulimits', 'mem_limit', 'cpus', 'labels', 'x-sealed-secrets',
])

describe('catalog/apps/inference-relay', () => {
  it('manifest validates against catalog/schema/manifest.schema.json', () => {
    const schema = JSON.parse(readFileSync(join(repo, 'catalog/schema/manifest.schema.json'), 'utf8'))
    const ajv = new Ajv2020({ allErrors: true, strict: true })
    addFormats(ajv)
    const validate = ajv.compile(schema)
    const ok = validate(manifest)
    expect(validate.errors ?? []).toEqual([])
    expect(ok).toBe(true)
    expect(manifest).toMatchObject({ id: 'inference-relay', category: 'ai', metering: { unit: 'tokens', source: 'callback' } })
    expect(manifest.routes).toEqual([expect.objectContaining({ name: 'relay', service: 'inference-relay-front' })])
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
    expect(Object.keys(fragment.volumes)).toEqual(['inference-relay-pgdata', 'inference-relay-privatemode-ws'])
    expect(manifest.primary_service in fragment.services).toBe(true)
  })

  it('has no variable interpolation: the composer rejects any $ that is not $$ (the host env is not measured)', () => {
    const lines = fragmentText.split('\n').filter((line) => !line.trimStart().startsWith('#'))
    for (const line of lines) expect(line.replaceAll('$$', ''), line).not.toContain('$')
  })

  it('pins the payee as a literal and the markup to config/defaults.yaml', () => {
    const env = fragment.services['inference-relay-front'].environment
    expect(env.TREASURY_ADDRESS).toMatch(/^0x[0-9a-f]{40}$/)
    const defaults = YAML.parse(readFileSync(join(repo, 'config/defaults.yaml'), 'utf8'))
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

  it('shares the Privatemode proxy workspace read-only with the front for manifest evidence', () => {
    const front = fragment.services['inference-relay-front']
    expect(front.volumes).toContain(`inference-relay-privatemode-ws:${front.environment.PRIVATEMODE_WORKSPACE}:ro`)
    expect(front['x-sealed-secrets']).toContain('PRIVATEMODE_API_KEY')
    expect(fragment.services['inference-relay-privatemode'].volumes).toEqual(['inference-relay-privatemode-ws:/workspace'])
  })

  // Runs the real composer lint once runtime/composer is in this tree (after ws/composer merges).
  const composerCli = join(repo, 'runtime/composer/cmd/sealed-compose')
  const haveGo = spawnSync('go', ['version']).status === 0
  it.skipIf(!existsSync(composerCli) || !haveGo)('passes the composer catalog lint except for release-time digests and SBOMs', () => {
    const run = spawnSync('go', ['run', './runtime/composer/cmd/sealed-compose', 'lint', '--app-dir', 'catalog/apps/inference-relay'], {
      cwd: repo,
      encoding: 'utf8',
    })
    const errors = `${run.stdout}\n${run.stderr}`.split('\n').filter((l) => l.startsWith('error:'))
    expect(errors.filter((l) => !l.includes('[unbuilt-image]'))).toEqual([])
  })

  it('LiteLLM routes every priced model to its attested upstream with the right key', () => {
    const prices = loadPriceTable(join(repo, 'runtime/relay/config/prices.json'), 500)
    const byName = new Map(litellm.model_list.map((m: any) => [m.model_name, m.litellm_params]))
    expect(byName.size).toBe(prices.models.length)
    for (const m of prices.models) {
      const params = byName.get(m.id) as Record<string, string>
      expect(params, m.id).toBeDefined()
      expect(params.model).toBe(`openai/${m.upstreamModel}`)
      const host = m.provider === 'privatemode' ? 'http://inference-relay-privatemode:8080/v1' : `http://inference-relay-${m.provider}:8100/v1`
      expect(params.api_base).toBe(host)
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
