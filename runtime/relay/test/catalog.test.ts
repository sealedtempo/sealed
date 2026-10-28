import { readFileSync } from 'node:fs'
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
const fragment = YAML.parse(read('compose.fragment.yaml'))
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
      for (const value of Object.values(service.environment ?? {})) {
        expect(String(value)).not.toMatch(/sk-[0-9a-f]{8}|PRIVATE|BEGIN /)
        if (String(value).includes('$')) expect(value).toBe('${TREASURY_ADDRESS}')
      }
    }
    for (const image of manifest.images) {
      if (String(image.source).startsWith('build:')) expect(image.digest).toBe(`sha256:${'0'.repeat(64)}`)
      else expect(image.digest).not.toBe(`sha256:${'0'.repeat(64)}`)
    }
    expect(Object.keys(fragment.volumes)).toEqual(['inference-relay-pgdata'])
    expect(manifest.primary_service in fragment.services).toBe(true)
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
