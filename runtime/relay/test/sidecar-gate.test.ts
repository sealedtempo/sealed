import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ProviderGate, privatemodeManifestEvidence } from '../src/providers/gate.js'
import { ProviderSidecar } from '../src/providers/sidecar.js'
import { AttestationFailure, type ProviderVerifier, type VerifiedChannel } from '../src/providers/types.js'

function controllableVerifier() {
  const state = { pass: true, calls: 0, forwarded: [] as { url: string; auth: string | null; body: string }[] }
  const verifier: ProviderVerifier = {
    provider: 'tinfoil',
    async verify(): Promise<VerifiedChannel> {
      state.calls++
      if (!state.pass) throw new AttestationFailure('quote', 'measurement mismatch')
      return {
        baseURL: 'https://enclave.example/v1',
        expiresAt: Math.floor(Date.now() / 1000) + 600,
        evidence: { tlsSpkiSha256: 'ab'.repeat(32) },
        fetch: async (input, init) => {
          state.forwarded.push({
            url: String(input),
            auth: new Headers(init?.headers).get('authorization'),
            body: init?.body ? Buffer.from(init.body as ArrayBuffer).toString() : '',
          })
          return Response.json({ id: 'cmpl', choices: [] })
        },
      }
    },
  }
  return { state, verifier }
}

describe('provider sidecar', () => {
  it('forwards over the verified channel only after verification', async () => {
    const { state, verifier } = controllableVerifier()
    const sidecar = new ProviderSidecar(verifier, { provider: 'tinfoil' })
    const app = sidecar.app()
    const before = await app.request('/v1/chat/completions', { method: 'POST', body: '{}' })
    expect(before.status).toBe(503)
    await sidecar.refresh()
    const status = await (await app.request('/v1/status')).json()
    expect(status).toMatchObject({ provider: 'tinfoil', enabled: true, verified: true })
    const res = await app.request('/v1/chat/completions', {
      method: 'POST',
      headers: { authorization: 'Bearer provider-key', 'content-type': 'application/json', cookie: 'drop-me' },
      body: '{"model":"m"}',
    })
    expect(res.status).toBe(200)
    expect(state.forwarded[0]).toEqual({ url: 'https://enclave.example/v1/chat/completions', auth: 'Bearer provider-key', body: '{"model":"m"}' })
    await sidecar.stop()
  })

  it('refuses with 503 when re-verification fails and recovers after a pass', async () => {
    const { state, verifier } = controllableVerifier()
    const sidecar = new ProviderSidecar(verifier, { provider: 'tinfoil', retrySeconds: 3600 })
    await sidecar.refresh()
    state.pass = false
    await sidecar.refresh()
    const refused = await sidecar.app().request('/v1/chat/completions', { method: 'POST', body: '{}' })
    expect(refused.status).toBe(503)
    expect((await refused.json()).error).toMatchObject({ type: 'attestation_failed', provider: 'tinfoil' })
    expect(sidecar.getStatus()).toMatchObject({ verified: false, detail: 'quote: measurement mismatch' })
    state.pass = true
    await sidecar.refresh()
    expect((await sidecar.app().request('/v1/chat/completions', { method: 'POST', body: '{}' })).status).toBe(200)
    await sidecar.stop()
  })

  it('reports disabled when no API key is configured', async () => {
    const sidecar = new ProviderSidecar(undefined, { provider: 'phala' })
    expect(sidecar.getStatus()).toMatchObject({ enabled: false, verified: false })
    expect((await sidecar.app().request('/v1/models')).status).toBe(503)
  })

  it('marks the provider unverified when the TLS pin no longer matches', async () => {
    const { verifier } = controllableVerifier()
    const pinFailing: ProviderVerifier = {
      provider: 'tinfoil',
      async verify() {
        const ch = await verifier.verify()
        return { ...ch, fetch: async () => Promise.reject(Object.assign(new TypeError('fetch failed'), { cause: new Error('TLS pin check: peer SPKI ff is not attested') })) }
      },
    }
    const sidecar = new ProviderSidecar(pinFailing, { provider: 'tinfoil', retrySeconds: 3600 })
    await sidecar.refresh()
    const res = await sidecar.app().request('/v1/chat/completions', { method: 'POST', body: '{}' })
    expect(res.status).toBe(503)
    await sidecar.stop()
  })
})

describe('relay provider gate', () => {
  it('allows only enabled providers with fresh verified status', async () => {
    const now = Math.floor(Date.now() / 1000)
    const statuses: Record<string, unknown> = {
      'http://tinfoil/v1/status': { enabled: true, verified: true, expiresAt: now + 300, detail: 'attestation verified' },
      'http://nearai/v1/status': { enabled: true, verified: false, detail: 'quote: bad' },
    }
    const gate = new ProviderGate(
      [
        { provider: 'tinfoil', enabled: true, source: { kind: 'sidecar', statusUrl: 'http://tinfoil/v1/status' } },
        { provider: 'nearai', enabled: true, source: { kind: 'sidecar', statusUrl: 'http://nearai/v1/status' } },
        { provider: 'phala', enabled: false, source: { kind: 'sidecar', statusUrl: 'http://phala/v1/status' } },
        { provider: 'privatemode', enabled: true, source: { kind: 'privatemode', baseUrl: 'http://privatemode:8080', apiKey: () => 'pm-key', model: 'gpt-oss-120b' } },
      ],
      {
        fetch: async (input) => {
          const url = String(input)
          if (url.includes('privatemode')) return Response.json({ choices: [{ message: { content: 'ok' } }] })
          if (url in statuses) return Response.json(statuses[url])
          throw new Error('unreachable')
        },
      },
    )
    expect(gate.allows('tinfoil')).toBe(false)
    await gate.pollAll()
    expect(gate.allows('tinfoil')).toBe(true)
    expect(gate.allows('nearai')).toBe(false)
    expect(gate.status('nearai').detail).toBe('quote: bad')
    expect(gate.allows('phala')).toBe(false)
    expect(gate.status('phala').detail).toMatch(/not configured/)
    expect(gate.allows('privatemode')).toBe(true)
    // the status is capped by the gate's own freshness window
    expect(gate.status('tinfoil').expiresAt).toBeLessThanOrEqual(now + 61)
  })

  it('fails closed when a sidecar is unreachable or the probe is refused', async () => {
    const gate = new ProviderGate(
      [
        { provider: 'tinfoil', enabled: true, source: { kind: 'sidecar', statusUrl: 'http://tinfoil/v1/status' } },
        { provider: 'privatemode', enabled: true, source: { kind: 'privatemode', baseUrl: 'http://pm:8080', apiKey: () => 'k', model: 'm' } },
      ],
      { fetch: async (input) => (String(input).includes('pm') ? new Response('', { status: 500 }) : Promise.reject(new Error('ECONNREFUSED'))) },
    )
    await gate.pollAll()
    expect(gate.allows('tinfoil')).toBe(false)
    expect(gate.status('tinfoil').detail).toMatch(/ECONNREFUSED/)
    expect(gate.allows('privatemode')).toBe(false)
  })

  it('re-reads a sidecar status right before a payment settles', async () => {
    let verified = true
    let polls = 0
    const gate = new ProviderGate([{ provider: 'tinfoil', enabled: true, source: { kind: 'sidecar', statusUrl: 'http://tinfoil/v1/status' } }], {
      fetch: async () => {
        polls++
        return Response.json({ enabled: true, verified, expiresAt: Math.floor(Date.now() / 1000) + 300, detail: verified ? 'ok' : 'attestation lapsed' })
      },
    })
    await gate.pollAll()
    expect(gate.allows('tinfoil')).toBe(true)
    verified = false
    await gate.refresh('tinfoil')
    expect(gate.allows('tinfoil')).toBe(false)
    expect(polls).toBe(2)
  })
})

describe('Privatemode proxy gate', () => {
  // Response shapes follow privatemode-proxy/internal/server: 500 while it holds no secret released
  // after attestation, 401 when the API key is refused. They are modeled on that code, not recorded
  // from a live proxy (no Docker and no Privatemode key in this environment).
  const noSecret = () => new Response('getting latest secret: no secret available', { status: 500 })
  const badKey = () => new Response('trying API key: unauthorized', { status: 401 })

  function pm(respond: (init: RequestInit) => Response | Promise<Response>, extra: Partial<{ workspaceDir: string; probeSeconds: number; key: string | undefined }> = {}) {
    const calls: { url: string; init: RequestInit }[] = []
    let now = 1_000_000
    const gate = new ProviderGate(
      [
        {
          provider: 'privatemode',
          enabled: true,
          source: {
            kind: 'privatemode',
            baseUrl: 'http://inference-relay-privatemode:8080',
            apiKey: () => ('key' in extra ? extra.key : 'pm-secret'),
            model: 'gpt-oss-120b',
            workspaceDir: extra.workspaceDir,
            probeSeconds: extra.probeSeconds ?? 120,
          },
        },
      ],
      { now: () => now, fetch: async (input, init) => (calls.push({ url: String(input), init: init ?? {} }), respond(init ?? {})) },
    )
    return { gate, calls, advance: (s: number) => void (now += s) }
  }

  it('is verified only by an authenticated completion through the proxy', async () => {
    const { gate, calls } = pm(() => Response.json({ choices: [{ message: { content: 'o' } }] }))
    await gate.pollAll()
    expect(gate.allows('privatemode')).toBe(true)
    expect(calls[0]!.url).toBe('http://inference-relay-privatemode:8080/v1/chat/completions')
    expect(new Headers(calls[0]!.init.headers).get('authorization')).toBe('Bearer pm-secret')
    expect(JSON.parse(String(calls[0]!.init.body))).toMatchObject({ model: 'gpt-oss-120b', max_tokens: 1, stream: false })
    expect(gate.status('privatemode').evidence).toMatchObject({ probeStatus: '200' })
  })

  it('fails closed while the proxy holds no attested secret, refuses the key, or no key is readable', async () => {
    for (const respond of [noSecret, badKey]) {
      const { gate } = pm(respond)
      await gate.pollAll()
      expect(gate.allows('privatemode')).toBe(false)
      expect(gate.status('privatemode').detail).toMatch(/refused the probe \(HTTP (500|401)\)/)
    }
    const { gate, calls } = pm(() => Response.json({}), { key: undefined })
    await gate.pollAll()
    expect(gate.allows('privatemode')).toBe(false)
    expect(calls).toEqual([])
  })

  it('probes on its own schedule (a probe is a billed completion) and expires without one', async () => {
    const { gate, calls, advance } = pm(() => Response.json({}), { probeSeconds: 120 })
    await gate.pollAll()
    await gate.pollAll()
    await gate.refresh('privatemode')
    expect(calls.length).toBe(1)
    advance(121)
    await gate.refresh('privatemode')
    expect(calls.length).toBe(2)
    advance(181)
    expect(gate.allows('privatemode')).toBe(false)
    expect(gate.status('privatemode').detail).toBe('evidence expired')
  })

  it('records the manifest the proxy logged as evidence', async () => {
    const ws = mkdtempSync(join(tmpdir(), 'pm-ws-'))
    mkdirSync(join(ws, 'manifests'))
    writeFileSync(join(ws, 'manifests', '1.json'), '{"old":true}')
    writeFileSync(join(ws, 'manifests', '2.json'), '{"policies":{}}')
    writeFileSync(join(ws, 'manifests', 'log.txt'), '2026-10-28T10:00:00Z /workspace/manifests/1.json\n2026-10-28T11:00:00Z /workspace/manifests/2.json\n')
    const { gate } = pm(() => Response.json({}), { workspaceDir: ws })
    await gate.pollAll()
    expect(gate.status('privatemode').evidence).toMatchObject({
      manifestSha256: createHash('sha256').update('{"policies":{}}').digest('hex'),
      manifestLoggedAt: '2026-10-28T11:00:00Z',
      manifestVersion: '2',
    })
    expect(privatemodeManifestEvidence(join(ws, 'missing'))).toMatchObject({ manifest: expect.stringMatching(/unreadable: ENOENT/) })
  })
})
