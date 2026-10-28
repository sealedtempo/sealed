import { describe, expect, it } from 'vitest'
import { ProviderGate } from '../src/providers/gate.js'
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
      ],
      {
        fetch: async (input) => {
          const url = String(input)
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
    // the status is capped by the gate's own freshness window
    expect(gate.status('tinfoil').expiresAt).toBeLessThanOrEqual(now + 61)
  })

  it('fails closed when a sidecar is unreachable or answers an error', async () => {
    const gate = new ProviderGate(
      [
        { provider: 'tinfoil', enabled: true, source: { kind: 'sidecar', statusUrl: 'http://tinfoil/v1/status' } },
        { provider: 'phala', enabled: true, source: { kind: 'sidecar', statusUrl: 'http://phala/v1/status' } },
      ],
      { fetch: async (input) => (String(input).includes('phala') ? new Response('', { status: 500 }) : Promise.reject(new Error('ECONNREFUSED'))) },
    )
    await gate.pollAll()
    expect(gate.allows('tinfoil')).toBe(false)
    expect(gate.status('tinfoil').detail).toMatch(/ECONNREFUSED/)
    expect(gate.allows('phala')).toBe(false)
    expect(gate.status('phala').detail).toMatch(/HTTP 500/)
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
