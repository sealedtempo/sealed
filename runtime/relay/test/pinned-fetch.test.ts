import { X509Certificate, createHash } from 'node:crypto'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createCapturingFetch, createPinnedFetch, proxyFor, spkiSha256Hex } from '../src/providers/pinned-fetch.js'
import { type TlsFixture, httpsServer, selfSigned } from './helpers/tls.js'

describe('pinned TLS transport', () => {
  let tls: TlsFixture
  let server: Awaited<ReturnType<typeof httpsServer>>
  let pin: string

  beforeAll(async () => {
    tls = selfSigned()
    server = await httpsServer(tls, (req, res) => {
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ path: req.url }))
    })
    pin = spkiSha256Hex(new X509Certificate(tls.cert).raw)
  })
  afterAll(() => server?.close())

  it('computes sha256 over the DER SPKI', () => {
    const spki = new X509Certificate(tls.cert).publicKey.export({ type: 'spki', format: 'der' })
    expect(pin).toBe(createHash('sha256').update(spki).digest('hex'))
  })

  it('reaches a peer whose key is pinned', async () => {
    const pinned = createPinnedFetch({ baseURL: server.url, pins: [pin], ca: tls.cert, proxy: undefined })
    const res = await pinned.fetch(`${server.url}/v1/models`)
    expect(await res.json()).toEqual({ path: '/v1/models' })
    await pinned.close()
  })

  it('refuses a peer whose key is not pinned', async () => {
    const pinned = createPinnedFetch({ baseURL: server.url, pins: ['00'.repeat(32)], ca: tls.cert })
    await expect(pinned.fetch(`${server.url}/v1/models`)).rejects.toThrow()
    await pinned.close()
  })

  it('refuses other origins and plain http', async () => {
    const pinned = createPinnedFetch({ baseURL: server.url, pins: [pin], ca: tls.cert })
    await expect(pinned.fetch('https://example.com/v1/models')).rejects.toThrow(/origin/)
    await expect(pinned.fetch('http://localhost/v1/models')).rejects.toThrow(/http:/)
    await pinned.close()
    expect(() => createPinnedFetch({ baseURL: server.url, pins: [] })).toThrow(/at least one/)
  })

  it('still enforces normal chain validation', async () => {
    const pinned = createPinnedFetch({ baseURL: server.url, pins: [pin] })
    await expect(pinned.fetch(`${server.url}/x`)).rejects.toThrow()
    await pinned.close()
  })

  it('captures the SPKI of the connection that carried a response', async () => {
    const capturing = createCapturingFetch({ baseURL: server.url, ca: tls.cert })
    expect(capturing.observedSpki()).toBeUndefined()
    await (await capturing.fetch(`${server.url}/report`)).json()
    expect(capturing.observedSpki()).toBe(pin)
    await capturing.close()
  })

  it('selects the egress proxy from HTTPS_PROXY unless NO_PROXY matches', () => {
    const env = { HTTPS_PROXY: 'http://172.30.0.2:3128', NO_PROXY: 'localhost,.internal,inference-relay-litellm' }
    expect(proxyFor(new URL('https://cloud-api.near.ai'), env)).toBe('http://172.30.0.2:3128')
    expect(proxyFor(new URL('https://localhost:1'), env)).toBeUndefined()
    expect(proxyFor(new URL('https://a.internal'), env)).toBeUndefined()
    expect(proxyFor(new URL('https://x.example'), {})).toBeUndefined()
  })
})
