import { X509Certificate } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { generatePrivateKey } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { type TlsFixture, httpsServer, selfSigned } from '../../relay/test/helpers/tls.js'
import { RelayAttestationGate } from '../src/attestation-gate.js'
import { paymentFirewall } from '../src/payment-firewall.js'
import { RelayClient } from '../src/relay-client.js'
import { PinnedRelayTransport, RelayChannelError, RelayPinError, wasNotSent } from '../src/relay-transport.js'
import { createPayerApp } from '../src/server.js'
import { SpendGuard } from '../src/spend-guard.js'
import { tlsPubKeyHash } from '../src/tls-capture.js'
import { fakeAttest, fakeVerifierd } from './helpers/fake-relay-attest.js'

type Seen = { method: string; url: string; body: string; headers: IncomingMessage['headers'] }

function recordingHandler(seen: Seen[]) {
  return (req: IncomingMessage, res: ServerResponse) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      seen.push({ method: req.method ?? '', url: req.url ?? '', body, headers: req.headers })
      if (req.url === '/v1/stream') {
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        res.write('data: one\n\n')
        setTimeout(() => res.end('data: [DONE]\n\n'), 20)
        return
      }
      if (req.url === '/v1/empty') {
        res.writeHead(204)
        res.end()
        return
      }
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ path: req.url, echoed: body }))
    })
  }
}

describe('TLS-pinned relay transport', () => {
  let attested: TlsFixture
  let impostor: TlsFixture
  let relay: Awaited<ReturnType<typeof httpsServer>>
  let fake: Awaited<ReturnType<typeof httpsServer>>
  const seenRelay: Seen[] = []
  const seenFake: Seen[] = []
  let attestedPin: `0x${string}`
  let impostorPin: `0x${string}`
  // Both certificates are for localhost; trust both so only the pin tells them apart.
  let ca: string

  beforeAll(async () => {
    attested = selfSigned('attested relay')
    impostor = selfSigned('impostor relay')
    relay = await httpsServer(attested, recordingHandler(seenRelay))
    fake = await httpsServer(impostor, recordingHandler(seenFake))
    attestedPin = tlsPubKeyHash(new X509Certificate(attested.cert).raw)
    impostorPin = tlsPubKeyHash(new X509Certificate(impostor.cert).raw)
    ca = attested.cert + impostor.cert
  })
  afterAll(async () => {
    await relay?.close()
    await fake?.close()
  })

  it('sends over a connection presenting the attested key, keeping method, headers, body and streams', async () => {
    const t = new PinnedRelayTransport({ origin: relay.url, pin: () => attestedPin, ca, proxy: undefined })
    const res = await t.fetch(`${relay.url}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Payment abc' },
      body: '{"x":1}',
    })
    expect(await res.json()).toEqual({ path: '/v1/chat/completions', echoed: '{"x":1}' })
    expect(seenRelay.at(-1)).toMatchObject({ method: 'POST', body: '{"x":1}', headers: { authorization: 'Payment abc' } })
    const stream = await t.fetch(new Request(`${relay.url}/v1/stream`))
    expect(stream.headers.get('content-type')).toBe('text/event-stream')
    expect(await stream.text()).toBe('data: one\n\ndata: [DONE]\n\n')
    expect((await t.fetch(`${relay.url}/v1/empty`)).status).toBe(204)
    await t.close()
  })

  it('refuses a relay serving another key before writing a byte of the request', async () => {
    const before = seenFake.length
    const t = new PinnedRelayTransport({ origin: fake.url, pin: () => attestedPin, ca })
    const error = await t.fetch(`${fake.url}/v1/chat/completions`, { method: 'POST', body: '{"prompt":"secret"}' }).catch((e) => e)
    expect(error).toBeInstanceOf(RelayPinError)
    expect(error.observed).toBe(impostorPin)
    expect(wasNotSent(error)).toBe(true)
    expect(seenFake.length).toBe(before)
    await t.close()
  })

  it('refuses without a pin, and to any other origin', async () => {
    const closed = new PinnedRelayTransport({ origin: relay.url, pin: () => undefined, ca })
    await expect(closed.fetch(`${relay.url}/v1/models`)).rejects.toBeInstanceOf(RelayChannelError)
    const open = new PinnedRelayTransport({ origin: relay.url, pin: () => attestedPin, ca })
    await expect(open.fetch('https://example.com/v1/models')).rejects.toThrow(/only talks to the attested relay origin/)
    expect(() => new PinnedRelayTransport({ origin: 'http://relay.example', pin: () => attestedPin })).toThrow(/https/)
  })

  it('re-attests once after a key mismatch and retries only if the attested key changed', async () => {
    let pin: `0x${string}` = impostorPin
    let repins = 0
    const before = seenRelay.length
    const t = new PinnedRelayTransport({
      origin: relay.url,
      pin: () => pin,
      ca,
      repin: async () => {
        repins++
        pin = attestedPin // the relay renewed its certificate and the new key is attested
      },
    })
    expect((await t.fetch(`${relay.url}/v1/models`)).status).toBe(200)
    expect(repins).toBe(1)
    expect(seenRelay.length).toBe(before + 1)
    const stuck = new PinnedRelayTransport({ origin: relay.url, pin: () => impostorPin, ca, repin: async () => void repins++ })
    await expect(stuck.fetch(`${relay.url}/v1/models`)).rejects.toBeInstanceOf(RelayPinError)
    expect(repins).toBe(2)
    expect(seenRelay.length).toBe(before + 1)
    await t.close()
  })

  it('sends no prompt and spends nothing when the relay host serves a key the attestation did not bind', async () => {
    // The attest endpoint (same origin) bound the attested key, but the connection the payer gets presents another.
    const attest = fakeAttest({ observed: attestedPin })
    const gate = new RelayAttestationGate({
      attestUrl: `${fake.url}/attest`,
      verifierdUrl: 'http://sealed-verifierd:8088',
      relayOwner: ('0x' + '0a'.repeat(20)) as `0x${string}`,
      intervalSeconds: 900,
      fetchAttest: attest.fetchAttest,
      fetchVerifier: fakeVerifierd().fetchVerifier,
    })
    const transport = new PinnedRelayTransport({ origin: fake.url, pin: () => gate.pin(), repin: () => gate.recheckAfterKeyMismatch(), ca })
    const guard = new SpendGuard(2_000_000n)
    const firewalled = paymentFirewall(
      transport.fetch,
      {
        payerAddress: ('0x' + '11'.repeat(20)) as `0x${string}`,
        currency: '0x20c0000000000000000000000000000000000000',
        allowedChainIds: [4217],
        maxCharge: 50_000n,
        maxDeposit: 200_000n,
        expectedPayee: () => gate.payee(),
      },
      guard,
    )
    const relayClient = new RelayClient({
      relayUrl: fake.url,
      account: Account.fromSecp256k1(generatePrivateKey()),
      getClient: () => ({}) as never,
      currency: '0x20c0000000000000000000000000000000000000',
      chainId: 4217,
      decimals: 6,
      maxDeposit: 200_000n,
      maxCharge: 50_000n,
      expectedPayee: () => gate.payee(),
      fetch: firewalled,
    })
    const payer = createPayerApp({
      gate,
      relay: relayClient,
      models: () => transport.fetch(`${fake.url}/v1/models`),
      callers: { allows: () => true },
      remoteAddress: () => '127.0.0.1',
    })
    const before = seenFake.length
    const res = await payer.request('/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'tinfoil/gpt-oss-120b', messages: [{ role: 'user', content: 'private prompt' }] }),
    })
    expect(res.status).toBe(503)
    expect((await res.json()).error).toMatchObject({ type: 'relay_attestation_failed' })
    expect((await payer.request('/v1/models')).status).toBe(503)
    expect(seenFake.length).toBe(before)
    expect(guard.counters()).toMatchObject({ debited: '0', charges: 0, deposits: 0 })
    expect(relayClient.sessionsAvailable()).toBe(true)
    await transport.close()
  })
})
