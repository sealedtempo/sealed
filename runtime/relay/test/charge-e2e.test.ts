import { Challenge } from 'mppx'
import { Mppx as ClientMppx, tempo as clientTempo } from 'mppx/client'
import { Store } from 'mppx/server'
import { Account } from 'viem/tempo'
import { generatePrivateKey } from 'viem/accounts'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createPayments } from '../src/payments.js'
import { parsePriceTable } from '../src/prices.js'
import { createRelayApp, perRequestPrice } from '../src/server.js'
import { Upstream } from '../src/upstream.js'
import { DEV_KEYS, type LocalTempo, PATHUSD, anvilAvailable, balanceOf, startLocalTempo } from './helpers/anvil.js'
import { fakeLiteLLM } from './helpers/fake-litellm.js'

const prices = parsePriceTable(
  {
    currency: PATHUSD,
    decimals: 6,
    models: [{ id: 'tinfoil/gpt-oss-120b', provider: 'tinfoil', upstream_model: 'gpt-oss-120b', input_per_1m: 240000, output_per_1m: 780000, max_output_tokens: 256 }],
  },
  500,
)

async function waitFor(check: () => Promise<boolean>, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error('timed out waiting for chain state')
    await new Promise((r) => setTimeout(r, 300))
  }
}

const gate = {
  allows: () => true,
  status: (provider: string) => ({ provider, enabled: true, verified: true, detail: 'attestation verified' }),
  all: () => [],
} as never

describe.skipIf(!anvilAvailable())('MPP per-request charge, end to end on a local Tempo node', () => {
  let node: LocalTempo
  const treasury = Account.fromSecp256k1(generatePrivateKey()).address

  beforeAll(async () => {
    node = await startLocalTempo()
  })
  afterAll(() => node?.stop())

  function relayWith(settler = false) {
    const llm = fakeLiteLLM()
    const payments = createPayments({
      realm: 'relay.sealed.test',
      secretKey: 'test-secret-key-that-is-at-least-32-bytes',
      recipient: treasury,
      currency: PATHUSD,
      decimals: 6,
      chainId: 4217,
      store: Store.memory(),
      getClient: () => node.client as never,
      settler: settler ? Account.fromSecp256k1(generatePrivateKey()) : undefined,
      suggestedDeposit: '0.5',
    })
    const app = createRelayApp({
      prices,
      gate,
      payments,
      upstream: new Upstream({ baseURL: 'http://litellm/v1', apiKey: 'sk-master', fetch: llm.fetch }),
      batchTokens: 16,
    })
    return { app, llm, fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => app.fetch(new Request(input, init)) }
  }

  const body = { model: 'tinfoil/gpt-oss-120b', messages: [{ role: 'user', content: 'hi' }], max_tokens: 64 }

  it('advertises both a per-request charge and a per-token session when sessions are enabled', async () => {
    const relay = relayWith(true)
    const res = await relay.fetch('http://relay.sealed.test/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    expect(res.status).toBe(402)
    const challenges = Challenge.fromResponseList(res)
    const intents = challenges.map((c) => c.intent).sort()
    expect(intents).toEqual(['charge', 'session'])
    const session = challenges.find((c) => c.intent === 'session')!
    expect(session.request).toMatchObject({ currency: PATHUSD, unitType: 'usd_micro', recipient: treasury })
    const charge = challenges.find((c) => c.intent === 'charge')!
    expect(charge.request).toMatchObject({ currency: PATHUSD, recipient: treasury })
  })

  it('pays the treasury exactly the quoted amount from a root account and forwards the request', async () => {
    const relay = relayWith(false)
    const payer = Account.fromSecp256k1(DEV_KEYS[3])
    const client = ClientMppx.create({
      polyfill: false,
      fetch: relay.fetch,
      methods: [
        clientTempo.charge({
          account: payer,
          getClient: () => node.client as never,
          currencies: [PATHUSD],
          expectedRecipients: [treasury],
          expectedChainId: 4217,
          decimals: 6,
          maxAmount: '0.05',
        } as never),
      ],
    })
    const before = await balanceOf(node.client, treasury)
    const res = await client.fetch('http://relay.sealed.test/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('payment-receipt')).toBeTruthy()
    expect((await res.json()).choices[0].message.content).toBe('Hello from the relay')
    const quoted = perRequestPrice(prices, prices.models[0]!, body).amount
    expect((await balanceOf(node.client, treasury)) - before).toBe(quoted)
    expect(relay.llm.calls.length).toBe(1)
  })

  it('pays from a Tempo access key acting for its root account (access-key mode)', async () => {
    const relay = relayWith(false)
    const root = Account.fromSecp256k1(DEV_KEYS[4])
    const accessKey = Account.fromSecp256k1(generatePrivateKey(), { access: root })
    // Foundry 1.7.1's T4 node drops key authorizations that carry spending limits (viem 2.57.13 encodes the
    // post-T3 limit format), so the local key is authorized without limits; limits are verified on mainnet only.
    await node.client.accessKey.authorize({ account: root, accessKey, expiry: Math.floor(Date.now() / 1000) + 3600 } as never)
    await waitFor(async () => {
      const meta = (await node.client.accessKey.getMetadata({ account: root.address, accessKey: accessKey.accessKeyAddress } as never)) as { address: string }
      return meta.address.toLowerCase() === accessKey.accessKeyAddress.toLowerCase()
    })
    const client = ClientMppx.create({
      polyfill: false,
      fetch: relay.fetch,
      methods: [clientTempo.charge({ account: accessKey, getClient: () => node.client as never, currencies: [PATHUSD], expectedRecipients: [treasury], expectedChainId: 4217, decimals: 6 } as never)],
    })
    const rootBefore = await balanceOf(node.client, root.address)
    const treasuryBefore = await balanceOf(node.client, treasury)
    const res = await client.fetch('http://relay.sealed.test/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    expect(res.status).toBe(200)
    await res.text()
    const quoted = perRequestPrice(prices, prices.models[0]!, body).amount
    expect((await balanceOf(node.client, treasury)) - treasuryBefore).toBe(quoted)
    // the customer's root account pays (the amount plus its own network fee)
    expect(rootBefore - (await balanceOf(node.client, root.address)) >= quoted).toBe(true)
  })

  it('refuses a replayed credential', async () => {
    const relay = relayWith(false)
    const payer = Account.fromSecp256k1(DEV_KEYS[5])
    let credential: string | undefined
    const client = ClientMppx.create({
      polyfill: false,
      fetch: async (input, init) => {
        const auth = new Headers(init?.headers).get('authorization')
        if (auth?.startsWith('Payment ')) credential = auth
        return relay.fetch(input, init)
      },
      methods: [clientTempo.charge({ account: payer, getClient: () => node.client as never, currencies: [PATHUSD], expectedChainId: 4217, decimals: 6 } as never)],
    })
    const init = { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
    expect((await client.fetch('http://relay.sealed.test/v1/chat/completions', init)).status).toBe(200)
    const replay = await relay.fetch('http://relay.sealed.test/v1/chat/completions', {
      ...init,
      headers: { ...init.headers, authorization: credential! },
    })
    expect(replay.status).not.toBe(200)
    expect(relay.llm.calls.length).toBe(1)
  })
})
