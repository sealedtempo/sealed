import { Credential } from 'mppx'
import { Store } from 'mppx/server'
import { generatePrivateKey } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
// The real relay front and mppx server stand in for the remote relay.
import { createPayments } from '../../relay/src/payments.js'
import { parsePriceTable } from '../../relay/src/prices.js'
import { createRelayApp } from '../../relay/src/server.js'
import { Upstream } from '../../relay/src/upstream.js'
import { DEV_KEYS, PATHUSD, anvilAvailable, startLocalTempo, type LocalTempo } from '../../relay/test/helpers/anvil.js'
import { ESCROW, emulatedEscrowNode } from '../../relay/test/helpers/escrow-emulator.js'
import { fakeLiteLLM } from '../../relay/test/helpers/fake-litellm.js'
import { RelayAttestationGate } from '../src/attestation-gate.js'
import { paymentFirewall } from '../src/payment-firewall.js'
import { RelayClient } from '../src/relay-client.js'
import { createPayerApp } from '../src/server.js'
import { SpendGuard } from '../src/spend-guard.js'
import { fakeAttest, fakeVerifierd, relayAppCompose } from './helpers/fake-relay-attest.js'

/**
 * The preferred payment path, end to end with real mppx on both sides: the payer's
 * tempo.session.manager (through the payment firewall) against the relay's tempo.session server
 * (sse: true, usd_micro unit, SessionMeter charging stream.charge(amount)). Transactions are
 * signed by the payer and the relay's settler and mined by a local anvil; the TIP-1034 escrow
 * precompile, which Foundry 1.7.1 lacks, is emulated in the RPC layer
 * (relay/test/helpers/escrow-emulator.ts). What this cannot show: the precompile's own checks
 * and token movements on a real Tempo node.
 */
const prices = parsePriceTable(
  {
    currency: PATHUSD,
    decimals: 6,
    models: [{ id: 'nearai/z-ai/glm-5.3', provider: 'nearai', upstream_model: 'z-ai/glm-5.3', input_per_1m: 1800000, output_per_1m: 5750000, max_output_tokens: 256 }],
  },
  500,
)

describe.skipIf(!anvilAvailable())('MPP session over SSE with real mppx client and server (emulated TIP-1034 escrow)', () => {
  let node: LocalTempo
  let chain: ReturnType<typeof emulatedEscrowNode>
  const treasury = Account.fromSecp256k1(generatePrivateKey()).address.toLowerCase() as `0x${string}`
  const settler = Account.fromSecp256k1(DEV_KEYS[3])
  const payerAccount = Account.fromSecp256k1(DEV_KEYS[4])

  beforeAll(async () => {
    node = await startLocalTempo()
    chain = emulatedEscrowNode(node.rpcUrl)
  }, 60_000)
  afterAll(() => node?.stop())

  function stack(account: ReturnType<typeof Account.fromSecp256k1> = payerAccount) {
    const llm = fakeLiteLLM({ words: ['Metered', ' per', ' token', ' over', ' SSE'], usage: { prompt_tokens: 12, completion_tokens: 5 } })
    const store = Store.memory()
    const credited: bigint[] = []
    const payments = createPayments({
      realm: 'relay.sealed.test',
      secretKey: 'test-secret-key-that-is-at-least-32-bytes',
      recipient: treasury,
      currency: PATHUSD,
      decimals: 6,
      chainId: 4217,
      store,
      getClient: () => chain.client as never,
      settler,
      suggestedDeposit: '0.2',
    })
    const relayApp = createRelayApp({
      prices,
      gate: { allows: () => true, status: (p: string) => ({ provider: p, enabled: true, verified: true, detail: 'ok' }), all: () => [] } as never,
      payments: {
        ...payments,
        credit: async (channelId, amount, key) => {
          credited.push(amount)
          return payments.credit(channelId, amount, key)
        },
      },
      upstream: new Upstream({ baseURL: 'http://litellm/v1', apiKey: 'sk-master', fetch: llm.fetch }),
      batchTokens: 2,
    })
    const wire: { method: string; intent?: string; action?: string; cumulative?: bigint; status: number }[] = []
    const relayFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      let intent: string | undefined
      let action: string | undefined
      let cumulative: bigint | undefined
      const auth = request.headers.get('authorization')
      if (auth?.startsWith('Payment ')) {
        const credential = Credential.deserialize<{ action?: string; cumulativeAmount?: string }>(auth)
        intent = credential.challenge.intent
        action = credential.payload.action
        if (credential.payload.cumulativeAmount !== undefined) cumulative = BigInt(credential.payload.cumulativeAmount)
      }
      const response = await relayApp.fetch(request)
      wire.push({ method: request.method, intent, action, cumulative, status: response.status })
      return response
    }
    const gate = new RelayAttestationGate({
      attestUrl: 'https://relay.sealed.test/attest',
      verifierdUrl: 'http://sealed-verifierd:8088',
      relayOwner: ('0x' + '0a'.repeat(20)) as `0x${string}`,
      intervalSeconds: 900,
      fetchAttest: fakeAttest({ appCompose: relayAppCompose(treasury) }).fetchAttest,
      fetchVerifier: fakeVerifierd().fetchVerifier,
    })
    const guard = new SpendGuard(2_000_000n)
    const firewalled = paymentFirewall(
      relayFetch,
      { payerAddress: account.address, currency: PATHUSD, allowedChainIds: [4217], maxCharge: 50_000n, maxDeposit: 200_000n, expectedPayee: () => gate.payee() },
      guard,
    )
    const relay = new RelayClient({
      relayUrl: 'https://relay.sealed.test',
      account,
      getClient: () => chain.client as never,
      currency: PATHUSD,
      chainId: 4217,
      decimals: 6,
      maxDeposit: 200_000n,
      maxCharge: 50_000n,
      expectedPayee: () => gate.payee(),
      fetch: firewalled,
    })
    const payer = createPayerApp({
      gate,
      relay,
      models: () => relayFetch('https://relay.sealed.test/v1/models'),
      callers: { allows: () => true },
      remoteAddress: () => '172.30.0.16',
    })
    return { payer, relay, guard, llm, wire, credited, store }
  }

  const post = (b: unknown) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
  const body = { model: 'nearai/z-ai/glm-5.3', messages: [{ role: 'user', content: 'meter me' }], max_tokens: 64 }

  it('opens a channel, streams with vouchers posted through the firewall, then closes cooperatively', async () => {
    const { payer, relay, guard, llm, wire, credited } = stack()
    const res = await payer.request('/v1/chat/completions', post({ ...body, stream: true }))
    expect(res.status).toBe(200)
    const text = await res.text()
    const content = [...text.matchAll(/^data: (\{.*\})$/gm)]
      .map((m) => JSON.parse(m[1]!))
      .flatMap((c) => (c.choices ?? []).map((x: any) => x.delta?.content ?? ''))
      .join('')
    expect(content).toBe('Metered per token over SSE')
    expect(text.trimEnd().endsWith('data: [DONE]')).toBe(true)
    expect(relay.sessionsAvailable()).toBe(true)
    expect(llm.calls[0]!.body).toMatchObject({ stream: true, stream_options: { include_usage: true }, max_tokens: 64 })

    // One channel opened on chain for the attested payee, in pathUSD, at the canonical escrow.
    const channels = [...chain.channels.values()]
    expect(channels).toHaveLength(1)
    const channel = channels[0]!
    expect(channel.descriptor.payee.toLowerCase()).toBe(treasury)
    expect(channel.descriptor.token.toLowerCase()).toBe(PATHUSD)
    expect(channel.descriptor.payer.toLowerCase()).toBe(payerAccount.address.toLowerCase())
    expect(chain.events.map((e) => e.name)).toContain('ChannelOpened')

    // The firewall reserved exactly the deposit, and saw the vouchers.
    const counters = guard.counters()
    expect(counters).toMatchObject({ deposits: 1, depositAmount: channel.deposit.toString(), charges: 0 })
    expect(BigInt(counters.sessionAuthorized)).toBeGreaterThan(0n)
    const actions = wire.filter((w) => w.intent === 'session').map((w) => w.action)
    expect(actions[0]).toBe('open')
    expect(actions.filter((a) => a === 'voucher').length).toBeGreaterThan(0)
    expect(wire.every((w) => w.intent !== 'charge')).toBe(true)

    // Usage {12 prompt, 5 completion}: (12 x 1.8 + 5 x 5.75) x 1.05 = 52.8 -> 53 base units after credit.
    const authorized = BigInt(counters.sessionAuthorized)
    const creditedTotal = credited.reduce((a, b) => a + b, 0n)
    expect(authorized - creditedTotal).toBe(53n)

    // A second request reuses the channel (no second open, no second deposit).
    const again = await payer.request('/v1/chat/completions', post(body))
    expect(again.status).toBe(200)
    expect((await again.json()).choices[0].message.content).toBe('Metered per token over SSE')
    expect(chain.channels.size).toBe(1)
    expect(guard.counters().deposits).toBe(1)

    // Cooperative close: the relay's settler captures what was spent and the rest is refunded,
    // which the spend guard gives back to the day's budget.
    await relay.close()
    expect(chain.events.map((e) => e.name)).toContain('ChannelClosed')
    const closed = chain.events.find((e) => e.name === 'ChannelClosed')!
    const refunded = closed.args.refundedToPayer as bigint
    expect(refunded).toBeGreaterThan(0n)
    // The guard returns deposit minus the close voucher (the most the relay may capture); the
    // relay captures only what it charged after credits, so the real refund can be larger.
    const close = wire.find((w) => w.action === 'close')!
    expect([200, 204]).toContain(close.status)
    const final = guard.counters()
    expect(BigInt(final.refunded)).toBe(channel.deposit - close.cumulative!)
    expect(BigInt(final.refunded)).toBeLessThanOrEqual(refunded)
    expect(final.sessionAuthorized).toBe('0')
  }, 120_000)

  it('pays from the customer account through an access key (the production signer mode)', async () => {
    const customer = Account.fromSecp256k1(DEV_KEYS[5])
    const accessKey = Account.fromSecp256k1(generatePrivateKey(), { access: customer })
    await node.client.accessKey.authorize({ account: customer, accessKey, expiry: Math.floor(Date.now() / 1000) + 3600 } as never)
    for (let i = 0; i < 50; i++) {
      const meta = (await node.client.accessKey.getMetadata({ account: customer.address, accessKey: accessKey.accessKeyAddress } as never)) as { address: string }
      if (meta.address.toLowerCase() === accessKey.accessKeyAddress.toLowerCase()) break
      await new Promise((r) => setTimeout(r, 300))
    }
    const before = chain.channels.size
    const { payer, relay, guard } = stack(accessKey)
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(200)
    expect((await res.json()).choices[0].message.content).toBe('Metered per token over SSE')
    expect(relay.sessionsAvailable()).toBe(true)
    const opened = [...chain.channels.values()].slice(before)
    expect(opened).toHaveLength(1)
    // Money leaves the customer's root account; the access key only authorizes vouchers.
    expect(opened[0]!.descriptor.payer.toLowerCase()).toBe(customer.address.toLowerCase())
    expect(opened[0]!.descriptor.authorizedSigner.toLowerCase()).toBe(accessKey.accessKeyAddress.toLowerCase())
    expect(guard.counters().deposits).toBe(1)
    await relay.close()
  }, 120_000)

  it('the escrow emulator answers the views mppx reads', async () => {
    const id = [...chain.channels.keys()][0]!
    const state = (await chain.client.readContract({
      address: ESCROW,
      abi: [{ type: 'function', name: 'getChannelState', stateMutability: 'view', inputs: [{ name: 'channelId', type: 'bytes32' }], outputs: [{ type: 'tuple', components: [{ name: 'settled', type: 'uint96' }, { name: 'deposit', type: 'uint96' }, { name: 'closeRequestedAt', type: 'uint32' }] }] }],
      functionName: 'getChannelState',
      args: [id],
    })) as { deposit: bigint }
    expect(state.deposit).toBe(0n)
  })
})
