import { Store } from 'mppx/server'
import { generatePrivateKey } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
// The real relay front, from the sibling workspace package, stands in for the remote relay.
import { createPayments } from '../../relay/src/payments.js'
import { parsePriceTable } from '../../relay/src/prices.js'
import { createRelayApp, perRequestPrice } from '../../relay/src/server.js'
import { Upstream } from '../../relay/src/upstream.js'
import { DEV_KEYS, type LocalTempo, PATHUSD, anvilAvailable, balanceOf, startLocalTempo } from '../../relay/test/helpers/anvil.js'
import { fakeLiteLLM } from '../../relay/test/helpers/fake-litellm.js'
import { RelayAttestationGate } from '../src/attestation-gate.js'
import { paymentFirewall } from '../src/payment-firewall.js'
import { RelayClient } from '../src/relay-client.js'
import { createPayerApp } from '../src/server.js'
import { SpendGuard } from '../src/spend-guard.js'
import { fakeAgentBudget } from './helpers/fake-agent-budget.js'
import { fakeAttest, fakeVerifierd, relayAppCompose } from './helpers/fake-relay-attest.js'

const prices = parsePriceTable(
  {
    currency: PATHUSD,
    decimals: 6,
    models: [{ id: 'tinfoil/gpt-oss-120b', provider: 'tinfoil', upstream_model: 'gpt-oss-120b', input_per_1m: 240000, output_per_1m: 780000, max_output_tokens: 128 }],
  },
  500,
)

async function waitFor(check: () => Promise<boolean>, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 300))
  }
}

describe.skipIf(!anvilAvailable())('payer -> relay -> LiteLLM, paid with mppx on a local Tempo node', () => {
  let node: LocalTempo
  const treasury = Account.fromSecp256k1(generatePrivateKey()).address.toLowerCase() as `0x${string}`
  const customer = Account.fromSecp256k1(DEV_KEYS[5])
  const enclaveKey = generatePrivateKey()
  // access-key mode: the enclave key signs for the customer's root account
  const payerAccount = Account.fromSecp256k1(enclaveKey, { access: customer })

  beforeAll(async () => {
    node = await startLocalTempo()
    await node.client.accessKey.authorize({ account: customer, accessKey: payerAccount, expiry: Math.floor(Date.now() / 1000) + 3600 } as never)
    await waitFor(async () => {
      const meta = (await node.client.accessKey.getMetadata({ account: customer.address, accessKey: payerAccount.accessKeyAddress } as never)) as { address: string }
      return meta.address.toLowerCase() === payerAccount.accessKeyAddress.toLowerCase()
    })
  }, 60_000)
  afterAll(() => node?.stop())

  /** The payer draws from sealed-agent's shared budget (first cap) and its local guard (second cap). */
  function stack(options: { sessions: boolean; limit: bigint; verifierOk?: boolean; agent?: ReturnType<typeof fakeAgentBudget> }) {
    const agent = options.agent ?? fakeAgentBudget({ budget: 2_000_000n })
    const llm = fakeLiteLLM({ words: ['Paid', ' and', ' delivered'] })
    const relayApp = createRelayApp({
      prices,
      gate: { allows: () => true, status: (p: string) => ({ provider: p, enabled: true, verified: true, detail: 'ok' }), all: () => [] } as never,
      payments: createPayments({
        realm: 'relay.sealed.test',
        secretKey: 'test-secret-key-that-is-at-least-32-bytes',
        recipient: treasury,
        currency: PATHUSD,
        decimals: 6,
        chainId: 4217,
        store: Store.memory(),
        getClient: () => node.client as never,
        settler: options.sessions ? Account.fromSecp256k1(generatePrivateKey()) : undefined,
        suggestedDeposit: '0.2',
      }),
      upstream: new Upstream({ baseURL: 'http://litellm/v1', apiKey: 'sk-master', fetch: llm.fetch }),
      batchTokens: 16,
    })
    const relayFetch = async (input: RequestInfo | URL, init?: RequestInit) => relayApp.fetch(new Request(input, init))
    const verifier = fakeVerifierd({ ok: options.verifierOk ?? true })
    const gate = new RelayAttestationGate({
      attestUrl: 'https://relay.sealed.test/attest',
      verifierdUrl: 'http://sealed-verifierd:8088',
      relayOwner: ('0x' + '0a'.repeat(20)) as `0x${string}`,
      intervalSeconds: 900,
      retrySeconds: 0,
      fetchAttest: fakeAttest({ appCompose: relayAppCompose(treasury) }).fetchAttest,
      fetchVerifier: verifier.fetchVerifier,
    })
    const guard = new SpendGuard(options.limit)
    const firewalled = paymentFirewall(
      relayFetch,
      { payerAddress: payerAccount.address, currency: PATHUSD, allowedChainIds: [4217], maxCharge: 50_000n, maxDeposit: 200_000n, expectedPayee: () => gate.payee() },
      guard,
      agent.budget,
    )
    const relay = new RelayClient({
      relayUrl: 'https://relay.sealed.test',
      account: payerAccount,
      getClient: () => node.client as never,
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
    return { payer, llm, guard, relay, verifier, agent }
  }

  const body = { model: 'tinfoil/gpt-oss-120b', messages: [{ role: 'user', content: 'pay me' }], max_tokens: 32 }
  const post = (b: unknown) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

  it('pays a per-request charge from the customer account via the access key and returns the completion', async () => {
    const { payer, llm, guard, agent } = stack({ sessions: false, limit: 2_000_000n })
    const before = await balanceOf(node.client, treasury)
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(200)
    expect((await res.json()).choices[0].message.content).toBe('Paid and delivered')
    const quoted = perRequestPrice(prices, prices.models[0]!, body).amount
    expect((await balanceOf(node.client, treasury)) - before).toBe(quoted)
    expect(llm.calls.length).toBe(1)
    expect(guard.counters()).toMatchObject({ charges: 1, chargeAmount: quoted.toString() })
    // The shared budget saw one reservation for the charge plus its network fee cap, released as
    // used; the unpaid first attempt (402) never reserved anything.
    const fee = BigInt(guard.counters().debited) - quoted
    expect(fee).toBeGreaterThan(0n)
    expect(agent.calls.map((c) => c.path)).toEqual(['/v1/spend/reserve', '/v1/spend/release'])
    expect(agent.calls[0]!.body.amount).toBe((quoted + fee).toString())
    expect(agent.state.used).toBe(quoted + fee)
    expect(agent.state.reservations.size).toBe(0)
  })

  it('refuses before paying when fee settlement holds the shared budget, though the local guard allows it', async () => {
    // The agent keeps the next settlement's estimated fees: the payer may reserve only 100 base units.
    const agent = fakeAgentBudget({ budget: 2_000_000n, reservedForFees: 1_999_900n })
    const { payer, llm, guard } = stack({ sessions: false, limit: 2_000_000n, agent })
    const before = await balanceOf(node.client, treasury)
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(429)
    const error = (await res.json()).error
    expect(error.type).toBe('spend_limit_exceeded')
    expect(error.message).toMatch(/fee settlement has priority/)
    expect(await balanceOf(node.client, treasury)).toBe(before)
    expect(llm.calls.length).toBe(0)
    expect(guard.counters()).toMatchObject({ debited: '0', charges: 0 })
    expect(agent.state.used).toBe(0n)
  })

  it('answers 503 and pays nothing while the shared budget is unavailable', async () => {
    const agent = fakeAgentBudget({ budget: 2_000_000n })
    agent.state.down = true
    const { payer, llm, guard } = stack({ sessions: true, limit: 2_000_000n, agent })
    const before = await balanceOf(node.client, treasury)
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(503)
    expect((await res.json()).error.type).toBe('spend_budget_unavailable')
    expect(await balanceOf(node.client, treasury)).toBe(before)
    expect(llm.calls.length).toBe(0)
    expect(guard.counters().debited).toBe('0')
    agent.state.down = false
    expect((await payer.request('/v1/chat/completions', post(body))).status).toBe(200)
  })

  it('streams through the charge path when the client asked for a stream', async () => {
    const { payer } = stack({ sessions: false, limit: 2_000_000n })
    const res = await payer.request('/v1/chat/completions', post({ ...body, stream: true }))
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('data: [DONE]')
    expect(text).toContain('Paid')
  })

  it('falls back from sessions to per-request charges when no channel can be opened locally', async () => {
    const { payer, llm, relay } = stack({ sessions: true, limit: 2_000_000n })
    const before = await balanceOf(node.client, treasury)
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(200)
    expect((await res.json()).choices[0].message.content).toBe('Paid and delivered')
    expect(relay.sessionsAvailable()).toBe(false)
    expect((await balanceOf(node.client, treasury)) - before).toBe(perRequestPrice(prices, prices.models[0]!, body).amount)
    expect(llm.calls.length).toBe(1)
  })

  it('refuses before paying when the daily limit would be exceeded', async () => {
    const { payer, llm, guard } = stack({ sessions: false, limit: 10n })
    const before = await balanceOf(node.client, treasury)
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(429)
    expect((await res.json()).error.type).toBe('spend_limit_exceeded')
    expect(await balanceOf(node.client, treasury)).toBe(before)
    expect(llm.calls.length).toBe(0)
    expect(guard.counters().refused).toBe(1)
  })

  it('sends nothing to the relay while its attestation fails', async () => {
    const { payer, llm, verifier } = stack({ sessions: false, limit: 2_000_000n, verifierOk: false })
    const res = await payer.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(503)
    expect(llm.calls.length).toBe(0)
    verifier.state.ok = true
    expect((await payer.request('/v1/chat/completions', post(body))).status).toBe(200)
  })
})
