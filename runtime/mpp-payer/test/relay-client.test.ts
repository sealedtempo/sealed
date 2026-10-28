import { generatePrivateKey } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { describe, expect, it } from 'vitest'
import { RelayClient, type SessionManagerLike } from '../src/relay-client.js'
import { BudgetUnavailableError } from '../src/shared-budget.js'
import { PaymentPolicyError, SpendLimitError } from '../src/spend-guard.js'

const payee = ('0x' + 'ab'.repeat(20)) as `0x${string}`

function client(options: {
  session: (init: RequestInit, fetchImpl: (input: string, init?: RequestInit) => Promise<Response>) => Promise<AsyncIterable<string>>
  charge?: () => Promise<Response>
  relayFetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  payee?: `0x${string}` | undefined
}) {
  const created: Record<string, unknown>[] = []
  let now = 1_000
  const relay = new RelayClient({
    relayUrl: 'https://relay.example',
    account: Account.fromSecp256k1(generatePrivateKey()),
    getClient: () => ({}) as never,
    currency: '0x20c0000000000000000000000000000000000000',
    chainId: 4217,
    decimals: 6,
    maxDeposit: 500_000n,
    maxCharge: 50_000n,
    expectedPayee: () => ('payee' in options ? options.payee : payee),
    fetch: options.relayFetch ?? (async () => new Response(null, { status: 500 })),
    now: () => now,
    sessionManagerFactory: (parameters) => {
      created.push(parameters)
      const manager: SessionManagerLike = {
        sse: (_input, init) => options.session(init ?? {}, parameters.fetch as never),
        close: async () => {},
      }
      return manager
    },
    chargeClientFactory: (parameters) => {
      created.push({ charge: parameters })
      return { fetch: async () => (options.charge ? options.charge() : Response.json({ ok: true })) }
    },
  })
  return { relay, created, advance: (s: number) => void (now += s) }
}

describe('RelayClient', () => {
  it('uses a session with capped deposit, canonical escrow and bootstrap', async () => {
    const { relay, created } = client({ session: async () => (async function* () { yield 'x' })() })
    const result = await relay.chat({ model: 'm', messages: [] })
    expect(result.kind).toBe('session')
    expect(created[0]).toMatchObject({ maxDeposit: '0.5', allowedChainIds: [4217], escrow: '0x4d50500000000000000000000000000000000000', bootstrap: true, decimals: 6 })
  })

  it('falls back to a per-request charge when the session cannot be used, and retries sessions later', async () => {
    let sessionCalls = 0
    const { relay, created, advance } = client({
      session: async () => {
        sessionCalls++
        throw new Error('No session challenge offered')
      },
    })
    const first = await relay.chat({ model: 'm' })
    expect(first).toMatchObject({ kind: 'response', intent: 'charge' })
    expect(created.find((c) => 'charge' in c)).toMatchObject({ charge: { expectedRecipients: [payee], maxAmount: '0.05', mode: 'pull', expectedChainId: 4217 } })
    expect(relay.sessionsAvailable()).toBe(false)
    await relay.chat({ model: 'm' })
    expect(sessionCalls).toBe(1)
    advance(301)
    await relay.chat({ model: 'm' })
    expect(sessionCalls).toBe(2)
  })

  it('passes a relay refusal through without disabling sessions', async () => {
    const { relay } = client({
      relayFetch: async () => Response.json({ error: { type: 'attestation_failed', provider: 'nearai' } }, { status: 503 }),
      session: async (init, fetchImpl) => {
        await fetchImpl('https://relay.example/v1/chat/completions', { ...init, method: 'POST' })
        throw new Error('SSE response is not an event stream.')
      },
    })
    const result = await relay.chat({ model: 'nearai/x' })
    expect(result.kind).toBe('response')
    if (result.kind !== 'response') return
    expect(result.intent).toBe('refused')
    expect(result.response.status).toBe(503)
    expect(relay.sessionsAvailable()).toBe(true)
  })

  it('never falls back on payment policy violations, and surfaces spend limits from the charge path', async () => {
    const policy = client({ session: async () => Promise.reject(Object.assign(new Error('wrapped'), { cause: new PaymentPolicyError('recipient mismatch') })) })
    await expect(policy.relay.chat({})).rejects.toThrow(PaymentPolicyError)
    const limit = client({
      session: async () => Promise.reject(new SpendLimitError(500_000n, 100n)),
      charge: async () => Promise.reject(Object.assign(new Error('payment failed'), { cause: new SpendLimitError(40n, 10n) })),
    })
    await expect(limit.relay.chat({})).rejects.toThrow(SpendLimitError)
  })

  it('falls back to a charge when the shared budget cannot cover a deposit, but never when it is unavailable', async () => {
    const short = client({ session: async () => Promise.reject(Object.assign(new Error('open failed'), { cause: new SpendLimitError(500_360n, 9_000n, 'shared') })) })
    expect(await short.relay.chat({})).toMatchObject({ kind: 'response', intent: 'charge' })
    expect(short.relay.sessionsAvailable()).toBe(false)
    let charged = false
    const down = client({
      session: async () => Promise.reject(Object.assign(new Error('open failed'), { cause: new BudgetUnavailableError('sealed-agent spend budget unreachable') })),
      charge: async () => {
        charged = true
        return Response.json({})
      },
    })
    await expect(down.relay.chat({})).rejects.toThrow(BudgetUnavailableError)
    expect(charged).toBe(false)
    expect(down.relay.sessionsAvailable()).toBe(true)
  })

  it('refuses to pay before the relay payee is attested', async () => {
    const { relay } = client({ session: async () => (async function* () {})(), payee: undefined })
    await expect(relay.chat({})).rejects.toThrow(/attestation has not passed/)
  })
})
