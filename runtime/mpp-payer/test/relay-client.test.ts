import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { hashTypedData, recoverAddress } from 'viem'
import { generatePrivateKey } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { describe, expect, it } from 'vitest'
import { ChannelJournal, FileKv } from '../src/channel-journal.js'
import { RelayClient, RelaySessionFailedError, type SessionManagerLike, withPrimitiveCloseSignatures } from '../src/relay-client.js'
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

  it('never sends a session request again as a charge once its paid attempt reached the relay (M3)', async () => {
    let charged = false
    const { relay } = client({
      relayFetch: async () => new Response('event: message\ndata: x\n\n', { headers: { 'content-type': 'text/event-stream' } }),
      session: async (init, fetchImpl) => {
        // mppx's paid retry: the credential and the prompt reach the relay, then the stream breaks.
        await fetchImpl('https://relay.example/v1/chat/completions', { ...init, method: 'POST', headers: { ...(init.headers as Record<string, string>), authorization: 'Payment voucher' } })
        throw new TypeError('terminated: other side closed')
      },
      charge: async () => {
        charged = true
        return Response.json({})
      },
    })
    await expect(relay.chat({ model: 'm' })).rejects.toThrow(RelaySessionFailedError)
    expect(charged).toBe(false)
    expect(relay.sessionsAvailable()).toBe(true)
  })

  it('falls back to a charge when the session failed before its paid attempt left (an unpaid 402 does not count)', async () => {
    let charged = 0
    const { relay } = client({
      relayFetch: async () => new Response(null, { status: 402 }),
      session: async (init, fetchImpl) => {
        await fetchImpl('https://relay.example/v1/chat/completions', { ...init, method: 'POST' })
        await fetchImpl('https://relay.example/v1/chat/completions', { ...init, method: 'POST', headers: { ...(init.headers as Record<string, string>), authorization: 'Payment open' } })
        throw new Error('No session challenge offered')
      },
      charge: async () => (charged++, Response.json({}, { headers: { 'payment-receipt': 'r' } })),
    })
    expect(await relay.chat({ model: 'm' })).toMatchObject({ kind: 'response', intent: 'charge', paid: true })
    expect(charged).toBe(1)
  })

  it('sends charges as streams, and reports whether the relay took the charge', async () => {
    const bodies: Record<string, unknown>[] = []
    const relay = new RelayClient({
      relayUrl: 'https://relay.example',
      account: Account.fromSecp256k1(generatePrivateKey()),
      getClient: () => ({}) as never,
      currency: '0x20c0000000000000000000000000000000000000',
      chainId: 4217,
      decimals: 6,
      maxDeposit: 500_000n,
      maxCharge: 50_000n,
      expectedPayee: () => payee,
      fetch: async () => new Response(null, { status: 500 }),
      sessionManagerFactory: () => ({ sse: async () => Promise.reject(new Error('no session')), close: async () => {} }),
      chargeClientFactory: () => ({
        fetch: async (_input, init) => {
          bodies.push(JSON.parse(String(init?.body)))
          return new Response('{"error":{"charged":false}}', { status: 503 })
        },
      }),
    })
    const result = await relay.chat({ model: 'm', messages: [] })
    expect(bodies[0]).toMatchObject({ model: 'm', stream: true, stream_options: { include_usage: true } })
    expect(result).toMatchObject({ kind: 'response', intent: 'refused', paid: false, streamed: false })
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

  describe('channel rotation, retirement and resumption (M1, M2)', () => {
    type Fake = SessionManagerLike & { closed: boolean; params: Record<string, unknown>; state: { channelId?: string; cumulative: bigint } }
    function rotating(options: { journal?: ChannelJournal; kv?: FileKv; payee?: () => `0x${string}`; closeFails?: boolean; stream?: () => AsyncIterable<string> } = {}) {
      const managers: Fake[] = []
      const relay = new RelayClient({
        relayUrl: 'https://relay.example',
        account: Account.fromSecp256k1(generatePrivateKey()),
        getClient: () => ({}) as never,
        currency: '0x20c0000000000000000000000000000000000000',
        chainId: 4217,
        decimals: 6,
        maxDeposit: 500_000n,
        maxCharge: 50_000n,
        expectedPayee: options.payee ?? (() => payee),
        fetch: async () => new Response(null, { status: 500 }),
        journal: options.journal,
        channelKv: options.kv,
        sessionManagerFactory: (params) => {
          const state = { channelId: `0x${String(managers.length + 1).padStart(64, '0')}` as string | undefined, cumulative: 0n }
          const m: Fake = {
            params,
            state,
            closed: false,
            get channelId() {
              return state.channelId
            },
            get cumulative() {
              return state.cumulative
            },
            sse: async () => (options.stream ?? (() => (async function* () { yield 'x' })()))(),
            close: async () => {
              if (options.closeFails) throw new Error('relay unreachable')
              m.closed = true
            },
          }
          managers.push(m)
          return m
        },
      })
      return { relay, managers }
    }
    const drain = async (r: Awaited<ReturnType<RelayClient['chat']>>) => {
      if (r.kind === 'session') for await (const _ of r.events);
    }

    it('rotates a channel before its vouchers reach maxDeposit: closes it cooperatively and opens a new one without bootstrap', async () => {
      const { relay, managers } = rotating()
      await drain(await relay.chat({}))
      expect(managers).toHaveLength(1)
      expect(managers[0]!.params).toMatchObject({ bootstrap: true })
      managers[0]!.state.cumulative = 460_000n // less than one charge (50_000) left below 500_000
      await drain(await relay.chat({}))
      expect(managers).toHaveLength(2)
      expect(managers[1]!.params).toMatchObject({ bootstrap: false })
      await new Promise((r) => setTimeout(r, 0))
      expect(managers[0]!.closed).toBe(true)
      managers[1]!.state.cumulative = 440_000n
      await drain(await relay.chat({}))
      expect(managers).toHaveLength(2)
    })

    it('closes a rotated channel only after its running streams end', async () => {
      let release!: () => void
      const gate = new Promise<void>((r) => (release = r))
      const { relay, managers } = rotating({ stream: () => (async function* () { await gate; yield 'x' })() })
      const first = await relay.chat({})
      managers[0]!.state.cumulative = 499_000n
      const second = await relay.chat({})
      expect(managers).toHaveLength(2)
      expect(managers[0]!.closed).toBe(false)
      expect(await relay.liveChannels()).toContain(managers[0]!.channelId)
      release()
      await drain(first)
      await drain(second)
      await new Promise((r) => setTimeout(r, 0))
      expect(managers[0]!.closed).toBe(true)
    })

    it('retires a channel whose rotation close fails, and one whose payee changed, for onchain recovery', async () => {
      const journal = new ChannelJournal(undefined)
      const record = (id: string) =>
        journal.recordOpen({ channelId: id, chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', deposit: 500_000n, descriptor: { payer: payee, payee, operator: payee, token: '0x20c0000000000000000000000000000000000000', salt: `0x${'00'.repeat(32)}`, authorizedSigner: payee, expiringNonceHash: `0x${'00'.repeat(32)}` } })
      let current: `0x${string}` = payee
      const { relay, managers } = rotating({ journal, closeFails: true, payee: () => current })
      await drain(await relay.chat({}))
      record(managers[0]!.channelId!)
      managers[0]!.state.cumulative = 480_000n
      await drain(await relay.chat({}))
      await new Promise((r) => setTimeout(r, 0))
      expect(journal.get(managers[0]!.channelId!)).toMatchObject({ status: 'retired', reason: 'rotated_close_failed' })
      record(managers[1]!.channelId!)
      current = ('0x' + 'cd'.repeat(20)) as `0x${string}`
      await drain(await relay.chat({}))
      expect(journal.get(managers[1]!.channelId!)).toMatchObject({ status: 'retired', reason: 'payee_changed' })
      expect(managers[1]!.closed).toBe(false)
      expect(managers).toHaveLength(3)
    })

    it('persists the session channel for the next process, and replaces a stored channel that is exhausted', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'payer-store-'))
      const kv = new FileKv(join(dir, 'session-store.json'))
      const { relay, managers } = rotating({ kv })
      await drain(await relay.chat({}))
      const store = managers[0]!.params.channelStore as { set(entry: unknown): Promise<void> }
      const entry = (cumulativeAmount: bigint) => ({
        channelId: managers[0]!.channelId,
        chainId: 4217,
        escrow: '0x4d50500000000000000000000000000000000000',
        descriptor: { payee, token: '0x20c0000000000000000000000000000000000000' },
        cumulativeAmount,
        deposit: 500_000n,
        opened: true,
      })
      await store.set(entry(100_000n))
      const reopened = new FileKv(join(dir, 'session-store.json'))
      expect(reopened.keys()).toHaveLength(1)
      const next = rotating({ kv: reopened })
      expect(await next.relay.liveChannels()).toContain(managers[0]!.channelId)
      // An exhausted stored channel is dropped and retired instead of resumed.
      await store.set(entry(490_000n))
      const journal = new ChannelJournal(undefined)
      const third = rotating({ kv: new FileKv(join(dir, 'session-store.json')), journal })
      await drain(await third.relay.chat({}))
      expect(third.managers[0]!.params).toMatchObject({ bootstrap: false })
      expect(new FileKv(join(dir, 'session-store.json')).keys()).toHaveLength(0)
    })

    it('counts every open channel as live until the relay payee is attested, then only the resumable one', async () => {
      const journal = new ChannelJournal(undefined)
      const open = (n: number, payeeOf: `0x${string}`) =>
        journal.recordOpen({ channelId: `0x${String(n).padStart(64, '0')}`, chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', deposit: 1n, descriptor: { payer: payee, payee: payeeOf, operator: payee, token: '0x20c0000000000000000000000000000000000000', salt: `0x${'00'.repeat(32)}`, authorizedSigner: payee, expiringNonceHash: `0x${'00'.repeat(32)}` } })
      open(91, payee)
      open(92, ('0x' + 'cd'.repeat(20)) as `0x${string}`)
      let attested: `0x${string}` | undefined
      const { relay } = rotating({ journal, payee: () => attested as `0x${string}` })
      expect([...(await relay.liveChannels())].sort()).toEqual([`0x${'91'.padStart(64, '0')}`, `0x${'92'.padStart(64, '0')}`])
      attested = payee
      // The channel to the attested payee is the one the bootstrap would resume; the other is an orphan.
      expect([...(await relay.liveChannels())]).toEqual([`0x${'91'.padStart(64, '0')}`])
    })

    it('runs one session handshake at a time, so concurrent requests never trip mppx\'s single-flight guard', async () => {
      let inFlight = 0
      let overlap = false
      const relay = new RelayClient({
        relayUrl: 'https://relay.example',
        account: Account.fromSecp256k1(generatePrivateKey()),
        getClient: () => ({}) as never,
        currency: '0x20c0000000000000000000000000000000000000',
        chainId: 4217,
        decimals: 6,
        maxDeposit: 500_000n,
        maxCharge: 50_000n,
        expectedPayee: () => payee,
        fetch: async () => new Response(null, { status: 500 }),
        sessionManagerFactory: () => ({
          sse: async () => {
            if (inFlight++ > 0) overlap = true
            await new Promise((r) => setTimeout(r, 5))
            inFlight--
            return (async function* () { yield 'x' })()
          },
          close: async () => {},
        }),
      })
      const results = await Promise.all([relay.chat({}), relay.chat({}), relay.chat({})])
      expect(results.every((r) => r.kind === 'session')).toBe(true)
      expect(overlap).toBe(false)
    })
  })

  it('signs a channel close authorization with the access key itself (primitive), everything else as before', async () => {
    const root = Account.fromSecp256k1(generatePrivateKey())
    const key = Account.fromSecp256k1(generatePrivateKey(), { access: root })
    const wrapped = withPrimitiveCloseSignatures(key as never) as unknown as typeof key
    const typed = (primaryType: string) => ({
      domain: { name: 'TIP20 Channel Reserve', version: '1', chainId: 4217, verifyingContract: '0x4d50500000000000000000000000000000000000' as const },
      types: { [primaryType]: [{ name: 'channelId', type: 'bytes32' }, { name: 'cumulativeAmount', type: 'uint96' }] },
      primaryType,
      message: { channelId: `0x${'ab'.repeat(32)}`, cumulativeAmount: 5n },
    })
    const close = await wrapped.signTypedData(typed('CloseAuthorization') as never)
    expect(close).toMatch(/^0x[0-9a-f]{130}$/)
    expect((await recoverAddress({ hash: hashTypedData(typed('CloseAuthorization') as never), signature: close })).toLowerCase()).toBe(key.accessKeyAddress.toLowerCase())
    expect(await wrapped.signTypedData(typed('Other') as never)).toBe(await key.signTypedData(typed('Other') as never))
    expect(wrapped.address).toBe(root.address)
    const plain = Account.fromSecp256k1(generatePrivateKey())
    expect(withPrimitiveCloseSignatures(plain as never)).toBe(plain)
  })
})
