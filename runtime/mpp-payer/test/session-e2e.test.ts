import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generatePrivateKey } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DEV_KEYS, PATHUSD, anvilAvailable, balanceOf, startLocalTempo, type LocalTempo } from '../../relay/test/helpers/anvil.js'
import { ChannelJournal, FileKv } from '../src/channel-journal.js'
import { SpendGuard } from '../src/spend-guard.js'
import { fakeAgentBudget } from './helpers/fake-agent-budget.js'
import { channelState, escrowEvents, payerStack, post, relayWorld, testPrices } from './helpers/relay-world.js'

/**
 * The preferred payment path, end to end with real mppx on both sides: the payer's
 * tempo.session.manager (through the payment firewall) against the relay's tempo.session server
 * (sse: true, usd_micro unit, SessionMeter charging stream.charge(amount)), on a local Tempo node
 * (Foundry 1.8.6, hardfork T12) with the real TIP-1034 escrow precompile: channels are opened,
 * funded, settled and closed onchain.
 */
describe.skipIf(!anvilAvailable())('MPP session over SSE with real mppx client and server on the TIP-1034 escrow precompile', () => {
  let node: LocalTempo
  const treasury = Account.fromSecp256k1(generatePrivateKey()).address.toLowerCase() as `0x${string}`
  const settler = Account.fromSecp256k1(DEV_KEYS[3])
  const payerAccount = Account.fromSecp256k1(DEV_KEYS[4])
  const body = { model: 'nearai/z-ai/glm-5.3', messages: [{ role: 'user', content: 'meter me' }], max_tokens: 64 }

  beforeAll(async () => {
    node = await startLocalTempo()
  }, 60_000)
  afterAll(() => node?.stop())

  const content = (text: string) =>
    [...text.matchAll(/^data: (\{.*\})$/gm)]
      .map((m) => JSON.parse(m[1]!))
      .flatMap((c) => (c.choices ?? []).map((x: any) => x.delta?.content ?? ''))
      .join('')

  it('opens a channel onchain, streams with vouchers posted through the firewall, then closes cooperatively', async () => {
    const world = relayWorld({ node, treasury, settler })
    const journal = new ChannelJournal(undefined)
    const agent = fakeAgentBudget({ budget: 2_000_000n })
    const { app, relay, guard } = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, journal, budget: agent.budget })
    const balanceBefore = await balanceOf(node.client, payerAccount.address)

    const res = await app.request('/v1/chat/completions', post({ ...body, stream: true }))
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(content(text)).toBe('Metered per token over SSE')
    expect(text.trimEnd().endsWith('data: [DONE]')).toBe(true)
    expect(relay.sessionsAvailable()).toBe(true)
    expect(world.llm.calls[0]!.body).toMatchObject({ stream: true, stream_options: { include_usage: true }, max_tokens: 64 })

    // One channel, journaled with its descriptor before the open left, opened onchain for the
    // attested payee in the fee token.
    const [record] = journal.all()
    expect(journal.all()).toHaveLength(1)
    expect(record!.descriptor).toMatchObject({ payee: treasury, token: PATHUSD, payer: payerAccount.address.toLowerCase() })
    const opened = await channelState(node, record!.channelId)
    expect(opened.deposit).toBe(200_000n)
    expect((await escrowEvents(node, record!.channelId)).map((e) => e.eventName)).toContain('ChannelOpened')

    // The firewall reserved exactly the deposit plus the open transaction's fee cap; vouchers reserve nothing.
    const counters = guard.counters()
    expect(counters).toMatchObject({ deposits: 1, depositAmount: '200000', charges: 0 })
    const openFee = BigInt(counters.debited) - 200_000n
    expect(openFee).toBeGreaterThan(0n)
    expect(agent.calls.map((c) => c.path)).toEqual(['/v1/spend/reserve', '/v1/spend/release'])
    expect(agent.state.used).toBe(200_000n + openFee)
    const actions = world.wire.filter((w) => w.intent === 'session').map((w) => w.action)
    expect(actions[0]).toBe('open')
    expect(actions.filter((a) => a === 'voucher').length).toBeGreaterThan(0)
    // Only the bootstrap probe's zero-amount proof uses the charge intent; nothing was charged.
    expect(world.wire.filter((w) => w.intent === 'charge').every((w) => w.type === 'proof')).toBe(true)

    // Usage {12 prompt, 5 completion}: (12 x 1.8 + 5 x 5.75) x 1.05 = 52.8 -> 53 base units after credit.
    const credited = world.credited.reduce((a, b) => a + b, 0n)
    expect(BigInt(counters.sessionAuthorized) - credited).toBe(53n)

    // A second request reuses the channel.
    const again = await app.request('/v1/chat/completions', post(body))
    expect((await again.json()).choices[0].message.content).toBe('Metered per token over SSE')
    expect(journal.all()).toHaveLength(1)
    expect(guard.counters().deposits).toBe(1)

    // Cooperative close: the relay's settler captures what was spent and the escrow refunds the rest.
    await relay.close()
    const closed = (await escrowEvents(node, record!.channelId)).find((e) => e.eventName === 'ChannelClosed')!
    expect(closed).toBeDefined()
    const refunded = closed.args.refundedToPayer as bigint
    expect(refunded).toBeGreaterThan(190_000n)
    expect((await channelState(node, record!.channelId)).deposit).toBe(0n)
    expect(journal.get(record!.channelId)?.status).toBe('closed')
    const close = world.wire.find((w) => w.action === 'close')!
    expect([200, 204]).toContain(close.status)
    expect(BigInt(guard.counters().refunded)).toBe(200_000n - close.cumulative!)
    // The payer paid what was captured plus its own network fees.
    const spent = balanceBefore - (await balanceOf(node.client, payerAccount.address))
    expect(spent).toBeGreaterThan(200_000n - refunded)
    expect(spent).toBeLessThanOrEqual(200_000n - refunded + openFee)
    expect(agent.state.used).toBe(200_000n + openFee)
  }, 120_000)

  it('after a restart that lost the payer state, resumes the open channel through the bootstrap proof instead of opening another (M1)', async () => {
    const world = relayWorld({ node, treasury, settler })
    const first = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, journal: new ChannelJournal(undefined) })
    expect((await first.app.request('/v1/chat/completions', post(body))).status).toBe(200)
    const channelId = first.relay.liveChannels().then((ids) => [...ids][0])
    const opened = (await escrowEvents(node)).filter((e) => e.eventName === 'ChannelOpened').length

    // A new process: no channel store, an empty journal, nothing in memory.
    const second = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, guard: new SpendGuard(2_000_000n), journal: new ChannelJournal(undefined) })
    const res = await second.app.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(200)
    expect((await res.json()).choices[0].message.content).toBe('Metered per token over SSE')
    // The HEAD probe carried a zero-amount proof, the firewall let it through with no debit, and
    // the relay handed the channel back: no second open, no second deposit.
    const probes = world.wire.filter((w) => w.method === 'HEAD' && w.type === 'proof')
    expect(probes.at(-1)).toMatchObject({ intent: 'charge', status: 204 })
    // The resumed channel continues the voucher sequence of the first process.
    const vouchers = world.wire.filter((w) => w.action === 'voucher').map((w) => w.cumulative!)
    expect(vouchers).toEqual([...vouchers].sort((a, b) => (a < b ? -1 : 1)))
    expect((await escrowEvents(node)).filter((e) => e.eventName === 'ChannelOpened').length).toBe(opened)
    expect(second.guard.counters()).toMatchObject({ deposits: 0, debited: '0' })
    expect(await second.relay.liveChannels()).toContain(await channelId)
    await second.relay.close()
  }, 120_000)

  it('after a restart, resumes the channel from the persisted channel store, also without the relay bootstrap', async () => {
    const world = relayWorld({ node, treasury, settler, bootstrap: false })
    const dir = mkdtempSync(join(tmpdir(), 'payer-session-'))
    const kv = () => new FileKv(join(dir, 'session-store.json'))
    const first = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, channelKv: kv() })
    expect((await first.app.request('/v1/chat/completions', post(body))).status).toBe(200)
    const opened = (await escrowEvents(node)).filter((e) => e.eventName === 'ChannelOpened').length
    const second = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, guard: new SpendGuard(2_000_000n), channelKv: kv() })
    expect((await second.app.request('/v1/chat/completions', post(body))).status).toBe(200)
    expect((await escrowEvents(node)).filter((e) => e.eventName === 'ChannelOpened').length).toBe(opened)
    expect(second.guard.counters().deposits).toBe(0)
    await second.relay.close()
  }, 120_000)

  it('a session the relay cannot serve costs nothing and is answered 503 charged: false, a free retry (payments-6)', async () => {
    const world = relayWorld({ node, treasury, settler })
    const journal = new ChannelJournal(undefined)
    const { app, relay, guard } = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, journal })
    expect((await app.request('/v1/chat/completions', post(body))).status).toBe(200)
    const [record] = journal.all()
    const creditedBefore = world.credited.reduce((a, b) => a + b, 0n)

    // The relay's LiteLLM is down. Before the fix the relay kept the estimated prompt and the payer answered 502,
    // which SDKs retry: every retry paid again. A large prompt makes that estimate visible.
    world.upstream.down = true
    const big = { ...body, messages: [{ role: 'user', content: 'x'.repeat(30_000) }] }
    for (const request of [big, { ...big, stream: true }]) {
      const res = await app.request('/v1/chat/completions', post(request))
      expect(res.status).toBe(503)
      expect((await res.json()).error).toMatchObject({ type: 'upstream_unreachable', charged: false })
    }
    // Each attempt prepaid the estimated prompt (about 10k tokens) and got all of it credited back.
    expect(world.credited.reduce((a, b) => a + b, 0n) - creditedBefore).toBeGreaterThan(2n * 18_000n)
    expect(guard.counters().deposits).toBe(1)

    // The retry once LiteLLM is back is served on the same channel, and the relay captures only what was served.
    world.upstream.down = false
    const retry = await app.request('/v1/chat/completions', post(body))
    expect((await retry.json()).choices[0].message.content).toBe('Metered per token over SSE')
    expect(journal.all()).toHaveLength(1)
    await relay.close()
    const closed = (await escrowEvents(node, record!.channelId)).find((e) => e.eventName === 'ChannelClosed')!
    // The relay captured two served requests at 53 base units each, nothing for the two it could not serve.
    expect(200_000n - (closed.args.refundedToPayer as bigint)).toBe(106n)
  }, 120_000)

  it('rotates a channel before maxDeposit: closes it cooperatively and continues on a new one (M2)', async () => {
    // A pricey model and a small channel: a few requests exhaust it.
    const world = relayWorld({ node, treasury, settler, suggestedDeposit: '0.006', prices: testPrices(60_000_000, 120_000_000) })
    const journal = new ChannelJournal(undefined)
    const { app, relay } = payerStack({ relayFetch: world.fetch, treasury, account: payerAccount, node, journal, maxDeposit: 6_000n, maxCharge: 5_000n, rotateHeadroom: 2_500n })
    for (let i = 0; i < 6; i++) {
      const res = await app.request('/v1/chat/completions', post({ ...body, max_tokens: 4 }))
      expect(res.status, `request ${i}`).toBe(200)
      await res.json()
    }
    await new Promise((r) => setTimeout(r, 3_000))
    const records = journal.all()
    expect(records.length).toBeGreaterThanOrEqual(2)
    const [old] = records
    expect(old!.status).toBe('closed')
    expect((await channelState(node, old!.channelId)).deposit).toBe(0n)
    expect((await escrowEvents(node, old!.channelId)).map((e) => e.eventName)).toContain('ChannelClosed')
    // Every voucher stayed within the cap; nothing fell back to a per-request charge.
    for (const w of world.wire.filter((x) => x.cumulative !== undefined)) expect(w.cumulative!).toBeLessThanOrEqual(6_000n)
    expect(world.wire.some((w) => w.intent === 'charge' && w.type === 'transaction')).toBe(false)
    await relay.close()
  }, 180_000)
})
