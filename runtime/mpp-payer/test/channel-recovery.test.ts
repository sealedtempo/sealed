import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ChannelJournal, FileKv } from '../src/channel-journal.js'
import { ChannelRecovery, type ChannelState, type EscrowChain, type RecoveryCall } from '../src/channel-recovery.js'
import { SpendGuard } from '../src/spend-guard.js'
import { ChainTxWatcher } from '../src/tx-watcher.js'
import { fakeAgentBudget } from './helpers/fake-agent-budget.js'

const payee = ('0x' + 'ab'.repeat(20)) as `0x${string}`
const id = (n: number) => `0x${n.toString(16).padStart(64, '0')}` as `0x${string}`
const descriptor = (n: number) => ({
  payer: ('0x' + '11'.repeat(20)) as `0x${string}`,
  payee,
  operator: payee,
  token: '0x20c0000000000000000000000000000000000000' as `0x${string}`,
  salt: id(n),
  authorizedSigner: ('0x' + '22'.repeat(20)) as `0x${string}`,
  expiringNonceHash: id(n + 1000),
})

function fakeChain(states: Record<string, ChannelState>, fee = 100n) {
  const sent: { call: RecoveryCall; salt: string }[] = []
  const chain: EscrowChain = {
    state: async (channelId) => states[channelId] ?? { deposit: 0n, settled: 0n, closeRequestedAt: 0 },
    gracePeriod: async () => 900,
    prepare: async (call, d) => ({
      feeCap: fee,
      send: async () => {
        sent.push({ call, salt: d.salt })
        return call === 'requestClose' ? { status: 'success', closeRequestedAt: 10_000 } : { status: 'success', refunded: 400_000n }
      },
    }),
  }
  return { chain, sent }
}

describe('channel recovery (review M1)', () => {
  it('requestCloses orphaned channels, withdraws after the grace period, and leaves live or fresh ones alone', async () => {
    let now = 10_000
    const journal = new ChannelJournal(undefined, () => now)
    for (const n of [1, 2, 3, 4, 5]) journal.recordOpen({ channelId: id(n), chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', descriptor: descriptor(n), deposit: 500_000n })
    journal.retire(id(3), 'rotated_close_failed')
    now = 20_000
    journal.recordOpen({ channelId: id(6), chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', descriptor: descriptor(6), deposit: 500_000n })
    const { chain, sent } = fakeChain({
      [id(1)]: { deposit: 500_000n, settled: 0n, closeRequestedAt: 0 }, // live: the session channel
      [id(2)]: { deposit: 500_000n, settled: 100_000n, closeRequestedAt: 0 }, // orphan
      [id(3)]: { deposit: 500_000n, settled: 100_000n, closeRequestedAt: 18_000 }, // close requested, grace over
      // id(4): deposit 0 onchain: the open never landed (or it is already withdrawn)
      [id(5)]: { deposit: 500_000n, settled: 0n, closeRequestedAt: 19_500 }, // grace not over yet
      [id(6)]: { deposit: 500_000n, settled: 0n, closeRequestedAt: 0 }, // just opened
    })
    const guard = new SpendGuard(2_000_000n)
    const agent = fakeAgentBudget({ budget: 2_000_000n })
    const recovery = new ChannelRecovery({ journal, chain, liveChannels: () => new Set([id(1)]), guard, budget: agent.budget, now: () => now })
    await recovery.sweep()
    expect(sent).toEqual([
      { call: 'requestClose', salt: id(2) },
      { call: 'withdraw', salt: id(3) },
    ])
    expect(journal.get(id(1))?.status).toBe('open')
    expect(journal.get(id(2))).toMatchObject({ status: 'closeRequested', reason: 'orphaned', closeRequestedAt: 10_000 })
    expect(journal.get(id(3))).toMatchObject({ status: 'closed', refunded: '400000' })
    expect(journal.get(id(4))?.status).toBe('closed')
    expect(journal.get(id(5))).toMatchObject({ status: 'closeRequested', closeRequestedAt: 19_500 })
    expect(journal.get(id(6))?.status).toBe('open')
    // Each recovery transaction's network fee is budgeted in both caps; the refund gives nothing back.
    expect(agent.releases()).toEqual([100n, 100n])
    expect(guard.counters()).toMatchObject({ debited: '200', refunded: '0' })
    expect(recovery.snapshot()).toMatchObject({ requestCloses: 1, withdrawals: 1, recovered: '400000', failures: 0 })
  })

  it('defers recovery when the shared budget refuses the network fee', async () => {
    const journal = new ChannelJournal(undefined, () => 0)
    journal.recordOpen({ channelId: id(7), chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', descriptor: descriptor(7), deposit: 500_000n })
    const { chain, sent } = fakeChain({ [id(7)]: { deposit: 500_000n, settled: 0n, closeRequestedAt: 0 } })
    const agent = fakeAgentBudget({ budget: 2_000_000n, reservedForFees: 2_000_000n })
    const guard = new SpendGuard(2_000_000n)
    const recovery = new ChannelRecovery({ journal, chain, liveChannels: () => new Set(), guard, budget: agent.budget, now: () => 1_000 })
    await recovery.sweep()
    expect(sent).toEqual([])
    expect(journal.get(id(7))?.status).toBe('retired')
    expect(guard.counters().debited).toBe('0')
    // payments-8: it asked for the recovery allowance, and the deferral is reported with the deposit at stake.
    expect(agent.calls.find((c) => c.path === '/v1/spend/reserve')?.body).toMatchObject({ amount: '100', purpose: 'recovery' })
    expect(recovery.snapshot()).toMatchObject({ deferred: 1, deferredAmount: '500000' })
    // Once the agent has room (here: the limit was raised), the next pass goes through and the deferral is cleared.
    agent.state.reservedForFees = 0n
    await recovery.sweep()
    expect(sent).toEqual([{ call: 'requestClose', salt: id(7) }])
    expect(recovery.snapshot()).toMatchObject({ requestCloses: 1, deferred: 0, deferredAmount: '0' })
  })

  // payments-8: before the fix every pass was deferred while fee priority held the whole budget (a limit below the
  // app-hour floor), so the deposit stayed in escrow for good.
  it('recovers a deposit while fee priority holds the whole budget, through the recovery allowance', async () => {
    let now = 1_000
    const journal = new ChannelJournal(undefined, () => 0)
    journal.recordOpen({ channelId: id(9), chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', descriptor: descriptor(9), deposit: 500_000n })
    const states: Record<string, ChannelState> = { [id(9)]: { deposit: 500_000n, settled: 120_000n, closeRequestedAt: 0 } }
    const { chain, sent } = fakeChain(states)
    const agent = fakeAgentBudget({ budget: 2_000_000n, reservedForFees: 2_000_000n, recoveryAllowance: 10_000n })
    const recovery = new ChannelRecovery({ journal, chain, liveChannels: () => new Set(), guard: new SpendGuard(2_000_000n), budget: agent.budget, now: () => now })
    expect(agent.available()).toBe(0n)
    await recovery.sweep()
    expect(sent).toEqual([{ call: 'requestClose', salt: id(9) }])
    states[id(9)] = { deposit: 500_000n, settled: 120_000n, closeRequestedAt: 10_000 }
    now = 20_000
    await recovery.sweep()
    expect(sent.map((s) => s.call)).toEqual(['requestClose', 'withdraw'])
    expect(journal.get(id(9))).toMatchObject({ status: 'closed', refunded: '400000' })
    expect(recovery.snapshot()).toMatchObject({ requestCloses: 1, withdrawals: 1, recovered: '400000', deferred: 0 })
    expect(agent.releases()).toEqual([100n, 100n])
  })

  it('does not ask for the allowance when the fee is larger than what the channel still holds', async () => {
    const journal = new ChannelJournal(undefined, () => 0)
    journal.recordOpen({ channelId: id(10), chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', descriptor: descriptor(10), deposit: 500_000n })
    const { chain, sent } = fakeChain({ [id(10)]: { deposit: 500_000n, settled: 499_950n, closeRequestedAt: 0 } })
    const agent = fakeAgentBudget({ budget: 2_000_000n, reservedForFees: 2_000_000n, recoveryAllowance: 10_000n })
    const recovery = new ChannelRecovery({ journal, chain, liveChannels: () => new Set(), guard: new SpendGuard(2_000_000n), budget: agent.budget, now: () => 1_000 })
    await recovery.sweep()
    expect(sent).toEqual([])
    expect(agent.calls.find((c) => c.path === '/v1/spend/reserve')?.body.purpose).toBeUndefined()
    expect(recovery.snapshot()).toMatchObject({ deferred: 1, deferredAmount: '50' })
  })

  it('keeps the journal and the session store across restarts', () => {
    const dir = mkdtempSync(join(tmpdir(), 'payer-state-'))
    const a = new ChannelJournal(join(dir, 'channels.json'), () => 5)
    a.recordOpen({ channelId: id(8), chainId: 4217, escrow: '0x4d50500000000000000000000000000000000000', descriptor: descriptor(8), deposit: 1n })
    a.noteVoucher(id(8), 7n)
    a.noteTopUp(id(8), 2n)
    expect(new ChannelJournal(join(dir, 'channels.json')).get(id(8))).toMatchObject({ deposited: '3', maxVoucher: '7', status: 'open' })
    writeFileSync(join(dir, 'broken.json'), '{not json')
    expect(new ChannelJournal(join(dir, 'broken.json')).all()).toEqual([])
    const kv = new FileKv(join(dir, 'kv.json'))
    kv.set('chan:x', '{"a":1}')
    expect(JSON.parse(readFileSync(join(dir, 'kv.json'), 'utf8'))).toEqual({ 'chan:x': '{"a":1}' })
    expect(new FileKv(join(dir, 'kv.json')).get('chan:x')).toBe('{"a":1}')
  })
})

describe('ChainTxWatcher', () => {
  it('waits for validBefore, then reads the receipt: included, reverted, or absent for good', async () => {
    const slept: number[] = []
    const make = (receipt: () => Promise<{ status: 'success' | 'reverted' } | undefined>) =>
      new ChainTxWatcher({ receipt, now: () => 100, sleep: async (ms) => void slept.push(ms), settleSeconds: 3 })
    expect(await make(async () => ({ status: 'success' })).outcome('0x01', 120)).toBe('landed')
    expect(slept).toEqual([23_000])
    expect(await make(async () => ({ status: 'reverted' })).outcome('0x01', 90)).toBe('reverted')
    expect(await make(async () => undefined).outcome('0x01', 90)).toBe('absent')
    expect(await make(async () => undefined).outcome('0x01', undefined)).toBe('unknown')
    let calls = 0
    const flaky = make(async () => {
      if (calls++ < 2) throw new Error('rpc down')
      return undefined
    })
    expect(await flaky.outcome('0x01', 90)).toBe('absent')
    const down = make(async () => Promise.reject(new Error('rpc down')))
    expect(await down.outcome('0x01', 90)).toBe('unknown')
  })
})
