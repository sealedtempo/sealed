import { describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { FileSpendStore, PaymentPolicyError, SpendGuard, SpendLimitError } from '../src/spend-guard.js'

describe('SpendGuard', () => {
  it('reserves within the daily limit and refuses beyond it', () => {
    const guard = new SpendGuard(2_000_000n, () => Date.parse('2026-10-28T10:00:00Z'))
    guard.reserve(1_500_000n, 'deposit')
    expect(guard.remaining()).toBe(500_000n)
    expect(() => guard.reserve(600_000n, 'charge')).toThrow(SpendLimitError)
    guard.reserve(500_000n, 'charge')
    expect(guard.remaining()).toBe(0n)
    expect(guard.counters()).toMatchObject({ debited: '2000000', deposits: 1, charges: 1, refused: 1, remaining: '0' })
  })

  it('releases a reservation once and refunds give budget back', () => {
    const guard = new SpendGuard(1_000n)
    const release = guard.reserve(800n, 'charge')
    release()
    release()
    expect(guard.remaining()).toBe(1_000n)
    guard.reserve(1_000n, 'deposit')
    guard.refund(400n)
    expect(guard.remaining()).toBe(400n)
    expect(() => guard.reserve(0n, 'charge')).toThrow(PaymentPolicyError)
  })

  it('resets at the UTC day boundary', () => {
    let now = Date.parse('2026-10-28T23:59:59Z')
    const guard = new SpendGuard(100n, () => now)
    guard.reserve(100n, 'charge')
    expect(() => guard.reserve(1n, 'charge')).toThrow(SpendLimitError)
    now = Date.parse('2026-10-29T00:00:01Z')
    expect(guard.remaining()).toBe(100n)
    expect(guard.counters().day).toBe('2026-10-29')
    guard.reserve(100n, 'charge')
  })

  it('tracks the highest voucher per channel', () => {
    const guard = new SpendGuard(10n)
    guard.noteVoucher('0xa', 5n)
    guard.noteVoucher('0xa', 3n)
    guard.noteVoucher('0xb', 2n)
    expect(guard.counters().sessionAuthorized).toBe('7')
    guard.forgetChannel('0xa')
    expect(guard.counters().sessionAuthorized).toBe('2')
  })

  it('caps at the whole daily limit: the share for agent fees is kept by the shared budget in sealed-agent', () => {
    const guard = new SpendGuard(2_000_000n)
    expect(guard.remaining()).toBe(2_000_000n)
    expect(() => guard.reserve(2_000_001n, 'deposit')).toThrow(SpendLimitError)
    guard.reserve(2_000_000n, 'deposit')
    expect(guard.counters()).toMatchObject({ limit: '2000000', budget: '2000000', remaining: '0' })
  })

  it('reserves a payment and its network fee together or not at all', () => {
    const guard = new SpendGuard(1_000n)
    const release = guard.reserveAll([
      { amount: 600n, kind: 'charge' },
      { amount: 7n, kind: 'fee' },
    ])
    // Fees count in debited (they use the access-key limit) but not in the charge amount.
    expect(guard.counters()).toMatchObject({ debited: '607', charges: 1, chargeAmount: '600', remaining: '393' })
    expect(() =>
      guard.reserveAll([
        { amount: 390n, kind: 'charge' },
        { amount: 4n, kind: 'fee' },
      ]),
    ).toThrow(SpendLimitError)
    expect(guard.counters()).toMatchObject({ debited: '607', charges: 1, refused: 1 })
    release()
    expect(guard.counters()).toMatchObject({ debited: '0', charges: 0, chargeAmount: '0', remaining: '1000' })
    expect(() => guard.reserveAll([{ amount: 0n, kind: 'fee' }])).toThrow(PaymentPolicyError)
  })

  it('persists the day across restarts, so a crash loop cannot spend the budget again', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'payer-spend-')), 'state', 'spend.json')
    let now = Date.parse('2026-10-28T10:00:00Z')
    const first = new SpendGuard(1_000n, () => now, { store: new FileSpendStore(path) })
    first.reserve(400n, 'charge')
    const release = first.reserve(300n, 'deposit')
    release()
    first.refund(50n)
    const restarted = new SpendGuard(1_000n, () => now, { store: new FileSpendStore(path) })
    expect(restarted.remaining()).toBe(650n)
    expect(restarted.counters()).toMatchObject({ debited: '400', refunded: '50', charges: 1, chargeAmount: '400', deposits: 0 })
    expect(() => restarted.reserve(700n, 'charge')).toThrow(SpendLimitError)
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ day: '2026-10-28', debited: '400', refused: 1 })
    // A new UTC day starts from zero, and a stale or corrupt file is ignored.
    now = Date.parse('2026-10-29T00:00:01Z')
    expect(new SpendGuard(1_000n, () => now, { store: new FileSpendStore(path) }).remaining()).toBe(1_000n)
    writeFileSync(path, '{"day":')
    expect(new SpendGuard(1_000n, () => now, { store: new FileSpendStore(path) }).remaining()).toBe(1_000n)
  })

  it('keeps paying when the state file cannot be written', () => {
    const errors: string[] = []
    const store = new FileSpendStore('/dev/null/not-a-dir/spend.json', (e) => errors.push(e.message))
    const guard = new SpendGuard(1_000n, Date.now, { store })
    guard.reserve(10n, 'charge')
    expect(errors.length).toBeGreaterThan(0)
    expect(guard.remaining()).toBe(990n)
  })
})
