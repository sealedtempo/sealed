import { describe, expect, it } from 'vitest'
import { PaymentPolicyError, SpendGuard, SpendLimitError } from '../src/spend-guard.js'

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
})
