import { describe, expect, it } from 'vitest'
import { join } from 'node:path'
import {
  type ModelPrice,
  ceilToBaseUnits,
  costInBaseUnits,
  formatUnits,
  loadPriceTable,
  parsePriceTable,
  relayPricePer1M,
  scaledCost,
} from '../src/prices.js'
import { estimateDeltaTokens, estimatePromptTokens } from '../src/tokens.js'

const model: ModelPrice = {
  id: 'phala/openai/gpt-oss-120b',
  provider: 'phala',
  upstreamModel: 'openai/gpt-oss-120b',
  inputPer1M: 150_000n,
  outputPer1M: 600_000n,
  maxOutputTokens: 4096,
}

describe('relay pricing', () => {
  it('applies the markup exactly: list x (1 + bps/10000)', () => {
    // 1M input tokens at $0.15 list with 500 bps markup = $0.1575 = 157500 base units.
    expect(costInBaseUnits(model, 500, 1_000_000n, 0n)).toBe(157_500n)
    // 1M output tokens at $0.60 list with 500 bps = $0.63.
    expect(costInBaseUnits(model, 500, 0n, 1_000_000n)).toBe(630_000n)
    expect(costInBaseUnits(model, 0, 1_000_000n, 1_000_000n)).toBe(750_000n)
  })

  it('rounds partial base units up, never down', () => {
    // One output token costs 0.63 base units with markup: charge 1.
    expect(costInBaseUnits(model, 500, 0n, 1n)).toBe(1n)
    // 100 output tokens = 63 base units exactly.
    expect(costInBaseUnits(model, 500, 0n, 100n)).toBe(63n)
    // 101 tokens = 63.63 -> 64.
    expect(costInBaseUnits(model, 500, 0n, 101n)).toBe(64n)
    expect(ceilToBaseUnits(0n)).toBe(0n)
    expect(scaledCost(model, 500, 0n, 1n)).toBe(600_000n * 10_500n)
  })

  it('publishes per-1M relay prices as exact decimals', () => {
    expect(relayPricePer1M(150_000n, 500)).toBe('157500')
    expect(relayPricePer1M(1n, 500)).toBe('1.05')
    expect(relayPricePer1M(3n, 333)).toBe('3.0999')
    expect(formatUnits(157_500n, 6)).toBe('0.1575')
    expect(formatUnits(2_000_000n, 6)).toBe('2')
    expect(formatUnits(1n, 6)).toBe('0.000001')
  })

  it('rejects bad markups and malformed tables', () => {
    expect(() => costInBaseUnits(model, -1, 1n, 1n)).toThrow(/markup/)
    expect(() => parsePriceTable({ currency: '0x20c0000000000000000000000000000000000000', decimals: 18, models: [] }, 500)).toThrow(/decimals/)
    const base = { currency: '0x20c0000000000000000000000000000000000000', decimals: 6 }
    expect(() =>
      parsePriceTable({ ...base, models: [{ id: 'x/y', provider: 'tinfoil', upstream_model: 'y', input_per_1m: 1, output_per_1m: 1 }] }, 500),
    ).toThrow(/must start with "tinfoil\/"/)
    expect(() =>
      parsePriceTable({ ...base, models: [{ id: 'tinfoil/y', provider: 'tinfoil', upstream_model: 'y', input_per_1m: 0.5, output_per_1m: 1 }] }, 500),
    ).toThrow(/integer/)
    expect(() =>
      parsePriceTable({ ...base, models: [{ id: 'other/y', provider: 'other', upstream_model: 'y', input_per_1m: 1, output_per_1m: 1 }] }, 500),
    ).toThrow(/provider/)
  })

  it('loads the shipped price table', () => {
    const table = loadPriceTable(join(import.meta.dirname, '../config/prices.json'), 500)
    expect(table.currency).toBe('0x20c0000000000000000000000000000000000000')
    expect(table.models.length).toBeGreaterThan(0)
    const providers = new Set(table.models.map((m) => m.provider))
    expect([...providers].sort()).toEqual(['nearai', 'phala', 'privatemode', 'tinfoil'])
    for (const m of table.models) expect(m.id.startsWith(`${m.provider}/`)).toBe(true)
  })
})

describe('token estimates', () => {
  it('is deterministic and errs high', () => {
    const text = 'hello world, this is twelve tokens or so of English text'
    const body = { messages: [{ role: 'user', content: text }] }
    const a = estimatePromptTokens(body)
    expect(a).toBe(estimatePromptTokens(JSON.parse(JSON.stringify(body))))
    expect(a).toBe(3 + 4 + Math.ceil(Buffer.byteLength(text) / 3))
  })

  it('counts multi-part content, tool calls and tools', () => {
    const plain = estimatePromptTokens({ messages: [{ role: 'user', content: 'abc' }] })
    const parts = estimatePromptTokens({ messages: [{ role: 'user', content: [{ type: 'text', text: 'abc' }] }] })
    expect(parts).toBe(plain)
    const tools = estimatePromptTokens({ messages: [], tools: [{ type: 'function', function: { name: 'f' } }] })
    expect(tools).toBeGreaterThan(3)
  })

  it('counts at least one token per non-empty delta', () => {
    expect(estimateDeltaTokens('')).toBe(0)
    expect(estimateDeltaTokens('a')).toBe(1)
    expect(estimateDeltaTokens('abcdefgh')).toBe(2)
  })
})
