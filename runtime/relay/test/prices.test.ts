import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
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
import { modelsDocument } from '../src/server.js'
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

  it('loads the shipped price table, denominated in FEE_TOKEN (USDC.e, D-035)', () => {
    const table = loadPriceTable(join(import.meta.dirname, '../config/prices.json'), 500)
    expect(table.currency).toBe('0x20c000000000000000000000b9537d11c60e8b50')
    expect(table.models.length).toBeGreaterThan(0)
    const providers = new Set(table.models.map((m) => m.provider))
    expect([...providers].sort()).toEqual(['nearai', 'phala', 'tinfoil'])
    for (const m of table.models) expect(m.id.startsWith(`${m.provider}/`)).toBe(true)
  })

  // Read from Tinfoil's public model catalog (https://tinfoil.sh/models) on 2026-10-28:
  // GPT-OSS 120B $0.15 in / $0.60 out per 1M tokens, GLM-5.3 $1.80 / $5.75.
  const raw = JSON.parse(readFileSync(join(import.meta.dirname, '../config/prices.json'), 'utf8')) as {
    models: { id: string; input_per_1m: number; output_per_1m: number; source?: string; checked?: string; confirmed?: boolean }[]
  }
  it('sets the Tinfoil list prices from its public price list, with source and date', () => {
    const tinfoil = raw.models.filter((m) => m.id.startsWith('tinfoil/'))
    expect(tinfoil.map(({ id, input_per_1m, output_per_1m, source, checked, confirmed }) => ({ id, input_per_1m, output_per_1m, source, checked, confirmed }))).toEqual([
      { id: 'tinfoil/gpt-oss-120b', input_per_1m: 150_000, output_per_1m: 600_000, source: 'https://tinfoil.sh/models', checked: '2026-10-28', confirmed: true },
      { id: 'tinfoil/glm-5-3', input_per_1m: 1_800_000, output_per_1m: 5_750_000, source: 'https://tinfoil.sh/models', checked: '2026-10-28', confirmed: true },
    ])
    for (const m of raw.models) {
      expect(m.checked, m.id).toMatch(/^\d{4}-\d{2}-\d{2}$/)
      if (m.confirmed) expect(m.source, m.id).toMatch(/^https:\/\//)
    }
  })

  it('publishes Tinfoil prices with the 5% markup of spec 7.4 and charges by them', () => {
    const table = loadPriceTable(join(import.meta.dirname, '../config/prices.json'), 500)
    const gate = { allows: () => true, status: (p: string) => ({ provider: p, enabled: true, verified: true, detail: 'ok' }), all: () => [] }
    const listed = modelsDocument(table, gate as never).data
    const price = (id: string) => listed.find((m) => m.id === id)!.sealed.price
    // list x (1 + 500/10000): 150000 x 1.05 = 157500, 600000 x 1.05 = 630000 base units per 1M tokens.
    expect(price('tinfoil/gpt-oss-120b')).toMatchObject({
      currency: '0x20c000000000000000000000b9537d11c60e8b50',
      markup_bps: 500,
      input_per_1m: '157500',
      output_per_1m: '630000',
      list_input_per_1m: '150000',
      list_output_per_1m: '600000',
    })
    expect(price('tinfoil/glm-5-3')).toMatchObject({ input_per_1m: '1890000', output_per_1m: '6037500' })
    // 1000 prompt + 500 completion tokens of gpt-oss-120b: (150 + 300) x 1.05 = 472.5 -> 473 base units.
    const gptOss = table.models.find((m) => m.id === 'tinfoil/gpt-oss-120b')!
    expect(costInBaseUnits(gptOss, 500, 1_000n, 500n)).toBe(473n)
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
