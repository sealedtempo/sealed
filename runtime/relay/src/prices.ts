import { readFileSync } from 'node:fs'

export const PROVIDERS = ['tinfoil', 'phala', 'nearai', 'privatemode'] as const
export type ProviderId = (typeof PROVIDERS)[number]

/**
 * One relay model. Prices are provider list prices in FEE_TOKEN base units
 * (pathUSD, 6 decimals) per 1,000,000 tokens, so $0.90 per 1M tokens is 900000.
 */
export type ModelPrice = {
  id: string
  provider: ProviderId
  upstreamModel: string
  inputPer1M: bigint
  outputPer1M: bigint
  maxOutputTokens: number
}

export type PriceTable = {
  currency: `0x${string}`
  decimals: number
  markupBps: number
  defaultMaxTokens: number
  models: ModelPrice[]
}

const TOKENS_PER_PRICE_UNIT = 1_000_000n
const BPS = 10_000n

/** Denominator that turns a scaled cost into base units: 1M tokens times basis points. */
export const COST_SCALE = TOKENS_PER_PRICE_UNIT * BPS

export function markupFactor(markupBps: number): bigint {
  if (!Number.isInteger(markupBps) || markupBps < 0 || markupBps > 100_000)
    throw new Error(`relay_markup_bps out of range: ${markupBps}`)
  return BPS + BigInt(markupBps)
}

/** Cost scaled by COST_SCALE, exact: tokens x list price x (1 + markup_bps / 10000). */
export function scaledCost(model: ModelPrice, markupBps: number, inputTokens: bigint, outputTokens: bigint): bigint {
  if (inputTokens < 0n || outputTokens < 0n) throw new Error('negative token count')
  return (inputTokens * model.inputPer1M + outputTokens * model.outputPer1M) * markupFactor(markupBps)
}

/** Smallest whole number of base units that covers a scaled cost. */
export function ceilToBaseUnits(scaled: bigint): bigint {
  if (scaled <= 0n) return 0n
  return (scaled + COST_SCALE - 1n) / COST_SCALE
}

export function costInBaseUnits(model: ModelPrice, markupBps: number, inputTokens: bigint, outputTokens: bigint): bigint {
  return ceilToBaseUnits(scaledCost(model, markupBps, inputTokens, outputTokens))
}

/** Relay price per 1M tokens as an exact decimal string in base units (may carry up to 4 fractional digits). */
export function relayPricePer1M(listPer1M: bigint, markupBps: number): string {
  const scaled = listPer1M * markupFactor(markupBps)
  const whole = scaled / BPS
  const frac = scaled % BPS
  if (frac === 0n) return whole.toString()
  return `${whole}.${frac.toString().padStart(4, '0').replace(/0+$/, '')}`
}

/** Formats base units as a decimal string in token units (6 decimals for pathUSD). */
export function formatUnits(value: bigint, decimals: number): string {
  const negative = value < 0n
  const abs = negative ? -value : value
  const base = 10n ** BigInt(decimals)
  const whole = abs / base
  const frac = (abs % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${negative ? '-' : ''}${whole}${frac ? `.${frac}` : ''}`
}

type RawModel = {
  id?: unknown
  provider?: unknown
  upstream_model?: unknown
  input_per_1m?: unknown
  output_per_1m?: unknown
  max_output_tokens?: unknown
}

function parseBaseUnits(value: unknown, field: string): bigint {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value)
  if (typeof value === 'string' && /^\d+$/.test(value)) return BigInt(value)
  throw new Error(`price table: ${field} must be a non-negative integer in base units`)
}

export function parsePriceTable(json: unknown, markupBps: number): PriceTable {
  if (!json || typeof json !== 'object') throw new Error('price table: expected an object')
  const raw = json as Record<string, unknown>
  const currency = raw.currency
  if (typeof currency !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(currency))
    throw new Error('price table: currency must be an address')
  const decimals = raw.decimals
  if (decimals !== 6) throw new Error('price table: decimals must be 6 (pathUSD)')
  const defaultMaxTokens = raw.default_max_tokens ?? 1024
  if (typeof defaultMaxTokens !== 'number' || !Number.isSafeInteger(defaultMaxTokens) || defaultMaxTokens <= 0)
    throw new Error('price table: default_max_tokens must be a positive integer')
  if (!Array.isArray(raw.models) || raw.models.length === 0) throw new Error('price table: models must be a non-empty array')
  markupFactor(markupBps)
  const seen = new Set<string>()
  const models = raw.models.map((entry: RawModel, index): ModelPrice => {
    const where = `models[${index}]`
    if (typeof entry.id !== 'string' || !entry.id) throw new Error(`price table: ${where}.id missing`)
    if (seen.has(entry.id)) throw new Error(`price table: duplicate model ${entry.id}`)
    seen.add(entry.id)
    if (typeof entry.provider !== 'string' || !(PROVIDERS as readonly string[]).includes(entry.provider))
      throw new Error(`price table: ${where}.provider must be one of ${PROVIDERS.join(', ')}`)
    if (!entry.id.startsWith(`${entry.provider}/`))
      throw new Error(`price table: ${where}.id must start with "${entry.provider}/"`)
    if (typeof entry.upstream_model !== 'string' || !entry.upstream_model)
      throw new Error(`price table: ${where}.upstream_model missing`)
    const maxOutputTokens = entry.max_output_tokens ?? defaultMaxTokens
    if (typeof maxOutputTokens !== 'number' || !Number.isSafeInteger(maxOutputTokens) || maxOutputTokens <= 0)
      throw new Error(`price table: ${where}.max_output_tokens must be a positive integer`)
    return {
      id: entry.id,
      provider: entry.provider as ProviderId,
      upstreamModel: entry.upstream_model,
      inputPer1M: parseBaseUnits(entry.input_per_1m, `${where}.input_per_1m`),
      outputPer1M: parseBaseUnits(entry.output_per_1m, `${where}.output_per_1m`),
      maxOutputTokens,
    }
  })
  return { currency: currency.toLowerCase() as `0x${string}`, decimals, markupBps, defaultMaxTokens, models }
}

export function loadPriceTable(path: string, markupBps: number): PriceTable {
  return parsePriceTable(JSON.parse(readFileSync(path, 'utf8')), markupBps)
}

export function findModel(table: PriceTable, id: string): ModelPrice | undefined {
  return table.models.find((m) => m.id === id)
}
