import { COST_SCALE, type ModelPrice, ceilToBaseUnits, markupFactor, scaledCost } from './prices.js'
import { type ChatChunk, chunkText } from './upstream.js'
import { estimateDeltaTokens } from './tokens.js'

/** The part of mppx's SSE SessionController the meter needs. */
export type Charger = { charge(amount: bigint): Promise<void> }

/** Returns unused prepaid base units to the channel (mppx `tempo.session.credit`). */
export type Crediter = (amount: bigint, idempotencyKey: string) => Promise<'credited' | 'declined' | 'unknown'>

export type MeterResult = {
  chargedBaseUnits: bigint
  creditedBaseUnits: bigint
  promptTokens: number
  completionTokens: number
  usageReported: boolean
}

/**
 * Per-token session metering with batching. The meter keeps the exact owed cost scaled by
 * COST_SCALE and always charges ahead of delivery: before a chunk goes out, the charged
 * base units must cover everything delivered so far. When headroom runs out it charges
 * for the next `batchTokens` completion tokens in one voucher round trip. The final
 * `usage` chunk reconciles: a shortfall is charged, an overcharge is credited back.
 */
export class SessionMeter {
  private charged = 0n
  private credited = 0n
  private owedScaled = 0n
  private completionTokens = 0
  private promptTokens = 0
  private usageReported = false
  private readonly outputStep: bigint

  constructor(
    private readonly model: ModelPrice,
    private readonly markupBps: number,
    private readonly charger: Charger,
    private readonly options: { batchTokens: number; requestId: string; credit?: Crediter },
  ) {
    if (!Number.isSafeInteger(options.batchTokens) || options.batchTokens <= 0) throw new Error('batchTokens must be positive')
    this.outputStep = model.outputPer1M * markupFactor(markupBps)
  }

  /** Pays for the (estimated) prompt before any upstream work starts. */
  async reservePrompt(estimatedPromptTokens: number): Promise<void> {
    this.promptTokens = estimatedPromptTokens
    this.owedScaled = scaledCost(this.model, this.markupBps, BigInt(estimatedPromptTokens), 0n)
    await this.chargeUpTo(this.owedScaled + BigInt(this.options.batchTokens) * this.outputStep)
  }

  /** Accounts for one upstream chunk before it is delivered to the client. */
  async beforeDeliver(chunk: ChatChunk): Promise<void> {
    const tokens = estimateDeltaTokens(chunkText(chunk))
    if (tokens === 0) return
    this.completionTokens += tokens
    this.owedScaled += BigInt(tokens) * this.outputStep
    if (this.charged * COST_SCALE < this.owedScaled)
      await this.chargeUpTo(this.owedScaled + BigInt(this.options.batchTokens) * this.outputStep)
  }

  /** Reconciles against the provider's reported usage. */
  async reconcile(usage: { prompt_tokens?: number; completion_tokens?: number }): Promise<void> {
    const prompt = Number(usage.prompt_tokens ?? this.promptTokens)
    const completion = Number(usage.completion_tokens ?? this.completionTokens)
    if (!Number.isSafeInteger(prompt) || !Number.isSafeInteger(completion) || prompt < 0 || completion < 0) return
    this.usageReported = true
    this.promptTokens = prompt
    this.completionTokens = completion
    this.owedScaled = scaledCost(this.model, this.markupBps, BigInt(prompt), BigInt(completion))
    const owed = ceilToBaseUnits(this.owedScaled)
    if (owed > this.charged) {
      await this.chargeExactly(owed - this.charged)
    }
  }

  /** The request produced nothing billable (upstream failed before output): owe nothing. */
  voidAll(): void {
    this.owedScaled = 0n
    this.completionTokens = 0
  }

  /** Credits back what was prepaid beyond the final cost. Call once, after the stream ends. */
  async settleUnused(): Promise<void> {
    const owed = ceilToBaseUnits(this.owedScaled)
    const unused = this.charged - this.credited - owed
    if (unused <= 0n || !this.options.credit) return
    const outcome = await this.options.credit(unused, `relay-credit:${this.options.requestId}`)
    if (outcome === 'credited') this.credited += unused
  }

  result(): MeterResult {
    return {
      chargedBaseUnits: this.charged - this.credited,
      creditedBaseUnits: this.credited,
      promptTokens: this.promptTokens,
      completionTokens: this.completionTokens,
      usageReported: this.usageReported,
    }
  }

  private async chargeUpTo(targetScaled: bigint): Promise<void> {
    const target = ceilToBaseUnits(targetScaled)
    if (target > this.charged) await this.chargeExactly(target - this.charged)
  }

  private async chargeExactly(amount: bigint): Promise<void> {
    if (amount <= 0n) return
    await this.charger.charge(amount)
    this.charged += amount
  }
}
