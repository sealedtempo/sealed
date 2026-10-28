import { describe, expect, it } from 'vitest'
import { SessionMeter } from '../src/metering.js'
import type { ModelPrice } from '../src/prices.js'

const model: ModelPrice = {
  id: 'nearai/z-ai/glm-5.3',
  provider: 'nearai',
  upstreamModel: 'z-ai/glm-5.3',
  inputPer1M: 1_800_000n,
  outputPer1M: 5_750_000n,
  maxOutputTokens: 4096,
}

function recorder() {
  const charges: bigint[] = []
  const credits: { amount: bigint; key: string }[] = []
  return {
    charges,
    credits,
    charger: { charge: async (amount: bigint) => void charges.push(amount) },
    credit: async (amount: bigint, key: string) => {
      credits.push({ amount, key })
      return 'credited' as const
    },
  }
}

const chunk = (content: string) => ({ choices: [{ delta: { content } }] })

describe('SessionMeter', () => {
  it('charges the prompt plus one batch before any output', async () => {
    const r = recorder()
    const meter = new SessionMeter(model, 500, r.charger, { batchTokens: 32, requestId: 'a', credit: r.credit })
    await meter.reservePrompt(1000)
    // 1000 * 1.8 * 1.05 = 1890 base units; plus 32 * 5.75 * 1.05 = 193.2 -> ceil(2083.2) = 2084
    expect(r.charges).toEqual([2084n])
  })

  it('batches: one charge per batch of output tokens, always ahead of delivery', async () => {
    const r = recorder()
    const meter = new SessionMeter(model, 500, r.charger, { batchTokens: 10, requestId: 'b', credit: r.credit })
    await meter.reservePrompt(0)
    expect(r.charges.length).toBe(1)
    for (let i = 0; i < 10; i++) await meter.beforeDeliver(chunk('tok'))
    expect(r.charges.length).toBe(1)
    await meter.beforeDeliver(chunk('tok'))
    expect(r.charges.length).toBe(2)
    const total = r.charges.reduce((a, b) => a + b, 0n)
    // charged covers 11 delivered tokens plus a further batch of 10
    expect(total * 10_000_000_000n >= 21n * 5_750_000n * 10_500n).toBe(true)
    // chunks without content are free
    await meter.beforeDeliver({ choices: [{ delta: {} }] })
    expect(r.charges.length).toBe(2)
  })

  it('reconciles with reported usage: credits the unused prepaid amount', async () => {
    const r = recorder()
    const meter = new SessionMeter(model, 500, r.charger, { batchTokens: 32, requestId: 'c', credit: r.credit })
    await meter.reservePrompt(100)
    await meter.beforeDeliver(chunk('hi'))
    await meter.reconcile({ prompt_tokens: 20, completion_tokens: 1 })
    await meter.settleUnused()
    const charged = r.charges.reduce((a, b) => a + b, 0n)
    // exact cost: (20*1.8 + 1*5.75) * 1.05 = 43.8375 -> 44
    expect(charged - r.credits[0]!.amount).toBe(44n)
    expect(r.credits[0]!.key).toBe('relay-credit:c')
    expect(meter.result()).toMatchObject({ chargedBaseUnits: 44n, promptTokens: 20, completionTokens: 1, usageReported: true })
  })

  it('charges a shortfall when usage exceeds the estimate', async () => {
    const r = recorder()
    const meter = new SessionMeter(model, 500, r.charger, { batchTokens: 1, requestId: 'd', credit: r.credit })
    await meter.reservePrompt(1)
    await meter.reconcile({ prompt_tokens: 100_000, completion_tokens: 0 })
    const charged = r.charges.reduce((a, b) => a + b, 0n)
    expect(charged).toBe(189_000n)
    await meter.settleUnused()
    expect(r.credits).toEqual([])
  })

  it('voids everything when the upstream fails before output', async () => {
    const r = recorder()
    const meter = new SessionMeter(model, 500, r.charger, { batchTokens: 4, requestId: 'e', credit: r.credit })
    await meter.reservePrompt(50)
    meter.voidAll()
    await meter.settleUnused()
    expect(r.credits[0]!.amount).toBe(r.charges[0])
    expect(meter.result().chargedBaseUnits).toBe(0n)
  })

  it('keeps the charge when a credit is declined', async () => {
    const r = recorder()
    const meter = new SessionMeter(model, 500, r.charger, {
      batchTokens: 4,
      requestId: 'f',
      credit: async () => 'declined',
    })
    await meter.reservePrompt(50)
    meter.voidAll()
    await meter.settleUnused()
    expect(meter.result().chargedBaseUnits).toBe(r.charges[0])
  })
})
