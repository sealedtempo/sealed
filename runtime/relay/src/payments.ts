import { Credential } from 'mppx'
import { Mppx, type Store, tempo } from 'mppx/server'
import type { Account, Client } from 'viem'
import { formatUnits } from './prices.js'

/**
 * Session pricing unit: one FEE_TOKEN base unit (0.000001 pathUSD). Per-token relay prices are
 * fractions of a base unit, so the meter charges explicit raw amounts against this unit and the
 * per-model prices are published on GET /v1/models instead of in the challenge.
 */
export const SESSION_UNIT_AMOUNT = '0.000001'
export const SESSION_UNIT_TYPE = 'usd_micro'

export type PaymentsConfig = {
  realm: string
  secretKey: string
  recipient: `0x${string}`
  currency: `0x${string}`
  decimals: number
  chainId: number
  store: Store.AtomicStore
  getClient: (parameters: { chainId?: number }) => Client | Promise<Client>
  /** Hot key that sends settle/close (the channel operator). Without it, only per-request charges are offered. */
  settler?: Account
  suggestedDeposit: string
  settlementSchedule?: { amount?: string; intervalMs?: number }
  resolveChannelId?: (parameters: { source?: string }) => Promise<`0x${string}` | undefined>
  onSettlement?: (event: { channelId: string; txHash?: string }) => void
}

export type PaymentResult =
  | { status: 402; challenge: Response }
  | { status: 200; intent: 'charge' | 'session'; withReceipt: (response?: unknown) => Response | Promise<Response>; channelId?: `0x${string}` }

export type Payments = {
  sessionsEnabled: boolean
  /** Runs the MPP exchange for a request: a 402 with every applicable offer, or the verified payment. */
  handle(request: Request, offers: { chargeAmount?: bigint; description?: string }): Promise<PaymentResult>
  credit(channelId: `0x${string}`, amount: bigint, idempotencyKey: string): Promise<'credited' | 'declined' | 'unknown'>
}

export function createPayments(config: PaymentsConfig): Payments {
  const common = {
    chainId: config.chainId,
    currencies: [config.currency],
    store: config.store,
    getClient: config.getClient,
  }
  const [chargeMethod] = tempo.charge({ ...common, recipient: config.recipient } as never) as unknown as [unknown]
  const sessionMethod = config.settler
    ? (tempo.session({
        ...common,
        account: config.settler,
        recipient: config.recipient,
        operator: config.settler.address,
        sse: true,
        suggestedDeposit: config.suggestedDeposit,
        settlementSchedule: config.settlementSchedule,
        bootstrap: config.resolveChannelId !== undefined,
        resolveChannelId: config.resolveChannelId,
        onSessionSettlement: config.onSettlement,
      } as never) as unknown as [unknown])[0]
    : undefined
  const mppx = Mppx.create({
    realm: config.realm,
    secretKey: config.secretKey,
    methods: (sessionMethod ? [chargeMethod, sessionMethod] : [chargeMethod]) as never,
  }) as unknown as {
    compose(...entries: unknown[]): (request: Request) => Promise<{ status: 402; challenge: Response } | { status: 200; withReceipt: (r?: unknown) => Response }>
  }

  return {
    sessionsEnabled: sessionMethod !== undefined,
    async handle(request, offers) {
      const entries: unknown[] = []
      if (sessionMethod)
        entries.push([sessionMethod, { amount: SESSION_UNIT_AMOUNT, unitType: SESSION_UNIT_TYPE, suggestedDeposit: config.suggestedDeposit }])
      if (offers.chargeAmount !== undefined && offers.chargeAmount > 0n)
        entries.push([chargeMethod, { amount: formatUnits(offers.chargeAmount, config.decimals), description: offers.description }])
      if (entries.length === 0)
        return { status: 402, challenge: Response.json({ error: { type: 'no_payment_offer' } }, { status: 400 }) }
      const result = await mppx.compose(...entries)(request)
      if (result.status === 402) return { status: 402, challenge: result.challenge }
      const credential = Credential.fromRequest<{ channelId?: `0x${string}` }>(request)
      const intent = credential.challenge.intent === 'session' ? 'session' : 'charge'
      return {
        status: 200,
        intent,
        withReceipt: (response?: unknown) => result.withReceipt(response),
        channelId: intent === 'session' ? credential.payload.channelId : undefined,
      }
    },
    async credit(channelId, amount, idempotencyKey) {
      const outcome = await tempo.session.credit(config.store as never, channelId, amount, { idempotencyKey })
      return (outcome as { status?: string }).status as 'credited' | 'declined' | 'unknown'
    },
  }
}
