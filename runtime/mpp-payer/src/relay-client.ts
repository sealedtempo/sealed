import { randomUUID } from 'node:crypto'
import { Mppx, tempo } from 'mppx/client'
import type { Account, Client } from 'viem'
import { ESCROW_PRECOMPILE } from './config.js'
import { PaymentPolicyError, SpendLimitError } from './spend-guard.js'

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export type RelayClientDeps = {
  relayUrl: string
  account: Account
  getClient: (parameters: { chainId?: number }) => Client | Promise<Client>
  currency: `0x${string}`
  chainId: number
  decimals: number
  maxDeposit: bigint
  maxCharge: bigint
  expectedPayee: () => `0x${string}` | undefined
  /** The payment-firewalled fetch every mppx client must use. */
  fetch: FetchLike
  /** How long to stay on per-request charges after a session could not be used. */
  sessionRetrySeconds?: number
  now?: () => number
  log?: (event: Record<string, unknown>) => void
  /** Test seams. */
  sessionManagerFactory?: (parameters: Record<string, unknown>) => SessionManagerLike
  chargeClientFactory?: (parameters: Record<string, unknown>) => { fetch: FetchLike }
}

export type SessionManagerLike = {
  sse(input: string, init?: RequestInit): Promise<AsyncIterable<string>>
  close(): Promise<unknown>
  readonly channelId?: string | undefined
}

export type RelayResult =
  | { kind: 'session'; events: AsyncIterable<string> }
  /** A plain relay response: a paid per-request charge, or a refusal (for example an unattested provider). */
  | { kind: 'response'; intent: 'charge' | 'refused'; response: Response }

const REQUEST_ID_HEADER = 'x-sealed-request-id'

function formatUnits(value: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals)
  const frac = (value % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${value / base}${frac ? `.${frac}` : ''}`
}

/** The first SpendLimitError or PaymentPolicyError in an error's cause chain. */
export function rootPolicyError(error: unknown): SpendLimitError | PaymentPolicyError | undefined {
  let current: unknown = error
  for (let depth = 0; current && depth < 8; depth++) {
    if (current instanceof SpendLimitError || current instanceof PaymentPolicyError) return current
    current = (current as { cause?: unknown }).cause
  }
  return undefined
}

/**
 * Pays the relay with mppx: per-token MPP sessions over SSE first, per-request charges as the
 * fallback when a session cannot be opened or used (no session offer, escrow unavailable,
 * remaining budget below one deposit). Payment policy violations never fall back.
 */
export class RelayClient {
  private session: SessionManagerLike | undefined
  private sessionPayee: string | undefined
  private charge: { fetch: FetchLike } | undefined
  private chargePayee: string | undefined
  private sessionsDisabledUntil = 0
  private readonly now: () => number
  /** Non-payment error responses the relay gave to a session request, keyed by our request id. */
  private readonly refusals = new Map<string, Response>()
  private readonly sessionFetch: FetchLike

  constructor(private readonly deps: RelayClientDeps) {
    this.now = deps.now ?? (() => Math.floor(Date.now() / 1000))
    this.sessionFetch = async (input, init) => {
      const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase()
      const id = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).get(REQUEST_ID_HEADER)
      const response = await deps.fetch(input, init)
      const type = response.headers.get('content-type') ?? ''
      if (id && method === 'POST' && response.status >= 400 && response.status !== 402 && !type.includes('text/event-stream'))
        this.refusals.set(id, response.clone())
      return response
    }
  }

  get chatUrl(): string {
    return `${this.deps.relayUrl}/v1/chat/completions`
  }

  sessionsAvailable(): boolean {
    return this.now() >= this.sessionsDisabledUntil
  }

  async chat(body: Record<string, unknown>, signal?: AbortSignal): Promise<RelayResult> {
    const payee = this.deps.expectedPayee()
    if (!payee) throw new PaymentPolicyError('relay payee unknown: relay attestation has not passed')
    if (this.sessionsAvailable()) {
      const requestId = randomUUID()
      try {
        const manager = this.sessionFor(payee)
        const events = await manager.sse(this.chatUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'text/event-stream', [REQUEST_ID_HEADER]: requestId },
          body: JSON.stringify({ ...body, stream: true, stream_options: { include_usage: true } }),
          signal,
        })
        return { kind: 'session', events }
      } catch (error) {
        const policy = rootPolicyError(error)
        if (policy instanceof PaymentPolicyError) throw policy
        const refusal = this.refusals.get(requestId)
        if (refusal) return { kind: 'response', intent: 'refused', response: refusal }
        this.sessionsDisabledUntil = this.now() + (this.deps.sessionRetrySeconds ?? 300)
        this.deps.log?.({ event: 'session_unavailable', reason: (policy ?? (error as Error)).message?.slice(0, 200) })
      } finally {
        this.refusals.delete(requestId)
      }
    }
    try {
      const response = await this.chargeFor(payee).fetch(this.chatUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal,
      })
      return { kind: 'response', intent: response.status === 402 || response.status >= 400 ? 'refused' : 'charge', response }
    } catch (error) {
      throw rootPolicyError(error) ?? error
    }
  }

  /** Cooperative close of the open channel, so the unspent deposit is refunded. */
  async close(): Promise<void> {
    await this.session?.close().catch(() => {})
    this.session = undefined
  }

  private sessionFor(payee: string): SessionManagerLike {
    if (this.session && this.sessionPayee === payee) return this.session
    if (this.session) void this.session.close().catch(() => {})
    const parameters = {
      account: this.deps.account,
      getClient: this.deps.getClient,
      decimals: this.deps.decimals,
      maxDeposit: formatUnits(this.deps.maxDeposit, this.deps.decimals),
      allowedChainIds: [this.deps.chainId],
      escrow: ESCROW_PRECOMPILE,
      bootstrap: true,
      fetch: this.sessionFetch,
    }
    this.session = this.deps.sessionManagerFactory
      ? this.deps.sessionManagerFactory(parameters)
      : (tempo.session.manager(parameters as never) as unknown as SessionManagerLike)
    this.sessionPayee = payee
    return this.session
  }

  private chargeFor(payee: `0x${string}`): { fetch: FetchLike } {
    if (this.charge && this.chargePayee === payee) return this.charge
    const parameters = {
      account: this.deps.account,
      getClient: this.deps.getClient,
      currencies: [this.deps.currency],
      decimals: this.deps.decimals,
      expectedRecipients: [payee],
      expectedChainId: this.deps.chainId,
      maxAmount: formatUnits(this.deps.maxCharge, this.deps.decimals),
      mode: 'pull',
    }
    this.charge = this.deps.chargeClientFactory
      ? this.deps.chargeClientFactory(parameters)
      : (Mppx.create({ polyfill: false, fetch: this.deps.fetch, maxPaymentRetries: 1, methods: [tempo.charge(parameters as never)] } as never) as unknown as {
          fetch: FetchLike
        })
    this.chargePayee = payee
    return this.charge
  }
}
