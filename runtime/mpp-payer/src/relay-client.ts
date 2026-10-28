import { randomUUID } from 'node:crypto'
import { Mppx, createChannelStore, createJsonChannelStore, entryKey, tempo } from 'mppx/client'
import { type Account, type Client, type Hex, hashTypedData } from 'viem'
import type { ChannelJournal, FileKv } from './channel-journal.js'
import { ESCROW_PRECOMPILE } from './config.js'
import { RelayChannelError, wasNotSent } from './relay-transport.js'
import { BudgetUnavailableError } from './shared-budget.js'
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
  /** Persists the session channel across restarts (mppx createJsonChannelStore); in memory without it. */
  channelKv?: FileKv
  /** Channels the payer opened; retired ones are recovered by ChannelRecovery. */
  journal?: ChannelJournal
  /**
   * A channel is closed and replaced once less than this is left below maxDeposit (mppx caps
   * every voucher of a channel at maxDeposit and never rotates by itself). Default maxCharge.
   */
  rotateHeadroom?: bigint
  /** How long to stay on per-request charges after a session could not be used. */
  sessionRetrySeconds?: number
  /** Time allowed for a cooperative close (the relay waits up to 30 s for its close transaction). */
  closeTimeoutMs?: number
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
  /** Highest voucher signed on the open channel, in base units. */
  readonly cumulative?: bigint
}

export type RelayResult =
  | { kind: 'session'; events: AsyncIterable<string> }
  /**
   * A plain relay response. paid: the relay took a per-request charge (it attached a payment
   * receipt). A charge request is always sent as a stream (the relay settles a charge only after
   * the upstream's first byte); streamed tells the server to fold it back for a non-stream client.
   */
  | { kind: 'response'; intent: 'charge' | 'refused'; paid: boolean; streamed: boolean; response: Response }

/**
 * The session request reached the relay with a payment credential and then failed. It is not
 * sent again as a charge: the relay may have started (and been paid for) the work.
 */
export class RelaySessionFailedError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'RelaySessionFailedError'
  }
}

const REQUEST_ID_HEADER = 'x-sealed-request-id'

type SignTypedData = (typedData: Parameters<typeof hashTypedData>[0]) => Promise<Hex>

/**
 * mppx 0.15.0 signs a channel's cooperative close authorization with the account's
 * signTypedData, which for a Tempo access key is a keychain envelope, and the escrow requires a
 * primitive signature by the channel's authorizedSigner (the access key). Vouchers already get
 * one (viem's signVoucher signs raw with the key). This signs the CloseAuthorization the same
 * way, so a channel opened in access-key mode can be closed cooperatively; every other typed
 * signature is unchanged.
 */
export function withPrimitiveCloseSignatures(account: Account): Account {
  const a = account as Account & { source?: string; sign?: (p: { hash: Hex; raw?: boolean }) => Promise<Hex>; signTypedData?: SignTypedData }
  if (a.source !== 'accessKey' || typeof a.sign !== 'function' || typeof a.signTypedData !== 'function') return account
  const sign = a.sign
  const signTypedData = a.signTypedData
  return {
    ...a,
    signTypedData: (async (typedData: Parameters<typeof hashTypedData>[0]) =>
      typedData.primaryType === 'CloseAuthorization' ? sign({ hash: hashTypedData(typedData), raw: true }) : signTypedData(typedData)) as never,
  } as Account
}

function formatUnits(value: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals)
  const frac = (value % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${value / base}${frac ? `.${frac}` : ''}`
}

type PolicyError = SpendLimitError | PaymentPolicyError | RelayChannelError | BudgetUnavailableError

/** The first SpendLimitError, PaymentPolicyError, RelayChannelError or BudgetUnavailableError in an error's cause chain. */
export function rootPolicyError(error: unknown): PolicyError | undefined {
  let current: unknown = error
  for (let depth = 0; current && depth < 8; depth++) {
    if (
      current instanceof SpendLimitError ||
      current instanceof PaymentPolicyError ||
      current instanceof RelayChannelError ||
      current instanceof BudgetUnavailableError
    )
      return current
    current = (current as { cause?: unknown }).cause
  }
  return undefined
}

function hasPayment(headers: Headers): boolean {
  return /^Payment\s+/i.test(headers.get('authorization') ?? '') || /^Payment\s+/i.test(headers.get('payment-authorization') ?? '')
}

function bodyLength(input: RequestInfo | URL, init?: RequestInit): number {
  const body = init?.body
  if (typeof body === 'string') return body.length
  if (body instanceof Uint8Array) return body.byteLength
  if (body instanceof ArrayBuffer) return body.byteLength
  if (body !== undefined && body !== null) return 1
  return input instanceof Request && input.body ? 1 : 0
}

type ChannelEntry = { channelId: string; cumulativeAmount: bigint; deposit: bigint; descriptor: { payee: string; token: string }; escrow: string; chainId: number }
type ChannelStore = { get(key: string): unknown; set(entry: ChannelEntry): unknown; delete(key: string): unknown }

/**
 * One manager's view of the channel store. Only the current generation writes the shared store
 * (so a restart resumes its channel); a generation rotated out keeps working on its own copy,
 * so its close cannot delete the entry of the channel that replaced it.
 */
class StoreView implements ChannelStore {
  current = true
  private readonly local = new Map<string, ChannelEntry>()

  constructor(private readonly backing: ChannelStore) {}

  async get(key: string) {
    if (this.local.has(key)) return this.local.get(key)
    if (!this.current) return undefined
    return (await this.backing.get(key)) as ChannelEntry | undefined
  }

  async set(entry: ChannelEntry) {
    this.local.set(entryKey(entry as never), entry)
    if (this.current) await this.backing.set(entry)
  }

  async delete(key: string) {
    this.local.delete(key)
    if (this.current) await this.backing.delete(key)
  }
}

type Generation = {
  id: number
  payee: `0x${string}`
  manager: SessionManagerLike
  view: StoreView
  /** SSE streams still being read. */
  active: number
  retired?: string
  /** Close cooperatively once the last stream ends. */
  closeWhenIdle?: boolean
  closing?: Promise<void>
}

/**
 * Pays the relay with mppx: per-token MPP sessions over SSE first, per-request charges as the
 * fallback when a session cannot be used before the request leaves (no session offer, no
 * channel can be opened, remaining budget below one deposit). A session request that reached
 * the relay with a credential is never sent again as a charge. Payment policy violations,
 * refusals of the pinned relay channel and an unavailable shared budget never fall back.
 * `deps.fetch` is the payment firewall over the TLS-pinned relay transport, so mppx can only
 * reach the attested relay key.
 *
 * Channels: the session channel is persisted (channelKv) and resumed after a restart; mppx's
 * bootstrap proof lets the relay hand it back when the local copy is gone. A channel is rotated
 * (closed cooperatively and replaced) before its vouchers reach maxDeposit. A channel the payer
 * stops using without a successful close is retired in the journal for ChannelRecovery.
 */
export class RelayClient {
  private current: Generation | undefined
  private readonly generations = new Set<Generation>()
  private created = 0
  private charge: { fetch: FetchLike } | undefined
  private chargePayee: string | undefined
  private sessionsDisabledUntil = 0
  private handshake: Promise<void> = Promise.resolve()
  private readonly now: () => number
  private readonly backing: ChannelStore
  /** Non-payment error responses the relay gave to a session request, keyed by our request id. */
  private readonly refusals = new Map<string, Response>()
  /** Session requests whose paid attempt reached the relay. */
  private readonly sent = new Set<string>()
  private readonly sessionFetch: FetchLike

  constructor(private readonly deps: RelayClientDeps) {
    this.now = deps.now ?? (() => Math.floor(Date.now() / 1000))
    const kv = deps.channelKv
    this.backing = kv ? (createJsonChannelStore({ get: (k) => kv.get(k), set: (k, v) => kv.set(k, v), delete: (k) => kv.delete(k) }) as ChannelStore) : (createChannelStore() as ChannelStore)
    this.sessionFetch = async (input, init) => {
      const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase()
      const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined))
      const id = headers.get(REQUEST_ID_HEADER)
      const paidRequest = id !== null && method === 'POST' && hasPayment(headers) && bodyLength(input, init) > 0
      let response: Response
      try {
        response = await deps.fetch(input, init)
      } catch (error) {
        if (paidRequest && !wasNotSent(error) && !rootPolicyError(error)) this.sent.add(id!)
        throw error
      }
      if (paidRequest && response.status !== 402) this.sent.add(id!)
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
      let generation: Generation | undefined
      try {
        // One mppx SessionManager handles one request handshake at a time; streams then run in parallel.
        const events = await this.locked(async () => {
          generation = await this.generationFor(payee)
          return generation.manager.sse(this.chatUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'text/event-stream', [REQUEST_ID_HEADER]: requestId },
            body: JSON.stringify({ ...body, stream: true, stream_options: { include_usage: true } }),
            signal,
          })
        })
        return { kind: 'session', events: this.track(generation!, events) }
      } catch (error) {
        const policy = rootPolicyError(error)
        // A policy violation, an unattested relay channel or an unavailable shared budget never
        // falls back to another payment path.
        if (policy instanceof PaymentPolicyError || policy instanceof RelayChannelError || policy instanceof BudgetUnavailableError) throw policy
        const refusal = this.refusals.get(requestId)
        if (refusal) return { kind: 'response', intent: 'refused', paid: false, streamed: false, response: refusal }
        if (/funding outcome is unknown/i.test(String((error as Error)?.message)) && generation) this.retire(generation, 'funding_uncertain', false)
        if (this.sent.has(requestId)) {
          this.deps.log?.({ event: 'session_failed_after_send', reason: (error as Error).message?.slice(0, 200) })
          throw new RelaySessionFailedError('the relay session failed after the request was sent; it is not sent again as a charge', { cause: error })
        }
        this.sessionsDisabledUntil = this.now() + (this.deps.sessionRetrySeconds ?? 300)
        this.deps.log?.({ event: 'session_unavailable', reason: (policy ?? (error as Error)).message?.slice(0, 200) })
      } finally {
        this.refusals.delete(requestId)
        this.sent.delete(requestId)
      }
    }
    try {
      const response = await this.chargeFor(payee).fetch(this.chatUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
        body: JSON.stringify({ ...body, stream: true, stream_options: { include_usage: true } }),
        signal,
      })
      const paid = response.headers.has('payment-receipt')
      const refused = !paid && (response.status === 402 || response.status >= 400)
      const streamed = (response.headers.get('content-type') ?? '').includes('text/event-stream')
      return { kind: 'response', intent: refused ? 'refused' : 'charge', paid, streamed, response }
    } catch (error) {
      throw rootPolicyError(error) ?? error
    }
  }

  /**
   * Channels the payer still uses: the current session channel, channels a stream or a close is
   * still running on, and the channel the next session would resume.
   */
  async liveChannels(): Promise<Set<string>> {
    const ids = new Set<string>()
    for (const g of this.generations) {
      if ((g === this.current || g.active > 0 || g.closing) && g.manager.channelId) ids.add(g.manager.channelId.toLowerCase())
    }
    // Every stored session channel (one per payee scope) is resumed by the next session to it.
    for (const key of this.deps.channelKv?.keys() ?? []) {
      try {
        const id = (JSON.parse(this.deps.channelKv!.get(key) ?? '{}') as { channelId?: string }).channelId
        if (id) ids.add(id.toLowerCase())
      } catch {}
    }
    const open = (this.deps.journal?.all() ?? []).filter((r) => r.status === 'open')
    const payee = this.current?.payee ?? this.deps.expectedPayee()
    if (!payee) {
      // Until the relay is attested the payee is unknown: no open channel counts as orphaned yet.
      for (const r of open) ids.add(r.channelId)
      return ids
    }
    const stored = (await this.backing.get(this.scopeKey(payee))) as ChannelEntry | undefined
    if (stored) ids.add(stored.channelId.toLowerCase())
    if (!this.current?.manager.channelId && !stored) {
      // Without a local copy the relay's bootstrap resumes its newest channel to this payee.
      const newest = open
        .filter((r) => r.descriptor.payee === payee.toLowerCase() && r.descriptor.token === this.deps.currency.toLowerCase())
        .sort((a, b) => b.lastUsedAt - a.lastUsedAt)[0]
      if (newest) ids.add(newest.channelId)
    }
    return ids
  }

  /**
   * Cooperative close of every channel, so the unspent deposit is refunded (shutdown). A channel
   * that does not close in time stays stored and is resumed, or recovered, after the restart.
   */
  async close(): Promise<void> {
    await Promise.all([...this.generations].map((g) => this.closeGeneration(g, false)))
    this.current = undefined
  }

  private async locked<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.handshake
    let release!: () => void
    this.handshake = new Promise<void>((resolve) => (release = resolve))
    await previous
    try {
      return await operation()
    } finally {
      release()
    }
  }

  private scopeKey(payee: string): string {
    return entryKey({ descriptor: { payee, token: this.deps.currency }, escrow: ESCROW_PRECOMPILE, chainId: this.deps.chainId } as never)
  }

  private headroom(): bigint {
    return this.deps.rotateHeadroom ?? this.deps.maxCharge
  }

  private exhausted(cumulative: bigint | undefined): boolean {
    return cumulative !== undefined && this.deps.maxDeposit - cumulative < this.headroom()
  }

  private async generationFor(payee: `0x${string}`): Promise<Generation> {
    let g = this.current
    if (g && g.payee !== payee) {
      // The attested payee changed: the firewall refuses a close to the old payee, so the old
      // channel is recovered onchain (requestClose, withdraw).
      this.retire(g, 'payee_changed', false)
      g = undefined
    }
    if (g && this.exhausted(g.manager.cumulative)) {
      this.retire(g, 'rotated', true)
      this.deps.log?.({ event: 'session_channel_rotated', channelId: g.manager.channelId, cumulative: g.manager.cumulative?.toString() })
      g = undefined
    }
    return g ?? (this.current = await this.newGeneration(payee))
  }

  private async newGeneration(payee: `0x${string}`): Promise<Generation> {
    const key = this.scopeKey(payee)
    const stored = (await this.backing.get(key)) as ChannelEntry | undefined
    let bootstrap = this.created === 0
    if (stored && this.exhausted(stored.cumulativeAmount)) {
      // Resuming an exhausted channel would only pin the payer to it; replace it instead.
      this.deps.journal?.retire(stored.channelId, 'exhausted')
      await this.backing.delete(key)
      bootstrap = false
    }
    this.created++
    const view = new StoreView(this.backing)
    const parameters = {
      account: withPrimitiveCloseSignatures(this.deps.account),
      getClient: this.deps.getClient,
      decimals: this.deps.decimals,
      maxDeposit: formatUnits(this.deps.maxDeposit, this.deps.decimals),
      allowedChainIds: [this.deps.chainId],
      escrow: ESCROW_PRECOMPILE,
      // After a rotation the relay's bootstrap would hand back the channel just rotated out.
      bootstrap,
      channelStore: view,
      fetch: this.sessionFetch,
    }
    const manager = this.deps.sessionManagerFactory
      ? this.deps.sessionManagerFactory(parameters)
      : (tempo.session.manager(parameters as never) as unknown as SessionManagerLike)
    const generation: Generation = { id: this.created, payee, manager, view, active: 0 }
    this.generations.add(generation)
    return generation
  }

  /** Stops using a generation's channel: closes it cooperatively when allowed, else hands it to recovery. */
  private retire(g: Generation, reason: string, cooperative: boolean): void {
    if (g.retired) return
    g.retired = reason
    g.view.current = false
    if (this.current === g) this.current = undefined
    const channelId = g.manager.channelId
    if (channelId) void Promise.resolve(this.backing.delete(this.scopeKey(g.payee))).catch(() => {})
    if (!cooperative) {
      if (channelId) this.deps.journal?.retire(channelId, reason)
      // Streams already running finish on it; recovery leaves it alone until then.
      if (g.active === 0) this.generations.delete(g)
      return
    }
    g.closeWhenIdle = true
    if (g.active === 0) void this.closeGeneration(g, true)
  }

  private closeGeneration(g: Generation, retireOnFailure: boolean): Promise<void> {
    g.closing ??= (async () => {
      const channelId = g.manager.channelId
      let timer: NodeJS.Timeout | undefined
      try {
        await Promise.race([
          g.manager.close(),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('close timed out')), this.deps.closeTimeoutMs ?? 35_000)
            timer.unref?.()
          }),
        ])
      } catch (error) {
        this.deps.log?.({ event: 'session_close_failed', channelId, reason: (error as Error).message?.slice(0, 200) })
        if (retireOnFailure && channelId) this.deps.journal?.retire(channelId, `${g.retired ?? 'close'}_close_failed`)
      } finally {
        if (timer) clearTimeout(timer)
        this.generations.delete(g)
      }
    })()
    return g.closing
  }

  /** Counts a running stream on its generation, so a rotation closes the channel only after it. */
  private track(g: Generation, events: AsyncIterable<string>): AsyncIterable<string> {
    g.active++
    let finished = false
    const finish = () => {
      if (finished) return
      finished = true
      g.active--
      if (g.active > 0) return
      if (g.closeWhenIdle) void this.closeGeneration(g, true)
      else if (g.retired) this.generations.delete(g)
    }
    return {
      [Symbol.asyncIterator]() {
        const it = events[Symbol.asyncIterator]()
        return {
          async next() {
            try {
              const r = await it.next()
              if (r.done) finish()
              return r
            } catch (error) {
              finish()
              throw error
            }
          },
          async return(value?: unknown) {
            finish()
            return (await it.return?.(value)) ?? { done: true as const, value: undefined }
          },
        } as AsyncIterator<string>
      },
    }
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
