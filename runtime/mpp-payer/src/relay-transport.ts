import { checkServerIdentity, type PeerCertificate } from 'node:tls'
import { Agent, type Dispatcher, ProxyAgent, fetch as undiciFetch } from 'undici'
import { proxyFor, tlsPubKeyHash } from './tls-capture.js'

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

/** A relay request that was refused before any byte of it left the payer. */
export class RelayChannelError extends Error {
  readonly notSent = true
  constructor(message: string) {
    super(message)
    this.name = 'RelayChannelError'
  }
}

/** The relay presented a TLS key other than the attested one; the request was not sent. */
export class RelayPinError extends RelayChannelError {
  constructor(
    readonly observed: string,
    readonly expected: string,
  ) {
    super(`relay TLS key ${observed} is not the attested key ${expected}; nothing was sent`)
    this.name = 'RelayPinError'
  }
}

/** True when an error (or its cause chain) proves the request never left the payer. */
export function wasNotSent(error: unknown): boolean {
  let current: unknown = error
  for (let depth = 0; current && depth < 8; depth++) {
    if (current instanceof RelayChannelError) return true
    current = (current as { cause?: unknown }).cause
  }
  return false
}

function pinMismatchIn(error: unknown): RelayPinError | undefined {
  let current: unknown = error
  for (let depth = 0; current && depth < 8; depth++) {
    if (current instanceof RelayPinError) return current
    current = (current as { cause?: unknown }).cause
  }
  return undefined
}

const NULL_BODY_STATUS = new Set([101, 103, 204, 205, 304])

export type PinnedRelayTransportOptions = {
  /** The relay origin (https). Requests to any other origin are refused. */
  origin: string
  /** The TLS key hash the latest passing attestation bound (INTERFACES section 3); undefined while closed. */
  pin: () => `0x${string}` | undefined
  /** Re-runs attestation after a key mismatch (for example a renewed certificate); resolves when done. */
  repin?: () => Promise<void>
  /** Extra CA (tests). */
  ca?: string | Buffer
  /** CONNECT proxy; defaults to HTTPS_PROXY / NO_PROXY from the environment. */
  proxy?: string
}

/**
 * fetch for everything the payer sends to the relay (prompts, payment credentials, model list).
 * Every TLS connection must present the key whose hash the relay's live attestation bound;
 * the check runs in the handshake, before the request is written, so a relay host serving an
 * unattested key never receives a byte. The pin follows the attestation gate: a new key after
 * a re-check gets a fresh connection pool, and an explicit attestation failure tears the pool
 * down.
 */
export class PinnedRelayTransport {
  readonly fetch: FetchLike
  private readonly origin: URL
  private pool: { pin: string; dispatcher: Dispatcher } | undefined

  constructor(private readonly options: PinnedRelayTransportOptions) {
    this.origin = new URL(options.origin)
    if (this.origin.protocol !== 'https:') throw new Error('the relay must be reached over https')
    this.fetch = (input, init) => this.send(new Request(input, init), true)
  }

  /** Drops every pooled connection, aborting requests in flight (attestation failed). */
  reset(): void {
    const pool = this.pool
    this.pool = undefined
    void pool?.dispatcher.destroy().catch(() => {})
  }

  async close(): Promise<void> {
    const pool = this.pool
    this.pool = undefined
    await pool?.dispatcher.close().catch(() => {})
  }

  private dispatcherFor(pin: string): Dispatcher {
    if (this.pool?.pin === pin) return this.pool.dispatcher
    const previous = this.pool
    const check = (host: string, cert: PeerCertificate): Error | undefined => {
      const standard = checkServerIdentity(host, cert)
      if (standard) return standard
      if (!cert?.raw) return new RelayChannelError('relay peer certificate unavailable')
      const observed = tlsPubKeyHash(cert.raw)
      return observed === pin ? undefined : new RelayPinError(observed, pin)
    }
    const tls = { checkServerIdentity: check, ...(this.options.ca ? { ca: this.options.ca } : {}) }
    const proxy = this.options.proxy ?? proxyFor(this.origin)
    const dispatcher: Dispatcher = proxy ? new ProxyAgent({ uri: proxy, requestTls: tls }) : new Agent({ connect: tls })
    this.pool = { pin, dispatcher }
    // Streams already running on the previous key were attested when they connected; let them finish.
    void previous?.dispatcher.close().catch(() => {})
    return dispatcher
  }

  private async send(request: Request, mayRetry: boolean): Promise<Response> {
    const url = new URL(request.url)
    if (url.origin !== this.origin.origin)
      throw new RelayChannelError(`refusing ${url.origin}: the payer only talks to the attested relay origin ${this.origin.origin}`)
    const pin = this.options.pin()?.toLowerCase()
    if (!pin) throw new RelayChannelError('relay attestation has not passed: no attested TLS key to pin')
    const body = request.body ? Buffer.from(await request.clone().arrayBuffer()) : undefined
    let res: Awaited<ReturnType<typeof undiciFetch>>
    try {
      res = await undiciFetch(url, {
        method: request.method,
        headers: [...request.headers],
        body,
        signal: request.signal,
        redirect: 'manual',
        dispatcher: this.dispatcherFor(pin),
      })
    } catch (error) {
      const mismatch = pinMismatchIn(error)
      if (!mismatch) throw error
      if (mayRetry && this.options.repin) {
        await this.options.repin().catch(() => {})
        const next = this.options.pin()?.toLowerCase()
        if (next && next !== pin) return this.send(request, false)
      }
      throw mismatch
    }
    const status = res.status
    return new Response(NULL_BODY_STATUS.has(status) ? null : (res.body as ReadableStream<Uint8Array> | null), {
      status,
      statusText: res.statusText,
      headers: res.headers as unknown as Headers,
    })
  }
}
