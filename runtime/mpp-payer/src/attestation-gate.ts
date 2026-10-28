import { createHash, randomBytes } from 'node:crypto'
import { type CapturedResponse, fetchWithPeerKey } from './tls-capture.js'

/** GET /attest response of a deployment's sealed-agent (INTERFACES section 11). */
export type AttestDocument = {
  quote: string
  eventLog: unknown
  config: Record<string, unknown>
  releaseIds: string[]
  appCompose: string
  enclaveSigner: string
  tlsPubKeyHash: string
  reportData: string
}

/**
 * Body of POST sealed-verifierd /v1/verify/live for an attestation the payer fetched itself
 * (verifier/httpapi liveRequest, caller-fetched form): verifierd makes no connection and checks
 * the document against our nonce and the key we observed on our own connection.
 */
export type VerifyLiveRequest = {
  attestUrl: string
  nonce: `0x${string}`
  attest: AttestDocument
  observedTlsPubKeyHash: `0x${string}`
  options: { expectedCustomer: `0x${string}`; expectedAppIds: string[] }
}

export type VerifyCheck = { name: string; ok: boolean; detail?: string }

/** verifier.Report, the JSON sealed-verifierd answers (HTTP 200 for every verdict). */
export type VerifyReport = {
  ok: boolean
  simulated: boolean
  mode?: string
  stackHash?: string
  deploymentId?: string
  checks: VerifyCheck[]
}

/** The relay stack's single app and the service whose environment names the payee. */
export const RELAY_APP_ID = 'inference-relay'
export const RELAY_PAYEE_SERVICE = 'inference-relay-front'

/**
 * Checks a passing report must contain. A verifierd that silently ignored an option (for example
 * expectedAppIds) would leave its check out, so absence counts as failure.
 */
export const REQUIRED_CHECKS = [
  'tls_binding',
  'freshness',
  'report_data',
  'quote',
  'image_approved',
  'rtmr3',
  'compose_hash',
  'config_binding',
  'releases_active',
  'stack_recompute',
  'stack_approved',
  'expected_customer',
  'expected_apps',
] as const

export type GateState = {
  ok: boolean
  /** When the last verdict (pass or failure) was reached. */
  checkedAt?: number
  /** When the verdict currently in force passed. */
  verifiedAt?: number
  detail: string
  payee?: `0x${string}`
  /** sha256 of the relay's attested TLS SubjectPublicKeyInfo; every relay connection is pinned to it. */
  tlsPubKeyHash?: `0x${string}`
  enclaveSigner?: string
  stackHash?: string
  deploymentId?: string
  simulated?: boolean
  /** Set while a passing verdict stays in force although its re-check could not complete. */
  recheckError?: string
}

export type GateDeps = {
  attestUrl: string
  verifierdUrl: string
  relayOwner: `0x${string}`
  intervalSeconds: number
  /** Retry delay after a failure; failures are also cached this long. Default 60. */
  retrySeconds?: number
  /** Re-check once this fraction of the interval has passed, so the verdict never lapses. Default 0.8. */
  refreshFraction?: number
  /** Jitter applied to every scheduled check, as a fraction of its delay. Default 0.1. */
  jitterFraction?: number
  /** Pins the payee; it must equal the one in the attested compose. */
  payeeOverride?: `0x${string}`
  allowSimulated?: boolean
  fetchAttest?: (url: string) => Promise<CapturedResponse>
  fetchVerifier?: (input: string, init: RequestInit) => Promise<Response>
  newNonce?: () => `0x${string}`
  now?: () => number
  random?: () => number
  log?: (event: Record<string, unknown>) => void
  /** Called when a verdict fails explicitly (not merely unreachable), so open relay connections are dropped. */
  onExplicitFailure?: (state: GateState) => void
}

/**
 * explicit: the relay or verifierd gave a verdict against the relay (rejected checks, wrong key,
 * wrong stack). Otherwise the check could not complete (endpoint unreachable, verifierd busy).
 */
export class AttestationError extends Error {
  constructor(
    message: string,
    readonly explicit = true,
  ) {
    super(message)
    this.name = 'AttestationError'
  }
}

const ZERO_ADDRESS = `0x${'0'.repeat(40)}`

function envValue(env: unknown, name: string): unknown {
  if (Array.isArray(env)) {
    const entry = env.find((e) => typeof e === 'string' && e.startsWith(`${name}=`)) as string | undefined
    return entry?.slice(name.length + 1)
  }
  if (env && typeof env === 'object') return (env as Record<string, unknown>)[name]
  return undefined
}

/**
 * The relay's payee as measured: TREASURY_ADDRESS in the environment of the relay front
 * service (inference-relay-front) inside the attested app-compose.json. Any other service is
 * ignored; a missing, malformed or zero value throws.
 */
export function payeeFromAppCompose(appCompose: string): `0x${string}` {
  let services: Record<string, { environment?: unknown }> | undefined
  try {
    const outer = JSON.parse(appCompose) as { docker_compose_file?: unknown }
    if (typeof outer.docker_compose_file !== 'string') throw new Error('no docker_compose_file')
    services = (JSON.parse(outer.docker_compose_file) as { services?: Record<string, { environment?: unknown }> }).services
  } catch (error) {
    throw new AttestationError(`attested app-compose is unreadable: ${(error as Error).message}`)
  }
  const front = services?.[RELAY_PAYEE_SERVICE]
  if (!front) throw new AttestationError(`attested relay compose has no ${RELAY_PAYEE_SERVICE} service`)
  const value = envValue(front.environment, 'TREASURY_ADDRESS')
  if (typeof value !== 'string' || !value)
    throw new AttestationError(`relay payee unknown: no TREASURY_ADDRESS on ${RELAY_PAYEE_SERVICE} in the attested compose`)
  const payee = value.toLowerCase()
  if (!/^0x[0-9a-f]{40}$/.test(payee)) throw new AttestationError('attested TREASURY_ADDRESS is not an address')
  if (payee === ZERO_ADDRESS) throw new AttestationError('attested TREASURY_ADDRESS is the zero address')
  return payee as `0x${string}`
}

/** The attested public config must describe exactly the relay stack, owned by the relay owner. */
export function checkRelayConfig(config: unknown, relayOwner: string): void {
  const cfg = (config ?? {}) as { customer?: unknown; apps?: unknown }
  if (typeof cfg.customer !== 'string' || cfg.customer.toLowerCase() !== relayOwner.toLowerCase())
    throw new AttestationError('attested relay stack does not belong to the relay owner')
  const apps = Array.isArray(cfg.apps) ? cfg.apps : []
  const ids = apps.map((a) => (a && typeof a === 'object' ? (a as { id?: unknown }).id : undefined))
  if (ids.length !== 1 || ids[0] !== RELAY_APP_ID)
    throw new AttestationError(`attested stack runs ${JSON.stringify(ids)}, not exactly ["${RELAY_APP_ID}"]`)
}

export function parseVerifyReport(json: unknown): VerifyReport {
  const r = (json ?? {}) as Record<string, unknown>
  const checks = Array.isArray(r.checks)
    ? (r.checks as Record<string, unknown>[]).map((c) => ({ name: String(c?.name ?? ''), ok: c?.ok === true, detail: typeof c?.detail === 'string' ? c.detail : undefined }))
    : []
  return {
    ok: r.ok === true,
    simulated: r.simulated === true,
    mode: typeof r.mode === 'string' ? r.mode : undefined,
    stackHash: typeof r.stackHash === 'string' ? r.stackHash.toLowerCase() : undefined,
    deploymentId: typeof r.deploymentId === 'string' ? r.deploymentId.toLowerCase() : undefined,
    checks,
  }
}

function describeFailed(checks: VerifyCheck[]): string {
  return checks
    .filter((c) => !c.ok)
    .map((c) => (c.detail ? `${c.name}: ${c.detail}` : c.name))
    .join('; ')
}

/**
 * Gate in front of every paid request: the relay must have passed live attestation
 * verification (sealed-verifierd: quote, image, RTMR3 and compose, stack approved by the relay
 * owner, releases active, report_data binding our nonce and the TLS key of our connection),
 * plus local checks that the attested stack is the inference relay and names its payee.
 *
 * A pass stays in force for intervalSeconds. The next check starts at refreshFraction of the
 * interval (with jitter) so the verdict is renewed before it lapses. An explicit failure closes
 * the gate at once; a check that merely could not complete keeps the previous pass until it
 * expires and is retried sooner. Failures are cached for retrySeconds, so a closed gate never
 * re-runs attestation per request.
 */
export class RelayAttestationGate {
  private current: GateState = { ok: false, detail: 'relay attestation not yet checked' }
  private lastFailureAt: number | undefined
  private inflight: Promise<GateState> | undefined
  private timer: NodeJS.Timeout | undefined
  private stopped = false
  private readonly now: () => number

  constructor(private readonly deps: GateDeps) {
    this.now = deps.now ?? (() => Math.floor(Date.now() / 1000))
  }

  state(): GateState {
    return this.isOpen() || !this.current.ok ? this.current : { ...this.current, ok: false, detail: 'relay attestation expired' }
  }

  payee(): `0x${string}` | undefined {
    return this.isOpen() ? this.current.payee : undefined
  }

  /** The attested relay TLS key while the gate is open; relay connections are pinned to it. */
  pin(): `0x${string}` | undefined {
    return this.isOpen() ? this.current.tlsPubKeyHash : undefined
  }

  /** Open only with a passing verdict younger than the interval. */
  isOpen(): boolean {
    const s = this.current
    return s.ok && s.verifiedAt !== undefined && this.now() - s.verifiedAt < this.deps.intervalSeconds
  }

  /** The verdict for a request: the open gate, a cached recent failure, or one (shared) fresh check. */
  async ensureFresh(): Promise<GateState> {
    if (this.isOpen()) return this.current
    if (this.inflight) return this.inflight
    if (this.lastFailureAt !== undefined && this.now() - this.lastFailureAt < this.retrySeconds()) return this.state()
    return this.check()
  }

  /** Runs one check now; concurrent callers share it. */
  check(): Promise<GateState> {
    this.inflight ??= this.runCheck().finally(() => {
      this.inflight = undefined
    })
    return this.inflight
  }

  /** A relay connection presented an unexpected key: re-check unless one ran very recently. */
  async recheckAfterKeyMismatch(): Promise<void> {
    if (this.inflight) {
      await this.inflight
      return
    }
    const last = this.current.checkedAt
    if (last !== undefined && this.now() - last < Math.min(this.retrySeconds(), 30)) return
    await this.check()
  }

  start(): void {
    this.stopped = false
    const loop = async () => {
      await this.check()
      if (this.stopped) return
      this.timer = setTimeout(loop, this.nextDelaySeconds() * 1000)
      this.timer.unref?.()
    }
    void loop()
  }

  stop(): void {
    this.stopped = true
    if (this.timer) clearTimeout(this.timer)
  }

  /** Seconds until the scheduled check after the current state, jittered. */
  nextDelaySeconds(): number {
    const renewing = this.current.ok && this.current.recheckError === undefined
    const base = renewing
      ? Math.max(1, this.deps.intervalSeconds * (this.deps.refreshFraction ?? 0.8) - (this.now() - (this.current.verifiedAt ?? this.now())))
      : this.retrySeconds()
    const jitter = this.deps.jitterFraction ?? 0.1
    const factor = 1 - jitter + 2 * jitter * (this.deps.random ?? Math.random)()
    return Math.max(1, Math.round(base * factor))
  }

  private retrySeconds(): number {
    return this.deps.retrySeconds ?? 60
  }

  private async runCheck(): Promise<GateState> {
    try {
      this.current = await this.verifyOnce()
      this.lastFailureAt = undefined
      this.deps.log?.({ event: 'relay_attestation', ok: true, simulated: this.current.simulated ?? false, stackHash: this.current.stackHash })
    } catch (error) {
      const at = this.now()
      const detail = (error as Error).message
      const explicit = !(error instanceof AttestationError) || error.explicit
      this.lastFailureAt = at
      if (!explicit && this.isOpen()) {
        this.current = { ...this.current, checkedAt: at, recheckError: detail }
        this.deps.log?.({ event: 'relay_attestation', ok: true, recheck: 'incomplete', detail })
      } else {
        this.current = { ok: false, checkedAt: at, detail }
        this.deps.log?.({ event: 'relay_attestation', ok: false, explicit, detail })
        if (explicit) this.deps.onExplicitFailure?.(this.current)
      }
    }
    return this.current
  }

  private async verifyOnce(): Promise<GateState> {
    const nonce = this.deps.newNonce?.() ?? (`0x${randomBytes(32).toString('hex')}` as const)
    const url = new URL(this.deps.attestUrl)
    url.searchParams.set('nonce', nonce)
    const fetchAttest = this.deps.fetchAttest ?? ((u: string) => fetchWithPeerKey(u))
    let captured: CapturedResponse
    try {
      captured = await fetchAttest(url.toString())
    } catch (error) {
      throw new AttestationError(`relay attest endpoint unreachable: ${(error as Error).message}`, false)
    }
    if (!captured.response.ok)
      throw new AttestationError(`relay attest endpoint answered HTTP ${captured.response.status}`, captured.response.status < 500)
    let attest: AttestDocument
    try {
      attest = (await captured.response.json()) as AttestDocument
    } catch {
      throw new AttestationError('relay attest response is not JSON')
    }
    if (typeof attest?.appCompose !== 'string' || typeof attest.quote !== 'string' || typeof attest.tlsPubKeyHash !== 'string')
      throw new AttestationError('relay attest response is malformed')
    const observed = captured.tlsPubKeyHash.toLowerCase() as `0x${string}`
    if (attest.tlsPubKeyHash.toLowerCase() !== observed)
      throw new AttestationError('relay attest TLS key differs from the key of this connection')

    const report = await this.verifyWithVerifierd({
      attestUrl: this.deps.attestUrl,
      nonce,
      attest,
      observedTlsPubKeyHash: observed,
      options: { expectedCustomer: this.deps.relayOwner, expectedAppIds: [RELAY_APP_ID] },
    })
    if (!report.ok) {
      const failed = describeFailed(report.checks)
      throw new AttestationError(`relay attestation rejected${failed ? ` (${failed})` : ''}`)
    }
    const missing = REQUIRED_CHECKS.filter((name) => !report.checks.some((c) => c.name === name && c.ok))
    if (missing.length > 0) throw new AttestationError(`sealed-verifierd report lacks required checks: ${missing.join(', ')}`)
    // Required, like the checks: a report without a mode is not a verdict on the submitted attestation (review I1).
    if (report.mode !== 'live_submitted')
      throw new AttestationError(`sealed-verifierd verified in mode ${report.mode ?? '(none)'}, not the submitted attestation`)
    const stackHash = `0x${createHash('sha256').update(attest.appCompose, 'utf8').digest('hex')}`
    if (report.stackHash !== stackHash) throw new AttestationError('sealed-verifierd verified a different app-compose than the one received')
    if (report.simulated && !this.deps.allowSimulated) throw new AttestationError('relay presented a simulated quote')

    // Local identity checks on the exact document verifierd verified.
    checkRelayConfig(attest.config, this.deps.relayOwner)
    const payee = payeeFromAppCompose(attest.appCompose)
    if (this.deps.payeeOverride && payee !== this.deps.payeeOverride.toLowerCase())
      throw new AttestationError('configured relay payee differs from the attested one')
    const at = this.now()
    return {
      ok: true,
      checkedAt: at,
      verifiedAt: at,
      detail: 'relay attestation verified',
      payee,
      tlsPubKeyHash: observed,
      enclaveSigner: attest.enclaveSigner?.toLowerCase(),
      stackHash,
      deploymentId: report.deploymentId,
      simulated: report.simulated,
    }
  }

  private async verifyWithVerifierd(body: VerifyLiveRequest): Promise<VerifyReport> {
    const fetchVerifier = this.deps.fetchVerifier ?? fetch
    let res: Response
    try {
      res = await fetchVerifier(`${this.deps.verifierdUrl}/v1/verify/live`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      })
    } catch (error) {
      throw new AttestationError(`sealed-verifierd unavailable: ${(error as Error).message}`, false)
    }
    let json: unknown
    try {
      json = await res.json()
    } catch {
      json = undefined
    }
    if (res.status !== 200) {
      const message = (json as { error?: unknown } | undefined)?.error
      // 400: verifierd could not use our request (a contract mismatch); 429 / 5xx: try again later.
      throw new AttestationError(`sealed-verifierd answered HTTP ${res.status}${typeof message === 'string' ? `: ${message}` : ''}`, res.status === 400)
    }
    return parseVerifyReport(json)
  }
}
