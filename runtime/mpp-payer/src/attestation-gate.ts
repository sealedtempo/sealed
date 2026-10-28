import { randomBytes } from 'node:crypto'
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

/** Body of POST sealed-verifierd /v1/verify/live (proposed in this workstream's interface_changes). */
export type VerifyLiveRequest = {
  attestUrl: string
  nonce: `0x${string}`
  attest: AttestDocument
  observedTlsPubKeyHash: `0x${string}`
  expectedCustomer: `0x${string}`
  expectedAppIds: string[]
}

export type VerifyReport = { ok: boolean; simulated?: boolean; checks?: { name: string; ok: boolean; detail?: string }[] }

export type GateState = {
  ok: boolean
  checkedAt?: number
  detail: string
  payee?: `0x${string}`
  enclaveSigner?: string
  stackHash?: string
  simulated?: boolean
}

export type GateDeps = {
  attestUrl: string
  verifierdUrl: string
  relayOwner: `0x${string}`
  intervalSeconds: number
  retrySeconds?: number
  /** Payee pinned by configuration; otherwise taken from the attested relay compose. */
  payeeOverride?: `0x${string}`
  allowSimulated?: boolean
  fetchAttest?: (url: string) => Promise<CapturedResponse>
  fetchVerifier?: (input: string, init: RequestInit) => Promise<Response>
  now?: () => number
  log?: (event: Record<string, unknown>) => void
}

export class AttestationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AttestationError'
  }
}

/**
 * The relay's payee as measured: the TREASURY_ADDRESS environment value of the relay
 * stack's services inside the attested app-compose.json (exactly one distinct value).
 */
export function payeeFromAppCompose(appCompose: string): `0x${string}` | undefined {
  const outer = JSON.parse(appCompose) as { docker_compose_file?: unknown }
  const composeText = outer.docker_compose_file
  if (typeof composeText !== 'string') return undefined
  const compose = JSON.parse(composeText) as { services?: Record<string, { environment?: unknown }> }
  const found = new Set<string>()
  for (const service of Object.values(compose.services ?? {})) {
    const env = service.environment
    let value: unknown
    if (Array.isArray(env)) value = env.find((e) => typeof e === 'string' && e.startsWith('TREASURY_ADDRESS='))?.slice(17)
    else if (env && typeof env === 'object') value = (env as Record<string, unknown>).TREASURY_ADDRESS
    if (typeof value === 'string' && value) found.add(value.toLowerCase())
  }
  if (found.size > 1) throw new AttestationError('attested relay compose names more than one TREASURY_ADDRESS')
  const [payee] = [...found]
  if (payee && !/^0x[0-9a-f]{40}$/.test(payee)) throw new AttestationError('attested TREASURY_ADDRESS is not an address')
  return payee as `0x${string}` | undefined
}

/**
 * Gate in front of every paid request: the relay must have passed live attestation
 * verification (sealed-verifierd: quote, image, RTMR3 and compose, stack approved by the
 * relay owner, releases active, report_data binding the nonce and TLS key) within the last
 * interval. Checked before first use and every 15 minutes; failures retry sooner and keep
 * the gate closed until a check passes.
 */
export class RelayAttestationGate {
  private current: GateState = { ok: false, detail: 'relay attestation not yet checked' }
  private inflight: Promise<GateState> | undefined
  private timer: NodeJS.Timeout | undefined
  private readonly now: () => number

  constructor(private readonly deps: GateDeps) {
    this.now = deps.now ?? (() => Math.floor(Date.now() / 1000))
  }

  state(): GateState {
    return this.current
  }

  payee(): `0x${string}` | undefined {
    return this.isOpen() ? this.current.payee : undefined
  }

  /** Open only with a passing check younger than the interval. */
  isOpen(): boolean {
    const s = this.current
    return s.ok && s.checkedAt !== undefined && this.now() - s.checkedAt < this.deps.intervalSeconds
  }

  /** Re-checks when the last pass is older than the interval (or never happened). */
  async ensureFresh(): Promise<GateState> {
    if (this.isOpen()) return this.current
    return this.check()
  }

  check(): Promise<GateState> {
    this.inflight ??= this.runCheck().finally(() => {
      this.inflight = undefined
    })
    return this.inflight
  }

  start(): void {
    const loop = async () => {
      const state = await this.check()
      const next = state.ok ? this.deps.intervalSeconds : (this.deps.retrySeconds ?? 60)
      this.timer = setTimeout(loop, next * 1000)
      this.timer.unref?.()
    }
    void loop()
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer)
  }

  private async runCheck(): Promise<GateState> {
    try {
      this.current = await this.verifyOnce()
      this.deps.log?.({ event: 'relay_attestation', ok: true, simulated: this.current.simulated ?? false })
    } catch (error) {
      this.current = { ok: false, checkedAt: this.now(), detail: (error as Error).message }
      this.deps.log?.({ event: 'relay_attestation', ok: false, detail: this.current.detail })
    }
    return this.current
  }

  private async verifyOnce(): Promise<GateState> {
    const nonce = `0x${randomBytes(32).toString('hex')}` as const
    const url = new URL(this.deps.attestUrl)
    url.searchParams.set('nonce', nonce)
    const fetchAttest = this.deps.fetchAttest ?? ((u: string) => fetchWithPeerKey(u))
    let captured: CapturedResponse
    try {
      captured = await fetchAttest(url.toString())
    } catch (error) {
      throw new AttestationError(`relay attest endpoint unreachable: ${(error as Error).message}`)
    }
    if (!captured.response.ok) throw new AttestationError(`relay attest endpoint answered HTTP ${captured.response.status}`)
    const attest = (await captured.response.json()) as AttestDocument
    if (typeof attest?.appCompose !== 'string' || typeof attest.quote !== 'string')
      throw new AttestationError('relay attest response is malformed')
    if (attest.tlsPubKeyHash?.toLowerCase() !== captured.tlsPubKeyHash)
      throw new AttestationError('relay attest TLS key differs from the key of this connection')

    const body: VerifyLiveRequest = {
      attestUrl: this.deps.attestUrl,
      nonce,
      attest,
      observedTlsPubKeyHash: captured.tlsPubKeyHash,
      expectedCustomer: this.deps.relayOwner,
      expectedAppIds: ['inference-relay'],
    }
    const fetchVerifier = this.deps.fetchVerifier ?? fetch
    let report: VerifyReport
    try {
      const res = await fetchVerifier(`${this.deps.verifierdUrl}/v1/verify/live`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      })
      const json = (await res.json()) as Record<string, unknown>
      report = { ok: json.ok === true || json.OK === true, simulated: json.simulated === true, checks: (json.checks ?? json.Checks) as VerifyReport['checks'] }
    } catch (error) {
      throw new AttestationError(`sealed-verifierd unavailable: ${(error as Error).message}`)
    }
    if (!report.ok) {
      const failed = (report.checks ?? []).filter((c) => !c.ok).map((c) => (c.detail ? `${c.name}: ${c.detail}` : c.name))
      throw new AttestationError(`relay attestation rejected${failed.length ? ` (${failed.join('; ')})` : ''}`)
    }
    if (report.simulated && !this.deps.allowSimulated) throw new AttestationError('relay presented a simulated quote')

    const attestedPayee = payeeFromAppCompose(attest.appCompose)
    const payee = this.deps.payeeOverride ?? attestedPayee
    if (!payee) throw new AttestationError('relay payee unknown: no TREASURY_ADDRESS in the attested compose')
    if (this.deps.payeeOverride && attestedPayee && attestedPayee !== this.deps.payeeOverride)
      throw new AttestationError('configured relay payee differs from the attested one')
    return {
      ok: true,
      checkedAt: this.now(),
      detail: 'relay attestation verified',
      payee,
      enclaveSigner: attest.enclaveSigner?.toLowerCase(),
      simulated: report.simulated,
    }
  }
}
