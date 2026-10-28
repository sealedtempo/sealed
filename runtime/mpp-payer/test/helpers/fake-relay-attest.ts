import { createHash } from 'node:crypto'
import { REQUIRED_CHECKS } from '../../src/attestation-gate.js'
import type { CapturedResponse } from '../../src/tls-capture.js'

export const TREASURY = '0x' + 'ab'.repeat(20)
export const TLS_HASH = ('0x' + 'cd'.repeat(32)) as `0x${string}`
export const OWNER = ('0x' + '0a'.repeat(20)) as `0x${string}`

/** An app-compose.json shaped like the composer's output for the inference-relay stack. */
export function relayAppCompose(treasury = TREASURY, extraServices: Record<string, unknown> = {}): string {
  const compose = {
    services: {
      'inference-relay-front': { image: 'ghcr.io/x/relay@sha256:' + '0'.repeat(64), environment: { TREASURY_ADDRESS: treasury, PORT: '8080' } },
      'inference-relay-litellm': { image: 'ghcr.io/x/litellm@sha256:' + '0'.repeat(64), environment: ['LITELLM_LOG=ERROR'] },
      ...extraServices,
    },
  }
  return JSON.stringify({ docker_compose_file: JSON.stringify(compose), manifest_version: 2, name: 'sealed-12345678' })
}

export function relayConfig(overrides: Record<string, unknown> = {}) {
  return { schema: 'sealed-config/v1', customer: OWNER, apps: [{ id: 'inference-relay', releaseId: '0x' + '01'.repeat(32) }], ...overrides }
}

export const sha256Hex = (text: string) => `0x${createHash('sha256').update(text, 'utf8').digest('hex')}`

/** A fake relay /attest endpoint; records the nonces it was asked for. */
export function fakeAttest(
  options: { appCompose?: string; config?: Record<string, unknown>; tlsOnWire?: string; observed?: `0x${string}`; status?: number; fail?: boolean } = {},
) {
  const nonces: string[] = []
  const state = { observed: options.observed ?? TLS_HASH, tlsOnWire: options.tlsOnWire, fail: options.fail ?? false }
  const fetchAttest = async (url: string): Promise<CapturedResponse> => {
    nonces.push(new URL(url).searchParams.get('nonce') ?? '')
    if (state.fail) throw new Error('ECONNRESET')
    const body = {
      quote: '0x' + '00'.repeat(16),
      eventLog: [],
      config: options.config ?? relayConfig(),
      releaseIds: ['0x' + '01'.repeat(32)],
      appCompose: options.appCompose ?? relayAppCompose(),
      enclaveSigner: '0x' + 'ef'.repeat(20),
      tlsPubKeyHash: state.tlsOnWire ?? state.observed,
      reportData: '0x' + '00'.repeat(64),
    }
    return { response: Response.json(body, { status: options.status ?? 200 }), tlsPubKeyHash: state.observed }
  }
  return { nonces, state, fetchAttest }
}

type VerifierState = {
  ok: boolean
  simulated?: boolean
  failing?: string
  status?: number
  /** Check names to leave out of a passing report (a verifierd ignoring an option). */
  omit?: string[]
  /** null: the report carries no mode at all. */
  mode?: string | null
  stackHash?: string
  down?: boolean
}

/** A fake sealed-verifierd answering /v1/verify/live with verifier.Report JSON; records requests. */
export function fakeVerifierd(initial: VerifierState = { ok: true }) {
  const state: VerifierState = { ...initial }
  const requests: { url: string; body: any }[] = []
  const fetchVerifier = async (input: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body))
    requests.push({ url: input, body })
    if (state.down) throw new Error('ECONNREFUSED')
    if (state.status && state.status !== 200) return Response.json({ error: 'too many verifications in flight, retry later' }, { status: state.status })
    const failing = state.failing ?? 'stack_approved'
    const checks = REQUIRED_CHECKS.filter((name) => !(state.omit ?? []).includes(name)).map((name) => ({
      name,
      ok: state.ok || name !== failing,
      detail: !state.ok && name === failing ? 'stack not approved by owner' : 'ok',
    }))
    return Response.json({
      ok: state.ok,
      simulated: state.simulated ?? false,
      ...(state.mode === null ? {} : { mode: state.mode ?? 'live_submitted' }),
      stackHash: state.stackHash ?? sha256Hex(body.attest?.appCompose ?? ''),
      deploymentId: '0x' + '77'.repeat(32),
      verifiedAt: 1,
      checks,
    })
  }
  return { state, requests, fetchVerifier }
}
