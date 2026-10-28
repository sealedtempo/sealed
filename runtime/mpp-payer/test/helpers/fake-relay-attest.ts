import type { CapturedResponse } from '../../src/tls-capture.js'

export const TREASURY = '0x' + 'ab'.repeat(20)
export const TLS_HASH = ('0x' + 'cd'.repeat(32)) as `0x${string}`

export function relayAppCompose(treasury = TREASURY): string {
  const compose = {
    services: {
      'inference-relay-front': { image: 'ghcr.io/x/relay@sha256:' + '0'.repeat(64), environment: { TREASURY_ADDRESS: treasury, PORT: '8080' } },
      'inference-relay-litellm': { image: 'ghcr.io/x/litellm@sha256:' + '0'.repeat(64), environment: ['LITELLM_LOG=ERROR'] },
    },
  }
  return JSON.stringify({ docker_compose_file: JSON.stringify(compose), manifest_version: 2, name: 'sealed-12345678' })
}

/** A fake relay /attest endpoint; records the nonces it was asked for. */
export function fakeAttest(options: { appCompose?: string; tlsOnWire?: string; observed?: `0x${string}`; status?: number } = {}) {
  const nonces: string[] = []
  const fetchAttest = async (url: string): Promise<CapturedResponse> => {
    nonces.push(new URL(url).searchParams.get('nonce') ?? '')
    const body = {
      quote: '0x' + '00'.repeat(16),
      eventLog: [],
      config: { schema: 'sealed-config/v1' },
      releaseIds: ['0x' + '01'.repeat(32)],
      appCompose: options.appCompose ?? relayAppCompose(),
      enclaveSigner: '0x' + 'ef'.repeat(20),
      tlsPubKeyHash: options.tlsOnWire ?? TLS_HASH,
      reportData: '0x' + '00'.repeat(64),
    }
    return { response: Response.json(body, { status: options.status ?? 200 }), tlsPubKeyHash: options.observed ?? TLS_HASH }
  }
  return { nonces, fetchAttest }
}

/** A fake sealed-verifierd: answers /v1/verify/live with the configured verdict and records requests. */
export function fakeVerifierd(initial: { ok: boolean; simulated?: boolean; failing?: string } = { ok: true }) {
  const state = { ...initial }
  const requests: any[] = []
  const fetchVerifier = async (input: string, init: RequestInit) => {
    requests.push({ url: input, body: JSON.parse(String(init.body)) })
    return Response.json({
      ok: state.ok,
      simulated: state.simulated ?? false,
      checks: [{ name: state.failing ?? 'stack_approved', ok: state.ok, detail: state.ok ? undefined : 'stack not approved by owner' }],
    })
  }
  return { state, requests, fetchVerifier }
}
