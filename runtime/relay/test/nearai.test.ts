import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { nearAiVerifier } from '../src/providers/nearai.js'
import { AttestationFailure } from '../src/providers/types.js'
import { APP_COMPOSE, COMPOSE_HASH, OS_MEASUREMENTS_HASH, eventLog, fakeQuote, fakeQuoteVerifier } from './helpers/fake-tdx.js'

const SIGNER = '0x1234567890abcdef1234567890abcdef12345678'
const SPKI = 'ab'.repeat(32)

type Tamper = { echoNonce?: string; spkiOnWire?: string; observed?: string; reportDataFor?: string; tcb?: string; compose?: string; status?: number }

function reportFor(nonce: string, t: Tamper) {
  const fp = t.spkiOnWire ?? SPKI
  const bindNonce = t.reportDataFor ?? nonce
  const reportData = Buffer.concat([
    createHash('sha256').update(Buffer.concat([Buffer.from(SIGNER.slice(2), 'hex'), Buffer.from(fp, 'hex')])).digest(),
    Buffer.from(bindNonce, 'hex'),
  ])
  return {
    gateway_attestation: {
      intel_quote: fakeQuote({ reportData, tcbStatus: t.tcb }),
      event_log: JSON.stringify(eventLog()),
      request_nonce: t.echoNonce ?? nonce,
      signing_address: SIGNER,
      signing_algo: 'ecdsa',
      tls_cert_fingerprint: fp,
      info: { tcb_info: JSON.stringify({ app_compose: t.compose ?? APP_COMPOSE }) },
    },
  }
}

function verifierWith(t: Tamper = {}, extra: { acceptedComposeHashes?: string[]; acceptedOsMeasurements?: string[]; allowUnpinned?: boolean } = {}) {
  const seen: { url?: string; auth?: string } = {}
  const verifier = nearAiVerifier({
    apiKey: 'test-key',
    quoteVerifier: fakeQuoteVerifier,
    acceptedComposeHashes: extra.acceptedComposeHashes,
    acceptedOsMeasurements: extra.acceptedOsMeasurements,
    allowUnpinned: extra.allowUnpinned,
    transport: () => ({
      fetch: async (input, init) => {
        const url = new URL(String(input))
        seen.url = url.toString()
        seen.auth = new Headers(init?.headers).get('authorization') ?? undefined
        const nonce = url.searchParams.get('nonce')!
        return Response.json(reportFor(nonce, t), { status: t.status ?? 200 })
      },
      observedSpki: () => t.observed ?? SPKI,
      close: async () => {},
    }),
  })
  return { verifier, seen }
}

describe('NEAR AI gateway attestation', () => {
  it('verifies a TLS-bound gateway report and pins the attested key', async () => {
    const { verifier, seen } = verifierWith({}, { acceptedComposeHashes: [COMPOSE_HASH], acceptedOsMeasurements: [`0x${OS_MEASUREMENTS_HASH}`] })
    const channel = await verifier.verify()
    expect(seen.url).toMatch(/\/v1\/attestation\/report\?signing_algo=ecdsa&nonce=[0-9a-f]{64}&include_tls_fingerprint=true$/)
    expect(seen.auth).toBe('Bearer test-key')
    expect(channel.baseURL).toBe('https://cloud-api.near.ai/v1')
    expect(channel.evidence).toMatchObject({
      tlsSpkiSha256: SPKI,
      composeHash: COMPOSE_HASH,
      osMeasurementsHash: OS_MEASUREMENTS_HASH,
      signingAddress: SIGNER,
      pinned: 'compose and OS image',
      unverified: expect.stringMatching(/model_attestations/),
    })
    await channel.close?.()
  })

  it.each([
    ['nonce echo', { echoNonce: '00'.repeat(32) }, 'nonce'],
    ['stale report_data', { reportDataFor: '11'.repeat(32) }, 'report_data'],
    ['TLS key of another connection', { observed: 'cd'.repeat(32) }, 'tls'],
    ['TCB out of date', { tcb: 'OutOfDate' }, 'tcb'],
    ['compose not measured', { compose: '{"other":true}' }, 'compose'],
    ['HTTP error', { status: 503 }, 'fetch'],
  ] as const)('rejects %s', async (_name, tamper, check) => {
    const { verifier } = verifierWith(tamper)
    const error = await verifier.verify().catch((e) => e)
    expect(error).toBeInstanceOf(AttestationFailure)
    expect((error as AttestationFailure).check).toBe(check)
  })

  it('rejects a compose hash outside the allowlist', async () => {
    const { verifier } = verifierWith({}, { acceptedComposeHashes: ['ee'.repeat(32)] })
    await expect(verifier.verify()).rejects.toThrow(/accepted list/)
  })

  it('refuses an unreviewed gateway: empty allowlists fail and name the observed values', async () => {
    const none = await verifierWith().verifier.verify().catch((e) => e)
    expect(none).toBeInstanceOf(AttestationFailure)
    expect(none.message).toContain(`compose hash ${COMPOSE_HASH} is not pinned`)
    const noOs = await verifierWith({}, { acceptedComposeHashes: [COMPOSE_HASH] }).verifier.verify().catch((e) => e)
    expect(noOs.check).toBe('os_image')
    expect(noOs.message).toContain(OS_MEASUREMENTS_HASH)
    const otherOs = verifierWith({}, { acceptedComposeHashes: [COMPOSE_HASH], acceptedOsMeasurements: ['ab'.repeat(32)] })
    await expect(otherOs.verifier.verify()).rejects.toThrow(/not in NEARAI_ACCEPTED_OS_MEASUREMENTS/)
    const dev = await verifierWith({}, { allowUnpinned: true }).verifier.verify()
    expect(dev.evidence.pinned).toBe('not pinned (development)')
  })
})
