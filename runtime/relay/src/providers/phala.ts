import { proxyFor } from './pinned-fetch.js'
import { INTEL_PCS_URL, assertPinned } from './tdx.js'
import { AttestationFailure, type FetchLike, type ProviderVerifier, type VerifiedChannel, nowSeconds } from './types.js'

/**
 * Phala Confidential AI through its official SDK `@phala/aci-verifier` (Apache-2.0).
 * `connectAci()` fetches a nonce-bound ACI report, verifies the TDX quote with dcap-qvl,
 * the keyset binding and expiry, the RTMR3 compose measurement, and returns a fetch whose
 * TLS is pinned to the attested SPKI set. We additionally require a VERIFIED verdict and a
 * compose hash on the reviewed allowlist: with an empty list the SDK only reports the
 * measurement without claiming the release was reviewed, so the sidecar refuses it.
 */
export type PhalaOptions = {
  baseURL?: string
  /** Reviewed compose hashes of the Phala serving stack (PHALA_ACCEPTED_COMPOSE_HASHES). */
  acceptedComposeHashes?: readonly string[]
  /** Development only: accept an unreviewed compose (empty allowlist). */
  allowUnpinned?: boolean
  requireReceipt?: boolean
  pccsUrl?: string
  proxy?: string
  /** Test seam for the official connector. */
  connect?: (options: AciConnectOptions) => Promise<AciConnectionLike>
}

type AciConnectOptions = {
  baseURL: string
  policy?: { acceptedComposeHashes?: readonly string[] }
  serving?: { requireVerified?: boolean; requireReceipt?: boolean }
  pccsUrl?: string
  proxy?: string
}

type AciConnectionLike = {
  baseURL: string
  fetch: FetchLike
  identity: {
    composeHash: string
    tlsSpkiPins: readonly string[]
    expiresAt: number
    workloadKeysetDigest: string
    transcript: { verdict: { verified: boolean; line: string } }
  }
  close(): Promise<void>
}

export const PHALA_DEFAULT_BASE_URL = 'https://inference.phala.com/v1'

const officialConnect = async (options: AciConnectOptions): Promise<AciConnectionLike> => {
  const { connectAci } = await import('@phala/aci-verifier/runtime')
  return (await connectAci(options as never)) as unknown as AciConnectionLike
}

/** ACI expiry fields are unix seconds; tolerate milliseconds defensively. */
function toSeconds(value: number): number {
  return value > 1e12 ? Math.floor(value / 1000) : Math.floor(value)
}

export function phalaVerifier(options: PhalaOptions = {}): ProviderVerifier {
  const baseURL = (options.baseURL ?? PHALA_DEFAULT_BASE_URL).replace(/\/+$/, '')
  return {
    provider: 'phala',
    async verify(): Promise<VerifiedChannel> {
      const connect = options.connect ?? officialConnect
      let aci: AciConnectionLike
      try {
        const accepted = options.acceptedComposeHashes ?? []
        aci = await connect({
          baseURL,
          ...(accepted.length > 0 ? { policy: { acceptedComposeHashes: accepted } } : {}),
          serving: { requireVerified: true, requireReceipt: options.requireReceipt ?? false },
          pccsUrl: options.pccsUrl ?? INTEL_PCS_URL,
          proxy: options.proxy ?? proxyFor(new URL(baseURL)),
        })
      } catch (error) {
        throw new AttestationFailure('aci', (error as Error).message)
      }
      const verdict = aci.identity.transcript.verdict
      if (!verdict.verified) {
        await aci.close().catch(() => {})
        throw new AttestationFailure('aci', verdict.line)
      }
      try {
        assertPinned('compose', aci.identity.composeHash, options.acceptedComposeHashes ?? [], 'PHALA_ACCEPTED_COMPOSE_HASHES', options.allowUnpinned)
      } catch (error) {
        await aci.close().catch(() => {})
        throw error
      }
      return {
        baseURL: aci.baseURL.replace(/\/+$/, ''),
        fetch: aci.fetch,
        close: () => aci.close(),
        expiresAt: Math.min(toSeconds(aci.identity.expiresAt), nowSeconds() + 3600),
        evidence: {
          composeHash: aci.identity.composeHash,
          workloadKeysetDigest: aci.identity.workloadKeysetDigest,
          tlsSpkiSha256: aci.identity.tlsSpkiPins.join(','),
          verdict: verdict.line,
          pinned: options.acceptedComposeHashes?.length ? 'compose' : 'not pinned (development)',
        },
      }
    },
  }
}
