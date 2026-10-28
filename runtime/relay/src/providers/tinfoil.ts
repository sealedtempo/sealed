import { createPinnedFetch } from './pinned-fetch.js'
import { AttestationFailure, type ProviderVerifier, type VerifiedChannel, nowSeconds } from './types.js'

/**
 * Tinfoil, through its official verifier `@tinfoilsh/verifier` (Apache-2.0): the enclave's
 * hardware attestation (AMD SEV-SNP / TDX), Sigstore code provenance of the configured repo,
 * and the comparison of the two measurements. The attested TLS key fingerprint is then pinned
 * on every connection, which the library leaves to the caller.
 */
export type TinfoilOptions = {
  enclaveURL?: string
  configRepo?: string
  evidenceTtlSeconds?: number
  proxy?: string
  /** Test seam for the official verifier. */
  verifierFactory?: VerifierFactory
}

type TinfoilVerifierLike = {
  verify(): Promise<{ tlsPublicKeyFingerprint?: string; measurement: { type: string; registers: string[] } }>
  getVerificationDocument?(): { releaseTag?: string; securityVerified?: boolean } | undefined
}
type VerifierFactory = (opts: { serverURL: string; configRepo: string }) => Promise<TinfoilVerifierLike>

const officialVerifier: VerifierFactory = async (opts) => {
  const { Verifier } = await import('@tinfoilsh/verifier')
  return new Verifier(opts)
}

export const TINFOIL_DEFAULT_ENCLAVE = 'https://inference.tinfoil.sh'
export const TINFOIL_DEFAULT_REPO = 'tinfoilsh/confidential-model-router'

export function tinfoilVerifier(options: TinfoilOptions = {}): ProviderVerifier {
  const enclaveURL = (options.enclaveURL ?? TINFOIL_DEFAULT_ENCLAVE).replace(/\/+$/, '')
  const configRepo = options.configRepo ?? TINFOIL_DEFAULT_REPO
  const ttl = options.evidenceTtlSeconds ?? 600
  return {
    provider: 'tinfoil',
    async verify(): Promise<VerifiedChannel> {
      const verifier = await (options.verifierFactory ?? officialVerifier)({ serverURL: enclaveURL, configRepo })
      let result: Awaited<ReturnType<TinfoilVerifierLike['verify']>>
      try {
        result = await verifier.verify()
      } catch (error) {
        throw new AttestationFailure('tinfoil', (error as Error).message)
      }
      const doc = verifier.getVerificationDocument?.()
      if (doc && doc.securityVerified === false) throw new AttestationFailure('tinfoil', 'verification document is not securityVerified')
      const fingerprint = result.tlsPublicKeyFingerprint?.toLowerCase()
      if (!fingerprint || !/^[0-9a-f]{64}$/.test(fingerprint))
        throw new AttestationFailure('tls', 'attestation carries no TLS public key fingerprint')
      const pinned = createPinnedFetch({ baseURL: enclaveURL, pins: [fingerprint], proxy: options.proxy })
      return {
        baseURL: `${enclaveURL}/v1`,
        fetch: pinned.fetch,
        close: pinned.close,
        expiresAt: nowSeconds() + ttl,
        evidence: {
          tlsSpkiSha256: fingerprint,
          measurementType: result.measurement.type,
          measurement: result.measurement.registers.join(':'),
          ...(doc?.releaseTag ? { releaseTag: doc.releaseTag } : {}),
          configRepo,
        },
      }
    },
  }
}
