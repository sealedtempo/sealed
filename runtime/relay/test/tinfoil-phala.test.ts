import { describe, expect, it } from 'vitest'
import { phalaVerifier } from '../src/providers/phala.js'
import { tinfoilVerifier } from '../src/providers/tinfoil.js'
import { AttestationFailure } from '../src/providers/types.js'

describe('Tinfoil verifier module', () => {
  const fp = 'ab'.repeat(32)
  it('uses the official verifier result and pins its TLS key', async () => {
    let seen: unknown
    const v = tinfoilVerifier({
      verifierFactory: async (opts) => {
        seen = opts
        return {
          verify: async () => ({ tlsPublicKeyFingerprint: fp, measurement: { type: 'snp-tdx-multiplatform/v1', registers: ['aa', 'bb'] } }),
          getVerificationDocument: () => ({ releaseTag: 'v1.2.3', securityVerified: true }),
        }
      },
    })
    const channel = await v.verify()
    expect(seen).toEqual({ serverURL: 'https://inference.tinfoil.sh', configRepo: 'tinfoilsh/confidential-model-router' })
    expect(channel.baseURL).toBe('https://inference.tinfoil.sh/v1')
    expect(channel.evidence).toMatchObject({ tlsSpkiSha256: fp, measurement: 'aa:bb', releaseTag: 'v1.2.3' })
    await channel.close?.()
  })

  it('fails closed on verifier errors, unverified documents and missing key fingerprints', async () => {
    const failing = tinfoilVerifier({
      verifierFactory: async () => ({ verify: async () => Promise.reject(new Error('measurement mismatch')) }),
    })
    await expect(failing.verify()).rejects.toThrow(AttestationFailure)
    const unverified = tinfoilVerifier({
      verifierFactory: async () => ({
        verify: async () => ({ tlsPublicKeyFingerprint: fp, measurement: { type: 't', registers: [] } }),
        getVerificationDocument: () => ({ securityVerified: false }),
      }),
    })
    await expect(unverified.verify()).rejects.toThrow(/securityVerified/)
    const noKey = tinfoilVerifier({
      verifierFactory: async () => ({ verify: async () => ({ measurement: { type: 't', registers: [] } }) }),
    })
    await expect(noKey.verify()).rejects.toThrow(/fingerprint/)
  })
})

describe('Phala ACI verifier module', () => {
  const identity = (verified: boolean) => ({
    composeHash: 'cc'.repeat(32),
    tlsSpkiPins: ['dd'.repeat(32)],
    expiresAt: Math.floor(Date.now() / 1000) + 120,
    workloadKeysetDigest: `sha256:${'ee'.repeat(32)}`,
    transcript: { verdict: { verified, line: verified ? 'VERIFIED (5 pass)' : 'NOT VERIFIED (1 fail: id-1)' } },
  })

  it('requires a VERIFIED verdict and passes our policy to connectAci', async () => {
    let options: any
    let closed = false
    const v = phalaVerifier({
      acceptedComposeHashes: ['cc'.repeat(32)],
      connect: async (o) => {
        options = o
        return { baseURL: 'https://inference.phala.com/v1', fetch: async () => new Response('ok'), identity: identity(true), close: async () => void (closed = true) }
      },
    })
    const channel = await v.verify()
    expect(options).toMatchObject({
      baseURL: 'https://inference.phala.com/v1',
      policy: { acceptedComposeHashes: ['cc'.repeat(32)] },
      serving: { requireVerified: true },
      pccsUrl: 'https://api.trustedservices.intel.com',
    })
    expect(channel.evidence.composeHash).toBe('cc'.repeat(32))
    expect(channel.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 120)
    await channel.close?.()
    expect(closed).toBe(true)
  })

  it('rejects unverified verdicts and connection errors', async () => {
    let closed = false
    const notVerified = phalaVerifier({
      connect: async () => ({ baseURL: 'x', fetch: fetch, identity: identity(false), close: async () => void (closed = true) }),
    })
    await expect(notVerified.verify()).rejects.toThrow(/NOT VERIFIED/)
    expect(closed).toBe(true)
    const broken = phalaVerifier({ connect: async () => Promise.reject(new Error('attestation_verification')) })
    await expect(broken.verify()).rejects.toThrow(AttestationFailure)
  })
})
