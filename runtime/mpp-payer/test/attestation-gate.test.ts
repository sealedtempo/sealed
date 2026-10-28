import { describe, expect, it } from 'vitest'
import { RelayAttestationGate, payeeFromAppCompose } from '../src/attestation-gate.js'
import { TLS_HASH, TREASURY, fakeAttest, fakeVerifierd, relayAppCompose } from './helpers/fake-relay-attest.js'

const OWNER = ('0x' + '0a'.repeat(20)) as `0x${string}`

function gateWith(attest = fakeAttest(), verifier = fakeVerifierd(), extra: Partial<ConstructorParameters<typeof RelayAttestationGate>[0]> = {}) {
  let now = 1_000_000
  const gate = new RelayAttestationGate({
    attestUrl: 'https://attest.relay.example/attest',
    verifierdUrl: 'http://sealed-verifierd:8088',
    relayOwner: OWNER,
    intervalSeconds: 900,
    fetchAttest: attest.fetchAttest,
    fetchVerifier: verifier.fetchVerifier,
    now: () => now,
    ...extra,
  })
  return { gate, attest, verifier, advance: (s: number) => void (now += s) }
}

describe('relay attestation gate', () => {
  it('verifies through sealed-verifierd with a fresh nonce, the relay owner and the observed TLS key', async () => {
    const { gate, attest, verifier } = gateWith()
    const state = await gate.check()
    expect(state).toMatchObject({ ok: true, payee: TREASURY })
    expect(attest.nonces[0]).toMatch(/^0x[0-9a-f]{64}$/)
    const req = verifier.requests[0]
    expect(req.url).toBe('http://sealed-verifierd:8088/v1/verify/live')
    expect(req.body).toMatchObject({
      nonce: attest.nonces[0],
      expectedCustomer: OWNER,
      expectedAppIds: ['inference-relay'],
      observedTlsPubKeyHash: TLS_HASH,
      attestUrl: 'https://attest.relay.example/attest',
    })
    expect(gate.isOpen()).toBe(true)
    expect(gate.payee()).toBe(TREASURY)
    await gate.check()
    expect(attest.nonces[1]).not.toBe(attest.nonces[0])
  })

  it('stays closed when the verifier rejects, and opens after a later pass', async () => {
    const { gate, verifier } = gateWith(undefined, fakeVerifierd({ ok: false }))
    const failed = await gate.check()
    expect(failed.ok).toBe(false)
    expect(failed.detail).toMatch(/stack_approved: stack not approved by owner/)
    expect(gate.payee()).toBeUndefined()
    verifier.state.ok = true
    expect((await gate.ensureFresh()).ok).toBe(true)
  })

  it('re-checks after 15 minutes and closes if the relay stops verifying', async () => {
    const { gate, verifier, advance } = gateWith()
    await gate.ensureFresh()
    advance(899)
    await gate.ensureFresh()
    expect(verifier.requests.length).toBe(1)
    advance(2)
    expect(gate.isOpen()).toBe(false)
    verifier.state.ok = false
    expect((await gate.ensureFresh()).ok).toBe(false)
    expect(verifier.requests.length).toBe(2)
  })

  it('rejects a TLS key that differs from the connection, simulated quotes and unreachable endpoints', async () => {
    expect((await gateWith(fakeAttest({ observed: ('0x' + '99'.repeat(32)) as `0x${string}` })).gate.check()).detail).toMatch(/TLS key/)
    expect((await gateWith(undefined, fakeVerifierd({ ok: true, simulated: true })).gate.check()).detail).toMatch(/simulated/)
    expect((await gateWith(undefined, fakeVerifierd({ ok: true, simulated: true }), { allowSimulated: true }).gate.check()).ok).toBe(true)
    expect((await gateWith(fakeAttest({ status: 500 })).gate.check()).detail).toMatch(/HTTP 500/)
    const down = gateWith(undefined, { ...fakeVerifierd(), fetchVerifier: async () => Promise.reject(new Error('ECONNREFUSED')) } as never)
    expect((await down.gate.check()).detail).toMatch(/sealed-verifierd unavailable/)
  })

  it('takes the payee from the attested compose, or checks a pinned one against it', async () => {
    expect(payeeFromAppCompose(relayAppCompose())).toBe(TREASURY)
    expect(() => payeeFromAppCompose(JSON.stringify({ docker_compose_file: JSON.stringify({ services: { a: { environment: { TREASURY_ADDRESS: '0x' + '01'.repeat(20) } }, b: { environment: ['TREASURY_ADDRESS=0x' + '02'.repeat(20)] } } }) }))).toThrow(/more than one/)
    const pinned = gateWith(undefined, undefined, { payeeOverride: ('0x' + '12'.repeat(20)) as `0x${string}` })
    expect((await pinned.gate.check()).detail).toMatch(/differs/)
    const noPayee = gateWith(fakeAttest({ appCompose: JSON.stringify({ docker_compose_file: '{"services":{}}' }) }))
    expect((await noPayee.gate.check()).detail).toMatch(/payee unknown/)
  })
})
