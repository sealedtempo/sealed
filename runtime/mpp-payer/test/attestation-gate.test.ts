import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { RelayAttestationGate, checkRelayConfig, payeeFromAppCompose } from '../src/attestation-gate.js'
import { OWNER, TLS_HASH, TREASURY, fakeAttest, fakeVerifierd, relayAppCompose, relayConfig } from './helpers/fake-relay-attest.js'

function gateWith(attest = fakeAttest(), verifier = fakeVerifierd(), extra: Partial<ConstructorParameters<typeof RelayAttestationGate>[0]> = {}) {
  let now = 1_000_000
  const failures: string[] = []
  const gate = new RelayAttestationGate({
    attestUrl: 'https://relay.example/attest',
    verifierdUrl: 'http://sealed-verifierd:8088',
    relayOwner: OWNER,
    intervalSeconds: 900,
    retrySeconds: 60,
    fetchAttest: attest.fetchAttest,
    fetchVerifier: verifier.fetchVerifier,
    onExplicitFailure: (s) => failures.push(s.detail),
    now: () => now,
    random: () => 0.5,
    ...extra,
  })
  return { gate, attest, verifier, failures, advance: (s: number) => void (now += s) }
}

describe('relay attestation gate', () => {
  it('verifies through sealed-verifierd with a fresh nonce, the relay owner, the relay app and the observed TLS key', async () => {
    const { gate, attest, verifier } = gateWith()
    const state = await gate.check()
    expect(state).toMatchObject({ ok: true, payee: TREASURY, tlsPubKeyHash: TLS_HASH, deploymentId: '0x' + '77'.repeat(32) })
    expect(attest.nonces[0]).toMatch(/^0x[0-9a-f]{64}$/)
    const req = verifier.requests[0]!
    expect(req.url).toBe('http://sealed-verifierd:8088/v1/verify/live')
    // The caller-fetched form of verifier/httpapi liveRequest.
    expect(Object.keys(req.body).sort()).toEqual(['attest', 'attestUrl', 'nonce', 'observedTlsPubKeyHash', 'options'])
    expect(req.body).toMatchObject({
      nonce: attest.nonces[0],
      observedTlsPubKeyHash: TLS_HASH,
      attestUrl: 'https://relay.example/attest',
      options: { expectedCustomer: OWNER, expectedAppIds: ['inference-relay'] },
    })
    expect(gate.isOpen()).toBe(true)
    expect(gate.payee()).toBe(TREASURY)
    expect(gate.pin()).toBe(TLS_HASH)
    await gate.check()
    expect(attest.nonces[1]).not.toBe(attest.nonces[0])
  })

  it('stays closed when the verifier rejects, caches the failure, and opens after a later pass', async () => {
    const { gate, verifier, failures, advance } = gateWith(undefined, fakeVerifierd({ ok: false }))
    const failed = await gate.ensureFresh()
    expect(failed.ok).toBe(false)
    expect(failed.detail).toMatch(/stack_approved: stack not approved by owner/)
    expect(failures).toHaveLength(1)
    expect(gate.payee()).toBeUndefined()
    expect(gate.pin()).toBeUndefined()
    // Requests inside the retry window reuse the cached failure instead of re-attesting.
    for (let i = 0; i < 5; i++) expect((await gate.ensureFresh()).ok).toBe(false)
    expect(verifier.requests.length).toBe(1)
    verifier.state.ok = true
    advance(61)
    expect((await gate.ensureFresh()).ok).toBe(true)
    expect(verifier.requests.length).toBe(2)
  })

  it('shares one check between concurrent requests', async () => {
    const { gate, verifier } = gateWith()
    const states = await Promise.all([gate.ensureFresh(), gate.ensureFresh(), gate.ensureFresh()])
    expect(states.every((s) => s.ok)).toBe(true)
    expect(verifier.requests.length).toBe(1)
  })

  it('renews before expiry and keeps the pass in force while the re-check runs', async () => {
    const { gate, verifier, advance } = gateWith()
    await gate.ensureFresh()
    // The next scheduled check is at 80% of the interval (random 0.5 means no jitter).
    expect(gate.nextDelaySeconds()).toBe(720)
    advance(720)
    let release!: () => void
    const original = verifier.fetchVerifier
    const slow = new Promise<void>((r) => (release = r))
    const gate2 = gate as unknown as { deps: { fetchVerifier: typeof original } }
    gate2.deps.fetchVerifier = async (input, init) => {
      await slow
      return original(input, init)
    }
    const recheck = gate.check()
    advance(100)
    expect(gate.isOpen()).toBe(true)
    expect(gate.payee()).toBe(TREASURY)
    release()
    await recheck
    advance(800)
    expect(gate.isOpen()).toBe(true)
  })

  it('keeps an unexpired pass when a re-check cannot complete, and closes once it expires', async () => {
    const { gate, attest, failures, advance } = gateWith()
    await gate.check()
    advance(720)
    attest.state.fail = true
    const state = await gate.check()
    expect(state.ok).toBe(true)
    expect(state.recheckError).toMatch(/unreachable/)
    expect(gate.isOpen()).toBe(true)
    expect(failures).toEqual([])
    expect(gate.nextDelaySeconds()).toBe(60)
    advance(181)
    expect(gate.isOpen()).toBe(false)
    expect(gate.state()).toMatchObject({ ok: false, detail: 'relay attestation expired' })
  })

  it('closes at once on an explicit failure during a re-check', async () => {
    const { gate, verifier, failures, advance } = gateWith()
    await gate.check()
    advance(720)
    verifier.state.ok = false
    expect((await gate.check()).ok).toBe(false)
    expect(gate.isOpen()).toBe(false)
    expect(failures).toHaveLength(1)
  })

  it('treats verifierd overload as transient and a 400 (contract mismatch) as explicit', async () => {
    const busy = gateWith(undefined, fakeVerifierd({ ok: true, status: 429 }))
    expect((await busy.gate.check()).detail).toMatch(/HTTP 429/)
    expect(busy.failures).toEqual([])
    const bad = gateWith(undefined, fakeVerifierd({ ok: true, status: 400 }))
    expect((await bad.gate.check()).detail).toMatch(/HTTP 400/)
    expect(bad.failures).toHaveLength(1)
    const down = gateWith(undefined, fakeVerifierd({ ok: true, down: true }))
    expect((await down.gate.check()).detail).toMatch(/sealed-verifierd unavailable/)
  })

  it('rejects a TLS key that differs from the connection, simulated quotes and unreachable endpoints', async () => {
    expect((await gateWith(fakeAttest({ observed: ('0x' + '99'.repeat(32)) as `0x${string}`, tlsOnWire: TLS_HASH })).gate.check()).detail).toMatch(/TLS key/)
    expect((await gateWith(undefined, fakeVerifierd({ ok: true, simulated: true })).gate.check()).detail).toMatch(/simulated/)
    expect((await gateWith(undefined, fakeVerifierd({ ok: true, simulated: true }), { allowSimulated: true }).gate.check()).ok).toBe(true)
    expect((await gateWith(fakeAttest({ status: 500 })).gate.check()).detail).toMatch(/HTTP 500/)
    expect((await gateWith(fakeAttest({ fail: true })).gate.check()).detail).toMatch(/unreachable/)
  })

  it('requires the checks a verifier that ignored an option would leave out', async () => {
    const lax = gateWith(undefined, fakeVerifierd({ ok: true, omit: ['expected_apps'] }))
    expect((await lax.gate.check()).detail).toMatch(/lacks required checks: expected_apps/)
    const otherMode = gateWith(undefined, fakeVerifierd({ ok: true, mode: 'evidence' }))
    expect((await otherMode.gate.check()).detail).toMatch(/mode evidence/)
    const otherStack = gateWith(undefined, fakeVerifierd({ ok: true, stackHash: '0x' + '12'.repeat(32) }))
    expect((await otherStack.gate.check()).detail).toMatch(/different app-compose/)
  })

  it('checks locally that the attested stack is exactly the inference relay of the relay owner', async () => {
    const demo = gateWith(fakeAttest({ config: relayConfig({ apps: [{ id: 'inference-relay' }, { id: 'crm' }] }) }))
    expect((await demo.gate.check()).detail).toMatch(/not exactly \["inference-relay"\]/)
    const crmOnly = gateWith(fakeAttest({ config: relayConfig({ apps: [{ id: 'crm' }] }) }))
    expect((await crmOnly.gate.check()).ok).toBe(false)
    const stranger = gateWith(fakeAttest({ config: relayConfig({ customer: '0x' + '0b'.repeat(20) }) }))
    expect((await stranger.gate.check()).detail).toMatch(/relay owner/)
    expect(() => checkRelayConfig(relayConfig(), OWNER.toUpperCase().replace('0X', '0x'))).not.toThrow()
  })

  it('takes the payee only from inference-relay-front, and checks a pinned one against it', async () => {
    expect(payeeFromAppCompose(relayAppCompose())).toBe(TREASURY)
    const decoy = relayAppCompose(TREASURY, { 'other-app': { environment: { TREASURY_ADDRESS: '0x' + '01'.repeat(20) } } })
    expect(payeeFromAppCompose(decoy)).toBe(TREASURY)
    const listForm = JSON.stringify({
      docker_compose_file: JSON.stringify({ services: { 'inference-relay-front': { environment: [`TREASURY_ADDRESS=${'0x' + 'AB'.repeat(20)}`] } } }),
    })
    expect(payeeFromAppCompose(listForm)).toBe(TREASURY)
    const elsewhere = JSON.stringify({ docker_compose_file: JSON.stringify({ services: { a: { environment: { TREASURY_ADDRESS: TREASURY } } } }) })
    expect(() => payeeFromAppCompose(elsewhere)).toThrow(/no inference-relay-front/)
    expect(() => payeeFromAppCompose(relayAppCompose('0x' + '00'.repeat(20)))).toThrow(/zero address/)
    expect(() => payeeFromAppCompose(relayAppCompose('${TREASURY_ADDRESS}'))).toThrow(/not an address/)
    const pinned = gateWith(undefined, undefined, { payeeOverride: ('0x' + '12'.repeat(20)) as `0x${string}` })
    expect((await pinned.gate.check()).detail).toMatch(/differs/)
    const pinnedOk = gateWith(undefined, undefined, { payeeOverride: TREASURY as `0x${string}` })
    expect((await pinnedOk.gate.check()).ok).toBe(true)
  })

  it('jitters scheduled checks within the configured fraction', async () => {
    const low = gateWith(undefined, undefined, { random: () => 0 })
    const high = gateWith(undefined, undefined, { random: () => 0.999 })
    await low.gate.check()
    await high.gate.check()
    expect(low.gate.nextDelaySeconds()).toBe(648)
    expect(high.gate.nextDelaySeconds()).toBeGreaterThan(790)
    expect(high.gate.nextDelaySeconds()).toBeLessThanOrEqual(792)
  })
})

describe('payee from the real composer output', () => {
  // test/fixtures/relay-app-compose.json: `sealed-compose compose --print app-compose` (ws/composer
  // 75f1c57) over this branch's catalog/apps/inference-relay, an OWNER config with only that app.
  const composed = readFileSync(join(import.meta.dirname, 'fixtures/relay-app-compose.json'), 'utf8')

  it('refuses the zero-address placeholder the unreleased fragment carries', () => {
    expect(() => payeeFromAppCompose(composed)).toThrow(/zero address/)
  })

  it('reads TREASURY_ADDRESS of inference-relay-front once the release pins it', () => {
    const pinned = composed.replaceAll('0x0000000000000000000000000000000000000000', TREASURY)
    expect(payeeFromAppCompose(pinned)).toBe(TREASURY)
  })
})
