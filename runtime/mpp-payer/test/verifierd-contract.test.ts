import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REQUIRED_CHECKS, RelayAttestationGate, parseVerifyReport } from '../src/attestation-gate.js'

/**
 * Contract with sealed-verifierd POST /v1/verify/live, caller-fetched form. The fixture was
 * recorded by running this branch's RelayAttestationGate against the real verifier/httpapi
 * handler of ws/verifier (simulated quotes, a fixture chain where the owner approved an
 * inference-relay stack). Replaying it here fails when the payer's request drifts from what
 * was recorded (re-record against the real handler then), or when the payer misreads a real
 * report.
 */
type Case = {
  name: string
  nonce: `0x${string}`
  observedTlsPubKeyHash: `0x${string}`
  relayOwner: `0x${string}`
  attest: Record<string, unknown>
  request: Record<string, unknown>
  status: number
  response: Record<string, unknown>
  gate: { ok: boolean; detail: string }
}

const fixture = JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures/verifierd-live-submitted.json'), 'utf8')) as {
  verifierd: { requestFields: string[]; optionFields: string[]; reportFields: string[]; checkFields: string[] }
  cases: Case[]
}

function replay(c: Case) {
  const sent: unknown[] = []
  const gate = new RelayAttestationGate({
    attestUrl: 'https://relay.34-1-2-3.sslip.io/attest',
    verifierdUrl: 'http://sealed-verifierd:8088',
    relayOwner: c.relayOwner,
    intervalSeconds: 900,
    allowSimulated: true,
    newNonce: () => c.nonce,
    fetchAttest: async () => ({ response: Response.json(c.attest), tlsPubKeyHash: c.observedTlsPubKeyHash }),
    fetchVerifier: async (url, init) => {
      expect(url).toBe('http://sealed-verifierd:8088/v1/verify/live')
      sent.push(JSON.parse(String(init.body)))
      return Response.json(c.response, { status: c.status })
    },
  })
  return { gate, sent }
}

describe('sealed-verifierd /v1/verify/live contract (recorded against verifier/httpapi)', () => {
  it('sends only fields the handler decodes', () => {
    const { requestFields, optionFields } = fixture.verifierd
    for (const c of fixture.cases) {
      for (const key of Object.keys(c.request)) expect(requestFields, key).toContain(key)
      for (const key of Object.keys(c.request.options as object)) expect(optionFields, `options.${key}`).toContain(key)
    }
  })

  it('reads only fields the verifier report has, and every required check exists in a real report', () => {
    const { reportFields, checkFields } = fixture.verifierd
    for (const field of ['ok', 'simulated', 'mode', 'stackHash', 'deploymentId', 'checks']) expect(reportFields).toContain(field)
    for (const field of ['name', 'ok', 'detail']) expect(checkFields).toContain(field)
    const verified = fixture.cases.find((c) => c.name === 'verified')!
    const report = parseVerifyReport(verified.response)
    expect(report).toMatchObject({ ok: true, simulated: true, mode: 'live_submitted' })
    for (const name of REQUIRED_CHECKS) expect(report.checks.find((x) => x.name === name), name).toMatchObject({ ok: true })
  })

  for (const c of fixture.cases) {
    it(`replays "${c.name}" byte for byte and reaches the recorded verdict`, async () => {
      const { gate, sent } = replay(c)
      const state = await gate.check()
      expect(sent).toEqual([c.request])
      expect(c.status).toBe(200)
      expect({ ok: state.ok, detail: state.detail }).toEqual(c.gate)
    })
  }

  it('passes the verifier and fails only the local relay identity check on the fixture stack', () => {
    // The fixture composer renders one service per app with no environment, so the payer's own
    // check that inference-relay-front names a TREASURY_ADDRESS is what stops it; every verifierd
    // check passed. Unit tests cover the local checks on a composer-shaped app-compose.
    const verified = fixture.cases.find((c) => c.name === 'verified')!
    expect(verified.gate.detail).toBe('attested relay compose has no inference-relay-front service')
    expect(fixture.cases.find((c) => c.name === 'wrong relay owner')!.gate.detail).toMatch(/expected_customer/)
    expect(fixture.cases.find((c) => c.name === 'replayed attestation')!.gate.detail).toMatch(/freshness/)
  })
})
