// Re-records test/fixtures/verifierd-live-submitted.json: pnpm --filter @sealed/mpp-payer build,
// then node test/fixtures/recorder/record.mjs <path to the built record-payer-fixture binary>.
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { RelayAttestationGate } from '../../../dist/attestation-gate.js'

const h = (s) => '0x' + createHash('sha256').update(s).digest('hex')
const proc = spawn(process.argv[2], [], { stdio: ['pipe', 'pipe', 'inherit'] })
const info = await new Promise((resolve) => createInterface({ input: proc.stdout }).once('line', (l) => resolve(JSON.parse(l))))
const observed = h('relay certificate SPKI')

async function record(name, { relayOwner, nonce, docNonce }) {
  let attest, request, status, response
  const gate = new RelayAttestationGate({
    attestUrl: 'https://relay.34-1-2-3.sslip.io/attest',
    verifierdUrl: info.base,
    relayOwner,
    intervalSeconds: 900,
    allowSimulated: true,
    newNonce: () => nonce,
    fetchAttest: async () => {
      const res = await fetch(info.base + '/fixture/attest?nonce=' + (docNonce ?? nonce) + '&spki=' + observed)
      attest = await res.json()
      return { response: Response.json(attest), tlsPubKeyHash: observed }
    },
    fetchVerifier: async (url, init) => {
      request = JSON.parse(String(init.body))
      const res = await fetch(url, init)
      status = res.status
      response = await res.json()
      return Response.json(response, { status })
    },
  })
  const state = await gate.check()
  return { name, nonce, observedTlsPubKeyHash: observed, relayOwner, attest, request, status, response, gate: { ok: state.ok, detail: state.detail } }
}

const cases = [
  await record('verified', { relayOwner: info.relayOwner, nonce: h('payer contract nonce 1') }),
  await record('wrong relay owner', { relayOwner: '0x000000000000000000000000000000000000dead', nonce: h('payer contract nonce 2') }),
  await record('replayed attestation', { relayOwner: info.relayOwner, nonce: h('payer contract nonce 3'), docNonce: h('an older nonce') }),
]
proc.stdin.end()
const fixture = {
  recordedFrom: 'ws/verifier 91022b1: the real verifier/httpapi handler (simulated quotes, fixture chain with OWNER approval of an inference-relay stack); the payer side is RelayAttestationGate from this branch',
  recordedAt: '2026-10-28',
  verifierd: { requestFields: info.requestFields, optionFields: info.optionFields, reportFields: info.reportFields, checkFields: info.checkFields },
  cases,
}
writeFileSync(new URL('../verifierd-live-submitted.json', import.meta.url), JSON.stringify(fixture, null, 2) + '\n')
for (const c of cases) console.log(c.name, c.status, c.response.ok, c.response.mode, JSON.stringify(c.gate), (c.response.checks||[]).filter(x=>!x.ok).map(x=>x.name))
console.log(cases[0].response.checks.map((c) => c.name).join(','))
