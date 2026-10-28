import { Challenge, Credential } from 'mppx'
import { Session } from 'mppx/tempo'
import { encodeFunctionData } from 'viem'
import { generatePrivateKey } from 'viem/accounts'
import { Account, Transaction } from 'viem/tempo'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ChannelJournal } from '../src/channel-journal.js'
import { ESCROW_PRECOMPILE, PATHUSD } from '../src/config.js'
import { type FirewallPolicy, feeCap, inspectCredential, paymentFirewall } from '../src/payment-firewall.js'
import { RelayPinError } from '../src/relay-transport.js'
import { BudgetUnavailableError } from '../src/shared-budget.js'
import { PaymentPolicyError, SpendGuard, SpendLimitError } from '../src/spend-guard.js'
import { fakeAgentBudget } from './helpers/fake-agent-budget.js'

const payee = '0x' + '77'.repeat(20)
const payer = Account.fromSecp256k1(generatePrivateKey())
const policy: FirewallPolicy = {
  payerAddress: payer.address,
  currency: PATHUSD,
  allowedChainIds: [4217],
  maxCharge: 50_000n,
  maxDeposit: 500_000n,
  expectedPayee: () => payee as `0x${string}`,
}

const tip20 = [
  { type: 'function', name: 'transferWithMemo', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'memo', type: 'bytes32' }], outputs: [] },
  { type: 'function', name: 'approve', stateMutability: 'nonpayable', inputs: [{ name: 's', type: 'address' }, { name: 'a', type: 'uint256' }], outputs: [{ type: 'bool' }] },
] as const
const escrow = [
  { type: 'function', name: 'open', stateMutability: 'nonpayable', inputs: [{ name: 'payee', type: 'address' }, { name: 'operator', type: 'address' }, { name: 'token', type: 'address' }, { name: 'deposit', type: 'uint96' }, { name: 'salt', type: 'bytes32' }, { name: 'authorizedSigner', type: 'address' }], outputs: [{ type: 'bytes32' }] },
] as const

/** 300k gas at 1.2e9 attodollars per gas: the account pays at most 360 base units in fees. */
const GAS = 300_000n
const MAX_FEE_PER_GAS = 1_200_000_000n
const FEE = 360n

async function signedTx(calls: { to: `0x${string}`; data: `0x${string}` }[], chainId = 4217, maxFeePerGas = MAX_FEE_PER_GAS) {
  return payer.signTransaction(
    { type: 'tempo', chainId, calls, nonce: 0, gas: GAS, maxFeePerGas, maxPriorityFeePerGas: 1n, feeToken: PATHUSD } as never,
    { serializer: Transaction.serialize } as never,
  )
}

function header(intent: 'charge' | 'session', request: Record<string, unknown>, payload: Record<string, unknown>) {
  const challenge = Challenge.from({ id: 'test-challenge', realm: 'relay.test', method: 'tempo', intent, request } as never)
  return Credential.serialize(Credential.from({ challenge, payload } as never))
}

/** The channel descriptor mppx sends with an open (ChannelOps.createOpenPayload). */
function channelOf(transaction: `0x${string}`, to: `0x${string}`, operator: `0x${string}`, salt: `0x${string}`) {
  const expiringNonceHash = Session.Precompile.Channel.computeExpiringNonceHash(
    Session.Precompile.Channel.transactionForExpiringNonceHash({ transaction: Transaction.deserialize(transaction as `0x76${string}`) as never }) as never,
    { sender: payer.address },
  )
  return { payer: payer.address, payee: to, operator, token: PATHUSD, salt, authorizedSigner: payer.address, expiringNonceHash }
}
const channelIdOf = (descriptor: ReturnType<typeof channelOf>) =>
  Session.Precompile.Channel.computeId({ ...descriptor, chainId: 4217, escrow: ESCROW_PRECOMPILE } as never) as `0x${string}`

const chargeRequest = (amount: string, recipient = payee) => ({ amount, currency: PATHUSD, recipient, methodDetails: { chainId: 4217 } })
const transfer = (to: string, amount: bigint) =>
  ({ to: PATHUSD, data: encodeFunctionData({ abi: tip20, functionName: 'transferWithMemo', args: [to as `0x${string}`, amount, `0x${'00'.repeat(32)}`] }) }) as const

describe('payment firewall', () => {
  it('accepts a charge that pays exactly the attested payee in the fee token, and budgets its network fee', async () => {
    const tx = await signedTx([transfer(payee, 1234n)])
    const { debits } = inspectCredential(header('charge', chargeRequest('1234'), { type: 'transaction', signature: tx }), policy, new Map())
    expect(debits).toEqual([
      { kind: 'charge', amount: 1234n },
      { kind: 'fee', amount: FEE },
    ])
    const free = await signedTx([transfer(payee, 1234n)], 4217, 0n)
    expect(inspectCredential(header('charge', chargeRequest('1234'), { type: 'transaction', signature: free }), policy, new Map()).debits).toEqual([
      { kind: 'charge', amount: 1234n },
    ])
  })

  it('computes the fee cap as gas x maxFeePerGas / 10^12 rounded up, and nothing for sponsored transactions', () => {
    expect(feeCap({ gas: GAS, maxFeePerGas: MAX_FEE_PER_GAS })).toBe(360n)
    expect(feeCap({ gas: 1n, maxFeePerGas: 1n })).toBe(1n)
    expect(feeCap({ gas: 271_000n, maxFeePerGas: 12_000_000_000n })).toBe(3_252n)
    expect(feeCap({ gas: GAS, maxFeePerGas: MAX_FEE_PER_GAS, feePayerSignature: null })).toBe(0n)
    expect(feeCap({ gas: GAS, maxFeePerGas: MAX_FEE_PER_GAS, feePayerSignature: { r: 1n, s: 1n, yParity: 0 } })).toBe(0n)
    expect(feeCap({})).toBe(0n)
  })

  it.each([
    ['another recipient', async () => header('charge', chargeRequest('1', '0x' + '11'.repeat(20)), { type: 'transaction', signature: await signedTx([transfer(payee, 1n)]) }), /recipient/],
    ['a transfer elsewhere', async () => header('charge', chargeRequest('1'), { type: 'transaction', signature: await signedTx([transfer('0x' + '11'.repeat(20), 1n)]) }), /other than the payee/],
    ['an amount mismatch', async () => header('charge', chargeRequest('5'), { type: 'transaction', signature: await signedTx([transfer(payee, 6n)]) }), /differs/],
    ['over the per-request cap', async () => header('charge', chargeRequest('60000'), { type: 'transaction', signature: await signedTx([transfer(payee, 60_000n)]) }), /cap/],
    ['a smuggled approve', async () => header('charge', chargeRequest('1'), { type: 'transaction', signature: await signedTx([transfer(payee, 1n), { to: PATHUSD, data: encodeFunctionData({ abi: tip20, functionName: 'approve', args: [payee as `0x${string}`, 10n ** 18n] }) }]) }), /unexpected charge call/],
    ['another chain', async () => header('charge', { ...chargeRequest('1'), methodDetails: { chainId: 1 } }, { type: 'transaction', signature: await signedTx([transfer(payee, 1n)]) }), /chain 1/],
    ['push mode', async () => header('charge', chargeRequest('1'), { type: 'hash', hash: '0x' + '00'.repeat(32) }), /pull mode/],
    ['another currency', async () => header('charge', { ...chargeRequest('1'), currency: '0x20c0000000000000000000000000000000000001' }, { type: 'transaction', signature: await signedTx([transfer(payee, 1n)]) }), /currency/],
  ])('refuses %s', async (_name, build, message) => {
    const value = await (build as () => Promise<string>)()
    expect(() => inspectCredential(value, policy, new Map())).toThrow(message)
  })

  it('refuses every payment while the relay payee is unknown', async () => {
    const tx = await signedTx([transfer(payee, 1n)])
    const closed = { ...policy, expectedPayee: () => undefined }
    expect(() => inspectCredential(header('charge', chargeRequest('1'), { type: 'transaction', signature: tx }), closed, new Map())).toThrow(/attestation has not passed/)
  })

  it('meters a session open by its deposit and caps the channel', async () => {
    const operator = payee as `0x${string}`
    const salt = `0x${'00'.repeat(32)}` as const
    const open = (deposit: bigint, to: `0x${string}` = payee as `0x${string}`) =>
      signedTx([{ to: ESCROW_PRECOMPILE, data: encodeFunctionData({ abi: escrow, functionName: 'open', args: [to, operator, PATHUSD, deposit, salt, payer.address] }) }])
    const request = { amount: '0.000001', unitType: 'usd_micro', currency: PATHUSD, recipient: payee, methodDetails: { chainId: 4217, escrowContract: ESCROW_PRECOMPILE } }
    const openPayload = async (deposit: bigint, to: `0x${string}` = payee as `0x${string}`) => {
      const transaction = await open(deposit, to)
      const descriptor = channelOf(transaction, to, operator, salt)
      return { action: 'open', channelId: channelIdOf(descriptor), transaction, descriptor, cumulativeAmount: '10', signature: '0x' }
    }
    const okPayload = await openPayload(400_000n)
    const decoded = inspectCredential(header('session', request, okPayload), policy, new Map())
    expect(decoded.debits).toEqual([
      { kind: 'deposit', amount: 400_000n, channelId: okPayload.channelId },
      { kind: 'fee', amount: FEE },
    ])
    // The descriptor the journal records for recovery is the channel the transaction opens.
    expect(decoded.open).toMatchObject({ channelId: okPayload.channelId, deposit: 400_000n, chainId: 4217, escrow: ESCROW_PRECOMPILE })
    expect(decoded.signed?.hash).toMatch(/^0x[0-9a-f]{64}$/)
    const big = header('session', request, await openPayload(600_000n))
    expect(() => inspectCredential(big, policy, new Map())).toThrow(/cap/)
    const elsewhere = header('session', request, await openPayload(1n, ('0x' + '11'.repeat(20)) as `0x${string}`))
    expect(() => inspectCredential(elsewhere, policy, new Map())).toThrow(/another payee/)
    // A descriptor that is not the opened channel is refused (recovery could not close it).
    const otherSalt = { ...okPayload, descriptor: { ...okPayload.descriptor, salt: `0x${'01'.repeat(32)}` } }
    expect(() => inspectCredential(header('session', request, otherSalt), policy, new Map())).toThrow(/descriptor differs/)
    const otherId = { ...okPayload, channelId: `0x${'cd'.repeat(32)}` }
    expect(() => inspectCredential(header('session', request, otherId), policy, new Map())).toThrow(/channel id differs/)
    const { descriptor: _d, ...noDescriptor } = okPayload
    expect(() => inspectCredential(header('session', request, noDescriptor), policy, new Map())).toThrow(/no descriptor/)
    const customEscrow = header('session', { ...request, methodDetails: { chainId: 4217, escrowContract: '0x33b901018174DDabE4841042ab76ba85D4e24f25' } }, { action: 'voucher', channelId: '0x01', cumulativeAmount: '1', signature: '0x' })
    expect(() => inspectCredential(customEscrow, policy, new Map())).toThrow(/precompile/)
    const voucher = header('session', request, { action: 'voucher', channelId: '0x' + 'cd'.repeat(32), cumulativeAmount: '500', signature: '0x' })
    expect(() => inspectCredential(voucher, policy, new Map([['0x' + 'cd'.repeat(32), 400n]]))).toThrow(/exceeds the channel deposit/)
  })

  it('reserves before sending, releases on 402, and refuses over the daily limit', async () => {
    const guard = new SpendGuard(2_000n)
    let status = 402
    const sent: string[] = []
    const fetchImpl = paymentFirewall(async (input) => {
      sent.push((input as Request).headers.get('authorization') ?? '')
      return new Response(null, { status })
    }, policy, guard)
    const tx = await signedTx([transfer(payee, 1_500n)])
    const auth = header('charge', chargeRequest('1500'), { type: 'transaction', signature: tx })
    await fetchImpl('https://relay/v1/chat/completions', { method: 'POST', headers: { authorization: auth } })
    expect(guard.remaining()).toBe(2_000n)
    status = 200
    await fetchImpl('https://relay/v1/chat/completions', { method: 'POST', headers: { authorization: auth } })
    expect(guard.remaining()).toBe(2_000n - 1_500n - FEE)
    await expect(fetchImpl('https://relay/v1/chat/completions', { method: 'POST', headers: { authorization: auth } })).rejects.toThrow(SpendLimitError)
    expect(sent.length).toBe(2)
    // plain requests pass untouched
    await fetchImpl('https://relay/v1/models')
    expect(sent.length).toBe(3)
    await expect(fetchImpl('https://relay/x', { headers: { authorization: 'Payment !!!' } })).rejects.toThrow(PaymentPolicyError)
  })

  describe('with the shared budget in sealed-agent (D-048)', () => {
    const charge = async (amount: bigint) =>
      header('charge', chargeRequest(amount.toString()), { type: 'transaction', signature: await signedTx([transfer(payee, amount)]) })
    const post = (auth: string) => ({ method: 'POST', headers: { authorization: auth } })

    it('reserves the charge plus its fee cap before sending and releases it as used', async () => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(2_000_000n)
      const order: string[] = []
      agent.onCall = (path) => order.push(path)
      const fetchImpl = paymentFirewall(async () => {
        order.push('relay')
        return new Response('{}', { status: 200 })
      }, policy, guard, agent.budget)
      await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_500n)))
      expect(order).toEqual(['/v1/spend/reserve', 'relay', '/v1/spend/release'])
      expect(agent.calls[0]!.body).toEqual({ amount: (1_500n + FEE).toString() })
      expect(agent.calls[1]!.body).toEqual({ reservationId: 'r1', used: (1_500n + FEE).toString() })
      expect(agent.state.used).toBe(1_500n + FEE)
      expect(agent.state.reservations.size).toBe(0)
      expect(guard.counters()).toMatchObject({ debited: (1_500n + FEE).toString(), chargeAmount: '1500' })
    })

    it('gives the reservation back (used 0) when the relay answers 402 or the request never left', async () => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(2_000_000n)
      let mode: 'payment' | 'pin' | 'reset' = 'payment'
      const fetchImpl = paymentFirewall(async () => {
        if (mode === 'pin') throw new RelayPinError('0x' + '01'.repeat(32), '0x' + '02'.repeat(32))
        if (mode === 'reset') throw new TypeError('socket hang up')
        return new Response(null, { status: 402 })
      }, policy, guard, agent.budget)
      await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))
      mode = 'pin'
      await expect(fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))).rejects.toThrow(/nothing was sent/)
      expect(agent.releases()).toEqual([0n, 0n])
      expect(agent.state.used).toBe(0n)
      expect(guard.counters().debited).toBe('0')
      // A failure after the credential may have left counts as spent in both caps.
      mode = 'reset'
      await expect(fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))).rejects.toThrow(/socket/)
      expect(agent.state.used).toBe(1_000n + FEE)
      expect(guard.counters().debited).toBe((1_000n + FEE).toString())
    })

    it('sends nothing when the shared budget refuses, although the local guard would allow it', async () => {
      // The agent holds back the next settlement's estimated fees: only 1000 is left for the payer.
      const agent = fakeAgentBudget({ budget: 2_000_000n, reservedForFees: 1_999_000n })
      const guard = new SpendGuard(2_000_000n)
      let sent = 0
      const fetchImpl = paymentFirewall(async () => {
        sent++
        return new Response('{}', { status: 200 })
      }, policy, guard, agent.budget)
      const refusal = await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n))).catch((e) => e)
      expect(refusal).toBeInstanceOf(SpendLimitError)
      expect(refusal).toMatchObject({ scope: 'shared', requested: 1_000n + FEE, remaining: 1_000n })
      expect(refusal.message).toMatch(/fee settlement has priority/)
      expect(sent).toBe(0)
      expect(guard.counters()).toMatchObject({ debited: '0', charges: 0 })
      // A payment that fits the shared remainder goes through.
      await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n - FEE)))
      expect(sent).toBe(1)
      expect(agent.state.used).toBe(1_000n)
    })

    it('refuses to pay while the shared budget is unavailable (fail closed)', async () => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(2_000_000n)
      let sent = 0
      const fetchImpl = paymentFirewall(async () => {
        sent++
        return new Response('{}', { status: 200 })
      }, policy, guard, agent.budget)
      agent.state.down = true
      await expect(fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))).rejects.toThrow(BudgetUnavailableError)
      agent.state.down = false
      agent.state.status = 503
      await expect(fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))).rejects.toThrow(/HTTP 503/)
      expect(sent).toBe(0)
      expect(guard.counters().debited).toBe('0')
    })

    it('a local refusal never reaches the shared budget, and vouchers reserve nothing', async () => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(1_000n)
      const fetchImpl = paymentFirewall(async () => new Response('{}', { status: 200 }), policy, guard, agent.budget)
      await expect(fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))).rejects.toMatchObject({ scope: 'local' })
      const request = { amount: '0.000001', unitType: 'usd_micro', currency: PATHUSD, recipient: payee, methodDetails: { chainId: 4217, escrowContract: ESCROW_PRECOMPILE } }
      const voucher = header('session', request, { action: 'voucher', channelId: '0x' + 'cd'.repeat(32), cumulativeAmount: '5', signature: '0x' })
      await fetchImpl('https://relay/v1/chat/completions', post(voucher))
      expect(agent.calls).toEqual([])
    })
  })

  describe('session bootstrap proof (review M1)', () => {
    const proof = (request: Record<string, unknown>) => header('charge', request, { type: 'proof', signature: `0x${'11'.repeat(65)}` })

    it('lets mppx\'s zero-amount proof through with no debit when chain, currency and recipient match', async () => {
      expect(inspectCredential(proof(chargeRequest('0')), policy, new Map()).debits).toEqual([])
      const guard = new SpendGuard(1_000n)
      const agent = fakeAgentBudget({ budget: 1_000n })
      const sent: string[] = []
      const fetchImpl = paymentFirewall(async (input) => (sent.push((input as Request).method), new Response(null, { status: 200 })), policy, guard, agent.budget)
      await fetchImpl('https://relay/v1/chat/completions', { method: 'HEAD', headers: { authorization: proof(chargeRequest('0')) } })
      expect(sent).toEqual(['HEAD'])
      expect(agent.calls).toEqual([])
      expect(guard.counters().debited).toBe('0')
    })

    it.each([
      ['a non-zero amount', chargeRequest('1'), /zero-amount/],
      ['another recipient', chargeRequest('0', '0x' + '11'.repeat(20)), /recipient/],
      ['another currency', { ...chargeRequest('0'), currency: '0x20c0000000000000000000000000000000000001' }, /currency/],
      ['another chain', { ...chargeRequest('0'), methodDetails: { chainId: 1 } }, /chain 1/],
    ])('refuses a proof for %s', (_name, request, message) => {
      expect(() => inspectCredential(proof(request), policy, new Map())).toThrow(message)
    })
  })

  describe('uncertain outcomes (402, an error without a receipt, a failure after sending)', () => {
    const charge = async (amount: bigint) =>
      header('charge', chargeRequest(amount.toString()), { type: 'transaction', signature: await signedTx([transfer(payee, amount)]) })
    const post = (auth: string) => ({ method: 'POST', headers: { authorization: auth } })

    it('gives a charge back when the relay failed before taking it (an error without a payment receipt)', async () => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(2_000_000n)
      let receipt = false
      const fetchImpl = paymentFirewall(
        async () => new Response('{"error":{"charged":false}}', { status: 503, headers: receipt ? { 'payment-receipt': 'r' } : {} }),
        policy,
        guard,
        agent.budget,
      )
      await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))
      expect(agent.releases()).toEqual([0n])
      expect(guard.counters().debited).toBe('0')
      // With a receipt the charge was taken: it stays counted (the payer answers 424).
      receipt = true
      await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))
      expect(agent.state.used).toBe(1_000n + FEE)
      expect(guard.counters().debited).toBe((1_000n + FEE).toString())
    })

    it.each([
      ['absent', 0n, '0'],
      ['reverted', FEE, FEE.toString()],
      ['landed', 1_000n + FEE, (1_000n + FEE).toString()],
      ['unknown', 1_000n + FEE, (1_000n + FEE).toString()],
    ] as const)('with a chain watcher, settles a 402 from the transaction outcome: %s', async (outcome, used, debited) => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(2_000_000n)
      const asked: { hash: string; validBefore?: number }[] = []
      const fetchImpl = paymentFirewall(async () => new Response(null, { status: 402 }), policy, guard, agent.budget, {
        watcher: { outcome: async (hash, validBefore) => (asked.push({ hash, validBefore }), outcome) },
      })
      await fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))
      await fetchImpl.idle()
      expect(asked).toHaveLength(1)
      expect(agent.releases()).toEqual([used])
      expect(guard.counters().debited).toBe(debited)
    })

    it('with a chain watcher, a failure after sending is settled from the chain too', async () => {
      const agent = fakeAgentBudget({ budget: 2_000_000n })
      const guard = new SpendGuard(2_000_000n)
      const fetchImpl = paymentFirewall(async () => Promise.reject(new TypeError('socket hang up')), policy, guard, agent.budget, {
        watcher: { outcome: async () => 'absent' },
      })
      await expect(fetchImpl('https://relay/v1/chat/completions', post(await charge(1_000n)))).rejects.toThrow(/socket/)
      await fetchImpl.idle()
      expect(agent.state.used).toBe(0n)
      expect(guard.counters().debited).toBe('0')
    })
  })

  it('journals a channel open before its credential leaves, then its vouchers and its close', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'payer-journal-'))
    const journal = new ChannelJournal(join(dir, 'channels.json'), () => 1_000)
    const guard = new SpendGuard(2_000_000n)
    const operator = payee as `0x${string}`
    const salt = `0x${'02'.repeat(32)}` as const
    const transaction = await signedTx([{ to: ESCROW_PRECOMPILE, data: encodeFunctionData({ abi: escrow, functionName: 'open', args: [payee as `0x${string}`, operator, PATHUSD, 300_000n, salt, payer.address] }) }])
    const descriptor = channelOf(transaction, payee as `0x${string}`, operator, salt)
    const channelId = channelIdOf(descriptor)
    const request = { amount: '0.000001', unitType: 'usd_micro', currency: PATHUSD, recipient: payee, methodDetails: { chainId: 4217, escrowContract: ESCROW_PRECOMPILE } }
    const seen: (string | undefined)[] = []
    const fetchImpl = paymentFirewall(async () => {
      seen.push(journal.get(channelId)?.status)
      return new Response(null, { status: 200 })
    }, policy, guard, undefined, { journal })
    const send = (payload: Record<string, unknown>) => fetchImpl('https://relay/v1/chat/completions', { method: 'POST', headers: { authorization: header('session', request, payload) } })
    await send({ action: 'open', channelId, transaction, descriptor, cumulativeAmount: '10', signature: '0x' })
    expect(seen).toEqual(['open'])
    await send({ action: 'voucher', channelId, cumulativeAmount: '500', signature: '0x' })
    expect(journal.get(channelId)).toMatchObject({ status: 'open', deposited: '300000', maxVoucher: '500', descriptor: { salt, payee } })
    // Persisted: a restarted payer finds the descriptor it needs for requestClose and withdraw.
    expect(new ChannelJournal(join(dir, 'channels.json')).get(channelId)?.descriptor.expiringNonceHash).toBe(descriptor.expiringNonceHash.toLowerCase())
    await send({ action: 'close', channelId, cumulativeAmount: '500', signature: '0x', closeSignature: '0x' })
    expect(journal.get(channelId)?.status).toBe('closed')
  })
})
