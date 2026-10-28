import { Challenge, Credential } from 'mppx'
import { encodeFunctionData } from 'viem'
import { generatePrivateKey } from 'viem/accounts'
import { Account, Transaction } from 'viem/tempo'
import { describe, expect, it } from 'vitest'
import { ESCROW_PRECOMPILE, PATHUSD } from '../src/config.js'
import { type FirewallPolicy, inspectCredential, paymentFirewall } from '../src/payment-firewall.js'
import { PaymentPolicyError, SpendGuard, SpendLimitError } from '../src/spend-guard.js'

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

async function signedTx(calls: { to: `0x${string}`; data: `0x${string}` }[], chainId = 4217) {
  return payer.signTransaction(
    { type: 'tempo', chainId, calls, nonce: 0, gas: 300_000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, feeToken: PATHUSD } as never,
    { serializer: Transaction.serialize } as never,
  )
}

function header(intent: 'charge' | 'session', request: Record<string, unknown>, payload: Record<string, unknown>) {
  const challenge = Challenge.from({ id: 'test-challenge', realm: 'relay.test', method: 'tempo', intent, request } as never)
  return Credential.serialize(Credential.from({ challenge, payload } as never))
}

const chargeRequest = (amount: string, recipient = payee) => ({ amount, currency: PATHUSD, recipient, methodDetails: { chainId: 4217 } })
const transfer = (to: string, amount: bigint) =>
  ({ to: PATHUSD, data: encodeFunctionData({ abi: tip20, functionName: 'transferWithMemo', args: [to as `0x${string}`, amount, `0x${'00'.repeat(32)}`] }) }) as const

describe('payment firewall', () => {
  it('accepts a charge that pays exactly the attested payee in pathUSD', async () => {
    const tx = await signedTx([transfer(payee, 1234n)])
    const { debits } = inspectCredential(header('charge', chargeRequest('1234'), { type: 'transaction', signature: tx }), policy, new Map())
    expect(debits).toEqual([{ kind: 'charge', amount: 1234n }])
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
    const open = (deposit: bigint, to: `0x${string}` = payee as `0x${string}`) =>
      signedTx([{ to: ESCROW_PRECOMPILE, data: encodeFunctionData({ abi: escrow, functionName: 'open', args: [to, payee as `0x${string}`, PATHUSD, deposit, `0x${'00'.repeat(32)}`, payer.address] }) }])
    const request = { amount: '0.000001', unitType: 'usd_micro', currency: PATHUSD, recipient: payee, methodDetails: { chainId: 4217, escrowContract: ESCROW_PRECOMPILE } }
    const ok = header('session', request, { action: 'open', channelId: '0x' + 'cd'.repeat(32), transaction: await open(400_000n), cumulativeAmount: '10', signature: '0x' })
    expect(inspectCredential(ok, policy, new Map()).debits).toEqual([{ kind: 'deposit', amount: 400_000n, channelId: '0x' + 'cd'.repeat(32) }])
    const big = header('session', request, { action: 'open', channelId: '0x' + 'cd'.repeat(32), transaction: await open(600_000n), cumulativeAmount: '0', signature: '0x' })
    expect(() => inspectCredential(big, policy, new Map())).toThrow(/cap/)
    const elsewhere = header('session', request, { action: 'open', channelId: '0x' + 'cd'.repeat(32), transaction: await open(1n, ('0x' + '11'.repeat(20)) as `0x${string}`), cumulativeAmount: '0', signature: '0x' })
    expect(() => inspectCredential(elsewhere, policy, new Map())).toThrow(/another payee/)
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
    expect(guard.remaining()).toBe(500n)
    await expect(fetchImpl('https://relay/v1/chat/completions', { method: 'POST', headers: { authorization: auth } })).rejects.toThrow(SpendLimitError)
    expect(sent.length).toBe(2)
    // plain requests pass untouched
    await fetchImpl('https://relay/v1/models')
    expect(sent.length).toBe(3)
    await expect(fetchImpl('https://relay/x', { headers: { authorization: 'Payment !!!' } })).rejects.toThrow(PaymentPolicyError)
  })
})
