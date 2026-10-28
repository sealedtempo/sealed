import { Credential } from 'mppx'
import { decodeFunctionData, isAddressEqual } from 'viem'
import { Transaction } from 'viem/tempo'
import { ESCROW_PRECOMPILE } from './config.js'
import { PaymentPolicyError, type SpendGuard } from './spend-guard.js'

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

const TIP20_ABI = [
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ type: 'bool' }] },
  {
    type: 'function',
    name: 'transferWithMemo',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'memo', type: 'bytes32' }],
    outputs: [],
  },
] as const

const DESCRIPTOR = {
  name: 'descriptor',
  type: 'tuple',
  components: [
    { name: 'payer', type: 'address' },
    { name: 'payee', type: 'address' },
    { name: 'operator', type: 'address' },
    { name: 'token', type: 'address' },
    { name: 'salt', type: 'bytes32' },
    { name: 'authorizedSigner', type: 'address' },
    { name: 'expiringNonceHash', type: 'bytes32' },
  ],
} as const

/** TIP-1034 escrow precompile functions that move the payer's tokens (mppx 0.15.0 escrow ABI). */
const ESCROW_ABI = [
  {
    type: 'function',
    name: 'open',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'payee', type: 'address' },
      { name: 'operator', type: 'address' },
      { name: 'token', type: 'address' },
      { name: 'deposit', type: 'uint96' },
      { name: 'salt', type: 'bytes32' },
      { name: 'authorizedSigner', type: 'address' },
    ],
    outputs: [{ name: 'channelId', type: 'bytes32' }],
  },
  { type: 'function', name: 'topUp', stateMutability: 'nonpayable', inputs: [DESCRIPTOR, { name: 'additionalDeposit', type: 'uint96' }], outputs: [] },
] as const

export type FirewallPolicy = {
  /** Account the customer's money leaves from (the root account in access-key mode). */
  payerAddress: `0x${string}`
  currency: `0x${string}`
  allowedChainIds: readonly number[]
  maxCharge: bigint
  maxDeposit: bigint
  /** The relay payee proven by attestation; undefined means no payment may be made. */
  expectedPayee: () => `0x${string}` | undefined
}

type Debit = { kind: 'charge' | 'deposit' | 'topUp'; amount: bigint; channelId?: string }

type Decoded = { credential: Credential.Credential<Record<string, unknown>>; debits: Debit[] }

function lower(value: unknown): string {
  return typeof value === 'string' ? value.toLowerCase() : ''
}

function paymentHeader(headers: Headers): string | undefined {
  for (const name of ['authorization', 'payment-authorization']) {
    const value = headers.get(name)
    if (value && /^Payment\s+/i.test(value)) return value
  }
  return undefined
}

function decodeCall<const abi extends readonly unknown[]>(abi: abi, data: `0x${string}` | undefined, what: string) {
  try {
    return decodeFunctionData({ abi: abi as never, data: data ?? '0x' }) as unknown as { functionName: string; args: readonly any[] }
  } catch {
    throw new PaymentPolicyError(`unexpected ${what} call`)
  }
}

function parseTx(serialized: unknown, policy: FirewallPolicy, chainId: number) {
  if (typeof serialized !== 'string' || !serialized.startsWith('0x76'))
    throw new PaymentPolicyError('payment transaction is not a signed Tempo transaction')
  const tx = Transaction.deserialize(serialized as `0x76${string}`) as {
    chainId?: number
    calls?: { to?: string; data?: `0x${string}`; value?: bigint }[]
    from?: string
  }
  if (tx.chainId !== chainId) throw new PaymentPolicyError(`transaction chain ${tx.chainId} differs from challenge chain ${chainId}`)
  if (tx.from && !isAddressEqual(tx.from as `0x${string}`, policy.payerAddress))
    throw new PaymentPolicyError('transaction is not paid from the configured account')
  const calls = tx.calls ?? []
  if (calls.length === 0) throw new PaymentPolicyError('transaction has no calls')
  for (const call of calls) if (call.value && call.value !== 0n) throw new PaymentPolicyError('transaction carries native value')
  return calls
}

/**
 * Decodes a Payment credential and computes exactly what it would debit, refusing anything
 * outside policy: wrong chain, currency or payee, a non-canonical escrow, unexpected calls,
 * caps exceeded. Throws PaymentPolicyError.
 */
export function inspectCredential(header: string, policy: FirewallPolicy, deposits: Map<string, bigint>): Decoded {
  let credential: Credential.Credential<Record<string, unknown>>
  try {
    credential = Credential.deserialize<Record<string, unknown>>(header)
  } catch {
    throw new PaymentPolicyError('malformed payment credential')
  }
  const challenge = credential.challenge as { method: string; intent: string; request: Record<string, any> }
  if (challenge.method !== 'tempo') throw new PaymentPolicyError(`payment method ${challenge.method} is not allowed`)
  const request = challenge.request ?? {}
  const chainId = Number(request.methodDetails?.chainId ?? request.chainId)
  if (!policy.allowedChainIds.includes(chainId)) throw new PaymentPolicyError(`chain ${chainId} is not allowed`)
  if (lower(request.currency) !== policy.currency) throw new PaymentPolicyError(`currency ${request.currency} is not allowed`)
  const payee = policy.expectedPayee()
  if (!payee) throw new PaymentPolicyError('relay payee unknown: relay attestation has not passed')
  if (lower(request.recipient) !== payee) throw new PaymentPolicyError(`recipient ${request.recipient} is not the attested relay payee`)

  const payload = credential.payload
  if (challenge.intent === 'charge') {
    if (payload.type !== 'transaction') throw new PaymentPolicyError(`charge payload ${String(payload.type)} is not allowed (pull mode only)`)
    const calls = parseTx(payload.signature, policy, chainId)
    let total = 0n
    for (const call of calls) {
      if (lower(call.to) !== policy.currency) throw new PaymentPolicyError('charge calls a contract other than the currency')
      const { functionName, args } = decodeCall(TIP20_ABI, call.data, 'charge')
      if (functionName !== 'transfer' && functionName !== 'transferWithMemo') throw new PaymentPolicyError('unexpected charge call')
      if (lower(args[0]) !== payee) throw new PaymentPolicyError('charge transfers to an address other than the payee')
      total += args[1]
    }
    if (String(total) !== String(request.amount)) throw new PaymentPolicyError('charge amount differs from the challenge')
    if (total > policy.maxCharge) throw new PaymentPolicyError(`charge ${total} exceeds the per-request cap ${policy.maxCharge}`)
    return { credential, debits: [{ kind: 'charge', amount: total }] }
  }

  if (challenge.intent !== 'session') throw new PaymentPolicyError(`intent ${challenge.intent} is not allowed`)
  const escrow = lower(request.methodDetails?.escrowContract ?? ESCROW_PRECOMPILE)
  if (escrow !== ESCROW_PRECOMPILE) throw new PaymentPolicyError(`escrow ${escrow} is not the TIP-1034 precompile`)
  const channelId = lower(payload.channelId)
  const action = payload.action
  if (action === 'open' || action === 'topUp') {
    const calls = parseTx(payload.transaction, policy, chainId)
    let debit: Debit | undefined
    for (const call of calls) {
      if (lower(call.to) !== ESCROW_PRECOMPILE) throw new PaymentPolicyError('session transaction calls a contract other than the escrow')
      const decoded = decodeCall(ESCROW_ABI, call.data, 'escrow')
      if (debit) throw new PaymentPolicyError('session transaction carries more than one escrow call')
      if (decoded.functionName === 'open' && action === 'open') {
        const [openPayee, , token, deposit] = decoded.args
        if (lower(openPayee) !== payee || lower(token) !== policy.currency)
          throw new PaymentPolicyError('channel open names another payee or token')
        debit = { kind: 'deposit', amount: deposit, channelId }
      } else if (decoded.functionName === 'topUp' && action === 'topUp') {
        const [descriptor, additional] = decoded.args
        if (lower(descriptor.payee) !== payee || lower(descriptor.token) !== policy.currency)
          throw new PaymentPolicyError('top-up names another payee or token')
        debit = { kind: 'topUp', amount: additional, channelId }
      } else throw new PaymentPolicyError(`unexpected escrow call ${decoded.functionName} for ${action}`)
    }
    if (!debit) throw new PaymentPolicyError('session transaction has no escrow call')
    const after = (deposits.get(channelId) ?? 0n) + debit.amount
    if (after > policy.maxDeposit) throw new PaymentPolicyError(`channel deposit ${after} would exceed the cap ${policy.maxDeposit}`)
    return { credential, debits: [debit] }
  }
  if (action === 'voucher' || action === 'close') {
    const cumulative = BigInt(String(payload.cumulativeAmount ?? '0'))
    const deposit = deposits.get(channelId)
    if (cumulative > policy.maxDeposit || (deposit !== undefined && cumulative > deposit))
      throw new PaymentPolicyError(`voucher ${cumulative} exceeds the channel deposit`)
    return { credential, debits: [] }
  }
  throw new PaymentPolicyError(`session action ${String(action)} is not allowed`)
}

/**
 * A fetch for mppx clients that inspects every outgoing Payment credential, reserves the
 * debit in the spend guard before the credential leaves, and releases it if the relay
 * answers 402 (payment not accepted).
 */
export function paymentFirewall(inner: FetchLike, policy: FirewallPolicy, guard: SpendGuard): FetchLike {
  const deposits = new Map<string, bigint>()
  return async (input, init) => {
    const request = new Request(input, init)
    const header = paymentHeader(request.headers)
    if (!header) return inner(request)
    const { credential, debits } = inspectCredential(header, policy, deposits)
    const releases = debits.map((d) => guard.reserve(d.amount, d.kind))
    // If the request throws, the credential may have been delivered, so the reservation is kept.
    const response = await inner(request)
    if (response.status === 402) {
      for (const release of releases) release()
      return response
    }
    const payload = credential.payload
    const channelId = lower(payload.channelId)
    for (const d of debits) if (d.channelId) deposits.set(d.channelId, (deposits.get(d.channelId) ?? 0n) + d.amount)
    if (credential.challenge.intent === 'session' && (payload.action === 'voucher' || payload.action === 'open'))
      guard.noteVoucher(channelId, BigInt(String(payload.cumulativeAmount ?? '0')))
    if (credential.challenge.intent === 'session' && payload.action === 'close' && response.ok) {
      const deposit = deposits.get(channelId) ?? 0n
      const captured = BigInt(String(payload.cumulativeAmount ?? '0'))
      if (deposit > captured) guard.refund(deposit - captured)
      deposits.delete(channelId)
      guard.forgetChannel(channelId)
    }
    return response
  }
}
