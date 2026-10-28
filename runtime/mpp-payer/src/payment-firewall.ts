import { Credential } from 'mppx'
import { Session } from 'mppx/tempo'
import { decodeFunctionData, isAddressEqual, keccak256 } from 'viem'
import { Transaction } from 'viem/tempo'
import type { ChannelDescriptor, ChannelJournal } from './channel-journal.js'
import { ESCROW_PRECOMPILE } from './config.js'
import { wasNotSent } from './relay-transport.js'
import type { SharedReservation, SpendBudget } from './shared-budget.js'
import { type DebitKind, PaymentPolicyError, type SpendGuard } from './spend-guard.js'
import type { TxOutcome, TxWatcher } from './tx-watcher.js'

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

type Debit = { kind: DebitKind; amount: bigint; channelId?: string }

/** Attodollars per gas to FEE_TOKEN base units (6 decimals): fee = gas x price / 10^12 (Tempo fee units). */
const ATTO_PER_BASE_UNIT = 10n ** 12n

/** The signed Tempo transaction a credential carries (a pull-mode charge, a channel open or top-up). */
export type SignedPayment = { hash: `0x${string}`; validBefore?: number }

/** A channel open as the journal records it. */
export type OpenedChannel = { channelId: `0x${string}`; chainId: number; escrow: `0x${string}`; descriptor: ChannelDescriptor; deposit: bigint }

type Decoded = {
  credential: Credential.Credential<Record<string, unknown>>
  debits: Debit[]
  signed?: SignedPayment
  open?: OpenedChannel
}

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

type ParsedTx = {
  chainId?: number
  calls?: { to?: string; data?: `0x${string}`; value?: bigint }[]
  from?: string
  gas?: bigint
  maxFeePerGas?: bigint
  feePayerSignature?: unknown
  validBefore?: number
}

function parseTx(serialized: unknown, policy: FirewallPolicy, chainId: number) {
  if (typeof serialized !== 'string' || !serialized.startsWith('0x76'))
    throw new PaymentPolicyError('payment transaction is not a signed Tempo transaction')
  let tx: ParsedTx
  try {
    tx = Transaction.deserialize(serialized as `0x76${string}`) as ParsedTx
  } catch {
    throw new PaymentPolicyError('payment transaction cannot be decoded')
  }
  if (tx.chainId !== chainId) throw new PaymentPolicyError(`transaction chain ${tx.chainId} differs from challenge chain ${chainId}`)
  if (tx.from && !isAddressEqual(tx.from as `0x${string}`, policy.payerAddress))
    throw new PaymentPolicyError('transaction is not paid from the configured account')
  const calls = tx.calls ?? []
  if (calls.length === 0) throw new PaymentPolicyError('transaction has no calls')
  for (const call of calls) if (call.value && call.value !== 0n) throw new PaymentPolicyError('transaction carries native value')
  const validBefore = tx.validBefore !== undefined && Number(tx.validBefore) > 0 ? Number(tx.validBefore) : undefined
  return { tx, calls, fee: feeCap(tx), signed: { hash: keccak256(serialized as `0x${string}`), validBefore } satisfies SignedPayment }
}

/**
 * The most this transaction can cost the payer's account in network fees, in FEE_TOKEN base
 * units: gas x maxFeePerGas / 10^12, rounded up. Fees an account pays itself count against its
 * access-key spending limit, so they are budgeted like any other debit. A transaction that
 * names a fee payer (sponsored) costs the payer nothing.
 */
export function feeCap(tx: { gas?: bigint; maxFeePerGas?: bigint; feePayerSignature?: unknown }): bigint {
  if (tx.feePayerSignature !== undefined) return 0n
  const gas = tx.gas ?? 0n
  const price = tx.maxFeePerGas ?? 0n
  if (gas <= 0n || price <= 0n) return 0n
  return (gas * price + ATTO_PER_BASE_UNIT - 1n) / ATTO_PER_BASE_UNIT
}

function withFee(debits: Debit[], fee: bigint): Debit[] {
  return fee > 0n ? [...debits, { kind: 'fee', amount: fee }] : debits
}

function amountOf(value: unknown): bigint | undefined {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint') return undefined
  try {
    return BigInt(value)
  } catch {
    return undefined
  }
}

/**
 * The open payload's descriptor must be the channel the signed transaction opens: the escrow
 * computes the channel id from these fields, and recovery (requestClose, withdraw) needs them.
 */
function checkOpenDescriptor(
  raw: unknown,
  parsed: { tx: ParsedTx; args: readonly any[] },
  policy: FirewallPolicy,
  chainId: number,
  channelId: string,
): ChannelDescriptor {
  const d = raw as Partial<Record<keyof ChannelDescriptor, string>> | undefined
  const fields = ['payer', 'payee', 'operator', 'token', 'salt', 'authorizedSigner', 'expiringNonceHash'] as const
  if (!d || typeof d !== 'object' || fields.some((f) => typeof d[f] !== 'string'))
    throw new PaymentPolicyError('channel open carries no descriptor')
  const [payee, operator, token, , salt, authorizedSigner] = parsed.args
  const descriptor = d as ChannelDescriptor
  if (
    lower(descriptor.payer) !== lower(policy.payerAddress) ||
    lower(descriptor.payee) !== lower(payee) ||
    lower(descriptor.operator) !== lower(operator) ||
    lower(descriptor.token) !== lower(token) ||
    lower(descriptor.salt) !== lower(salt) ||
    lower(descriptor.authorizedSigner) !== lower(authorizedSigner)
  )
    throw new PaymentPolicyError('channel descriptor differs from the open call')
  const nonceHash = Session.Precompile.Channel.computeExpiringNonceHash(
    Session.Precompile.Channel.transactionForExpiringNonceHash({ transaction: parsed.tx as never }) as never,
    { sender: policy.payerAddress },
  )
  if (lower(nonceHash) !== lower(descriptor.expiringNonceHash)) throw new PaymentPolicyError('channel descriptor nonce hash differs from the open transaction')
  const id = Session.Precompile.Channel.computeId({ ...descriptor, chainId, escrow: ESCROW_PRECOMPILE } as never)
  if (lower(id) !== lower(channelId)) throw new PaymentPolicyError('channel id differs from the open descriptor')
  return descriptor
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
    if (payload.type === 'proof') {
      // mppx's session bootstrap answers a zero-amount charge challenge with a signed proof of
      // the payer address and no transaction, so the relay can hand back the open channel after
      // a restart. Chain, currency and recipient are checked above; nothing is debited.
      if (amountOf(request.amount) !== 0n) throw new PaymentPolicyError('a proof credential is allowed only for a zero-amount charge')
      return { credential, debits: [] }
    }
    if (payload.type !== 'transaction') throw new PaymentPolicyError(`charge payload ${String(payload.type)} is not allowed (pull mode only)`)
    const { calls, fee, signed } = parseTx(payload.signature, policy, chainId)
    let total = 0n
    for (const call of calls) {
      if (lower(call.to) !== policy.currency) throw new PaymentPolicyError('charge calls a contract other than the currency')
      const { functionName, args } = decodeCall(TIP20_ABI, call.data, 'charge')
      if (functionName !== 'transfer' && functionName !== 'transferWithMemo') throw new PaymentPolicyError('unexpected charge call')
      if (lower(args[0]) !== payee) throw new PaymentPolicyError('charge transfers to an address other than the payee')
      total += args[1]
    }
    if (String(total) !== String(request.amount)) throw new PaymentPolicyError('charge amount differs from the challenge')
    if (total <= 0n) throw new PaymentPolicyError('a transaction charge must move a positive amount')
    if (total > policy.maxCharge) throw new PaymentPolicyError(`charge ${total} exceeds the per-request cap ${policy.maxCharge}`)
    return { credential, debits: withFee([{ kind: 'charge', amount: total }], fee), signed }
  }

  if (challenge.intent !== 'session') throw new PaymentPolicyError(`intent ${challenge.intent} is not allowed`)
  const escrow = lower(request.methodDetails?.escrowContract ?? ESCROW_PRECOMPILE)
  if (escrow !== ESCROW_PRECOMPILE) throw new PaymentPolicyError(`escrow ${escrow} is not the TIP-1034 precompile`)
  const channelId = lower(payload.channelId)
  const action = payload.action
  if (action === 'open' || action === 'topUp') {
    const { tx, calls, fee, signed } = parseTx(payload.transaction, policy, chainId)
    let debit: Debit | undefined
    let open: OpenedChannel | undefined
    for (const call of calls) {
      if (lower(call.to) !== ESCROW_PRECOMPILE) throw new PaymentPolicyError('session transaction calls a contract other than the escrow')
      const decoded = decodeCall(ESCROW_ABI, call.data, 'escrow')
      if (debit) throw new PaymentPolicyError('session transaction carries more than one escrow call')
      if (decoded.functionName === 'open' && action === 'open') {
        const [openPayee, , token, deposit] = decoded.args
        if (lower(openPayee) !== payee || lower(token) !== policy.currency)
          throw new PaymentPolicyError('channel open names another payee or token')
        const descriptor = checkOpenDescriptor(payload.descriptor, { tx, args: decoded.args }, policy, chainId, channelId)
        debit = { kind: 'deposit', amount: deposit, channelId }
        open = { channelId: channelId as `0x${string}`, chainId, escrow: ESCROW_PRECOMPILE, descriptor, deposit }
      } else if (decoded.functionName === 'topUp' && action === 'topUp') {
        const [descriptor, additional] = decoded.args
        if (lower(descriptor.payee) !== payee || lower(descriptor.token) !== policy.currency)
          throw new PaymentPolicyError('top-up names another payee or token')
        debit = { kind: 'topUp', amount: additional, channelId }
      } else throw new PaymentPolicyError(`unexpected escrow call ${decoded.functionName} for ${action}`)
    }
    if (!debit) throw new PaymentPolicyError('session transaction has no escrow call')
    if (debit.amount <= 0n) throw new PaymentPolicyError(`refusing a non-positive ${debit.kind}`)
    const after = (deposits.get(channelId) ?? 0n) + debit.amount
    if (after > policy.maxDeposit) throw new PaymentPolicyError(`channel deposit ${after} would exceed the cap ${policy.maxDeposit}`)
    return { credential, debits: withFee([debit], fee), signed, open }
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

export type FirewallOptions = {
  /** Records every channel open before its credential leaves, for recovery (channel-recovery.ts). */
  journal?: ChannelJournal
  /**
   * Settles uncertain payments from the chain: a 402, an error answer without a payment
   * receipt, or a failure after the credential may have left. Without it a 402 and an error
   * without a receipt give the budget back at once, and a failure after sending counts as spent.
   */
  watcher?: TxWatcher
  log?: (event: Record<string, unknown>) => void
}

export type FirewalledFetch = FetchLike & {
  /** Resolves when every payment whose outcome was being checked onchain is settled (tests, shutdown). */
  idle(): Promise<void>
}

/**
 * A fetch for mppx clients that inspects every outgoing Payment credential and reserves what it
 * would debit before the credential leaves: first in the local spend guard (the second cap),
 * then in sealed-agent's shared daily budget (D-048).
 *
 * A credential counts as taken when the relay answers with a payment receipt, or without one
 * below 400. It was not taken when the request provably never left (pinned transport refusal).
 * The relay answers 402 when it did not accept a payment, and an error without a receipt when it
 * failed before taking a per-request charge (it settles the charge only after the upstream's
 * first byte). Those outcomes, and failures after the credential may have left, are uncertain
 * for credentials that carry a signed transaction: with a TxWatcher the reservation stays held
 * until the transaction's validity window has passed, then the chain decides (not included:
 * everything is given back; reverted: only the network fee stays; included: all of it stays).
 */
export function paymentFirewall(
  inner: FetchLike,
  policy: FirewallPolicy,
  guard: SpendGuard,
  budget?: SpendBudget,
  options: FirewallOptions = {},
): FirewalledFetch {
  const deposits = new Map<string, bigint>()
  const pending = new Set<Promise<void>>()
  const { journal, watcher } = options

  const noteDeposits = (debits: Debit[]) => {
    for (const d of debits) {
      if (!d.channelId) continue
      deposits.set(d.channelId, (deposits.get(d.channelId) ?? 0n) + d.amount)
      if (d.kind === 'topUp') journal?.noteTopUp(d.channelId, d.amount)
    }
  }

  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init)
    const header = paymentHeader(request.headers)
    if (!header) return inner(request)
    const { credential, debits, signed, open } = inspectCredential(header, policy, deposits)
    const total = debits.reduce((sum, d) => sum + d.amount, 0n)
    const fee = debits.filter((d) => d.kind === 'fee').reduce((sum, d) => sum + d.amount, 0n)
    const releaseLocal = debits.length > 0 ? guard.reserveAll(debits) : () => {}
    let shared: SharedReservation | undefined
    if (budget && total > 0n) {
      try {
        shared = await budget.reserve(total)
      } catch (error) {
        releaseLocal()
        throw error
      }
    }
    if (open) journal?.recordOpen(open)
    const notTaken = async () => {
      releaseLocal()
      if (shared) await budget!.release(shared, 0n)
    }
    const taken = async () => {
      if (shared) await budget!.release(shared, total)
    }
    /** The outcome depends on whether the signed transaction was included. */
    const uncertain = async (fallback: 'refund' | 'keep') => {
      if (!signed || !watcher) return fallback === 'refund' ? notTaken() : taken()
      const settle = (async () => {
        let outcome: TxOutcome = 'unknown'
        try {
          outcome = await watcher.outcome(signed.hash, signed.validBefore)
        } catch {}
        options.log?.({ event: 'payment_outcome', intent: credential.challenge.intent, outcome })
        if (outcome === 'absent') return notTaken()
        if (outcome === 'reverted') {
          releaseLocal((d) => d.kind === 'fee')
          if (shared) await budget!.release(shared, fee)
          return
        }
        if (outcome === 'landed') noteDeposits(debits)
        await taken()
      })()
      pending.add(settle)
      void settle.finally(() => pending.delete(settle))
    }

    let response: Response
    try {
      response = await inner(request)
    } catch (error) {
      // Refused before sending (for example a relay key that is not the attested one): nothing was spent.
      if (wasNotSent(error)) await notTaken()
      else await uncertain('keep')
      throw error
    }
    const receipt = response.headers.has('payment-receipt')
    if (response.status === 402 || (signed !== undefined && response.status >= 400 && !receipt)) {
      await uncertain('refund')
      return response
    }
    await taken()
    const payload = credential.payload
    const channelId = lower(payload.channelId)
    noteDeposits(debits)
    if (credential.challenge.intent === 'session' && (payload.action === 'voucher' || payload.action === 'open')) {
      const cumulative = BigInt(String(payload.cumulativeAmount ?? '0'))
      guard.noteVoucher(channelId, cumulative)
      journal?.noteVoucher(channelId, cumulative)
    }
    if (credential.challenge.intent === 'session' && payload.action === 'close' && response.ok) {
      const deposit = deposits.get(channelId) ?? 0n
      const captured = BigInt(String(payload.cumulativeAmount ?? '0'))
      // Local budget only: the refund returns to the account, not to its access-key limit, so
      // the shared budget keeps the deposit counted as used.
      if (deposit > captured) guard.refund(deposit - captured)
      deposits.delete(channelId)
      guard.forgetChannel(channelId)
      journal?.markClosed(channelId)
    }
    return response
  }
  return Object.assign(fetchImpl, {
    idle: async () => {
      while (pending.size > 0) await Promise.allSettled([...pending])
    },
  })
}
