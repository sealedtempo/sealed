import { Session } from 'mppx/tempo'
import { type Account, type Client, encodeFunctionData, parseEventLogs } from 'viem'
import { prepareTransactionRequest, readContract, sendRawTransactionSync, signTransaction } from 'viem/actions'
import type { ChannelDescriptor, ChannelJournal, ChannelRecord } from './channel-journal.js'
import { ESCROW_PRECOMPILE } from './config.js'
import { feeCap } from './payment-firewall.js'
import { BudgetUnavailableError, type SpendBudget } from './shared-budget.js'
import { type SpendGuard, SpendLimitError } from './spend-guard.js'

const { escrowAbi } = Session.Precompile

export type ChannelState = { deposit: bigint; settled: bigint; closeRequestedAt: number }

export type RecoveryCall = 'requestClose' | 'withdraw'

export type PreparedRecovery = {
  /** Network fee cap the payer's account pays, in fee-token base units. */
  feeCap: bigint
  send(): Promise<{ status: 'success' | 'reverted'; closeRequestedAt?: number; refunded?: bigint }>
}

/** The escrow precompile as recovery needs it (TIP-1034, mppx 0.15.0 ABI). */
export interface EscrowChain {
  state(channelId: `0x${string}`): Promise<ChannelState>
  gracePeriod(): Promise<number>
  prepare(call: RecoveryCall, descriptor: ChannelDescriptor): Promise<PreparedRecovery>
}

/**
 * The escrow on a Tempo node, sending as the payer account (in access-key mode the access key
 * signs for the customer's root account, which is every channel's payer). Transactions use
 * expiring nonces, so they never take a protocol nonce the agent's fee settlement needs.
 */
export class ViemEscrowChain implements EscrowChain {
  private grace: number | undefined

  constructor(
    private readonly client: Client,
    private readonly account: Account,
    private readonly feeToken: `0x${string}`,
    /** Unix seconds the expiring nonce's validBefore counts from (wall time; tests that move the node's clock pass the chain's). */
    private readonly now: () => number | Promise<number> = () => Math.floor(Date.now() / 1000),
  ) {}

  async state(channelId: `0x${string}`): Promise<ChannelState> {
    const s = (await readContract(this.client, { address: ESCROW_PRECOMPILE, abi: escrowAbi, functionName: 'getChannelState', args: [channelId] })) as {
      deposit: bigint
      settled: bigint
      closeRequestedAt: number | bigint
    }
    return { deposit: s.deposit, settled: s.settled, closeRequestedAt: Number(s.closeRequestedAt) }
  }

  async gracePeriod(): Promise<number> {
    this.grace ??= Number(await readContract(this.client, { address: ESCROW_PRECOMPILE, abi: escrowAbi, functionName: 'CLOSE_GRACE_PERIOD' }))
    return this.grace
  }

  async prepare(call: RecoveryCall, descriptor: ChannelDescriptor): Promise<PreparedRecovery> {
    const data = encodeFunctionData({ abi: escrowAbi, functionName: call, args: [descriptor] as never })
    const prepared = await prepareTransactionRequest(this.client, {
      account: this.account,
      calls: [{ to: ESCROW_PRECOMPILE, data }],
      nonceKey: 'expiring',
      validBefore: (await this.now()) + 25,
      feeToken: this.feeToken,
    } as never)
    return {
      feeCap: feeCap(prepared as { gas?: bigint; maxFeePerGas?: bigint }),
      send: async () => {
        const serialized = await signTransaction(this.client, prepared as never)
        const receipt = await sendRawTransactionSync(this.client, { serializedTransaction: serialized as `0x${string}` })
        const events = parseEventLogs({ abi: escrowAbi, logs: receipt.logs }) as unknown as { eventName: string; args: Record<string, unknown> }[]
        const requested = events.find((e) => e.eventName === 'CloseRequested')
        const closed = events.find((e) => e.eventName === 'ChannelClosed')
        return {
          status: receipt.status,
          ...(requested ? { closeRequestedAt: Number(requested.args.closeGraceEnd) - (await this.gracePeriod()) } : {}),
          ...(closed ? { refunded: closed.args.refundedToPayer as bigint } : {}),
        }
      },
    }
  }
}

/**
 * `deferred` and `deferredAmount` (payments-8): channels whose last recovery attempt waited for budget, and the
 * deposit they still hold (deposit - settled).
 */
export type RecoveryCounters = { requestCloses: number; withdrawals: number; recovered: string; failures: number; deferred: number; deferredAmount: string }

export type ChannelRecoveryDeps = {
  journal: ChannelJournal
  chain: EscrowChain
  /** Channel ids the payer keeps using: the session channel and the one it would resume. */
  liveChannels: () => ReadonlySet<string> | Promise<ReadonlySet<string>>
  guard: SpendGuard
  budget?: SpendBudget
  now?: () => number
  /** A channel opened or used less than this long ago is left alone (its open may be in flight). Default 300 s. */
  minAgeSeconds?: number
  intervalSeconds?: number
  log?: (event: Record<string, unknown>) => void
}

/**
 * Takes back the deposits of channels the payer no longer uses (M1 of the payments review):
 * a channel the payer can no longer resume (lost session state, a relay that forgot it), a
 * channel rotated out whose cooperative close failed, a channel opened to an earlier attested
 * payee. For each such channel in the journal it sends the escrow's requestClose, then, once the
 * grace period (900 s on mainnet) has passed, withdraw, which returns everything the relay did
 * not settle to the payer. The relay's close supervisor settles the vouchers it holds during the
 * grace period, so the relay is paid what it earned.
 *
 * Both transactions are network fees the account pays itself, so they are budgeted like any
 * other debit (local guard and shared budget). The refund returns to the account but not to the
 * access-key limit, so no budget is given back for it. When the deposit at stake is larger than
 * the fee, the shared reservation says `purpose: recovery`, which the agent lets past its fee
 * priority by a small allowance (payments-8): otherwise a limit below the fee floor would keep the
 * deposit in escrow for good. A channel still waiting for budget is reported (`deferred`).
 */
export class ChannelRecovery {
  private timer: NodeJS.Timeout | undefined
  private running: Promise<void> | undefined
  private readonly counters: Omit<RecoveryCounters, 'deferred' | 'deferredAmount'> = { requestCloses: 0, withdrawals: 0, recovered: '0', failures: 0 }
  /** Channels whose last recovery attempt was deferred for lack of budget, and the deposit at stake. */
  private readonly deferred = new Map<string, bigint>()
  private readonly now: () => number

  constructor(private readonly deps: ChannelRecoveryDeps) {
    this.now = deps.now ?? (() => Math.floor(Date.now() / 1000))
  }

  start(): void {
    const every = (this.deps.intervalSeconds ?? 60) * 1000
    this.timer = setInterval(() => void this.sweep(), every)
    this.timer.unref?.()
    setTimeout(() => void this.sweep(), 5_000).unref?.()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
  }

  snapshot(): RecoveryCounters {
    const atStake = [...this.deferred.values()].reduce((a, b) => a + b, 0n)
    return { ...this.counters, deferred: this.deferred.size, deferredAmount: atStake.toString() }
  }

  /** One pass over the journal. Never throws; a pass already running is joined. */
  sweep(): Promise<void> {
    this.running ??= this.pass().finally(() => {
      this.running = undefined
    })
    return this.running
  }

  private async pass(): Promise<void> {
    const live = await this.deps.liveChannels()
    for (const record of this.deps.journal.all()) {
      if (record.status === 'closed') continue
      try {
        await this.recover(record, live)
      } catch (error) {
        this.counters.failures++
        this.deps.log?.({ event: 'channel_recovery_failed', channelId: record.channelId, detail: (error as Error).message?.slice(0, 200) })
      }
    }
  }

  private async recover(record: ChannelRecord, live: ReadonlySet<string>): Promise<void> {
    const { journal, chain } = this.deps
    const now = this.now()
    const minAge = this.deps.minAgeSeconds ?? 300
    const recent = now - Math.max(record.openedAt, record.lastUsedAt) < minAge
    // A channel still in use, or one a stream is still running on, is never closed from here.
    if (live.has(record.channelId) || (record.status === 'open' && recent)) return
    const state = await chain.state(record.channelId)
    if (state.deposit === 0n) {
      // Never opened (the open was refused or expired) or already closed or withdrawn.
      if (record.status === 'open' && recent) return
      journal.markClosed(record.channelId)
      this.deferred.delete(record.channelId)
      return
    }
    const atStake = state.deposit > state.settled ? state.deposit - state.settled : 0n
    if (state.closeRequestedAt > 0) {
      journal.markCloseRequested(record.channelId, state.closeRequestedAt)
      if (now < state.closeRequestedAt + (await chain.gracePeriod())) return
      const result = await this.send('withdraw', record, atStake)
      if (result?.status === 'success') {
        const refunded = result.refunded ?? state.deposit - state.settled
        journal.markClosed(record.channelId, refunded)
        this.counters.withdrawals++
        this.counters.recovered = (BigInt(this.counters.recovered) + refunded).toString()
        this.deps.log?.({ event: 'channel_withdrawn', channelId: record.channelId, refunded: refunded.toString() })
      }
      return
    }
    if (record.status === 'open') journal.retire(record.channelId, 'orphaned')
    const result = await this.send('requestClose', record, atStake)
    if (result?.status === 'success') {
      journal.markCloseRequested(record.channelId, result.closeRequestedAt ?? now)
      this.counters.requestCloses++
      this.deps.log?.({ event: 'channel_close_requested', channelId: record.channelId, deposit: state.deposit.toString(), settled: state.settled.toString() })
    }
  }

  /**
   * Sends one recovery transaction with its network fee reserved in both caps. `atStake` is what the channel still
   * holds for the payer; only when it is larger than the fee is the shared reservation a `recovery` one.
   */
  private async send(call: RecoveryCall, record: ChannelRecord, atStake: bigint) {
    const prepared = await this.deps.chain.prepare(call, record.descriptor)
    const fee = prepared.feeCap
    let release: (() => void) | undefined
    let shared: Awaited<ReturnType<SpendBudget['reserve']>> | undefined
    try {
      if (fee > 0n) {
        release = this.deps.guard.reserve(fee, 'fee')
        if (this.deps.budget) shared = await this.deps.budget.reserve(fee, atStake > fee ? 'recovery' : undefined)
      }
    } catch (error) {
      release?.()
      if (error instanceof SpendLimitError || error instanceof BudgetUnavailableError) {
        this.deferred.set(record.channelId, atStake)
        this.deps.log?.({ event: 'channel_recovery_deferred', channelId: record.channelId, call, atStake: atStake.toString(), detail: error.message.slice(0, 200) })
        return undefined
      }
      throw error
    }
    this.deferred.delete(record.channelId)
    try {
      const result = await prepared.send()
      if (shared) await this.deps.budget!.release(shared, fee)
      return result
    } catch (error) {
      // The transaction may have been included: its fee stays counted.
      if (shared) await this.deps.budget!.release(shared, fee)
      throw error
    }
  }
}
