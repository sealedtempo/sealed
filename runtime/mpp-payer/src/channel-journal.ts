import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** A TIP-1034 channel descriptor (mppx 0.15.0 escrow ABI): what requestClose and withdraw take. */
export type ChannelDescriptor = {
  payer: `0x${string}`
  payee: `0x${string}`
  operator: `0x${string}`
  token: `0x${string}`
  salt: `0x${string}`
  authorizedSigner: `0x${string}`
  expiringNonceHash: `0x${string}`
}

/**
 * open: in use or reusable. retired: the payer will not use it again (rotated, payee changed,
 * close failed, dropped by mppx) and recovers its deposit. closeRequested: requestClose landed,
 * withdraw is due after the escrow's grace period. closed: nothing left in escrow.
 */
export type ChannelStatus = 'open' | 'retired' | 'closeRequested' | 'closed'

export type ChannelRecord = {
  channelId: `0x${string}`
  chainId: number
  escrow: `0x${string}`
  descriptor: ChannelDescriptor
  /** Deposits sent for the channel (open plus top-ups), base units, decimal string. */
  deposited: string
  /** Highest cumulative voucher the payer signed for it, base units, decimal string. */
  maxVoucher: string
  /** Unix seconds. */
  openedAt: number
  lastUsedAt: number
  status: ChannelStatus
  reason?: string
  /** Onchain closeRequestedAt (unix seconds) once requestClose landed. */
  closeRequestedAt?: number
  /** What a withdraw or cooperative close returned to the payer, base units. */
  refunded?: string
}

const ID = /^0x[0-9a-f]{64}$/

function valid(record: unknown): record is ChannelRecord {
  const r = record as ChannelRecord
  return (
    typeof r === 'object' &&
    r !== null &&
    typeof r.channelId === 'string' &&
    ID.test(r.channelId) &&
    typeof r.descriptor === 'object' &&
    r.descriptor !== null &&
    typeof r.descriptor.payee === 'string' &&
    /^\d+$/.test(r.deposited ?? '') &&
    /^\d+$/.test(r.maxVoucher ?? '') &&
    ['open', 'retired', 'closeRequested', 'closed'].includes(r.status)
  )
}

/** Closed channels are kept this long (seconds) for the record, then pruned. */
const KEEP_CLOSED_SECONDS = 7 * 86_400

/**
 * Durable record of every payment channel the payer opened, written by the payment firewall
 * before an open credential leaves the payer. The deposit of a channel the payer can no longer
 * use (a restart that lost the session, a rotation whose cooperative close failed, a changed
 * relay payee) stays in escrow until someone calls requestClose and, after the grace period,
 * withdraw; ChannelRecovery does that from this journal. The chain is authoritative for amounts:
 * the journal only has to remember descriptors, which nothing onchain lists by payer.
 */
export class ChannelJournal {
  private readonly records = new Map<string, ChannelRecord>()

  constructor(
    private readonly path: string | undefined,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
    private readonly onError: (error: Error) => void = () => {},
  ) {
    if (!path) return
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as { channels?: unknown[] }
      for (const r of parsed.channels ?? []) if (valid(r)) this.records.set(r.channelId, r)
    } catch {
      // A missing or unreadable journal starts empty; the relay's bootstrap can still resume the open channel.
    }
  }

  get(channelId: string): ChannelRecord | undefined {
    const r = this.records.get(channelId.toLowerCase())
    return r ? { ...r, descriptor: { ...r.descriptor } } : undefined
  }

  all(): ChannelRecord[] {
    return [...this.records.values()].map((r) => ({ ...r, descriptor: { ...r.descriptor } }))
  }

  /** Records a channel open before its credential is sent; an existing record is kept. */
  recordOpen(entry: { channelId: string; chainId: number; escrow: string; descriptor: ChannelDescriptor; deposit: bigint }): void {
    const id = entry.channelId.toLowerCase() as `0x${string}`
    if (this.records.has(id)) return
    const now = this.now()
    this.records.set(id, {
      channelId: id,
      chainId: entry.chainId,
      escrow: entry.escrow.toLowerCase() as `0x${string}`,
      descriptor: lowerDescriptor(entry.descriptor),
      deposited: entry.deposit.toString(),
      maxVoucher: '0',
      openedAt: now,
      lastUsedAt: now,
      status: 'open',
    })
    this.save()
  }

  noteTopUp(channelId: string, amount: bigint): void {
    this.patch(channelId, (r) => ({ deposited: (BigInt(r.deposited) + amount).toString(), lastUsedAt: this.now() }))
  }

  noteVoucher(channelId: string, cumulative: bigint): void {
    this.patch(channelId, (r) => ({ maxVoucher: (cumulative > BigInt(r.maxVoucher) ? cumulative : BigInt(r.maxVoucher)).toString(), lastUsedAt: this.now() }))
  }

  /** The payer will not use this channel again; recovery takes its deposit back. */
  retire(channelId: string, reason: string): void {
    this.patch(channelId, (r) => (r.status === 'open' ? { status: 'retired', reason } : {}))
  }

  markCloseRequested(channelId: string, closeRequestedAt: number): void {
    this.patch(channelId, (r) => (r.status === 'closed' ? {} : { status: 'closeRequested', closeRequestedAt }))
  }

  markClosed(channelId: string, refunded?: bigint): void {
    this.patch(channelId, () => ({ status: 'closed', lastUsedAt: this.now(), ...(refunded !== undefined ? { refunded: refunded.toString() } : {}) }))
  }

  private patch(channelId: string, change: (r: ChannelRecord) => Partial<ChannelRecord>): void {
    const id = channelId.toLowerCase()
    const r = this.records.get(id)
    if (!r) return
    const next = { ...r, ...change(r) }
    if (JSON.stringify(next) === JSON.stringify(r)) return
    this.records.set(id, next)
    this.save()
  }

  private save(): void {
    const now = this.now()
    for (const [id, r] of this.records) if (r.status === 'closed' && now - r.lastUsedAt > KEEP_CLOSED_SECONDS) this.records.delete(id)
    if (!this.path) return
    try {
      mkdirSync(dirname(this.path), { recursive: true })
      const tmp = `${this.path}.tmp`
      writeFileSync(tmp, JSON.stringify({ schema: 'sealed-payer-channels/v1', channels: [...this.records.values()] }), { mode: 0o600 })
      renameSync(tmp, this.path)
    } catch (error) {
      this.onError(error as Error)
    }
  }
}

function lowerDescriptor(d: ChannelDescriptor): ChannelDescriptor {
  return {
    payer: d.payer.toLowerCase() as `0x${string}`,
    payee: d.payee.toLowerCase() as `0x${string}`,
    operator: d.operator.toLowerCase() as `0x${string}`,
    token: d.token.toLowerCase() as `0x${string}`,
    salt: d.salt.toLowerCase() as `0x${string}`,
    authorizedSigner: d.authorizedSigner.toLowerCase() as `0x${string}`,
    expiringNonceHash: d.expiringNonceHash.toLowerCase() as `0x${string}`,
  }
}

/**
 * A string key-value file for mppx's `createJsonChannelStore`, so the payer's session channel
 * survives a restart and is resumed instead of opened again (a new open would put another
 * deposit against the day's access-key limit).
 */
export class FileKv {
  private readonly values = new Map<string, string>()

  constructor(
    private readonly path: string | undefined,
    private readonly onError: (error: Error) => void = () => {},
  ) {
    if (!path) return
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
      for (const [k, v] of Object.entries(parsed)) if (typeof v === 'string') this.values.set(k, v)
    } catch {
      // starts empty
    }
  }

  get(key: string): string | undefined {
    return this.values.get(key)
  }

  set(key: string, value: string): void {
    this.values.set(key, value)
    this.save()
  }

  delete(key: string): void {
    if (this.values.delete(key)) this.save()
  }

  keys(): string[] {
    return [...this.values.keys()]
  }

  private save(): void {
    if (!this.path) return
    try {
      mkdirSync(dirname(this.path), { recursive: true })
      const tmp = `${this.path}.tmp`
      writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.values)), { mode: 0o600 })
      renameSync(tmp, this.path)
    } catch (error) {
      this.onError(error as Error)
    }
  }
}
