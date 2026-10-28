/** What became of a signed payment transaction the relay may or may not have broadcast. */
export type TxOutcome = 'landed' | 'reverted' | 'absent' | 'unknown'

export interface TxWatcher {
  /** Waits until the transaction can no longer be included (validBefore), then reads its receipt. */
  outcome(hash: `0x${string}`, validBefore: number | undefined): Promise<TxOutcome>
}

type ReceiptReader = (hash: `0x${string}`) => Promise<{ status: 'success' | 'reverted' } | undefined>

/**
 * Decides uncertain payments from the chain. mppx signs pull-mode charges and channel opens as
 * expiring-nonce Tempo transactions (validBefore about 25 s ahead), so once validBefore has
 * passed a transaction without a receipt can never be included. Transactions without validBefore
 * stay 'unknown' and their debit stays counted.
 */
export class ChainTxWatcher implements TxWatcher {
  constructor(
    private readonly deps: {
      receipt: ReceiptReader
      now?: () => number
      sleep?: (ms: number) => Promise<void>
      /** Seconds after validBefore before the receipt is read (block inclusion lag). Default 3. */
      settleSeconds?: number
      /** Receipt reads before giving up as 'unknown'. Default 5, 5 s apart. */
      attempts?: number
    },
  ) {}

  async outcome(hash: `0x${string}`, validBefore: number | undefined): Promise<TxOutcome> {
    if (validBefore === undefined) return 'unknown'
    const now = this.deps.now ?? (() => Date.now() / 1000)
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms).unref?.()))
    const wait = (validBefore + (this.deps.settleSeconds ?? 3) - now()) * 1000
    if (wait > 0) await sleep(wait)
    const attempts = this.deps.attempts ?? 5
    for (let i = 0; i < attempts; i++) {
      try {
        const receipt = await this.deps.receipt(hash)
        if (receipt) return receipt.status === 'success' ? 'landed' : 'reverted'
        return 'absent'
      } catch {
        if (i < attempts - 1) await sleep(5_000)
      }
    }
    return 'unknown'
  }
}

/** viem's getTransactionReceipt, with "not found" as undefined. */
export function receiptReader(client: { getTransactionReceipt(args: { hash: `0x${string}` }): Promise<{ status: 'success' | 'reverted' }> }): ReceiptReader {
  return async (hash) => {
    try {
      const receipt = await client.getTransactionReceipt({ hash })
      return { status: receipt.status }
    } catch (error) {
      const name = (error as { name?: string }).name ?? ''
      if (name === 'TransactionReceiptNotFoundError' || /could not be found/i.test((error as Error).message ?? '')) return undefined
      throw error
    }
  }
}
