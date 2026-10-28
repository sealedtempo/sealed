import { Session } from 'mppx/tempo'
import {
  type Hex,
  type Log,
  createClient,
  custom,
  decodeFunctionData,
  encodeEventTopics,
  encodeFunctionResult,
  http,
  publicActions,
  walletActions,
  encodeAbiParameters,
} from 'viem'
import { tempo as tempoChain } from 'viem/chains'
import { Transaction, tempoActions } from 'viem/tempo'
import { PATHUSD } from './anvil.js'

const { escrowAbi, Channel } = Session.Precompile

/** The TIP-1034 escrow precompile address (D-027). */
export const ESCROW = '0x4d50500000000000000000000000000000000000' as const

type Descriptor = {
  payer: Hex
  payee: Hex
  operator: Hex
  token: Hex
  salt: Hex
  authorizedSigner: Hex
  expiringNonceHash: Hex
}

export type EmulatedChannel = { descriptor: Descriptor; deposit: bigint; settled: bigint; closeRequestedAt: number; closed: boolean }

export type EscrowEvent = { name: string; channelId: Hex; args: Record<string, unknown> }

const lower = (a: string) => a.toLowerCase()

/**
 * A local Tempo node whose TIP-1034 escrow precompile is emulated in the RPC layer: Foundry
 * 1.7.1's anvil (hardfork T4) has no code at 0x4d505..., so every transaction is still signed,
 * fee-charged and mined by anvil (calls to the empty address succeed), while this layer applies
 * the escrow semantics, answers the escrow's view calls and adds its events to receipts.
 * Tokens do not move into or out of the emulated escrow; channel state is bookkeeping only.
 */
export function emulatedEscrowNode(rpcUrl: string, chainId = 4217) {
  const chain = tempoChain.extend({ feeToken: PATHUSD })
  const base = http(rpcUrl)({ chain })
  const channels = new Map<Hex, EmulatedChannel>()
  const pendingLogs = new Map<string, { address: Hex; topics: Hex[]; data: Hex }[]>()
  const events: EscrowEvent[] = []

  const stateTuple = (c: EmulatedChannel | undefined) =>
    c && !c.closed
      ? { settled: c.settled, deposit: c.deposit, closeRequestedAt: c.closeRequestedAt }
      : { settled: 0n, deposit: 0n, closeRequestedAt: 0 }

  const emit = (name: string, channelId: Hex, args: Record<string, unknown>) => {
    events.push({ name, channelId, args })
    const event = (escrowAbi as readonly { type: string; name?: string; inputs?: readonly { name: string; type: string; indexed?: boolean }[] }[]).find(
      (e) => e.type === 'event' && e.name === name,
    )!
    const topics = (encodeEventTopics as (p: unknown) => Hex[])({ abi: escrowAbi, eventName: name, args: { channelId, ...args } })
    const data = event.inputs!.filter((i) => !i.indexed)
    return {
      address: ESCROW as Hex,
      topics,
      data: encodeAbiParameters(data as never, data.map((i) => args[i.name]) as never),
    }
  }

  function apply(raw: Hex): { address: Hex; topics: Hex[]; data: Hex }[] {
    const tx = Transaction.deserialize(raw as `0x76${string}`) as unknown as { from?: Hex; calls?: { to?: Hex; data?: Hex }[] }
    const logs: { address: Hex; topics: Hex[]; data: Hex }[] = []
    for (const call of tx.calls ?? []) {
      if (!call.to || lower(call.to) !== ESCROW || !call.data) continue
      const { functionName, args } = decodeFunctionData({ abi: escrowAbi as never, data: call.data }) as { functionName: string; args: any[] }
      if (functionName === 'open') {
        const [payee, operator, token, deposit, salt, authorizedSigner] = args
        const payer = tx.from!
        const expiringNonceHash = Channel.computeExpiringNonceHash(tx as never, { sender: payer })
        const descriptor: Descriptor = { payer, payee, operator, token, salt, authorizedSigner, expiringNonceHash }
        const channelId = Channel.computeId({ ...descriptor, chainId, escrow: ESCROW }) as Hex
        channels.set(lower(channelId) as Hex, { descriptor, deposit, settled: 0n, closeRequestedAt: 0, closed: false })
        logs.push(emit('ChannelOpened', channelId, { payer, payee, operator, token, authorizedSigner, salt, expiringNonceHash, deposit }))
        continue
      }
      const descriptor = args[0] as Descriptor
      const channelId = Channel.computeId({ ...descriptor, chainId, escrow: ESCROW }) as Hex
      const channel = channels.get(lower(channelId) as Hex)
      if (!channel || channel.closed) throw new Error(`emulated escrow: ${functionName} on unknown channel ${channelId}`)
      const who = { payer: descriptor.payer, payee: descriptor.payee }
      if (functionName === 'topUp') {
        channel.deposit += args[1] as bigint
        logs.push(emit('TopUp', channelId, { ...who, additionalDeposit: args[1], newDeposit: channel.deposit }))
      } else if (functionName === 'settle') {
        const cumulative = args[1] as bigint
        if (cumulative > channel.deposit) throw new Error('emulated escrow: settle above deposit')
        const delta = cumulative - channel.settled
        channel.settled = cumulative
        logs.push(emit('Settled', channelId, { ...who, cumulativeAmount: cumulative, deltaPaid: delta, newSettled: cumulative }))
      } else if (functionName === 'close') {
        const capture = args[2] as bigint
        const settledToPayee = capture > channel.settled ? capture - channel.settled : 0n
        const refundedToPayer = channel.deposit - (capture > channel.settled ? capture : channel.settled)
        channel.settled = capture > channel.settled ? capture : channel.settled
        channel.closed = true
        logs.push(emit('ChannelClosed', channelId, { ...who, settledToPayee, refundedToPayer }))
      } else if (functionName === 'requestClose') {
        channel.closeRequestedAt = Math.floor(Date.now() / 1000)
        logs.push(emit('CloseRequested', channelId, { ...who, closeGraceEnd: BigInt(channel.closeRequestedAt + 900) }))
      } else if (functionName === 'withdraw') {
        const refundedToPayer = channel.deposit - channel.settled
        channel.closed = true
        logs.push(emit('ChannelClosed', channelId, { ...who, settledToPayee: 0n, refundedToPayer }))
      } else throw new Error(`emulated escrow: ${functionName} not supported`)
    }
    return logs
  }

  function viewCall(data: Hex): Hex {
    const { functionName, args } = decodeFunctionData({ abi: escrowAbi as never, data }) as { functionName: string; args: any[] }
    const result = (value: unknown) => (encodeFunctionResult as (p: unknown) => Hex)({ abi: escrowAbi, functionName, result: value })
    switch (functionName) {
      case 'getChannel': {
        const descriptor = args[0] as Descriptor
        const id = Channel.computeId({ ...descriptor, chainId, escrow: ESCROW }) as Hex
        return result({ descriptor, state: stateTuple(channels.get(lower(id) as Hex)) })
      }
      case 'getChannelState':
        return result(stateTuple(channels.get(lower(args[0]) as Hex)))
      case 'getChannelStatesBatch':
        return result((args[0] as Hex[]).map((id) => stateTuple(channels.get(lower(id) as Hex))))
      case 'computeChannelId':
        return result(Channel.computeId({ payer: args[0], payee: args[1], operator: args[2], token: args[3], salt: args[4], authorizedSigner: args[5], expiringNonceHash: args[6], chainId, escrow: ESCROW }))
      case 'CLOSE_GRACE_PERIOD':
        return result(900n)
      default:
        throw new Error(`emulated escrow: view ${functionName} not supported`)
    }
  }

  const withLogs = (receipt: Record<string, any> | null) => {
    if (!receipt) return receipt
    const extra = pendingLogs.get(lower(receipt.transactionHash))
    if (!extra || receipt.status !== '0x1') return receipt
    const start = receipt.logs?.length ?? 0
    const logs = extra.map((l, i) => ({
      ...l,
      blockHash: receipt.blockHash,
      blockNumber: receipt.blockNumber,
      transactionHash: receipt.transactionHash,
      transactionIndex: receipt.transactionIndex,
      logIndex: `0x${(start + i).toString(16)}`,
      removed: false,
    })) as unknown as Log[]
    return { ...receipt, logs: [...(receipt.logs ?? []), ...logs] }
  }

  const transport = custom({
    async request({ method, params }: { method: string; params?: any }) {
      if (method === 'eth_call' && params?.[0]?.to && lower(params[0].to) === ESCROW && params[0].data) return viewCall(params[0].data)
      if (method === 'eth_sendRawTransaction' || method === 'eth_sendRawTransactionSync') {
        const raw = params[0] as Hex
        // anvil's eth_sendRawTransactionSync takes the raw transaction only (no timeout).
        const out = await base.request({ method, params: [raw] } as never)
        if (method === 'eth_sendRawTransaction') {
          pendingLogs.set(lower(out as string), apply(raw))
          return out
        }
        const receipt = out as Record<string, any>
        if (receipt.status === '0x1') pendingLogs.set(lower(receipt.transactionHash), apply(raw))
        return withLogs(receipt)
      }
      if (method === 'eth_getTransactionReceipt') return withLogs((await base.request({ method, params } as never)) as never)
      return base.request({ method, params } as never)
    },
  })
  const client = createClient({ chain, transport }).extend(publicActions).extend(walletActions).extend(tempoActions())
  return { client, channels, events }
}
