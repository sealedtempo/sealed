import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Credential } from 'mppx'
import { Store } from 'mppx/server'
import { Session } from 'mppx/tempo'
import { type Hex, parseEventLogs, toFunctionSelector } from 'viem'
import { Abis, Addresses, type Account as TempoAccount } from 'viem/tempo'
// The real relay front and mppx server stand in for the remote relay.
import { createPayments } from '../../../relay/src/payments.js'
import { type PriceTable, parsePriceTable } from '../../../relay/src/prices.js'
import { createRelayApp } from '../../../relay/src/server.js'
import { Upstream } from '../../../relay/src/upstream.js'
import { PATHUSD, type LocalTempo } from '../../../relay/test/helpers/anvil.js'
import { fakeLiteLLM } from '../../../relay/test/helpers/fake-litellm.js'
import { RelayAttestationGate } from '../../src/attestation-gate.js'
import type { ChannelJournal, FileKv } from '../../src/channel-journal.js'
import { ESCROW_PRECOMPILE } from '../../src/config.js'
import { type FirewallOptions, paymentFirewall } from '../../src/payment-firewall.js'
import { RelayClient } from '../../src/relay-client.js'
import { createPayerApp } from '../../src/server.js'
import type { SpendBudget } from '../../src/shared-budget.js'
import { SpendGuard } from '../../src/spend-guard.js'
import { fakeAttest, fakeVerifierd, relayAppCompose } from './fake-relay-attest.js'

const { escrowAbi } = Session.Precompile

/** FeeSplitter on mainnet (contracts/deployments/tempo-mainnet.json); on the local node it has no code, which is enough for call scopes. */
export const MAINNET_FEE_SPLITTER = (
  JSON.parse(readFileSync(join(import.meta.dirname, '../../../../contracts/deployments/tempo-mainnet.json'), 'utf8')) as { contracts: { FeeSplitter: { address: string } } }
).contracts.FeeSplitter.address.toLowerCase() as `0x${string}`

type ChannelRow = { channelId: string; payer: string; payee: string; token: string; finalized: boolean; closeRequestedAt: bigint; updated: number }

/**
 * mppx's in-memory store, plus the index the relay keeps in Postgres (pg-store findOpenChannel):
 * open channels by payer, payee and token, so mppx's bootstrap can hand a payer its channel back.
 */
export function indexedStore() {
  const inner = Store.memory() as unknown as Store.AtomicStore & Record<string, (...args: any[]) => any>
  const channels = new Map<string, ChannelRow>()
  let tick = 0
  const note = (key: string, value: any) => {
    const id = key.slice(-66)
    if (!/^0x[0-9a-f]{64}$/i.test(id) || !value || value.backend !== 'precompile' || typeof value.payer !== 'string') return
    channels.set(id.toLowerCase(), {
      channelId: id.toLowerCase(),
      payer: value.payer.toLowerCase(),
      payee: String(value.payee).toLowerCase(),
      token: String(value.token).toLowerCase(),
      finalized: value.finalized === true,
      closeRequestedAt: BigInt(value.closeRequestedAt ?? 0),
      updated: ++tick,
    })
  }
  const store = {
    get: (key: string) => inner.get(key),
    delete: (key: string) => inner.delete(key),
    async put(key: string, value: unknown) {
      await inner.put(key, value)
      note(key, value)
    },
    async update(key: string, fn: (current: any) => any) {
      const result = await inner.update(key, fn)
      note(key, await inner.get(key))
      return result
    },
  } as unknown as Store.AtomicStore
  const resolveChannelId = async ({ source }: { source?: string }) => {
    const payer = source?.split(':').pop()?.toLowerCase()
    const open = [...channels.values()].filter((c) => c.payer === payer && !c.finalized && c.closeRequestedAt === 0n).sort((a, b) => b.updated - a.updated)
    return open[0]?.channelId as `0x${string}` | undefined
  }
  return { store, channels, resolveChannelId }
}

export const testPrices = (input = 1_800_000, output = 5_750_000): PriceTable =>
  parsePriceTable(
    {
      currency: PATHUSD,
      decimals: 6,
      models: [{ id: 'nearai/z-ai/glm-5.3', provider: 'nearai', upstream_model: 'z-ai/glm-5.3', input_per_1m: input, output_per_1m: output, max_output_tokens: 256 }],
    },
    500,
  )

export type WireEntry = { method: string; intent?: string; action?: string; type?: string; cumulative?: bigint; status: number }

/** The relay front with a real mppx server (charge and, with a settler, sessions) on the local node. */
export function relayWorld(options: {
  node: LocalTempo
  treasury: `0x${string}`
  settler?: TempoAccount.Account
  suggestedDeposit?: string
  prices?: PriceTable
  bootstrap?: boolean
  words?: string[]
}) {
  const llm = fakeLiteLLM({ words: options.words ?? ['Metered', ' per', ' token', ' over', ' SSE'], usage: { prompt_tokens: 12, completion_tokens: 5 } })
  const indexed = indexedStore()
  const credited: bigint[] = []
  const prices = options.prices ?? testPrices()
  const payments = createPayments({
    realm: 'relay.sealed.test',
    secretKey: 'test-secret-key-that-is-at-least-32-bytes',
    recipient: options.treasury,
    currency: PATHUSD,
    decimals: 6,
    chainId: 4217,
    store: indexed.store,
    getClient: () => options.node.client as never,
    settler: options.settler,
    suggestedDeposit: options.suggestedDeposit ?? '0.2',
    resolveChannelId: options.bootstrap === false ? undefined : indexed.resolveChannelId,
  })
  const app = createRelayApp({
    prices,
    gate: { allows: () => true, status: (p: string) => ({ provider: p, enabled: true, verified: true, detail: 'ok' }), all: () => [] } as never,
    payments: {
      ...payments,
      credit: async (channelId, amount, key) => {
        credited.push(amount)
        return payments.credit(channelId, amount, key)
      },
    },
    upstream: new Upstream({ baseURL: 'http://litellm/v1', apiKey: 'sk-master', fetch: llm.fetch }),
    batchTokens: 2,
  })
  const wire: WireEntry[] = []
  const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    const entry: Omit<WireEntry, 'status'> = { method: request.method }
    const auth = request.headers.get('authorization')
    if (auth?.startsWith('Payment ')) {
      const credential = Credential.deserialize<{ action?: string; type?: string; cumulativeAmount?: string }>(auth)
      entry.intent = credential.challenge.intent
      entry.action = credential.payload.action
      entry.type = credential.payload.type
      if (credential.payload.cumulativeAmount !== undefined) entry.cumulative = BigInt(credential.payload.cumulativeAmount)
    }
    const response = await app.fetch(request)
    wire.push({ ...entry, status: response.status })
    return response
  }
  return { fetch, llm, wire, credited, channels: indexed.channels, prices }
}

/** sealed-mpp-payer as main.ts wires it, minus the TLS-pinned transport (the relay is in process). */
export function payerStack(options: {
  relayFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  treasury: `0x${string}`
  account: TempoAccount.Account
  node: LocalTempo
  maxDeposit?: bigint
  maxCharge?: bigint
  rotateHeadroom?: bigint
  guard?: SpendGuard
  budget?: SpendBudget
  journal?: ChannelJournal
  channelKv?: FileKv
  firewall?: FirewallOptions
}) {
  const gate = new RelayAttestationGate({
    attestUrl: 'https://relay.sealed.test/attest',
    verifierdUrl: 'http://sealed-verifierd:8088',
    relayOwner: ('0x' + '0a'.repeat(20)) as `0x${string}`,
    intervalSeconds: 900,
    retrySeconds: 0,
    fetchAttest: fakeAttest({ appCompose: relayAppCompose(options.treasury) }).fetchAttest,
    fetchVerifier: fakeVerifierd().fetchVerifier,
  })
  const guard = options.guard ?? new SpendGuard(2_000_000n)
  const maxDeposit = options.maxDeposit ?? 200_000n
  const maxCharge = options.maxCharge ?? 50_000n
  const firewall = paymentFirewall(
    options.relayFetch,
    { payerAddress: options.account.address, currency: PATHUSD, allowedChainIds: [4217], maxCharge, maxDeposit, expectedPayee: () => gate.payee() },
    guard,
    options.budget,
    { journal: options.journal, ...options.firewall },
  )
  const relay = new RelayClient({
    relayUrl: 'https://relay.sealed.test',
    account: options.account,
    getClient: () => options.node.client as never,
    currency: PATHUSD,
    chainId: 4217,
    decimals: 6,
    maxDeposit,
    maxCharge,
    rotateHeadroom: options.rotateHeadroom,
    expectedPayee: () => gate.payee(),
    fetch: firewall,
    journal: options.journal,
    channelKv: options.channelKv,
    log: process.env.DEBUG_PAYER ? (e) => console.log(JSON.stringify(e)) : undefined,
  })
  const app = createPayerApp({
    gate,
    relay,
    models: () => options.relayFetch('https://relay.sealed.test/v1/models'),
    callers: { allows: () => true },
    remoteAddress: () => '172.30.0.16',
  })
  return { app, relay, guard, firewall, gate }
}

export const post = (b: unknown) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

export async function channelState(node: LocalTempo, channelId: string) {
  return (await node.client.readContract({ address: ESCROW_PRECOMPILE, abi: escrowAbi, functionName: 'getChannelState', args: [channelId as Hex] })) as {
    settled: bigint
    deposit: bigint
    closeRequestedAt: number
  }
}

/** Escrow events for a channel, from the node's logs. */
export async function escrowEvents(node: LocalTempo, channelId?: string) {
  const logs = await node.client.getLogs({ address: ESCROW_PRECOMPILE, fromBlock: 0n, toBlock: 'latest' })
  const events = parseEventLogs({ abi: escrowAbi, logs }) as unknown as { eventName: string; args: Record<string, any> }[]
  return channelId ? events.filter((e) => String(e.args.channelId).toLowerCase() === channelId.toLowerCase()) : events
}

/** Moves the node's clock (the escrow's close grace period). Expiring-nonce transactions follow wall time, so do this last. */
export async function increaseTime(node: LocalTempo, seconds: number) {
  for (const [method, params] of [
    ['evm_increaseTime', [seconds]],
    ['evm_mine', []],
  ] as const)
    await fetch(node.rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })
}

const selector = (abi: readonly unknown[], name: string) => toFunctionSelector((abi as { type: string; name: string }[]).find((f) => f.type === 'function' && f.name === name) as never)

/**
 * The access-key authorization of D-054, as the console sends it (AccountKeychain.authorizeKey
 * in a standard transaction): a periodic limit in the fee token, never allowAnyCalls, and calls
 * limited to FEE_TOKEN approve to FeeSplitter, FeeSplitter payFees and topUpFees,
 * FEE_TOKEN transferWithMemo to the treasury only (MPP charges), and the escrow precompile open,
 * topUp, requestClose and withdraw (MPP sessions).
 *
 * Mirrors the shared helper D-054 puts in @sealed/core (buildAccessKeyAuthorization, ws/fix-agent);
 * switch this test to it once that lands. The escrow rules carry no recipients: the
 * AccountKeychain refuses a recipient rule on escrow open (InvalidCallScope, checked on Foundry
 * 1.8.6 T12), so the treasury payee of escrow calls is enforced by the payer's payment firewall
 * only.
 */
export function d054Authorization(a: { keyId: `0x${string}`; feeToken: `0x${string}`; feeSplitter: `0x${string}`; treasury: `0x${string}`; limit: bigint; period?: number }) {
  return [
    a.keyId,
    0,
    {
      expiry: 2n ** 64n - 1n,
      enforceLimits: true,
      limits: [{ token: a.feeToken, amount: a.limit, period: BigInt(a.period ?? 86_400) }],
      allowAnyCalls: false,
      allowedCalls: [
        {
          target: a.feeToken,
          selectorRules: [
            { selector: toFunctionSelector('approve(address,uint256)'), recipients: [a.feeSplitter] },
            { selector: toFunctionSelector('transferWithMemo(address,uint256,bytes32)'), recipients: [a.treasury] },
          ],
        },
        {
          target: a.feeSplitter,
          selectorRules: [
            { selector: toFunctionSelector('payFees(bytes32,bytes32,address,uint256,bytes32)'), recipients: [] },
            { selector: toFunctionSelector('topUpFees(bytes32,bytes32,address,uint256,bytes32)'), recipients: [] },
          ],
        },
        {
          target: ESCROW_PRECOMPILE,
          selectorRules: ['open', 'topUp', 'requestClose', 'withdraw'].map((name) => ({ selector: selector(escrowAbi, name), recipients: [] as `0x${string}`[] })),
        },
      ],
    },
  ] as const
}

/** Sends the D-054 authorization from the root account and waits until the key is active. */
export async function authorizeD054(node: LocalTempo, root: TempoAccount.Account, args: ReturnType<typeof d054Authorization>) {
  const hash = await node.client.writeContract({
    account: root,
    address: Addresses.accountKeychain,
    abi: Abis.accountKeychain,
    functionName: 'authorizeKey',
    args: args as never,
    feeToken: PATHUSD,
    // About 8.1M gas on T12: the full scope list is storage-heavy (the console must not cap it lower).
    gas: 10_000_000n,
  } as never)
  const receipt = await node.client.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('authorizeKey reverted')
  return receipt
}

export async function remainingLimit(node: LocalTempo, root: `0x${string}`, keyId: `0x${string}`): Promise<bigint> {
  return ((await node.client.accessKey.getRemainingLimit({ account: root, accessKey: keyId, token: PATHUSD } as never)) as { remaining: bigint }).remaining
}
