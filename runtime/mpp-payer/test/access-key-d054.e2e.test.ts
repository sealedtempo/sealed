import { encodeFunctionData, toFunctionSelector } from 'viem'
import { generatePrivateKey } from 'viem/accounts'
import { Abis, Account, Addresses } from 'viem/tempo'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { perRequestPrice } from '../../relay/src/server.js'
import { DEV_KEYS, PATHUSD, anvilAvailable, balanceOf, startLocalTempo, type LocalTempo } from '../../relay/test/helpers/anvil.js'
import { ChannelJournal } from '../src/channel-journal.js'
import { ChannelRecovery, ViemEscrowChain } from '../src/channel-recovery.js'
import { ESCROW_PRECOMPILE } from '../src/config.js'
import { SpendGuard } from '../src/spend-guard.js'
import { fakeAgentBudget } from './helpers/fake-agent-budget.js'
import {
  MAINNET_FEE_SPLITTER,
  authorizeD054,
  channelState,
  d054Authorization,
  escrowEvents,
  increaseTime,
  payerStack,
  post,
  relayWorld,
  remainingLimit,
} from './helpers/relay-world.js'

/**
 * Review finding H1: the payer pays with the customer's access key as the production
 * authorization grants it (D-054), on a local Tempo node (Foundry 1.8.6, hardfork T12) with the
 * real AccountKeychain (0xaAAA...) and the real TIP-1034 escrow precompile. The key is authorized
 * exactly as the console sends it (AccountKeychain.authorizeKey: a daily limit in the fee token,
 * allowAnyCalls false, the D-054 call scopes); then fee settlement calls, a relay charge, a session
 * open, a top-up, a cooperative close and the recovery of an orphaned deposit (requestClose, then
 * withdraw after the grace period) run through it, and the key's remaining limit is checked after
 * each. Escrow deposits are metered against the limit; refunds do not restore it.
 *
 * The node's clock is moved forward once, by the last test (the grace period): expiring-nonce
 * transactions follow wall time, so nothing may run on this node after it.
 */
describe.skipIf(!anvilAvailable())('the payer on the D-054 access key (AccountKeychain and escrow precompile on a local node)', () => {
  let node: LocalTempo
  const LIMIT = 3_000_000n
  const root = Account.fromSecp256k1(DEV_KEYS[5])
  const enclaveKey = generatePrivateKey()
  /** access-key mode: the enclave key signs for the customer's root account (INTERFACES 15). */
  const payer = Account.fromSecp256k1(enclaveKey, { access: root })
  const treasury = Account.fromSecp256k1(generatePrivateKey()).address.toLowerCase() as `0x${string}`
  const settler = Account.fromSecp256k1(DEV_KEYS[3])
  const body = { model: 'nearai/z-ai/glm-5.3', messages: [{ role: 'user', content: 'pay me' }], max_tokens: 32 }
  const left = () => remainingLimit(node, root.address, payer.accessKeyAddress)

  beforeAll(async () => {
    node = await startLocalTempo()
    await authorizeD054(node, root, d054Authorization({ keyId: payer.accessKeyAddress, feeToken: PATHUSD, feeSplitter: MAINNET_FEE_SPLITTER, treasury, limit: LIMIT }))
  }, 60_000)
  afterAll(() => node?.stop())

  it('is authorized with a limit and exactly the D-054 call scopes, never allowAnyCalls', async () => {
    const [, scopes] = (await node.client.readContract({
      address: Addresses.accountKeychain,
      abi: Abis.accountKeychain,
      functionName: 'getAllowedCalls',
      args: [root.address, payer.accessKeyAddress],
    })) as [boolean, { target: string; selectorRules: { selector: string; recipients: string[] }[] }[]]
    const flat = scopes.flatMap((s) => s.selectorRules.map((r) => [s.target.toLowerCase(), r.selector, r.recipients.map((x) => x.toLowerCase())]))
    const sel = (sig: string) => toFunctionSelector(sig)
    expect(flat).toEqual([
      [PATHUSD, sel('approve(address,uint256)'), [MAINNET_FEE_SPLITTER]],
      [PATHUSD, sel('transferWithMemo(address,uint256,bytes32)'), [treasury]],
      [MAINNET_FEE_SPLITTER, sel('payFees(bytes32,bytes32,address,uint256,bytes32)'), []],
      [MAINNET_FEE_SPLITTER, sel('topUpFees(bytes32,bytes32,address,uint256,bytes32)'), []],
      [ESCROW_PRECOMPILE, '0xedc53b00', []],
      [ESCROW_PRECOMPILE, '0xdc48471e', []],
      [ESCROW_PRECOMPILE, '0x675402e5', []],
      [ESCROW_PRECOMPILE, '0x41e2c664', []],
    ])
    expect(await left()).toBe(LIMIT)
  })

  it('allows fee settlement (approve to FeeSplitter plus payFees in one transaction) and refuses calls outside the scopes', async () => {
    const before = await left()
    const hash = await node.client.sendTransaction({
      account: payer,
      calls: [
        { to: PATHUSD, data: encodeFunctionData({ abi: Abis.tip20, functionName: 'approve', args: [MAINNET_FEE_SPLITTER, 1_000n] }) },
        {
          to: MAINNET_FEE_SPLITTER,
          data: encodeFunctionData({
            abi: [{ type: 'function', name: 'payFees', stateMutability: 'nonpayable', inputs: [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'address' }, { type: 'uint256' }, { type: 'bytes32' }], outputs: [] }],
            functionName: 'payFees',
            args: [`0x${'01'.repeat(32)}`, `0x${'02'.repeat(32)}`, PATHUSD, 1_000n, `0x${'03'.repeat(32)}`],
          }),
        },
      ],
      feeToken: PATHUSD,
    } as never)
    expect((await node.client.waitForTransactionReceipt({ hash })).status).toBe('success')
    // The approval and the network fee count against the limit (D-026).
    const used = before - (await left())
    expect(used).toBeGreaterThan(1_000n)
    expect(used).toBeLessThan(1_000n + 20_000n)
    const other = Account.fromSecp256k1(generatePrivateKey()).address
    for (const data of [
      encodeFunctionData({ abi: Abis.tip20, functionName: 'approve', args: [other, 1n] }),
      encodeFunctionData({ abi: Abis.tip20, functionName: 'transferWithMemo', args: [other, 1n, `0x${'00'.repeat(32)}`] }),
      encodeFunctionData({ abi: Abis.tip20, functionName: 'transfer', args: [treasury, 1n] }),
    ])
      await expect(node.client.sendTransaction({ account: payer, calls: [{ to: PATHUSD, data }], feeToken: PATHUSD } as never)).rejects.toThrow()
  })

  it('pays a relay charge (transferWithMemo to the treasury): the limit drops by the charge plus its fee', async () => {
    const world = relayWorld({ node, treasury })
    const { app, guard } = payerStack({ relayFetch: world.fetch, treasury, account: payer, node })
    const before = await left()
    const treasuryBefore = await balanceOf(node.client, treasury)
    const res = await app.request('/v1/chat/completions', post(body))
    expect(res.status).toBe(200)
    expect((await res.json()).choices[0].message.content).toBe('Metered per token over SSE')
    const quoted = perRequestPrice(world.prices, world.prices.models[0]!, { ...body, stream: true, stream_options: { include_usage: true } }).amount
    expect((await balanceOf(node.client, treasury)) - treasuryBefore).toBe(quoted)
    const used = before - (await left())
    const feeCap = BigInt(guard.counters().debited) - quoted
    expect(used - quoted).toBeGreaterThan(0n)
    expect(used - quoted).toBeLessThanOrEqual(feeCap)
  }, 60_000)

  it('opens a session channel and tops it up: escrow deposits are metered against the limit; a close refund does not restore it', async () => {
    // A tiny suggested deposit, so the second request needs a top-up.
    const world = relayWorld({ node, treasury, settler, suggestedDeposit: '0.0001' })
    const journal = new ChannelJournal(undefined)
    const { app, relay, guard } = payerStack({ relayFetch: world.fetch, treasury, account: payer, node, journal })
    const before = await left()
    expect((await app.request('/v1/chat/completions', post(body))).status).toBe(200)
    const [record] = journal.all()
    const opened = await channelState(node, record!.channelId)
    expect(opened.deposit).toBe(100n)
    const afterOpen = await left()
    const openFee = before - afterOpen - opened.deposit
    expect(openFee).toBeGreaterThan(0n)
    expect(openFee).toBeLessThanOrEqual(BigInt(guard.counters().debited) - 100n)

    for (let i = 0; i < 2; i++) expect((await app.request('/v1/chat/completions', post(body))).status).toBe(200)
    const toppedUp = await channelState(node, record!.channelId)
    expect(guard.counters().topUps).toBeGreaterThan(0)
    expect(toppedUp.deposit).toBeGreaterThan(100n)
    const afterTopUp = await left()
    const topUpFees = afterOpen - afterTopUp - (toppedUp.deposit - 100n)
    expect(topUpFees).toBeGreaterThan(0n)
    expect(journal.get(record!.channelId)?.deposited).toBe(toppedUp.deposit.toString())

    const rootBefore = await balanceOf(node.client, root.address)
    await relay.close()
    const closed = (await escrowEvents(node, record!.channelId)).find((e) => e.eventName === 'ChannelClosed')!
    expect(closed.args.refundedToPayer as bigint).toBeGreaterThan(0n)
    expect((await balanceOf(node.client, root.address)) - rootBefore).toBe(closed.args.refundedToPayer as bigint)
    // The relay's settler sent the close; the refund returns to the account, not to the key's limit.
    expect(await left()).toBe(afterTopUp)
  }, 90_000)

  it('recovers an orphaned deposit with the key: requestClose, then withdraw after the grace period (moves the node clock)', async () => {
    const world = relayWorld({ node, treasury, settler })
    const journal = new ChannelJournal(undefined)
    const crashed = payerStack({ relayFetch: world.fetch, treasury, account: payer, node, journal })
    expect((await crashed.app.request('/v1/chat/completions', post(body))).status).toBe(200)
    // The process dies here: no close. A new process finds the channel in its journal.
    const [record] = journal.all()
    const deposit = (await channelState(node, record!.channelId)).deposit
    expect(deposit).toBe(200_000n)

    let chainNow = Math.floor(Date.now() / 1000)
    const guard = new SpendGuard(LIMIT)
    const agent = fakeAgentBudget({ budget: LIMIT })
    const recovery = new ChannelRecovery({
      journal,
      chain: new ViemEscrowChain(node.client as never, payer as never, PATHUSD, () => chainNow),
      liveChannels: () => new Set(),
      guard,
      budget: agent.budget,
      minAgeSeconds: 0,
      now: () => chainNow,
    })
    const beforeClose = await left()
    await recovery.sweep()
    const requested = await channelState(node, record!.channelId)
    expect(requested.closeRequestedAt).toBeGreaterThan(0)
    expect(journal.get(record!.channelId)).toMatchObject({ status: 'closeRequested', reason: 'orphaned' })
    const closeFee = beforeClose - (await left())
    expect(closeFee).toBeGreaterThan(0n)
    expect(closeFee).toBeLessThanOrEqual(BigInt(guard.counters().debited))

    // Within the grace period nothing is sent.
    await recovery.sweep()
    expect(recovery.snapshot()).toMatchObject({ requestCloses: 1, withdrawals: 0 })

    await increaseTime(node, 901)
    chainNow = Number((await node.client.getBlock()).timestamp)
    const rootBefore = await balanceOf(node.client, root.address)
    const beforeWithdraw = await left()
    await recovery.sweep()
    expect(journal.get(record!.channelId)?.status).toBe('closed')
    expect((await channelState(node, record!.channelId)).deposit).toBe(0n)
    const refunded = BigInt(journal.get(record!.channelId)!.refunded!)
    expect(refunded).toBe(deposit - requested.settled)
    const withdrawFee = beforeWithdraw - (await left())
    expect(withdrawFee).toBeGreaterThan(0n)
    expect((await balanceOf(node.client, root.address)) - rootBefore).toBe(refunded - withdrawFee)
    expect(recovery.snapshot()).toMatchObject({ requestCloses: 1, withdrawals: 1, recovered: refunded.toString(), failures: 0 })
    expect(agent.state.used).toBe(BigInt(guard.counters().debited))
  }, 90_000)
})
