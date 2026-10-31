import { serve } from '@hono/node-server'
import { http, createClient, publicActions, walletActions } from 'viem'
import { tempo as tempoChain } from 'viem/chains'
import { Account, tempoActions } from 'viem/tempo'
import { RelayAttestationGate } from './attestation-gate.js'
import { CallerAllowlist } from './caller-allowlist.js'
import { ChannelJournal, FileKv } from './channel-journal.js'
import { ChannelRecovery, ViemEscrowChain } from './channel-recovery.js'
import { SHUTDOWN_SECONDS, loadPayerConfig } from './config.js'
import { paymentFirewall } from './payment-firewall.js'
import { RelayClient } from './relay-client.js'
import { PinnedRelayTransport } from './relay-transport.js'
import { createPayerApp } from './server.js'
import { AgentSpendBudget } from './shared-budget.js'
import { FileSpendStore, SpendGuard } from './spend-guard.js'
import { SpendReporter, spendSnapshot } from './spend-reporter.js'
import { privateStateDir } from './state-dir.js'
import { ChainTxWatcher, receiptReader } from './tx-watcher.js'

const log = (event: Record<string, unknown>) => console.log(JSON.stringify({ t: new Date().toISOString(), ...event }))

function main(): void {
  const config = loadPayerConfig()
  // Before any state is read or written (defense in depth beside the composer's envexec private).
  privateStateDir(config.stateDir)
  // access-key mode: the enclave key signs for the customer's root account (D-026, INTERFACES 15)
  const account =
    config.mode === 'access-key'
      ? Account.fromSecp256k1(config.enclaveKey, { access: config.customer })
      : Account.fromSecp256k1(config.enclaveKey)
  const chain = tempoChain.extend({ id: config.chainId, feeToken: config.currency })
  const client = createClient({ chain, transport: http(config.rpcUrl) })
    .extend(publicActions)
    .extend(walletActions)
    .extend(tempoActions())

  let transport: PinnedRelayTransport | undefined
  const gate = new RelayAttestationGate({
    attestUrl: config.relayAttestUrl,
    verifierdUrl: config.verifierdUrl,
    relayOwner: config.relayOwner,
    intervalSeconds: config.attestIntervalSeconds,
    payeeOverride: config.relayPayee,
    allowSimulated: process.env.SEALED_DEV_SIM === '1',
    onExplicitFailure: () => transport?.reset(),
    log,
  })
  // Everything sent to the relay goes over connections pinned to the attested TLS key.
  transport = new PinnedRelayTransport({
    origin: config.relayUrl,
    pin: () => gate.pin(),
    repin: () => gate.recheckAfterKeyMismatch(),
  })
  // First cap: the daily budget shared with the agent's fee settlement, which has priority (D-048).
  const budget = new AgentSpendBudget({ agentUrl: config.agentUrl, currency: config.currency, log })
  // Second cap: the local guard, the whole daily limit, persisted across restarts.
  const guard = new SpendGuard(config.spendLimitPerDay, Date.now, {
    store: new FileSpendStore(config.spendStateFile, (e) => log({ event: 'spend_state_unsaved', detail: e.message })),
  })
  // Every channel the payer opens is journaled before its credential leaves, so a deposit the
  // payer can no longer use is taken back onchain (requestClose, then withdraw after the grace period).
  const journal = new ChannelJournal(config.channelJournalFile, undefined, (e) => log({ event: 'channel_journal_unsaved', detail: e.message }))
  const firewalled = paymentFirewall(
    transport.fetch,
    {
      payerAddress: account.address,
      currency: config.currency,
      allowedChainIds: [config.chainId],
      maxCharge: config.maxCharge,
      maxDeposit: config.maxDeposit,
      expectedPayee: () => gate.payee(),
    },
    guard,
    budget,
    { journal, watcher: new ChainTxWatcher({ receipt: receiptReader(client as never) }), log },
  )
  const relay = new RelayClient({
    relayUrl: config.relayUrl,
    account,
    getClient: () => client,
    currency: config.currency,
    chainId: config.chainId,
    decimals: 6,
    maxDeposit: config.maxDeposit,
    maxCharge: config.maxCharge,
    expectedPayee: () => gate.payee(),
    fetch: firewalled,
    channelKv: new FileKv(config.sessionStoreFile, (e) => log({ event: 'session_store_unsaved', detail: e.message })),
    journal,
    rotateHeadroom: config.rotateHeadroom,
    closeTimeoutMs: (SHUTDOWN_SECONDS - 3) * 1000,
    log,
  })
  const recovery = new ChannelRecovery({
    journal,
    chain: new ViemEscrowChain(client as never, account, config.currency),
    liveChannels: () => relay.liveChannels(),
    guard,
    budget,
    intervalSeconds: config.recoveryIntervalSeconds,
    log,
  })
  const reporter = new SpendReporter({
    agentUrl: config.agentUrl,
    intervalSeconds: config.reportIntervalSeconds,
    snapshot: () => spendSnapshot({ mode: config.mode, currency: config.currency, guard, gate, relay, recovery }),
    log,
  })
  const callers = new CallerAllowlist(config.allowedCallers)

  const app = createPayerApp({
    gate,
    relay,
    models: () => transport.fetch(`${config.relayUrl}/v1/models`, { signal: AbortSignal.timeout(15_000) }),
    callers,
    remoteAddress: (c) => (c.env as { incoming?: { socket?: { remoteAddress?: string } } })?.incoming?.socket?.remoteAddress,
    onPayment: () => reporter.poke(),
    log,
  })

  gate.start()
  callers.start()
  reporter.start()
  recovery.start()
  const server = serve({ fetch: app.fetch, port: config.port, hostname: '0.0.0.0' })
  log({ event: 'payer_started', port: config.port, mode: config.mode, payer: account.address.toLowerCase() })

  let stopping = false
  const shutdown = async () => {
    if (stopping) return
    stopping = true
    // Hard deadline inside the composer's stop_grace_period (at least SHUTDOWN_SECONDS + 5).
    setTimeout(() => process.exit(0), SHUTDOWN_SECONDS * 1000).unref()
    server.close()
    gate.stop()
    callers.stop()
    reporter.stop()
    recovery.stop()
    // The cooperative close refunds the unspent deposit; a channel that does not close in time
    // stays stored and journaled, and is resumed or recovered after the restart.
    await relay.close().catch(() => {})
    await Promise.race([firewalled.idle(), new Promise((r) => setTimeout(r, 2_000))])
    budget.stop()
    await transport.close()
    await reporter.send().catch(() => {})
    process.exit(0)
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

try {
  main()
} catch (error) {
  console.error(JSON.stringify({ event: 'payer_fatal', message: (error as Error).message }))
  process.exit(1)
}
