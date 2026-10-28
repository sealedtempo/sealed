import { serve } from '@hono/node-server'
import { http, createClient, publicActions, walletActions } from 'viem'
import { tempo as tempoChain } from 'viem/chains'
import { Account, tempoActions } from 'viem/tempo'
import { RelayAttestationGate } from './attestation-gate.js'
import { CallerAllowlist } from './caller-allowlist.js'
import { loadPayerConfig } from './config.js'
import { paymentFirewall } from './payment-firewall.js'
import { RelayClient } from './relay-client.js'
import { PinnedRelayTransport } from './relay-transport.js'
import { createPayerApp } from './server.js'
import { AgentSpendBudget } from './shared-budget.js'
import { FileSpendStore, SpendGuard } from './spend-guard.js'
import { SpendReporter } from './spend-reporter.js'

const log = (event: Record<string, unknown>) => console.log(JSON.stringify({ t: new Date().toISOString(), ...event }))

function main(): void {
  const config = loadPayerConfig()
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
    log,
  })
  const reporter = new SpendReporter({
    agentUrl: config.agentUrl,
    intervalSeconds: config.reportIntervalSeconds,
    snapshot: () => ({
      mode: config.mode,
      currency: config.currency,
      counters: guard.counters(),
      relay: {
        attested: gate.isOpen(),
        checkedAt: gate.state().checkedAt,
        stackHash: gate.state().stackHash,
        sessionsAvailable: relay.sessionsAvailable(),
      },
    }),
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
  const server = serve({ fetch: app.fetch, port: config.port, hostname: '0.0.0.0' })
  log({ event: 'payer_started', port: config.port, mode: config.mode, payer: account.address.toLowerCase() })

  const shutdown = async () => {
    gate.stop()
    callers.stop()
    reporter.stop()
    await relay.close()
    budget.stop()
    await transport.close()
    await reporter.send()
    server.close()
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
