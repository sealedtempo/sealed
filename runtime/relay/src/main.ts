import { serve } from '@hono/node-server'
import pg from 'pg'
import { http, createClient, parseUnits, publicActions, walletActions } from 'viem'
import { tempo as tempoChain } from 'viem/chains'
import { Account, tempoActions } from 'viem/tempo'
import { loadRelayConfig } from './config.js'
import { createPayments } from './payments.js'
import { PgStore } from './pg-store.js'
import { loadPriceTable } from './prices.js'
import { ProviderGate } from './providers/gate.js'
import { createRelayApp } from './server.js'
import { SettlementSupervisor } from './supervisor.js'
import { Upstream } from './upstream.js'
import { agentUsageSink } from './usage.js'

const log = (event: Record<string, unknown>) => console.log(JSON.stringify({ t: new Date().toISOString(), ...event }))

async function main(): Promise<void> {
  const config = loadRelayConfig()
  const prices = loadPriceTable(config.pricesPath, config.markupBps)
  if (prices.currency !== config.currency) throw new Error('price table currency differs from FEE_TOKEN_ADDRESS')

  const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 10 })
  const db = new PgStore(pool)
  await db.migrate()
  const store = db.asMppxStore()

  const chain = tempoChain.extend({ id: config.chainId, feeToken: config.currency })
  const client = createClient({ chain, transport: http(config.rpcUrl) })
    .extend(publicActions)
    .extend(walletActions)
    .extend(tempoActions())
  const settler = config.settlerKey ? Account.fromSecp256k1(config.settlerKey) : undefined

  const payments = createPayments({
    realm: config.realm,
    secretKey: config.secretKey,
    recipient: config.recipient,
    currency: config.currency,
    decimals: prices.decimals,
    chainId: config.chainId,
    store,
    getClient: () => client,
    settler,
    suggestedDeposit: config.suggestedDeposit,
    settlementSchedule: { amount: config.settleAmount, intervalMs: config.settleIntervalMs },
    resolveChannelId: async ({ source }) => {
      const payer = source?.split(':').pop()
      return payer ? db.findOpenChannel(payer, config.recipient, config.currency) : undefined
    },
    onSettlement: (event) => log({ event: 'session_settled', channelId: event.channelId, txHash: event.txHash }),
  })

  const gate = new ProviderGate(
    config.providers.map((p) => ({
      provider: p.provider,
      enabled: p.enabled,
      source: p.kind === 'probe' ? { kind: 'probe', probeUrl: p.statusUrl } : { kind: 'sidecar', statusUrl: p.statusUrl },
    })),
  )
  gate.start()

  const app = createRelayApp({
    prices,
    gate,
    payments,
    upstream: new Upstream({ baseURL: config.litellmUrl, apiKey: config.litellmKey }),
    batchTokens: config.batchTokens,
    log,
    onUsage: agentUsageSink(config.usageUrl),
  })

  let supervisor: SettlementSupervisor | undefined
  if (settler) {
    supervisor = new SettlementSupervisor({
      db,
      store,
      client,
      account: settler,
      schedule: { amount: parseUnits(config.settleAmount, prices.decimals), intervalMs: config.settleIntervalMs },
      intervalSeconds: config.superviseSeconds,
      log,
    })
    supervisor.start()
  }

  const server = serve({ fetch: app.fetch, port: config.port, hostname: '0.0.0.0' })
  log({
    event: 'relay_started',
    port: config.port,
    sessions: payments.sessionsEnabled,
    providers: config.providers.filter((p) => p.enabled).map((p) => p.provider),
  })

  const shutdown = async () => {
    gate.stop()
    supervisor?.stop()
    server.close()
    await pool.end().catch(() => {})
    process.exit(0)
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

main().catch((error) => {
  console.error(JSON.stringify({ event: 'relay_fatal', message: (error as Error).message }))
  process.exit(1)
})
