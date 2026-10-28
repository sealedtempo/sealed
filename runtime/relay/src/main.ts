import { serve } from '@hono/node-server'
import pg from 'pg'
import { http, createClient, parseUnits, publicActions, walletActions } from 'viem'
import { tempo as tempoChain } from 'viem/chains'
import { Account, tempoActions } from 'viem/tempo'
import { PROVIDER_KEY_ENV, loadRelayConfig, readSecret } from './config.js'
import { createPayments } from './payments.js'
import { PgStore } from './pg-store.js'
import { loadPriceTable } from './prices.js'
import { type GateEntry, ProviderGate } from './providers/gate.js'
import { RateLimiter, clientKey } from './rate-limit.js'
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

  const privatemodeModel = prices.models.find((m) => m.provider === 'privatemode')
  const gate = new ProviderGate(
    config.providers.map((p): GateEntry => {
      if (p.kind === 'sidecar') return { provider: p.provider, enabled: p.enabled, source: { kind: 'sidecar', statusUrl: p.statusUrl } }
      return {
        provider: p.provider,
        enabled: p.enabled && privatemodeModel !== undefined,
        source: {
          kind: 'privatemode',
          baseUrl: p.statusUrl,
          apiKey: () => readSecret(PROVIDER_KEY_ENV.privatemode),
          model: privatemodeModel?.upstreamModel ?? '',
          workspaceDir: config.privatemodeWorkspace,
          probeSeconds: config.privatemodeProbeSeconds,
        },
      }
    }),
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
    maxBodyBytes: config.maxBodyBytes,
    unpaidLimiter: new RateLimiter({ perMinute: config.unpaidPerMinute }),
    clientKey: (c) =>
      clientKey(
        (c.env as { incoming?: { socket?: { remoteAddress?: string } } })?.incoming?.socket?.remoteAddress,
        c.req.header('x-forwarded-for') ?? null,
        config.trustedProxies,
      ),
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
    settler: settler?.address.toLowerCase(),
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
