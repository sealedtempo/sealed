import { tempo } from 'mppx/server'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { PgStore } from '../src/pg-store.js'
import { type Cluster, postgresAvailable, startCluster } from './helpers/pg.js'

const CHANNEL = `0x${'ab'.repeat(32)}` as const

function channelState(overrides: Record<string, unknown> = {}) {
  return {
    backend: 'precompile',
    chainId: 4217,
    channelId: CHANNEL,
    escrowContract: '0x4d50500000000000000000000000000000000000',
    payer: '0x1111111111111111111111111111111111111111',
    payee: '0x2222222222222222222222222222222222222222',
    operator: '0x3333333333333333333333333333333333333333',
    token: '0x20c0000000000000000000000000000000000000',
    authorizedSigner: '0x4444444444444444444444444444444444444444',
    salt: `0x${'00'.repeat(32)}`,
    closeRequestedAt: 0n,
    deposit: 1_000_000n,
    settledOnChain: 0n,
    highestVoucherAmount: 500_000n,
    highestVoucher: { channelId: CHANNEL, cumulativeAmount: 500_000n, signature: '0x' },
    spent: 0n,
    units: 0,
    finalized: false,
    createdAt: new Date(0).toISOString(),
    ...overrides,
  }
}

describe.skipIf(!postgresAvailable())('PgStore (throwaway PostgreSQL 17 cluster)', () => {
  let cluster: Cluster
  let pool: pg.Pool
  let db: PgStore

  beforeAll(async () => {
    cluster = await startCluster()
    pool = new pg.Pool({ connectionString: cluster.url, max: 8 })
    db = new PgStore(pool)
    await db.migrate()
    await db.migrate() // idempotent
  })

  afterAll(async () => {
    await pool?.end()
    cluster?.stop()
  })

  it('round-trips values with bigints through ox-JSON', async () => {
    await db.put('k1', { a: 1n, b: 'x', c: [2n, 3] })
    expect(await db.get('k1')).toEqual({ a: 1n, b: 'x', c: [2n, 3] })
    await db.delete('k1')
    expect(await db.get('k1')).toBeNull()
  })

  it('update is linearizable under concurrency', async () => {
    const store = db.asMppxStore()
    await store.put('counter', { n: 0 })
    await Promise.all(
      Array.from({ length: 40 }, () =>
        store.update('counter', (current: unknown) => ({ op: 'set', value: { n: ((current as { n?: number } | null)?.n ?? 0) + 1 }, result: null })),
      ),
    )
    expect(await store.get('counter')).toEqual({ n: 40 })
  })

  it('update supports noop and delete and returns the callback result', async () => {
    const store = db.asMppxStore()
    await store.put('u', { v: 1 })
    expect(await store.update('u', () => ({ op: 'noop', result: 'kept' }))).toBe('kept')
    expect(await store.get('u')).toEqual({ v: 1 })
    expect(await store.update('u', () => ({ op: 'delete', result: 'gone' }))).toBe('gone')
    expect(await store.get('u')).toBeNull()
  })

  it('tryClaim records a replay key once and allows reuse only after expiry', async () => {
    const future = Date.now() + 60_000
    const results = await Promise.all(Array.from({ length: 10 }, () => db.tryClaim('replay:tx1', future)))
    expect(results.filter(Boolean).length).toBe(1)
    expect(await db.tryClaim('replay:tx2', Date.now() - 1)).toBe(false)
    await db.tryClaim('replay:tx3', Date.now() + 30)
    await new Promise((r) => setTimeout(r, 60))
    expect(await db.tryClaim('replay:tx3', Date.now() + 60_000)).toBe(true)
    // a non-replay value is never overwritten by a claim
    await db.put('replay:tx4', { not: 'a marker' })
    expect(await db.tryClaim('replay:tx4', Date.now() + 60_000)).toBe(false)
  })

  it('mirrors session channels and lists open ones for the close supervisor', async () => {
    await db.put(CHANNEL, channelState())
    const open = await db.listChannels()
    expect(open.map((c) => c.channelId)).toContain(CHANNEL)
    const row = open.find((c) => c.channelId === CHANNEL)!
    expect(row).toMatchObject({ deposit: 1_000_000n, spent: 0n, finalized: false })
    expect(await db.findOpenChannel(row.payer, row.payee, row.token)).toBe(CHANNEL)
    await db.markFinalized(CHANNEL)
    expect((await db.listChannels()).map((c) => c.channelId)).not.toContain(CHANNEL)
    expect((await db.listChannels({ includeFinalized: true })).map((c) => c.channelId)).toContain(CHANNEL)
    await pool.query(`UPDATE "${db.schema}".channels SET finalized = false`)
  })

  it('backs mppx session charge and credit, and the vouchers survive a restart', async () => {
    const store = db.asMppxStore()
    await store.put(CHANNEL, channelState())
    await tempo.session.charge(store as never, CHANNEL, 120_000n, { idempotencyKey: 'job-1' })
    await tempo.session.charge(store as never, CHANNEL, 120_000n, { idempotencyKey: 'job-1' }) // replayed, not charged twice
    const credit = await tempo.session.credit(store as never, CHANNEL, 20_000n, { idempotencyKey: 'refund-1' })
    expect(credit.status).toBe('credited')

    // "restart": a fresh pool and store over the same database
    const pool2 = new pg.Pool({ connectionString: cluster.url })
    const db2 = new PgStore(pool2)
    const state = (await db2.get(CHANNEL)) as { spent: bigint; highestVoucher: { cumulativeAmount: bigint } }
    expect(state.spent).toBe(100_000n)
    expect(state.highestVoucher.cumulativeAmount).toBe(500_000n)
    const mirrored = (await db2.listChannels()).find((c) => c.channelId === CHANNEL)!
    expect(mirrored.spent).toBe(100_000n)
    await pool2.end()

    // a charge beyond the accepted voucher is refused by mppx through this store
    await expect(tempo.session.charge(store as never, CHANNEL, 10_000_000n)).rejects.toThrow()
  })

  it('rejects unsafe schema names', () => {
    expect(() => new PgStore(pool, { schema: 'bad"; drop' })).toThrow(/invalid schema/)
  })
})
