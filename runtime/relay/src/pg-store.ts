import type { Store } from 'mppx'
import { Json } from 'ox'
import type { Pool, PoolClient } from 'pg'

/**
 * Durable mppx AtomicStore backed by Postgres (D-027). Every value is stored as
 * ox-JSON text (bigint aware, the same encoding mppx's own adapters use).
 * `update` serializes writers per key with a transaction-scoped advisory lock,
 * so read-modify-write is linearizable across connections and processes.
 *
 * The store also mirrors session channel records into a `channels` table, because
 * the mppx store interface cannot list keys and the close supervisor needs the ids.
 */
export type ChannelRow = {
  channelId: `0x${string}`
  payer: string
  payee: string
  token: string
  authorizedSigner: string | null
  deposit: bigint
  spent: bigint
  settled: bigint
  finalized: boolean
  updatedAt: Date
}

const CHANNEL_KEY = /^0x[0-9a-f]{64}$/

export class PgStore {
  readonly schema: string

  constructor(
    private readonly pool: Pool,
    options: { schema?: string } = {},
  ) {
    this.schema = options.schema ?? 'sealed_relay'
    if (!/^[a-z_][a-z0-9_]*$/.test(this.schema)) throw new Error(`invalid schema name: ${this.schema}`)
  }

  private get kv() {
    return `"${this.schema}".mppx_kv`
  }

  private get channels() {
    return `"${this.schema}".channels`
  }

  async migrate(): Promise<void> {
    await this.pool.query(`CREATE SCHEMA IF NOT EXISTS "${this.schema}"`)
    await this.pool.query(`CREATE TABLE IF NOT EXISTS ${this.kv} (
      key text PRIMARY KEY,
      value text NOT NULL,
      expires_ms bigint,
      updated_at timestamptz NOT NULL DEFAULT now()
    )`)
    await this.pool.query(`CREATE TABLE IF NOT EXISTS ${this.channels} (
      channel_id text PRIMARY KEY,
      payer text NOT NULL,
      payee text NOT NULL,
      token text NOT NULL,
      authorized_signer text,
      deposit numeric(78,0) NOT NULL DEFAULT 0,
      spent numeric(78,0) NOT NULL DEFAULT 0,
      settled numeric(78,0) NOT NULL DEFAULT 0,
      finalized boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    )`)
    await this.pool.query(
      `CREATE INDEX IF NOT EXISTS channels_open_idx ON ${this.channels} (finalized, payer)`,
    )
  }

  /** The mppx-facing AtomicStore view of this database. */
  asMppxStore(): Store.AtomicStore {
    return {
      get: (key) => this.get(key),
      put: (key, value) => this.put(key, value),
      delete: (key) => this.delete(key),
      update: (key, fn) => this.update(key, fn),
      tryClaim: (key, expires) => this.tryClaim(key, expires),
    } as Store.AtomicStore
  }

  async get(key: string): Promise<any> {
    const res = await this.pool.query<{ value: string }>(`SELECT value FROM ${this.kv} WHERE key = $1`, [key])
    const row = res.rows[0]
    return row ? Json.parse(row.value) : null
  }

  async put(key: string, value: unknown): Promise<void> {
    await this.withTransaction(async (client) => {
      await this.lockKey(client, key)
      await this.write(client, key, value)
    })
  }

  async delete(key: string): Promise<void> {
    await this.pool.query(`DELETE FROM ${this.kv} WHERE key = $1`, [key])
  }

  async update<result>(key: string, fn: (current: any) => Store.Change<any, result>): Promise<result> {
    return this.withTransaction(async (client) => {
      await this.lockKey(client, key)
      const res = await client.query<{ value: string }>(`SELECT value FROM ${this.kv} WHERE key = $1`, [key])
      const current = res.rows[0] ? Json.parse(res.rows[0].value) : null
      const change = fn(current)
      if (change.op === 'set') await this.write(client, key, change.value)
      else if (change.op === 'delete') await client.query(`DELETE FROM ${this.kv} WHERE key = $1`, [key])
      return change.result
    })
  }

  /** Single-statement replay claim: inserts, or replaces only an expired replay marker. */
  async tryClaim(key: string, expires: number): Promise<boolean> {
    const now = Date.now()
    if (!Number.isFinite(expires) || expires <= now) return false
    const value = Json.stringify({ expires, type: 'mppx:replay' })
    const res = await this.pool.query(
      `INSERT INTO ${this.kv} (key, value, expires_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_ms = EXCLUDED.expires_ms, updated_at = now()
       WHERE ${this.kv}.expires_ms IS NOT NULL AND ${this.kv}.expires_ms <= $4
       RETURNING key`,
      [key, value, expires, now],
    )
    return res.rowCount === 1
  }

  async listChannels(options: { includeFinalized?: boolean } = {}): Promise<ChannelRow[]> {
    const res = await this.pool.query(
      `SELECT channel_id, payer, payee, token, authorized_signer, deposit::text, spent::text, settled::text, finalized, updated_at
       FROM ${this.channels} ${options.includeFinalized ? '' : 'WHERE finalized = false'} ORDER BY created_at`,
    )
    return res.rows.map(toChannelRow)
  }

  /** Latest open channel a payer holds toward a payee in a token, for session bootstrap after a client restart. */
  async findOpenChannel(payer: string, payee: string, token: string): Promise<`0x${string}` | undefined> {
    const res = await this.pool.query<{ channel_id: string }>(
      `SELECT channel_id FROM ${this.channels}
       WHERE finalized = false AND lower(payer) = lower($1) AND lower(payee) = lower($2) AND lower(token) = lower($3)
       ORDER BY updated_at DESC LIMIT 1`,
      [payer, payee, token],
    )
    return res.rows[0]?.channel_id as `0x${string}` | undefined
  }

  async markFinalized(channelId: string): Promise<void> {
    await this.pool.query(`UPDATE ${this.channels} SET finalized = true, updated_at = now() WHERE channel_id = $1`, [
      channelId.toLowerCase(),
    ])
  }

  private async write(client: PoolClient, key: string, value: unknown): Promise<void> {
    const expires = isReplayMarker(value) ? value.expires : null
    await client.query(
      `INSERT INTO ${this.kv} (key, value, expires_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_ms = EXCLUDED.expires_ms, updated_at = now()`,
      [key, Json.stringify(value), expires],
    )
    const channel = channelKeyOf(key)
    if (channel && isChannelState(value)) await this.mirrorChannel(client, channel, value)
  }

  private async mirrorChannel(client: PoolClient, channelId: string, state: ChannelStateLike): Promise<void> {
    await client.query(
      `INSERT INTO ${this.channels} (channel_id, payer, payee, token, authorized_signer, deposit, spent, settled, finalized)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (channel_id) DO UPDATE SET
         deposit = EXCLUDED.deposit, spent = EXCLUDED.spent, settled = EXCLUDED.settled,
         finalized = ${this.channels}.finalized OR EXCLUDED.finalized, updated_at = now()`,
      [
        channelId,
        String(state.payer).toLowerCase(),
        String(state.payee).toLowerCase(),
        String(state.token).toLowerCase(),
        state.authorizedSigner ? String(state.authorizedSigner).toLowerCase() : null,
        toBig(state.deposit).toString(),
        toBig(state.spent).toString(),
        toBig(state.settledOnChain).toString(),
        state.finalized === true,
      ],
    )
  }

  private async lockKey(client: PoolClient, key: string): Promise<void> {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 7031))', [key])
  }

  private async withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      const result = await fn(client)
      await client.query('COMMIT')
      return result
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {})
      throw error
    } finally {
      client.release()
    }
  }
}

type ChannelStateLike = {
  payer: unknown
  payee: unknown
  token: unknown
  authorizedSigner?: unknown
  deposit?: unknown
  spent?: unknown
  settledOnChain?: unknown
  finalized?: unknown
}

/** Channel keys are the normalized channel id, optionally behind a store key prefix. */
function channelKeyOf(key: string): string | undefined {
  const id = key.slice(-66)
  return CHANNEL_KEY.test(id) ? id : undefined
}

function isChannelState(value: unknown): value is ChannelStateLike {
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return v.backend === 'precompile' && typeof v.payer === 'string' && typeof v.payee === 'string' && typeof v.token === 'string'
}

function isReplayMarker(value: unknown): value is { expires: number; type: 'mppx:replay' } {
  return (
    !!value &&
    typeof value === 'object' &&
    (value as { type?: unknown }).type === 'mppx:replay' &&
    typeof (value as { expires?: unknown }).expires === 'number'
  )
}

function toBig(value: unknown): bigint {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value))
  if (typeof value === 'string' && /^\d+$/.test(value)) return BigInt(value)
  return 0n
}

function toChannelRow(row: Record<string, any>): ChannelRow {
  return {
    channelId: row.channel_id,
    payer: row.payer,
    payee: row.payee,
    token: row.token,
    authorizedSigner: row.authorized_signer,
    deposit: BigInt(row.deposit),
    spent: BigInt(row.spent),
    settled: BigInt(row.settled),
    finalized: row.finalized,
    updatedAt: row.updated_at,
  }
}
