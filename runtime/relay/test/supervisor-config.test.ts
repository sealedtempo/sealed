import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { Account } from 'viem/tempo'
import { generatePrivateKey } from 'viem/accounts'
import { databaseUrl, loadRelayConfig, readSecret } from '../src/config.js'
import { SettlementSupervisor } from '../src/supervisor.js'
import { verifierFor } from '../src/sidecar-main.js'

describe('settlement supervisor', () => {
  it('supervises open channels, threads previousBlock and retires terminal channels', async () => {
    const finalized: string[] = []
    const calls: any[] = []
    const ids = ['0x' + '01'.repeat(32), '0x' + '02'.repeat(32), '0x' + '03'.repeat(32)] as `0x${string}`[]
    const supervisor = new SettlementSupervisor({
      db: {
        listChannels: async () => ids.map((channelId) => ({ channelId }) as never),
        markFinalized: async (id: string) => void finalized.push(id),
      },
      store: {} as never,
      client: {} as never,
      account: Account.fromSecp256k1(generatePrivateKey()),
      schedule: { amount: 1_000_000n },
      supervise: async (p) => {
        calls.push(p)
        return {
          block: 100n + BigInt(calls.length),
          complete: calls.length === 1,
          supervised: 3,
          settled: 1,
          closed: 1,
          failed: 0,
          unrecovered: 0,
          channels: [
            { channelId: ids[0]!, outcome: 'settled' },
            { channelId: ids[1]!, outcome: 'closed' },
            { channelId: ids[2]!, outcome: 'open' },
          ],
        }
      },
    })
    const first = await supervisor.runOnce()
    expect(first).toMatchObject({ supervised: 3, settled: 1, closed: 1, finalized: [ids[1]] })
    expect(calls[0]).toMatchObject({ channelIds: ids, previousBlock: undefined, settlementSchedule: { amount: 1_000_000n } })
    await supervisor.runOnce()
    expect(calls[1].previousBlock).toBe(101n) // only a complete run advances the bound
    await supervisor.runOnce()
    expect(calls[2].previousBlock).toBe(101n)
    expect(finalized).toEqual([ids[1], ids[1], ids[1]])
  })
})

describe('relay configuration', () => {
  const secrets = mkdtempSync(join(tmpdir(), 'relay-secrets-'))
  writeFileSync(join(secrets, 'MPP_SECRET_KEY'), 'k'.repeat(40) + '\n')
  writeFileSync(join(secrets, 'LITELLM_MASTER_KEY'), 'sk-master\n')
  writeFileSync(join(secrets, 'DATABASE_PASSWORD'), 'p@ss/word')
  writeFileSync(join(secrets, 'NEARAI_API_KEY'), 'near-key')
  writeFileSync(join(secrets, 'TINFOIL_API_KEY'), '')
  const env = { SEALED_SECRETS_DIR: secrets, MPP_REALM: 'relay.example', TREASURY_ADDRESS: '0x' + 'Aa'.repeat(20), FEE_TOKEN_ADDRESS: '0x20C000000000000000000000b9537d11c60E8b50' }

  it('reads secrets from tmpfs files and enables only providers with keys', () => {
    const config = loadRelayConfig(env)
    expect(config.secretKey).toBe('k'.repeat(40))
    expect(config.recipient).toBe('0x' + 'aa'.repeat(20))
    expect(config.markupBps).toBe(500)
    expect(config.chainId).toBe(4217)
    expect(config.currency).toBe('0x20c000000000000000000000b9537d11c60e8b50')
    expect(config.databaseUrl).toBe('postgresql://relay:p%40ss%2Fword@inference-relay-db:5432/relay')
    const enabled = config.providers.filter((p) => p.enabled).map((p) => p.provider)
    expect(enabled).toEqual(['nearai'])
    expect(config.providers.find((p) => p.provider === 'privatemode')).toMatchObject({ kind: 'privatemode', statusUrl: 'http://inference-relay-privatemode:8080' })
    expect(config.settlerKey).toBeUndefined()
  })

  it('rejects weak secrets and bad addresses', () => {
    expect(() => loadRelayConfig({ ...env, MPP_SECRET_KEY: 'short' })).toThrow(/32 bytes/)
    expect(() => loadRelayConfig({ ...env, TREASURY_ADDRESS: '0x1234' })).toThrow(/address/)
    expect(() => loadRelayConfig({ ...env, TREASURY_ADDRESS: '0x' + '0'.repeat(40) })).toThrow(/zero-address placeholder/)
    expect(() => loadRelayConfig({ ...env, RELAY_SETTLER_KEY: '0xabc' })).toThrow(/32-byte/)
    // No implicit pathUSD: the currency is the fragment's FEE_TOKEN_ADDRESS.
    expect(() => loadRelayConfig({ ...env, FEE_TOKEN_ADDRESS: '' })).toThrow(/FEE_TOKEN_ADDRESS/)
    expect(() => databaseUrl({ SEALED_SECRETS_DIR: '/nonexistent' })).toThrow(/DATABASE/)
  })

  it('prefers env over files and treats empty values as absent', () => {
    expect(readSecret('TINFOIL_API_KEY', env)).toBeUndefined()
    expect(readSecret('TINFOIL_API_KEY', { ...env, TINFOIL_API_KEY: 'x' })).toBe('x')
  })

  it('builds sidecar verifiers only for configured providers', () => {
    expect(verifierFor('nearai', env)?.provider).toBe('nearai')
    expect(verifierFor('tinfoil', env)).toBeUndefined()
    expect(() => verifierFor('privatemode', { ...env, PRIVATEMODE_API_KEY: 'x' })).toThrow(/proxy/)
  })
})
