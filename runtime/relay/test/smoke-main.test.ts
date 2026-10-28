import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { existsSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { postgresAvailable, startCluster } from './helpers/pg.js'

const built = join(import.meta.dirname, '../dist/main.js')

describe.skipIf(!postgresAvailable() || !existsSync(built))('relay process smoke test (built dist, throwaway Postgres)', () => {
  it('starts, migrates its store, publishes models and refuses unattested providers', async () => {
    const cluster = await startCluster()
    const secrets = mkdtempSync(join(tmpdir(), 'relay-smoke-'))
    writeFileSync(join(secrets, 'MPP_SECRET_KEY'), 's'.repeat(40))
    writeFileSync(join(secrets, 'LITELLM_MASTER_KEY'), 'sk-test')
    writeFileSync(join(secrets, 'TINFOIL_API_KEY'), 'tk')
    const port = 18000 + Math.floor(Math.random() * 1000)
    const proc = spawn('node', [built], {
      env: { ...process.env, SEALED_SECRETS_DIR: secrets, DATABASE_URL: cluster.url, MPP_REALM: 'relay.test', TREASURY_ADDRESS: '0x' + 'ab'.repeat(20), FEE_TOKEN_ADDRESS: '0x20c000000000000000000000b9537d11c60e8b50', PORT: String(port), TINFOIL_STATUS_URL: 'http://127.0.0.1:1/v1/status' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let output = ''
    proc.stdout.on('data', (d) => (output += d))
    proc.stderr.on('data', (d) => (output += d))
    try {
      const deadline = Date.now() + 15_000
      while (!output.includes('relay_started')) {
        if (Date.now() > deadline || proc.exitCode !== null) throw new Error(`relay did not start: ${output}`)
        await new Promise((r) => setTimeout(r, 100))
      }
      const models = await (await fetch(`http://127.0.0.1:${port}/v1/models`)).json()
      expect(models.data.length).toBeGreaterThan(0)
      const status = await (await fetch(`http://127.0.0.1:${port}/v1/attest-status`)).json()
      expect(status.providers.tinfoil.enabled).toBe(true)
      expect(status.providers.phala.enabled).toBe(false)
      const chat = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'tinfoil/gpt-oss-120b', messages: [{ role: 'user', content: 'x' }] }),
      })
      expect(chat.status).toBe(503)
      expect(output).toContain('"providers":["tinfoil"]')
    } finally {
      proc.kill('SIGTERM')
      await new Promise((r) => proc.once('exit', r))
      cluster.stop()
    }
  })
})
