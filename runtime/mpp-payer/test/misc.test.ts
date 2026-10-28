import { execFileSync } from 'node:child_process'
import { X509Certificate } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CallerAllowlist } from '../src/caller-allowlist.js'
import { loadPayerConfig } from '../src/config.js'
import { CompletionAccumulator } from '../src/openai.js'
import { SpendGuard } from '../src/spend-guard.js'
import { SpendReporter } from '../src/spend-reporter.js'
import { fetchWithPeerKey, tlsPubKeyHash } from '../src/tls-capture.js'

describe('completion accumulator', () => {
  it('merges content, reasoning and tool-call fragments by index', () => {
    const acc = new CompletionAccumulator()
    const chunks = [
      { id: 'c', model: 'm', created: 5, choices: [{ index: 0, delta: { role: 'assistant', content: 'A' } }] },
      { choices: [{ index: 0, delta: { reasoning_content: 'think' } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 't1', type: 'function', function: { name: 'get', arguments: '{"a"' } }] } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: ':1}' } }] }, finish_reason: 'tool_calls' }] },
      { choices: [], usage: { prompt_tokens: 1, completion_tokens: 2 } },
    ]
    for (const c of chunks) acc.add(JSON.stringify(c))
    acc.add('not json')
    expect(acc.result('fallback')).toEqual({
      id: 'c',
      object: 'chat.completion',
      created: 5,
      model: 'm',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: 'A', reasoning_content: 'think', tool_calls: [{ id: 't1', type: 'function', function: { name: 'get', arguments: '{"a":1}' } }] },
          finish_reason: 'tool_calls',
        },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 2 },
    })
  })
})

describe('caller allowlist', () => {
  it('allows only resolved service addresses and loopback', async () => {
    const list = new CallerAllowlist(['llm-gateway'], async () => ['172.30.0.16'])
    expect(list.allows('172.30.0.16')).toBe(false)
    await list.refresh()
    expect(list.allows('::ffff:172.30.0.16')).toBe(true)
    expect(list.allows('172.30.0.17')).toBe(false)
    expect(list.allows('127.0.0.1')).toBe(true)
    expect(new CallerAllowlist([]).allows('10.0.0.1')).toBe(true)
  })

  it('keeps the last good addresses when DNS fails', async () => {
    let fail = false
    const list = new CallerAllowlist(['llm-gateway'], async () => {
      if (fail) throw new Error('ENOTFOUND')
      return ['172.30.0.16']
    })
    await list.refresh()
    fail = true
    await list.refresh()
    expect(list.allows('172.30.0.16')).toBe(true)
  })
})

describe('spend reporter', () => {
  it('posts content-free counters to sealed-agent', async () => {
    const guard = new SpendGuard(2_000_000n)
    guard.reserve(1_234n, 'charge')
    const sent: any[] = []
    const reporter = new SpendReporter({
      agentUrl: 'http://sealed-agent:7070',
      intervalSeconds: 60,
      snapshot: () => ({ mode: 'access-key', currency: '0x20c0000000000000000000000000000000000000', counters: guard.counters(), relay: { attested: true, checkedAt: 1, sessionsAvailable: true } }),
      fetch: async (url, init) => {
        sent.push({ url, body: JSON.parse(String(init.body)) })
        return new Response(null, { status: 204 })
      },
    })
    expect(await reporter.send()).toBe(true)
    expect(sent[0].url).toBe('http://sealed-agent:7070/v1/spend')
    expect(sent[0].body).toMatchObject({ source: 'sealed-mpp-payer', mode: 'access-key', counters: { charges: 1, chargeAmount: '1234', limit: '2000000' }, relay: { attested: true } })
    const failing = new SpendReporter({ agentUrl: 'http://x', intervalSeconds: 60, snapshot: () => ({ mode: 'm', currency: 'c', counters: guard.counters(), relay: { attested: false, sessionsAvailable: false } }), fetch: async () => new Response(null, { status: 500 }) })
    expect(await failing.send()).toBe(false)
  })
})

describe('payer configuration', () => {
  const dir = mkdtempSync(join(tmpdir(), 'payer-cfg-'))
  const secrets = join(dir, 'secrets')
  execFileSync('mkdir', ['-p', secrets])
  writeFileSync(join(secrets, 'ENCLAVE_KEY'), '0x' + '11'.repeat(32) + '\n')
  writeFileSync(join(secrets, 'SPEND_LIMIT_PER_DAY'), '2000000\n')
  const config = {
    schema: 'sealed-config/v1',
    chainId: 4217,
    customer: '0x' + 'Cc'.repeat(20),
    feeToken: '0x20c0000000000000000000000000000000000000',
    endpoints: { relay: 'https://relay.example', relayAttest: 'https://attest.relay.example/attest', tempoRpc: 'https://rpc.tempo.xyz' },
    settlement: { mode: 'access-key', spendLimitPerDay: '5000000' },
    relayOwner: '0x' + '0a'.repeat(20),
  }
  writeFileSync(join(dir, 'config.json'), JSON.stringify(config))
  const env = { SEALED_SECRETS_DIR: secrets, SEALED_CONFIG_PATH: join(dir, 'config.json') }

  it('reads the enclave key and daily limit from the payer tmpfs and the rest from the public config', () => {
    const c = loadPayerConfig(env)
    expect(c).toMatchObject({ port: 8090, chainId: 4217, mode: 'access-key', customer: '0x' + 'cc'.repeat(20), spendLimitPerDay: 2_000_000n, maxDeposit: 500_000n, relayUrl: 'https://relay.example', verifierdUrl: 'http://sealed-verifierd:8088', agentUrl: 'http://sealed-agent:7070', attestIntervalSeconds: 900, allowedCallers: ['llm-gateway'] })
  })

  it('refuses other chains, plain-http relays and missing keys', () => {
    writeFileSync(join(dir, 'bad.json'), JSON.stringify({ ...config, chainId: 1 }))
    expect(() => loadPayerConfig({ ...env, SEALED_CONFIG_PATH: join(dir, 'bad.json') })).toThrow(/chain 1/)
    writeFileSync(join(dir, 'http.json'), JSON.stringify({ ...config, endpoints: { ...config.endpoints, relay: 'http://relay.example' } }))
    expect(() => loadPayerConfig({ ...env, SEALED_CONFIG_PATH: join(dir, 'http.json') })).toThrow(/https/)
    expect(() => loadPayerConfig({ ...env, SEALED_SECRETS_DIR: join(dir, 'none') })).toThrow(/ENCLAVE_KEY/)
  })
})

describe('TLS key capture for /attest', () => {
  it('returns the SPKI hash of the connection that served the response', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'payer-tls-'))
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' })
    const cert = readFileSync(join(dir, 'c.pem'), 'utf8')
    const key = readFileSync(join(dir, 'k.pem'), 'utf8')
    rmSync(dir, { recursive: true, force: true })
    const server = createServer({ cert, key }, (req, res) => res.end(JSON.stringify({ url: req.url })))
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
    const { port } = server.address() as AddressInfo
    try {
      const captured = await fetchWithPeerKey(`https://localhost:${port}/attest?nonce=0x01`, { ca: cert })
      expect(captured.tlsPubKeyHash).toBe(tlsPubKeyHash(new X509Certificate(cert).raw))
      expect(await captured.response.json()).toEqual({ url: '/attest?nonce=0x01' })
      await expect(fetchWithPeerKey(`https://localhost:${port}/attest`)).rejects.toThrow()
      await expect(fetchWithPeerKey(`http://localhost:${port}/attest`)).rejects.toThrow(/https/)
    } finally {
      server.closeAllConnections()
      server.close()
    }
  })
})
