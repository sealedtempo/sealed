import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { loadPayerConfig } from '../src/config.js'
import { privateStateDir } from '../src/state-dir.js'

const mode = (p: string) => statSync(p).mode & 0o7777

describe('payer state directory is private at boot (merge C open issue)', () => {
  let root: string
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'payer-state-'))
  })
  afterEach(() => rmSync(root, { recursive: true, force: true }))

  it('narrows a 0755 directory to 0700 and keeps its files', () => {
    const dir = join(root, 'state')
    mkdirSync(dir)
    chmodSync(dir, 0o755)
    writeFileSync(join(dir, 'channels.json'), '{}')
    privateStateDir(dir)
    expect(mode(dir)).toBe(0o700)
    expect(readFileSync(join(dir, 'channels.json'), 'utf8')).toBe('{}')
  })

  it('creates a missing directory 0700', () => {
    const dir = join(root, 'a', 'b')
    privateStateDir(dir)
    expect(statSync(dir).isDirectory()).toBe(true)
    expect(mode(dir)).toBe(0o700)
  })

  it('refuses a symlink and leaves its target alone', () => {
    const target = join(root, 'elsewhere')
    mkdirSync(target)
    chmodSync(target, 0o755)
    const link = join(root, 'state')
    symlinkSync(target, link)
    expect(() => privateStateDir(link)).toThrow(/not a symlink/)
    expect(mode(target)).toBe(0o755)
  })

  it('refuses a directory another uid owns', () => {
    const dir = join(root, 'state')
    mkdirSync(dir)
    chmodSync(dir, 0o755)
    const euid = process.geteuid?.() ?? 0
    expect(() => privateStateDir(dir, euid + 1)).toThrow(/owned by uid/)
    expect(mode(dir)).toBe(0o755)
  })

  it('refuses a file in its place', () => {
    const file = join(root, 'state')
    writeFileSync(file, '')
    expect(() => privateStateDir(file)).toThrow(/STATE_DIR/)
  })

  it('main applies it to STATE_DIR before any store is opened', () => {
    const dir = mkdtempSync(join(tmpdir(), 'payer-cfg-'))
    try {
      const secrets = join(dir, 'secrets')
      mkdirSync(secrets)
      writeFileSync(join(secrets, 'ENCLAVE_KEY'), `0x${'11'.repeat(32)}`)
      writeFileSync(join(secrets, 'SPEND_LIMIT_PER_DAY'), '2000000')
      writeFileSync(
        join(dir, 'config.json'),
        JSON.stringify({
          customer: `0x${'22'.repeat(20)}`,
          relayOwner: `0x${'33'.repeat(20)}`,
          feeToken: '0x20c0000000000000000000000000000000000000',
          chainId: 4217,
          endpoints: { relay: 'https://relay.example', relayAttest: 'https://relay.example/attest' },
        }),
      )
      const c = loadPayerConfig({ SEALED_CONFIG_PATH: join(dir, 'config.json'), SEALED_SECRETS_DIR: secrets, STATE_DIR: '/data/payer' })
      expect(c.stateDir).toBe('/data/payer')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
    const main = readFileSync(new URL('../src/main.ts', import.meta.url), 'utf8')
    const call = main.indexOf('privateStateDir(config.stateDir)')
    expect(call).toBeGreaterThan(main.indexOf('loadPayerConfig()'))
    for (const store of ['new FileSpendStore(', 'new ChannelJournal(', 'new FileKv(']) {
      expect(main.indexOf(store)).toBeGreaterThan(call)
    }
  })
})
