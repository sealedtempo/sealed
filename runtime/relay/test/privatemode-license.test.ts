import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'

const checker = join(import.meta.dirname, '../../../catalog/apps/inference-relay/license/check-privatemode-proxy.mjs')
const { linkedPackages, violations, checkBinary, MAIN_MODULE } = await import(checker)

const haveGo = spawnSync('go', ['version']).status === 0

describe('privatemode-proxy license check', () => {
  it('reads the main module packages from go tool nm output', () => {
    const nm = [
      ' 100 T github.com/edgelesssys/privatemode-public/privatemode-proxy/internal/server.(*Server).Serve',
      ' 101 T github.com/edgelesssys/privatemode-public/internal/oss/secretmanager.New',
      ' 102 D github.com/edgelesssys/privatemode-public/internal/gpu.attest',
      ' 103 T github.com/other/mod.Func',
      ' 104 T main.main',
    ].join('\n')
    const packages = linkedPackages(nm)
    expect(packages).toEqual([
      `${MAIN_MODULE}/internal/gpu`,
      `${MAIN_MODULE}/internal/oss/secretmanager`,
      `${MAIN_MODULE}/privatemode-proxy/internal/server`,
    ])
    expect(violations(packages)).toEqual([`${MAIN_MODULE}/internal/gpu`])
  })

  describe.skipIf(!haveGo)('on a built binary', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pm-license-'))
    afterAll(() => rmSync(dir, { recursive: true, force: true }))

    function build(withRestricted: boolean): string {
      const src = join(dir, withRestricted ? 'bad' : 'good')
      const file = (rel: string, text: string) => {
        mkdirSync(join(src, rel, '..'), { recursive: true })
        writeFileSync(join(src, rel), text)
      }
      file('go.mod', `module ${MAIN_MODULE}\n\ngo 1.24\n`)
      file('internal/oss/attest/attest.go', 'package attest\n\n//go:noinline\nfunc Verify(s string) int { return len(s) + 1 }\n')
      file('internal/closed/closed.go', 'package closed\n\n//go:noinline\nfunc Secret(s string) int { return len(s) * 3 }\n')
      const imports = withRestricted ? `"${MAIN_MODULE}/internal/closed"\n\t` : ''
      const call = withRestricted ? ' + closed.Secret(os.Args[0])' : ''
      file(
        'privatemode-proxy/main.go',
        `package main\n\nimport (\n\t${imports}"os"\n\n\t"${MAIN_MODULE}/internal/oss/attest"\n)\n\nfunc main() { os.Exit(attest.Verify(os.Args[0])${call}) }\n`,
      )
      const out = join(src, 'privatemode-proxy.bin')
      const res = spawnSync('go', ['build', '-o', out, './privatemode-proxy'], { cwd: src, env: { ...process.env, GOWORK: 'off', GOFLAGS: '-mod=mod' }, encoding: 'utf8' })
      if (res.status !== 0) throw new Error(res.stderr)
      return out
    }

    it('passes a binary linking only MIT directories and fails one that links another package', () => {
      const good = checkBinary(build(false))
      expect(good.problems).toEqual([])
      expect(good.packages).toContain(`${MAIN_MODULE}/internal/oss/attest`)
      const bad = checkBinary(build(true))
      expect(bad.problems).toEqual([`links ${MAIN_MODULE}/internal/closed, outside the MIT-licensed directories`])
    }, 120_000)
  })
})
