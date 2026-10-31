import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { dirname, join, parse } from 'node:path'
import { describe, expect, it } from 'vitest'
import YAML from 'yaml'

// Review finding policy-5 (D-069, license audit F10): the inference-relay bundle carries, in
// LICENSES/, the upstream license texts of what its images redistribute, byte for byte.
// LICENSE-NOTICE names each file, then "(<owner>/<repo> <ref> <path>, git blob <sha1>)", where the
// blob id is what `gh api repos/<owner>/<repo>/contents/<path>?ref=<ref>` reports as sha. Same
// format and check as llm-gateway (tests/license_texts.py) and scraper (runner/test/licenses.test.ts).

const relay = join(import.meta.dirname, '..')
const repo = join(relay, '../..')
const app = join(repo, 'catalog/apps/inference-relay')
const notice = readFileSync(join(app, 'LICENSE-NOTICE'), 'utf8')
const TEXT_ENTRY = /LICENSES\/([\w.-]+)\s*\n\s*\(([\w.-]+\/[\w.-]+) (\S+) (\S+), git blob ([0-9a-f]{40})\)/g

function gitBlobHash(data: Buffer): string {
  return createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${data.length}\0`), data])).digest('hex')
}

type NoticeText = { file: string; repo: string; ref: string; path: string; blob: string }

function noticeTexts(text: string): NoticeText[] {
  return [...text.matchAll(TEXT_ENTRY)].map((m) => ({
    file: m[1] ?? '',
    repo: m[2] ?? '',
    ref: m[3] ?? '',
    path: m[4] ?? '',
    blob: m[5] ?? '',
  }))
}

function present(): string[] {
  const dir = join(app, 'LICENSES')
  return existsSync(dir) ? readdirSync(dir).filter((n) => !n.startsWith('.')).sort() : []
}

describe('inference-relay upstream license texts (LICENSES/)', () => {
  const texts = noticeTexts(notice)

  it('ships the LiteLLM, PostgreSQL and @phala/dcap-qvl texts of the pinned versions, with their upstream blob ids', () => {
    expect(Object.fromEntries(texts.map((t) => [t.file, `${t.repo} ${t.ref} ${t.path} ${t.blob}`]))).toEqual({
      'litellm-v1.106.5-LICENSE': 'BerriAI/litellm v1.106.5 LICENSE 3bfef5bae9b48c334acf426d5b7f21bc1913aab9',
      'postgresql-16.15-COPYRIGHT': 'postgres/postgres REL_16_15 COPYRIGHT 0a397648dcd3c2177acc58bd7daecd11ad64be62',
      'phala-dcap-qvl-v0.7.0-LICENSE': 'Phala-Network/dcap-qvl v0.7.0 LICENSE 6f0b6ce4963f1a5a8ab3efa23ee4012cc37e5c9c',
    })
    // The refs are the versions the images run.
    const manifest = YAML.parse(readFileSync(join(app, 'manifest.yaml'), 'utf8')) as {
      images: { name: string; source: string }[]
    }
    expect(manifest.images.find((i) => i.name === 'postgres')?.source).toBe('docker.io/library/postgres:16.15')
    const dockerfile = readFileSync(join(app, 'images/litellm-relay/Dockerfile'), 'utf8')
    expect(dockerfile.match(/^FROM\s.*ghcr\.io\/berriai\/litellm-database:(v[\d.]+)@/m)?.[1]).toBe('v1.106.5')
    const pkg = JSON.parse(readFileSync(join(relay, 'package.json'), 'utf8')) as { dependencies: Record<string, string> }
    expect(`v${pkg.dependencies['@phala/dcap-qvl']}`).toBe('v0.7.0')
  })

  it('every text is byte for byte the upstream file', () => {
    expect(present()).not.toEqual([])
    for (const t of texts) {
      const path = join(app, 'LICENSES', t.file)
      expect(existsSync(path), `LICENSES/${t.file}`).toBe(true)
      expect(gitBlobHash(readFileSync(path)), t.file).toBe(t.blob)
    }
  })

  it('the LiteLLM text is the MIT grant with the enterprise/ carve-out the image relies on', () => {
    const litellm = readFileSync(join(app, 'LICENSES/litellm-v1.106.5-LICENSE'), 'utf8')
    expect(litellm).toContain('"enterprise/" directory')
    expect(litellm).toContain('MIT License')
    const postgres = readFileSync(join(app, 'LICENSES/postgresql-16.15-COPYRIGHT'), 'utf8')
    expect(postgres).toMatch(/^PostgreSQL Database Management System\n/)
  })

  it('LICENSE-NOTICE names every file in LICENSES/ with its source, and nothing else', () => {
    expect(texts.map((t) => t.file).sort()).toEqual(present())
    const mentioned = new Set([...notice.matchAll(/LICENSES\/([\w.-]+)/g)].map((m) => m[1]))
    expect([...mentioned].sort()).toEqual(present())
  })

  it("the hash is git's blob id", () => {
    // printf 'hello\n' | git hash-object --stdin
    expect(gitBlobHash(Buffer.from('hello\n'))).toBe('ce013625030ba8dba906f756967f9e9ca394464a')
  })
})

// The relay image ships runtime/relay's production node_modules as npm published them. A package
// whose npm tarball has no license text of its own (no LICENSE, COPYING or COPYRIGHT file, and no
// grant in its README) must be listed here: either with the upstream text LICENSES/ carries for it,
// or with the words LICENSE-NOTICE uses to say why there is none. LICENSE-NOTICE names both kinds.
const WITHOUT_OWN_TEXT: Record<string, { text: string } | { none: string }> = {
  '@phala/dcap-qvl@0.7.0': { text: 'phala-dcap-qvl-v0.7.0-LICENSE' },
  'tr46@0.0.3': { none: 'so there is no text of this version to ship' },
}

const TEXT_FILE = /^(un)?(licen[cs]e|copying|copyright)([._-].*)?$/i
const README_GRANT =
  /Permission is hereby granted|Permission to use, copy, modify|Licensed under the Apache License, Version 2\.0|Redistribution and use in source and binary forms/

type Installed = { name: string; version: string; dir: string }

function resolvePackage(name: string, fromDir: string): string | null {
  const { root } = parse(fromDir)
  for (let dir = fromDir; ; dir = dirname(dir)) {
    const candidate = join(dir, 'node_modules', name)
    if (existsSync(join(candidate, 'package.json'))) return realpathSync(candidate)
    if (dir === root) return null
  }
}

// The production dependency closure of runtime/relay (what pnpm deploy --prod puts in the image),
// found with Node's lookup rules from the package.json files.
function productionTree(): Installed[] {
  type Manifest = { name: string; version: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }
  const read = (dir: string) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Manifest
  const seen = new Map<string, Installed>()
  const queue = Object.keys(read(relay).dependencies ?? {}).map((name) => ({ name, from: relay, optional: false }))
  while (queue.length > 0) {
    const next = queue.shift()!
    const dir = resolvePackage(next.name, next.from)
    if (!dir) {
      if (next.optional) continue
      throw new Error(`${next.name} (needed from ${next.from}) is not installed; run pnpm install`)
    }
    if (seen.has(dir)) continue
    const m = read(dir)
    seen.set(dir, { name: m.name, version: m.version, dir })
    for (const name of Object.keys(m.dependencies ?? {})) queue.push({ name, from: dir, optional: false })
    for (const name of Object.keys(m.optionalDependencies ?? {})) queue.push({ name, from: dir, optional: true })
  }
  return [...seen.values()]
}

function ownText(pkg: Installed): boolean {
  const files = readdirSync(pkg.dir)
  if (files.some((f) => TEXT_FILE.test(f))) return true
  const readme = files.find((f) => /^readme(\.|$)/i.test(f))
  return readme !== undefined && README_GRANT.test(readFileSync(join(pkg.dir, readme), 'utf8'))
}

describe('relay image npm packages without a license text of their own', () => {
  const tree = productionTree()
  const without = tree.filter((p) => !ownText(p)).map((p) => `${p.name}@${p.version}`).sort()

  it('finds the whole production tree', () => {
    expect(tree.length).toBeGreaterThan(50)
    expect(tree.some((p) => p.name === 'mppx')).toBe(true)
    expect(tree.some((p) => p.name === 'vitest')).toBe(false)
  })

  it('are exactly the listed ones', () => {
    expect(without).toEqual(Object.keys(WITHOUT_OWN_TEXT).sort())
  })

  it('each has its upstream text in LICENSES/, or LICENSE-NOTICE says why there is none', () => {
    const files = new Set(noticeTexts(notice).map((t) => t.file))
    for (const [id, entry] of Object.entries(WITHOUT_OWN_TEXT)) {
      const at = id.lastIndexOf('@')
      const [name, version] = [id.slice(0, at), id.slice(at + 1)]
      expect(notice, id).toContain(`${name} ${version}`)
      if ('text' in entry) expect(files.has(entry.text), `${id}: LICENSES/${entry.text}`).toBe(true)
      else expect(notice, id).toContain(entry.none)
    }
  })
})
