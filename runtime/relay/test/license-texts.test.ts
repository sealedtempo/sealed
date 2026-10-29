import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import YAML from 'yaml'

// Review finding policy-5 (D-069, license audit F10): the inference-relay bundle carries, in
// LICENSES/, the upstream license texts of what its images redistribute, byte for byte.
// LICENSE-NOTICE names each file, then "(<owner>/<repo> <ref> <path>, git blob <sha1>)", where the
// blob id is what `gh api repos/<owner>/<repo>/contents/<path>?ref=<ref>` reports as sha. Same
// format and check as llm-gateway (tests/license_texts.py) and scraper (runner/test/licenses.test.ts).

const repo = join(import.meta.dirname, '../../..')
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

  it('ships the LiteLLM and PostgreSQL texts of the pinned versions, with their upstream blob ids', () => {
    expect(Object.fromEntries(texts.map((t) => [t.file, `${t.repo} ${t.ref} ${t.path} ${t.blob}`]))).toEqual({
      'litellm-v1.106.5-LICENSE': 'BerriAI/litellm v1.106.5 LICENSE 3bfef5bae9b48c334acf426d5b7f21bc1913aab9',
      'postgresql-16.15-COPYRIGHT': 'postgres/postgres REL_16_15 COPYRIGHT 0a397648dcd3c2177acc58bd7daecd11ad64be62',
    })
    // The refs are the versions the images run.
    const manifest = YAML.parse(readFileSync(join(app, 'manifest.yaml'), 'utf8')) as {
      images: { name: string; source: string }[]
    }
    expect(manifest.images.find((i) => i.name === 'postgres')?.source).toBe('docker.io/library/postgres:16.15')
    const dockerfile = readFileSync(join(app, 'images/litellm-relay/Dockerfile'), 'utf8')
    expect(dockerfile.match(/^FROM\s.*ghcr\.io\/berriai\/litellm-database:(v[\d.]+)@/m)?.[1]).toBe('v1.106.5')
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
