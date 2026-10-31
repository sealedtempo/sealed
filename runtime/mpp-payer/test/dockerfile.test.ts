import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// RUN instructions with comment lines dropped and continuation lines joined, as BuildKit reads them.
const runInstructions = (dockerfileText: string) =>
  dockerfileText.split('\n').filter((l) => !l.trimStart().startsWith('#')).join('\n').replace(/\\\n/g, ' ').split('\n').filter((l) => /^RUN\s/.test(l))

// images-preflight: both stages were FROM --platform=linux/amd64. BuildKit labels the result with
// the requested platform, so a linux/arm64 build shipped an amd64 node under an arm64 label, which
// ran only through binfmt emulation (the class of docker-checks bug 4). Production images are still
// linux/amd64 because the runtime image workflow passes --platform linux/amd64.
const text = readFileSync(join(import.meta.dirname, '..', 'Dockerfile'), 'utf8')
const froms = text.split('\n').filter((l) => /^FROM\s/i.test(l))

describe('runtime/mpp-payer/Dockerfile', () => {
  it('builds every stage for the requested platform', () => {
    expect(froms.length).toBeGreaterThanOrEqual(2)
    for (const l of froms) expect(l).not.toMatch(/--platform=(?!\$BUILDPLATFORM\b)/)
  })

  it('pins every base image by digest', () => {
    for (const l of froms) expect(l).toMatch(/@sha256:[0-9a-f]{64}(\s|$)/)
  })

  // images-preflight: pnpm writes the install time into node_modules/.modules.yaml (prunedAt) and
  // .pnpm-workspace-state-v1.json (lastValidatedTimestamp). Shipped in the image, they gave every
  // build a new digest, so the runtime image workflow's no-cache rebuild check (exit 4) failed.
  it('drops the pnpm metadata that records the install time', () => {
    const runs = runInstructions(text)
    const deploy = runs.filter((r) => /pnpm .*deploy .*--prod|pnpm .*--prod .*deploy/.test(r))
    expect(deploy).toHaveLength(1)
    const run = deploy[0]!
    const rm = run.indexOf('rm -f /out/node_modules/.modules.yaml /out/node_modules/.pnpm-workspace-state*.json')
    expect(rm).toBeGreaterThan(run.search(/pnpm [^&]*deploy/))
  })
})
