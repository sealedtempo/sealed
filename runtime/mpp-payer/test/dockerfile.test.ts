import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// images-preflight: both stages were FROM --platform=linux/amd64. BuildKit labels the result with
// the requested platform, so a linux/arm64 build shipped an amd64 node under an arm64 label, which
// ran only through binfmt emulation (the class of docker-checks bug 4). Production images are still
// linux/amd64 because the runtime image workflow passes --platform linux/amd64.
const froms = readFileSync(join(import.meta.dirname, '..', 'Dockerfile'), 'utf8')
  .split('\n')
  .filter((l) => /^FROM\s/i.test(l))

describe('runtime/mpp-payer/Dockerfile', () => {
  it('builds every stage for the requested platform', () => {
    expect(froms.length).toBeGreaterThanOrEqual(2)
    for (const l of froms) expect(l).not.toMatch(/--platform=(?!\$BUILDPLATFORM\b)/)
  })

  it('pins every base image by digest', () => {
    for (const l of froms) expect(l).toMatch(/@sha256:[0-9a-f]{64}(\s|$)/)
  })
})
