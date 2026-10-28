import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { releaseBlockers, repoReleaseInputs } from './helpers/release-check.js'

const repo = join(import.meta.dirname, '../../..')

const fragment = (env: Record<string, string>) =>
  `services:\n  inference-relay-front:\n    environment:\n${Object.entries(env)
    .map(([k, v]) => `      ${k}: "${v}"`)
    .join('\n')}\n`
const confirmed = { models: [{ id: 'tinfoil/x', confirmed: true }] }

describe('inference-relay release check', () => {
  it('passes a pinned treasury, the configured markup and confirmed prices', () => {
    expect(releaseBlockers({ fragment: fragment({ TREASURY_ADDRESS: '0x' + 'ab'.repeat(20), RELAY_MARKUP_BPS: '500' }), prices: confirmed, defaults: 'relay_markup_bps: 500\n' })).toEqual([])
  })

  it('blocks the placeholder treasury, interpolation, markup drift, unconfirmed prices and the dev flag', () => {
    const codes = (env: Record<string, string>, prices: unknown = confirmed) =>
      releaseBlockers({ fragment: fragment(env), prices, defaults: 'relay_markup_bps: 500\n' }).map((b) => b.code)
    expect(codes({ TREASURY_ADDRESS: '0x' + '0'.repeat(40), RELAY_MARKUP_BPS: '500' })).toEqual(['treasury-placeholder'])
    expect(codes({ TREASURY_ADDRESS: '${TREASURY_ADDRESS}', RELAY_MARKUP_BPS: '500' })).toEqual(['treasury-invalid'])
    expect(codes({ TREASURY_ADDRESS: '0x' + 'AB'.repeat(20), RELAY_MARKUP_BPS: '500' })).toEqual(['treasury-invalid'])
    expect(codes({ TREASURY_ADDRESS: '0x' + 'ab'.repeat(20), RELAY_MARKUP_BPS: '700' })).toEqual(['markup-drift'])
    expect(codes({ TREASURY_ADDRESS: '0x' + 'ab'.repeat(20), RELAY_MARKUP_BPS: '500', ALLOW_UNPINNED_PROVIDER_CODE: '1' })).toEqual(['unpinned-dev-flag'])
    expect(codes({ TREASURY_ADDRESS: '0x' + 'ab'.repeat(20), RELAY_MARKUP_BPS: '500' }, { models: [{ id: 'a' }, { id: 'b', confirmed: false }] })).toEqual([
      'unconfirmed-price',
      'unconfirmed-price',
    ])
  })

  // Documents the open release items; update it as the operator pins the treasury and confirms prices.
  it.skipIf(process.env.RELEASE_CHECK === '1')('lists what still blocks this tree: the treasury placeholder and the unconfirmed prices', () => {
    const blockers = releaseBlockers(repoReleaseInputs(repo))
    expect(blockers.map((b) => b.code).sort()).toEqual(['treasury-placeholder', 'unconfirmed-price', 'unconfirmed-price', 'unconfirmed-price'])
  })

  // CI runs this before publishing a release: pnpm --filter @sealed/relay release-check
  it.runIf(process.env.RELEASE_CHECK === '1')('has no release blockers', () => {
    expect(releaseBlockers(repoReleaseInputs(repo))).toEqual([])
  })
})
