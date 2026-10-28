import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { releaseBlockers, repoReleaseInputs } from './helpers/release-check.js'

const repo = join(import.meta.dirname, '../../..')

const USDCE = '0x20c000000000000000000000b9537d11c60e8b50'
const TREASURY = '0x' + 'ab'.repeat(20)
const fragment = (env: Record<string, string>) =>
  `services:\n  inference-relay-front:\n    environment:\n${Object.entries(env)
    .map(([k, v]) => `      ${k}: "${v}"`)
    .join('\n')}\n`
const confirmed = { currency: USDCE, models: [{ id: 'tinfoil/x', confirmed: true, source: 'https://tinfoil.sh/models', checked: '2026-10-28' }] }
const defaults = `relay_markup_bps: 500\nchain:\n  fee_token: "${USDCE}"\n`
const deployments = { config: { treasury: '0x' + 'AB'.repeat(20) } }
const good = { TREASURY_ADDRESS: TREASURY, RELAY_MARKUP_BPS: '500', FEE_TOKEN_ADDRESS: USDCE }

describe('inference-relay release check', () => {
  it('passes the deployed treasury, the configured markup and fee token, and sourced confirmed prices', () => {
    expect(releaseBlockers({ fragment: fragment(good), prices: confirmed, defaults, deployments })).toEqual([])
  })

  it('blocks the placeholder treasury, interpolation, markup drift, unconfirmed prices and the dev flag', () => {
    const codes = (env: Record<string, string>, prices: unknown = confirmed) =>
      releaseBlockers({ fragment: fragment(env), prices, defaults, deployments }).map((b) => b.code)
    expect(codes({ ...good, TREASURY_ADDRESS: '0x' + '0'.repeat(40) })).toEqual(['treasury-placeholder'])
    expect(codes({ ...good, TREASURY_ADDRESS: '${TREASURY_ADDRESS}' })).toEqual(['treasury-invalid'])
    expect(codes({ ...good, TREASURY_ADDRESS: '0x' + 'AB'.repeat(20) })).toEqual(['treasury-invalid'])
    expect(codes({ ...good, RELAY_MARKUP_BPS: '700' })).toEqual(['markup-drift'])
    expect(codes({ ...good, ALLOW_UNPINNED_PROVIDER_CODE: '1' })).toEqual(['unpinned-dev-flag'])
    expect(codes(good, { ...confirmed, models: [{ id: 'a' }, { id: 'b', confirmed: false }] })).toEqual(['unconfirmed-price', 'unconfirmed-price'])
  })

  it('blocks a treasury other than the deployed one, another fee token, and confirmed prices without a source', () => {
    const codes = (env: Record<string, string>, prices: unknown = confirmed) =>
      releaseBlockers({ fragment: fragment(env), prices, defaults, deployments }).map((b) => b.code)
    expect(codes({ ...good, TREASURY_ADDRESS: '0x' + 'cd'.repeat(20) })).toEqual(['treasury-mismatch'])
    expect(codes({ ...good, FEE_TOKEN_ADDRESS: '0x20c0000000000000000000000000000000000000' })).toEqual(['fee-token-mismatch'])
    expect(codes(good, { ...confirmed, currency: '0x20c0000000000000000000000000000000000000' })).toEqual(['price-currency-mismatch'])
    expect(codes(good, { ...confirmed, models: [{ id: 'a', confirmed: true }] })).toEqual(['unsourced-price'])
    expect(codes(good, { ...confirmed, models: [{ id: 'a', confirmed: true, source: 'third-party aggregator', checked: '2026-10-28' }] })).toEqual([
      'unsourced-price',
    ])
    expect(codes(good, { ...confirmed, models: [{ id: 'a', confirmed: true, source: 'https://tinfoil.sh/models' }] })).toEqual(['unsourced-price'])
  })

  // Documents the open release items; update it as the operator confirms the remaining prices.
  it.skipIf(process.env.RELEASE_CHECK === '1')('lists what still blocks this tree: nothing since Privatemode was dropped (D-055)', () => {
    expect(releaseBlockers(repoReleaseInputs(repo))).toEqual([])
  })

  // CI runs this before publishing a release: pnpm --filter @sealed/relay release-check
  it.runIf(process.env.RELEASE_CHECK === '1')('has no release blockers', () => {
    expect(releaseBlockers(repoReleaseInputs(repo))).toEqual([])
  })
})
