import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import YAML from 'yaml'

/**
 * Release blockers of the inference-relay catalog app that the composer's catalog lint does not
 * know about (it already blocks unbuilt images and fragment rule violations).
 */
export type Blocker = {
  code:
    | 'treasury-placeholder'
    | 'treasury-invalid'
    | 'treasury-mismatch'
    | 'fee-token-mismatch'
    | 'price-currency-mismatch'
    | 'markup-drift'
    | 'unconfirmed-price'
    | 'unsourced-price'
    | 'unpinned-dev-flag'
  detail: string
}

/**
 * fragment: compose.fragment.yaml; prices: runtime/relay/config/prices.json; defaults:
 * config/defaults.yaml; deployments: contracts/deployments/tempo-mainnet.json (optional, for the
 * treasury the contracts were deployed with).
 */
export type ReleaseInputs = { fragment: string; prices: unknown; defaults: string; deployments?: unknown }

const lower = (value: unknown) => (typeof value === 'string' ? value.toLowerCase() : '')

export function releaseBlockers(inputs: ReleaseInputs): Blocker[] {
  const blockers: Blocker[] = []
  const fragment = YAML.parse(inputs.fragment) as { services: Record<string, { environment?: Record<string, unknown> }> }
  const front = fragment.services['inference-relay-front']?.environment ?? {}
  const treasury = String(front.TREASURY_ADDRESS ?? '')
  if (!/^0x[0-9a-f]{40}$/.test(treasury))
    blockers.push({ code: 'treasury-invalid', detail: `TREASURY_ADDRESS ${JSON.stringify(treasury)} is not a lowercase literal address` })
  else if (/^0x0{40}$/.test(treasury)) blockers.push({ code: 'treasury-placeholder', detail: 'TREASURY_ADDRESS is the zero-address placeholder' })
  else if (inputs.deployments !== undefined) {
    const deployed = lower((inputs.deployments as { config?: { treasury?: unknown } })?.config?.treasury)
    if (treasury !== deployed)
      blockers.push({ code: 'treasury-mismatch', detail: `TREASURY_ADDRESS ${treasury} differs from the deployed treasury ${deployed || '(none)'}` })
  }
  const defaults = YAML.parse(inputs.defaults) as { relay_markup_bps?: unknown; chain?: { fee_token?: unknown } }
  const markup = defaults.relay_markup_bps
  if (String(front.RELAY_MARKUP_BPS) !== String(markup))
    blockers.push({ code: 'markup-drift', detail: `RELAY_MARKUP_BPS ${String(front.RELAY_MARKUP_BPS)} differs from config/defaults.yaml relay_markup_bps ${String(markup)}` })
  if (defaults.chain !== undefined) {
    const feeToken = lower(defaults.chain.fee_token)
    if (lower(front.FEE_TOKEN_ADDRESS) !== feeToken)
      blockers.push({ code: 'fee-token-mismatch', detail: `FEE_TOKEN_ADDRESS ${String(front.FEE_TOKEN_ADDRESS)} differs from config/defaults.yaml chain.fee_token ${feeToken}` })
    const currency = lower((inputs.prices as { currency?: unknown }).currency)
    if (currency !== feeToken)
      blockers.push({ code: 'price-currency-mismatch', detail: `prices.json currency ${currency} differs from chain.fee_token ${feeToken}` })
  }
  for (const [name, service] of Object.entries(fragment.services))
    if (service.environment && 'ALLOW_UNPINNED_PROVIDER_CODE' in service.environment)
      blockers.push({ code: 'unpinned-dev-flag', detail: `${name} sets ALLOW_UNPINNED_PROVIDER_CODE` })
  const models = (inputs.prices as { models?: { id: string; confirmed?: unknown; source?: unknown; checked?: unknown }[] }).models ?? []
  for (const m of models) {
    if (m.confirmed !== true) blockers.push({ code: 'unconfirmed-price', detail: `${m.id}: list price not confirmed` })
    else if (typeof m.source !== 'string' || !/^https:\/\//.test(m.source) || typeof m.checked !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(m.checked))
      blockers.push({ code: 'unsourced-price', detail: `${m.id}: a confirmed price needs an https source URL and the date it was read (checked)` })
  }
  return blockers
}

export function repoReleaseInputs(repo: string): ReleaseInputs {
  return {
    fragment: readFileSync(join(repo, 'catalog/apps/inference-relay/compose.fragment.yaml'), 'utf8'),
    prices: JSON.parse(readFileSync(join(repo, 'runtime/relay/config/prices.json'), 'utf8')),
    defaults: readFileSync(join(repo, 'config/defaults.yaml'), 'utf8'),
    deployments: JSON.parse(readFileSync(join(repo, 'contracts/deployments/tempo-mainnet.json'), 'utf8')),
  }
}
