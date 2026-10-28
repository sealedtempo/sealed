import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import YAML from 'yaml'

/**
 * Release blockers of the inference-relay catalog app that the composer's catalog lint does not
 * know about (it already blocks unbuilt images and fragment rule violations).
 */
export type Blocker = { code: 'treasury-placeholder' | 'treasury-invalid' | 'markup-drift' | 'unconfirmed-price' | 'unpinned-dev-flag'; detail: string }

export type ReleaseInputs = { fragment: string; prices: unknown; defaults: string }

export function releaseBlockers(inputs: ReleaseInputs): Blocker[] {
  const blockers: Blocker[] = []
  const fragment = YAML.parse(inputs.fragment) as { services: Record<string, { environment?: Record<string, unknown> }> }
  const front = fragment.services['inference-relay-front']?.environment ?? {}
  const treasury = String(front.TREASURY_ADDRESS ?? '')
  if (!/^0x[0-9a-f]{40}$/.test(treasury))
    blockers.push({ code: 'treasury-invalid', detail: `TREASURY_ADDRESS ${JSON.stringify(treasury)} is not a lowercase literal address` })
  else if (/^0x0{40}$/.test(treasury)) blockers.push({ code: 'treasury-placeholder', detail: 'TREASURY_ADDRESS is the zero-address placeholder' })
  const markup = (YAML.parse(inputs.defaults) as { relay_markup_bps?: unknown }).relay_markup_bps
  if (String(front.RELAY_MARKUP_BPS) !== String(markup))
    blockers.push({ code: 'markup-drift', detail: `RELAY_MARKUP_BPS ${String(front.RELAY_MARKUP_BPS)} differs from config/defaults.yaml relay_markup_bps ${String(markup)}` })
  for (const [name, service] of Object.entries(fragment.services))
    if (service.environment && 'ALLOW_UNPINNED_PROVIDER_CODE' in service.environment)
      blockers.push({ code: 'unpinned-dev-flag', detail: `${name} sets ALLOW_UNPINNED_PROVIDER_CODE` })
  const models = ((inputs.prices as { models?: { id: string; confirmed?: unknown }[] }).models ?? [])
  for (const m of models)
    if (m.confirmed !== true) blockers.push({ code: 'unconfirmed-price', detail: `${m.id}: list price not confirmed` })
  return blockers
}

export function repoReleaseInputs(repo: string): ReleaseInputs {
  return {
    fragment: readFileSync(join(repo, 'catalog/apps/inference-relay/compose.fragment.yaml'), 'utf8'),
    prices: JSON.parse(readFileSync(join(repo, 'runtime/relay/config/prices.json'), 'utf8')),
    defaults: readFileSync(join(repo, 'config/defaults.yaml'), 'utf8'),
  }
}
