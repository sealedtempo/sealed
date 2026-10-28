import type { ProviderId } from '../prices.js'

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>

/** A provider connection whose attestation was verified; `fetch` only reaches the attested endpoint. */
export type VerifiedChannel = {
  baseURL: string
  fetch: FetchLike
  /** Unix seconds after which the evidence must be refreshed. */
  expiresAt: number
  /** Short, content-free facts about what was verified (measurements, key pins). */
  evidence: Record<string, string>
  close?: () => Promise<void>
}

export interface ProviderVerifier {
  readonly provider: ProviderId
  /** Fetches fresh evidence with a new nonce and verifies it. Throws AttestationFailure on any failed check. */
  verify(): Promise<VerifiedChannel>
}

export type ProviderStatus = {
  provider: ProviderId
  enabled: boolean
  verified: boolean
  verifiedAt?: number
  expiresAt?: number
  detail: string
  evidence?: Record<string, string>
}

export class AttestationFailure extends Error {
  constructor(
    readonly check: string,
    message: string,
  ) {
    super(`${check}: ${message}`)
    this.name = 'AttestationFailure'
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}
