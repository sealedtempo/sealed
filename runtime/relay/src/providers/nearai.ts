import { createHash, randomBytes } from 'node:crypto'
import { createCapturingFetch, createPinnedFetch } from './pinned-fetch.js'
import {
  type QuoteVerifier,
  assertTcbAllowed,
  bytesToHex,
  dcapQuoteVerifier,
  equalBytes,
  hexToBytes,
  verifyDstackMeasurements,
} from './tdx.js'
import { AttestationFailure, type FetchLike, type ProviderVerifier, type VerifiedChannel, nowSeconds } from './types.js'

/**
 * NEAR AI Cloud gateway attestation (docs.near.ai/cloud/verification, gateway + TLS flows).
 * One TLS connection carries the report request, so the peer key we observe is the key
 * the quote binds. Checks, in order: nonce echo, Intel DCAP quote and TCB, report_data
 * layout `sha256(signing_address || spki_sha256) || nonce`, observed SPKI equals the
 * attested fingerprint, RTMR3 replay, MRCONFIGID commits to app_compose, optional compose
 * allowlist. Inference then runs over a transport pinned to that SPKI.
 */
export type NearAiOptions = {
  baseURL?: string
  apiKey: string
  quoteVerifier?: QuoteVerifier
  allowedTcb?: readonly string[]
  acceptedComposeHashes?: readonly string[]
  evidenceTtlSeconds?: number
  proxy?: string
  ca?: string | Buffer
  /** Test seam: replaces the capturing transport (must report the SPKI it observed). */
  transport?: () => { fetch: FetchLike; observedSpki: () => string | undefined; close: () => Promise<void> }
}

type GatewayAttestation = {
  intel_quote?: string
  event_log?: unknown
  request_nonce?: string
  report_data?: string
  signing_address?: string
  signing_algo?: string
  tls_cert_fingerprint?: string
  info?: { tcb_info?: unknown }
}

export const NEARAI_DEFAULT_BASE_URL = 'https://cloud-api.near.ai'

export function nearAiVerifier(options: NearAiOptions): ProviderVerifier {
  const baseURL = (options.baseURL ?? NEARAI_DEFAULT_BASE_URL).replace(/\/+$/, '')
  const quoteVerifier = options.quoteVerifier ?? dcapQuoteVerifier()
  const ttl = options.evidenceTtlSeconds ?? 600
  return {
    provider: 'nearai',
    async verify(): Promise<VerifiedChannel> {
      const nonce = randomBytes(32).toString('hex')
      const transport =
        options.transport?.() ?? createCapturingFetch({ baseURL, proxy: options.proxy, ca: options.ca })
      let report: { gateway_attestation?: GatewayAttestation }
      try {
        const url = new URL(`${baseURL}/v1/attestation/report`)
        url.searchParams.set('signing_algo', 'ecdsa')
        url.searchParams.set('nonce', nonce)
        url.searchParams.set('include_tls_fingerprint', 'true')
        const res = await transport.fetch(url, {
          headers: { accept: 'application/json', authorization: `Bearer ${options.apiKey}` },
        })
        if (!res.ok) throw new AttestationFailure('fetch', `attestation report HTTP ${res.status}`)
        report = (await res.json()) as typeof report
      } finally {
        await transport.close().catch(() => {})
      }
      const observed = transport.observedSpki()
      if (!observed) throw new AttestationFailure('tls', 'no TLS peer key observed for the report connection')
      const gateway = report.gateway_attestation
      if (!gateway?.intel_quote) throw new AttestationFailure('format', 'report has no gateway_attestation.intel_quote')
      const composeHash = verifyGatewayAttestation(gateway, {
        nonce,
        observedSpki: observed,
        quote: await quoteVerifier.verify(hexToBytes(gateway.intel_quote)),
        allowedTcb: options.allowedTcb,
        acceptedComposeHashes: options.acceptedComposeHashes,
      })
      const pinned = createPinnedFetch({ baseURL, pins: [observed], proxy: options.proxy, ca: options.ca })
      return {
        baseURL: `${baseURL}/v1`,
        fetch: pinned.fetch,
        close: pinned.close,
        expiresAt: nowSeconds() + ttl,
        evidence: {
          tlsSpkiSha256: observed,
          composeHash,
          signingAddress: String(gateway.signing_address).toLowerCase(),
        },
      }
    },
  }
}

/** Pure check of one gateway attestation against an already verified quote. Returns the compose hash. */
export function verifyGatewayAttestation(
  gateway: GatewayAttestation,
  ctx: {
    nonce: string
    observedSpki: string
    quote: Awaited<ReturnType<QuoteVerifier['verify']>>
    allowedTcb?: readonly string[]
    acceptedComposeHashes?: readonly string[]
  },
): string {
  if (gateway.request_nonce?.toLowerCase() !== ctx.nonce)
    throw new AttestationFailure('nonce', 'request_nonce does not echo our nonce')
  if (gateway.signing_algo && gateway.signing_algo !== 'ecdsa')
    throw new AttestationFailure('signer', `unexpected signing_algo ${gateway.signing_algo}`)
  assertTcbAllowed(ctx.quote, ctx.allowedTcb)
  const signer = gateway.signing_address
  if (!signer || !/^0x[0-9a-fA-F]{40}$/.test(signer)) throw new AttestationFailure('signer', 'signing_address missing or malformed')
  const fingerprint = gateway.tls_cert_fingerprint?.toLowerCase().replace(/^0x/, '')
  if (!fingerprint || !/^[0-9a-f]{64}$/.test(fingerprint))
    throw new AttestationFailure('tls', 'tls_cert_fingerprint missing; TLS binding unavailable')
  const expected = Buffer.concat([
    createHash('sha256')
      .update(Buffer.concat([Buffer.from(hexToBytes(signer)), Buffer.from(hexToBytes(fingerprint))]))
      .digest(),
    Buffer.from(hexToBytes(ctx.nonce)),
  ])
  if (!equalBytes(Uint8Array.from(expected), ctx.quote.reportData))
    throw new AttestationFailure('report_data', 'quote report_data does not bind signing_address, TLS key and nonce')
  if (gateway.report_data && gateway.report_data.toLowerCase().replace(/^0x/, '') !== bytesToHex(ctx.quote.reportData))
    throw new AttestationFailure('report_data', 'HTTP report_data differs from the verified quote')
  if (fingerprint !== ctx.observedSpki.toLowerCase())
    throw new AttestationFailure('tls', 'attested TLS key differs from the key of this connection')
  const appCompose = appComposeOf(gateway.info?.tcb_info)
  return verifyDstackMeasurements(ctx.quote, gateway.event_log, appCompose, ctx.acceptedComposeHashes)
}

function appComposeOf(tcbInfo: unknown): string {
  const info = typeof tcbInfo === 'string' ? (JSON.parse(tcbInfo) as unknown) : tcbInfo
  const compose = info && typeof info === 'object' ? (info as { app_compose?: unknown }).app_compose : undefined
  if (typeof compose !== 'string') throw new AttestationFailure('compose', 'info.tcb_info.app_compose missing')
  return compose
}
