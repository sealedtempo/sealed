import { createHash } from 'node:crypto'
import { AttestationFailure } from './types.js'

/** Fields of a verified TDX quote that provider checks need. */
export type VerifiedTdQuote = {
  tcbStatus: string
  advisoryIds: string[]
  reportData: Uint8Array
  rtmr3: Uint8Array
  mrConfigId: Uint8Array
  mrTd: Uint8Array
}

/** Verifies a raw TDX quote against Intel collateral. Implementations throw on an invalid signature chain. */
export interface QuoteVerifier {
  verify(quote: Uint8Array): Promise<VerifiedTdQuote>
}

export const INTEL_PCS_URL = 'https://api.trustedservices.intel.com'
export const DEFAULT_ALLOWED_TCB = ['UpToDate', 'SWHardeningNeeded'] as const

/** Quote verification with @phala/dcap-qvl (Apache-2.0), the verifier NEAR AI and Phala document. */
export function dcapQuoteVerifier(pccsUrl: string = INTEL_PCS_URL): QuoteVerifier {
  return {
    async verify(quote) {
      const qvl = (await import('@phala/dcap-qvl')).default as typeof import('@phala/dcap-qvl')
      let verified: Awaited<ReturnType<typeof qvl.getCollateralAndVerify>>
      try {
        verified = await qvl.getCollateralAndVerify(Buffer.from(quote), pccsUrl)
      } catch (error) {
        throw new AttestationFailure('quote', `TDX quote did not verify: ${(error as Error).message}`)
      }
      const td = verified.report.asTd10()
      if (!td) throw new AttestationFailure('quote', `quote is ${verified.report.type}, not a TDX TD report`)
      return {
        tcbStatus: verified.status,
        advisoryIds: verified.advisory_ids ?? [],
        reportData: td.reportData,
        rtmr3: td.rtMr3,
        mrConfigId: td.mrConfigId,
        mrTd: td.mrTd,
      }
    },
  }
}

export function assertTcbAllowed(quote: VerifiedTdQuote, allowed: readonly string[] = DEFAULT_ALLOWED_TCB): void {
  if (!allowed.includes(quote.tcbStatus))
    throw new AttestationFailure('tcb', `TCB status ${quote.tcbStatus} is not in the allowed list (${allowed.join(', ')})`)
}

export type DstackEvent = { imr: number; digest: string; event?: string; event_payload?: string; event_type?: number }

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) throw new AttestationFailure('format', 'invalid hex')
  return Uint8Array.from(Buffer.from(clean, 'hex'))
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.from(a).equals(Buffer.from(b))
}

export function parseEventLog(eventLog: unknown): DstackEvent[] {
  const parsed = typeof eventLog === 'string' ? JSON.parse(eventLog) : eventLog
  if (!Array.isArray(parsed)) throw new AttestationFailure('event_log', 'event log is not an array')
  return parsed as DstackEvent[]
}

/** RTMR3 = sha384(RTMR3 || digest) over the IMR 3 events, starting from 48 zero bytes. */
export function replayRtmr3(events: DstackEvent[]): Uint8Array {
  let rtmr: Buffer = Buffer.alloc(48)
  for (const event of events) {
    if (event.imr !== 3) continue
    const digest = Buffer.from(hexToBytes(event.digest))
    const padded = digest.length >= 48 ? digest : Buffer.concat([digest, Buffer.alloc(48 - digest.length)])
    rtmr = createHash('sha384').update(Buffer.concat([rtmr, padded])).digest()
  }
  return Uint8Array.from(rtmr)
}

/** dstack MRCONFIGID: 0x01 || sha256(app_compose) || 15 zero bytes. */
export function mrConfigIdForCompose(appCompose: string): Uint8Array {
  const out = Buffer.alloc(48)
  out[0] = 0x01
  createHash('sha256').update(appCompose, 'utf8').digest().copy(out, 1)
  return Uint8Array.from(out)
}

export function composeHash(appCompose: string): string {
  return createHash('sha256').update(appCompose, 'utf8').digest('hex')
}

/** Checks RTMR3 replay and the compose measurement for a dstack workload. Returns sha256(app_compose). */
export function verifyDstackMeasurements(
  quote: VerifiedTdQuote,
  eventLog: unknown,
  appCompose: string,
  acceptedComposeHashes: readonly string[] = [],
): string {
  const events = parseEventLog(eventLog)
  const replayed = replayRtmr3(events)
  if (!equalBytes(replayed, quote.rtmr3)) throw new AttestationFailure('rtmr3', 'event log does not replay to the quoted RTMR3')
  if (!equalBytes(mrConfigIdForCompose(appCompose), quote.mrConfigId))
    throw new AttestationFailure('compose', 'MRCONFIGID does not commit to sha256(app_compose)')
  const hash = composeHash(appCompose)
  const composeEvents = events.filter((e) => e.imr === 3 && e.event === 'compose-hash')
  if (composeEvents.length > 1) throw new AttestationFailure('compose', 'more than one compose-hash event')
  const measured = composeEvents[0]?.event_payload?.toLowerCase().replace(/^0x/, '')
  if (measured !== undefined && measured !== hash)
    throw new AttestationFailure('compose', 'compose-hash event does not equal sha256(app_compose)')
  if (acceptedComposeHashes.length > 0 && !acceptedComposeHashes.map((h) => h.toLowerCase().replace(/^0x/, '')).includes(hash))
    throw new AttestationFailure('compose', `compose hash ${hash} is not in the accepted list`)
  return hash
}
