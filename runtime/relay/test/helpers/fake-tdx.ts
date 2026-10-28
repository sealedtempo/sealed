import { createHash } from 'node:crypto'
import type { QuoteVerifier, VerifiedTdQuote } from '../../src/providers/tdx.js'
import { mrConfigIdForCompose, osMeasurementsHash, replayRtmr3 } from '../../src/providers/tdx.js'

export const APP_COMPOSE = '{"docker_compose_file":"services: {}","manifest_version":2,"name":"gateway"}'
export const COMPOSE_HASH = createHash('sha256').update(APP_COMPOSE).digest('hex')

export function eventLog(composeHash = COMPOSE_HASH) {
  const ev = (event: string, payload: string) => ({
    imr: 3,
    event_type: 134217729,
    event,
    event_payload: payload,
    digest: createHash('sha384').update(`${event}:${payload}`).digest('hex'),
  })
  return [ev('system-preparing', ''), ev('compose-hash', composeHash), ev('system-ready', '')]
}

/** A stand-in "quote": hex of JSON carrying the TD fields a real verified quote would expose. */
export function fakeQuote(fields: { reportData: Uint8Array; rtmr3?: Uint8Array; mrConfigId?: Uint8Array; tcbStatus?: string }): string {
  const json = JSON.stringify({
    reportData: Buffer.from(fields.reportData).toString('hex'),
    rtmr3: Buffer.from(fields.rtmr3 ?? replayRtmr3(eventLog())).toString('hex'),
    mrConfigId: Buffer.from(fields.mrConfigId ?? mrConfigIdForCompose(APP_COMPOSE)).toString('hex'),
    tcbStatus: fields.tcbStatus ?? 'UpToDate',
  })
  return Buffer.from(json).toString('hex')
}

/** OS measurements of the fake quotes: MRTD 0x11.., RTMR0 0x22.., RTMR1 0x33.., RTMR2 0x44... */
const OS = { mrTd: new Uint8Array(48).fill(0x11), rtmr0: new Uint8Array(48).fill(0x22), rtmr1: new Uint8Array(48).fill(0x33), rtmr2: new Uint8Array(48).fill(0x44) }
export const OS_MEASUREMENTS_HASH = osMeasurementsHash({ ...OS, tcbStatus: '', advisoryIds: [], reportData: new Uint8Array(), rtmr3: new Uint8Array(), mrConfigId: new Uint8Array() })

export const fakeQuoteVerifier: QuoteVerifier = {
  async verify(quote: Uint8Array): Promise<VerifiedTdQuote> {
    const f = JSON.parse(Buffer.from(quote).toString('utf8'))
    return {
      tcbStatus: f.tcbStatus,
      advisoryIds: [],
      reportData: Uint8Array.from(Buffer.from(f.reportData, 'hex')),
      rtmr3: Uint8Array.from(Buffer.from(f.rtmr3, 'hex')),
      mrConfigId: Uint8Array.from(Buffer.from(f.mrConfigId, 'hex')),
      ...OS,
    }
  },
}
