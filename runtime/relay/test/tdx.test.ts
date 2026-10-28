import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  assertTcbAllowed,
  mrConfigIdForCompose,
  replayRtmr3,
  verifyDstackMeasurements,
} from '../src/providers/tdx.js'
import { APP_COMPOSE, COMPOSE_HASH, eventLog, fakeQuote, fakeQuoteVerifier } from './helpers/fake-tdx.js'

describe('dstack measurement checks', () => {
  it('replays RTMR3 as sha384(rtmr || digest) from zero', () => {
    const log = eventLog()
    let expected = Buffer.alloc(48)
    for (const e of log) expected = createHash('sha384').update(Buffer.concat([expected, Buffer.from(e.digest, 'hex')])).digest()
    expect(Buffer.from(replayRtmr3(log)).equals(expected)).toBe(true)
    expect(Buffer.from(replayRtmr3([{ imr: 0, digest: 'ff'.repeat(48) }])).equals(Buffer.alloc(48))).toBe(true)
  })

  it('builds MRCONFIGID as 01 || sha256(app_compose) || zeros', () => {
    const id = Buffer.from(mrConfigIdForCompose(APP_COMPOSE))
    expect(id.length).toBe(48)
    expect(id[0]).toBe(1)
    expect(id.subarray(1, 33).toString('hex')).toBe(COMPOSE_HASH)
    expect(id.subarray(33).equals(Buffer.alloc(15))).toBe(true)
  })

  it('accepts a consistent quote, event log and compose', async () => {
    const quote = await fakeQuoteVerifier.verify(Buffer.from(fakeQuote({ reportData: new Uint8Array(64) }), 'hex'))
    expect(verifyDstackMeasurements(quote, eventLog(), APP_COMPOSE)).toBe(COMPOSE_HASH)
    expect(verifyDstackMeasurements(quote, JSON.stringify(eventLog()), APP_COMPOSE, [`0x${COMPOSE_HASH}`])).toBe(COMPOSE_HASH)
  })

  it('rejects RTMR3, compose and allowlist mismatches, and bad TCB', async () => {
    const good = await fakeQuoteVerifier.verify(Buffer.from(fakeQuote({ reportData: new Uint8Array(64) }), 'hex'))
    expect(() => verifyDstackMeasurements({ ...good, rtmr3: new Uint8Array(48) }, eventLog(), APP_COMPOSE)).toThrow(/rtmr3/)
    expect(() => verifyDstackMeasurements(good, eventLog(), `${APP_COMPOSE} `)).toThrow(/compose/)
    expect(() => verifyDstackMeasurements(good, eventLog(), APP_COMPOSE, ['00'.repeat(32)])).toThrow(/accepted list/)
    const otherLog = eventLog('11'.repeat(32))
    const quoteForOther = { ...good, rtmr3: replayRtmr3(otherLog) }
    expect(() => verifyDstackMeasurements(quoteForOther, otherLog, APP_COMPOSE)).toThrow(/compose-hash event/)
    expect(() => assertTcbAllowed({ ...good, tcbStatus: 'OutOfDate' })).toThrow(/TCB status OutOfDate/)
    expect(() => assertTcbAllowed({ ...good, tcbStatus: 'SWHardeningNeeded' })).not.toThrow()
  })
})
