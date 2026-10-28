// dstack runtime event log (RTMR3, event log v1) and the dev simulator quote format
// (INTERFACES sections 6 and 15).
import { sha256, sha384 } from "@noble/hashes/sha2";
import { canonicalize, parseCJSON } from "./cjson.js";
import { bytesToBareHex, concatBytes, equalBytes, hexToBytes, utf8 } from "./hex.js";

export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

// A type alias (not an interface) so it stays assignable to the loose zod event-log schema.
export type DstackEvent = {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
};

/** Event names and order a Sealed stack must produce (INTERFACES 6). */
export const SEALED_RTMR3_EVENTS = [
  "system-preparing",
  "app-id",
  "compose-hash",
  "gpu-policy-hash",
  "instance-id",
  "boot-mr-done",
  "key-provider",
  "storage-fs",
  "storage-encrypted",
  "system-ready",
] as const;

/** sha256(JCS({})): the gpu-policy-hash payload when the compose sets no GPU policy. */
export const NO_GPU_POLICY_HASH = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
export const TPM_KEY_PROVIDER_PAYLOAD = '{"name":"tpm","id":""}';

/** digest = sha384(le32(0x08000001) || ":" || name || ":" || payload) */
export function eventDigestV1(name: string, payload: Uint8Array): Uint8Array {
  const type = Uint8Array.of(0x01, 0x00, 0x00, 0x08);
  return sha384(concatBytes(type, utf8(":"), utf8(name), utf8(":"), payload));
}

export function makeEvent(name: string, payload: Uint8Array): DstackEvent {
  return {
    imr: 3,
    event_type: DSTACK_RUNTIME_EVENT_TYPE,
    digest: bytesToBareHex(eventDigestV1(name, payload)),
    event: name,
    event_payload: bytesToBareHex(payload),
  };
}

/** RTMR3 = fold(sha384(acc || digest)) from 48 zero bytes, over the imr 3 entries in order. */
export function replayRtmr3(events: readonly DstackEvent[]): Uint8Array {
  let mr: Uint8Array = new Uint8Array(48);
  for (const e of events) {
    if (e.imr !== 3) continue;
    mr = sha384(concatBytes(mr, hexToBytes(e.digest, 48)));
  }
  return mr;
}

export interface SealedEventLogInputs {
  appCompose: string;
  appId?: Uint8Array;
  instanceId?: Uint8Array;
}

/**
 * The exact RTMR3 event sequence dstack 0.6.1 emits for a Sealed app-compose (no init scripts,
 * no GPU policy, tpm key provider, ext4, encrypted storage). app-id defaults to the first 20
 * bytes of the compose hash, as dstack does when .instance_info gives none.
 */
export function sealedEventLog(inputs: SealedEventLogInputs): DstackEvent[] {
  const composeHash = sha256(utf8(inputs.appCompose));
  const appId = inputs.appId ?? composeHash.slice(0, 20);
  const instanceId = inputs.instanceId ?? sha256(concatBytes(utf8("sealed-sim/instance"), appId)).slice(0, 20);
  const payloads: Record<(typeof SEALED_RTMR3_EVENTS)[number], Uint8Array> = {
    "system-preparing": new Uint8Array(),
    "app-id": appId,
    "compose-hash": composeHash,
    "gpu-policy-hash": hexToBytes(NO_GPU_POLICY_HASH),
    "instance-id": instanceId,
    "boot-mr-done": new Uint8Array(),
    "key-provider": utf8(TPM_KEY_PROVIDER_PAYLOAD),
    "storage-fs": utf8("ext4"),
    "storage-encrypted": utf8("1"),
    "system-ready": new Uint8Array(),
  };
  return SEALED_RTMR3_EVENTS.map((name) => makeEvent(name, payloads[name]));
}

/** Checks digests, order and the compose-hash payload. Returns the replayed RTMR3. */
export function verifySealedEventLog(events: readonly DstackEvent[], appCompose: string): Uint8Array {
  const rtmr3 = events.filter((e) => e.imr === 3);
  const names = rtmr3.map((e) => e.event);
  if (names.join(",") !== SEALED_RTMR3_EVENTS.join(",")) throw new Error(`unexpected RTMR3 event sequence: ${names.join(",")}`);
  for (const e of rtmr3) {
    if (e.event_type !== DSTACK_RUNTIME_EVENT_TYPE) throw new Error(`unexpected event type for ${e.event}`);
    const d = eventDigestV1(e.event, hexToBytes(e.event_payload));
    if (!equalBytes(d, hexToBytes(e.digest))) throw new Error(`digest mismatch for ${e.event}`);
  }
  const composeEvent = rtmr3[2] as DstackEvent;
  if (composeEvent.event_payload.toLowerCase() !== bytesToBareHex(sha256(utf8(appCompose)))) {
    throw new Error("compose-hash event does not match appCompose");
  }
  return replayRtmr3(rtmr3);
}

// --- Simulated quotes (dev only; production verifiers reject them) ------------------------------

export const SIM_QUOTE_MAGIC = "SEALEDSIM1";
export const SIM_MEASUREMENTS = {
  mrtd: "11".repeat(48),
  rtmr0: "22".repeat(48),
  rtmr1: "33".repeat(48),
  rtmr2: "44".repeat(48),
} as const;
export const SIM_DEBUG_MRTD = "55".repeat(48);

export interface SimQuote {
  schema: "sealed-sim-quote/v1";
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  reportData: string;
  debug: boolean;
}

/** bytes = ASCII "SEALEDSIM1" || CJSON(quote fields), hex fields lowercase without 0x. */
export function encodeSimQuote(q: Omit<SimQuote, "schema">): Uint8Array {
  const body: SimQuote = { schema: "sealed-sim-quote/v1", ...q };
  for (const k of ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "reportData"] as const) body[k] = body[k].toLowerCase();
  return concatBytes(utf8(SIM_QUOTE_MAGIC), utf8(canonicalize(body)));
}

export function isSimQuote(quote: Uint8Array): boolean {
  const magic = utf8(SIM_QUOTE_MAGIC);
  return quote.length > magic.length && equalBytes(quote.slice(0, magic.length), magic);
}

export function decodeSimQuote(quote: Uint8Array): SimQuote {
  if (!isSimQuote(quote)) throw new Error("not a simulated quote");
  const body = parseCJSON(new TextDecoder().decode(quote.slice(SIM_QUOTE_MAGIC.length))) as unknown as SimQuote;
  if (body.schema !== "sealed-sim-quote/v1") throw new Error("unknown simulated quote schema");
  return body;
}

export function simMeasurements(debug: boolean) {
  return { ...SIM_MEASUREMENTS, mrtd: debug ? SIM_DEBUG_MRTD : SIM_MEASUREMENTS.mrtd };
}
