import { describe, expect, it } from "vitest";
import {
  decodeSimQuote,
  encodeSimQuote,
  eventDigestV1,
  isSimQuote,
  makeEvent,
  NO_GPU_POLICY_HASH,
  replayRtmr3,
  SIM_MEASUREMENTS,
  sealedEventLog,
  verifySealedEventLog,
} from "../src/dstack.js";
import { bytesToBareHex, hexToBytes, utf8 } from "../src/hex.js";
import { sha256Hex } from "../src/ids.js";

// Golden vectors from runtime/composer/testdata/dstack (docs/notes/dstack.md 6.3).
const SAMPLE_COMPOSE =
  '{"allowed_envs":[],"docker_compose_file":"services:\\n  web:\\n    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000\\n","gateway_enabled":false,"key_provider":"none","kms_enabled":false,"manifest_version":2,"name":"hello","no_instance_id":false,"public_logs":true,"public_sysinfo":true,"public_tcbinfo":true,"runner":"docker-compose","secure_time":false,"storage_fs":"ext4"}';

describe("dstack RTMR3 event log v1", () => {
  it("digest of app-id deadbeef", () => {
    expect(bytesToBareHex(eventDigestV1("app-id", hexToBytes("deadbeef")))).toBe(
      "67b4be4efed0893cfa2bb1d35dca209ad8348b4c97f980807bcde8b9a0f26398dd0923d6eccb5aa2096d98046da8740f",
    );
  });
  it("replays the golden full sequence", () => {
    const events = [
      makeEvent("system-preparing", new Uint8Array()),
      makeEvent("app-id", new Uint8Array(20).fill(0x11)),
      makeEvent("compose-hash", hexToBytes(sha256Hex(SAMPLE_COMPOSE))),
      makeEvent("gpu-policy-hash", hexToBytes(NO_GPU_POLICY_HASH)),
      makeEvent("instance-id", new Uint8Array(20).fill(0x33)),
      makeEvent("boot-mr-done", new Uint8Array()),
      makeEvent("key-provider", utf8('{"name":"none","id":""}')),
      makeEvent("storage-fs", utf8("ext4")),
      makeEvent("storage-encrypted", utf8("1")),
      makeEvent("system-ready", new Uint8Array()),
    ];
    expect(bytesToBareHex(replayRtmr3(events))).toBe(
      "30498094c86fca91569d7ea7dc79fcfd7dfbf7ac699a1fde8b673f659e1f0fcc08ee73fdccd5eb000694689b212822d1",
    );
    expect(bytesToBareHex(replayRtmr3(events.slice(0, 6)))).toBe(
      "5087565e0705ebbd36500f414ef35cff648b28d342eb1b2ac370909e46e866c19b817bec801d0877960febdb4283b00d",
    );
  });
  it("sealedEventLog emits the INTERFACES 6 sequence and verifies", () => {
    const log = sealedEventLog({ appCompose: SAMPLE_COMPOSE });
    expect(log.map((e) => e.event)).toEqual([
      "system-preparing", "app-id", "compose-hash", "gpu-policy-hash", "instance-id", "boot-mr-done",
      "key-provider", "storage-fs", "storage-encrypted", "system-ready",
    ]);
    expect(Buffer.from(hexToBytes(log[6]?.event_payload as string)).toString()).toBe('{"name":"tpm","id":""}');
    expect(verifySealedEventLog(log, SAMPLE_COMPOSE)).toEqual(replayRtmr3(log));
    expect(() => verifySealedEventLog(log, `${SAMPLE_COMPOSE} `)).toThrow("compose-hash");
    const reordered = [log[1], log[0], ...log.slice(2)] as typeof log;
    expect(() => verifySealedEventLog(reordered, SAMPLE_COMPOSE)).toThrow("sequence");
    const tampered = log.map((e, i) => (i === 7 ? { ...e, event_payload: bytesToBareHex(utf8("zfs")) } : e));
    expect(() => verifySealedEventLog(tampered, SAMPLE_COMPOSE)).toThrow("digest mismatch");
  });
});

describe("simulated quotes (INTERFACES 15)", () => {
  it("encodes SEALEDSIM1 || CJSON and decodes", () => {
    const q = encodeSimQuote({ ...SIM_MEASUREMENTS, rtmr3: "AA".repeat(48), reportData: "bb".repeat(64), debug: false });
    expect(new TextDecoder().decode(q.slice(0, 10))).toBe("SEALEDSIM1");
    expect(new TextDecoder().decode(q.slice(10))).toBe(
      `{"debug":false,"mrtd":"${"11".repeat(48)}","reportData":"${"bb".repeat(64)}","rtmr0":"${"22".repeat(48)}","rtmr1":"${"33".repeat(48)}","rtmr2":"${"44".repeat(48)}","rtmr3":"${"aa".repeat(48)}","schema":"sealed-sim-quote/v1"}`,
    );
    expect(isSimQuote(q)).toBe(true);
    expect(decodeSimQuote(q).rtmr3).toBe("aa".repeat(48));
    expect(isSimQuote(utf8("\x04\x00real quote"))).toBe(false);
  });
});
