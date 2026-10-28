// Key release failure paths (review finding: only the happy path was tested). The agent must refuse a
// broker answer that is for another stack or deployment, or that does not decrypt under its own
// ephemeral key, nonce and info.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bytesToHex, canonicalize, hexToBytes, loadDefaults, type ReleaseRequest, type ReleaseResponse, sealKbRelease, utf8 } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { buildContext, type DeploymentContext, parsePublicConfig } from "../src/context.js";
import { DstackClient } from "../src/dstack.js";
import { parseEndpoint } from "../src/http.js";
import { HttpKeyBroker, type KeyBroker, releaseKeys, releaseOnce } from "../src/keyRelease.js";
import { silentLogger } from "../src/log.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { CUSTOMER, makeAppCompose, makeConfig } from "./helpers/fixtures.js";

const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });

describe("key release answers the agent must refuse", () => {
  let dir: string;
  let sim: RunningSimulator;
  let broker: FakeBroker;
  let ctx: DeploymentContext;
  let dstack: DstackClient;
  const secrets = { crm: { APP_SECRET: "s" } };

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-kr-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets });
    const config = makeConfig({ endpoints: { keyBroker: broker.url } });
    const appCompose = makeAppCompose(config);
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    dstack = new DstackClient(parseEndpoint(sim.endpoint));
    const { config: c, json } = parsePublicConfig(canonicalize(config));
    ctx = buildContext({ config: c, configJson: json, appCompose, defaults });
  });
  afterAll(async () => {
    await Promise.all([broker?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  /** The real broker's answer, then `mutate` applied to it. */
  const tampering = (mutate: (res: ReleaseResponse, req: ReleaseRequest) => Promise<ReleaseResponse> | ReleaseResponse): KeyBroker => {
    const real = new HttpKeyBroker(broker.url);
    return { nonce: () => real.nonce(), release: async (req) => mutate(await real.release(req), req) };
  };

  it("accepts the genuine answer", async () => {
    const keys = await releaseOnce(ctx, dstack, new HttpKeyBroker(broker.url), silentLogger);
    expect(keys.secrets).toEqual(secrets);
    expect(keys.diskKey.length).toBe(32);
  });

  it("an answer for a different stackHash", async () => {
    const b = tampering((r) => ({ ...r, stackHash: `0x${"ee".repeat(32)}` }));
    await expect(releaseOnce(ctx, dstack, b, silentLogger)).rejects.toThrow("different stackHash");
  });

  it("an answer for a different deploymentId", async () => {
    const b = tampering((r) => ({ ...r, deploymentId: `0x${"ee".repeat(32)}` }));
    await expect(releaseOnce(ctx, dstack, b, silentLogger)).rejects.toThrow("different deploymentId");
  });

  it("a tampered ciphertext or enc", async () => {
    const flip = (hex: string, at: number) => {
      const b = hexToBytes(hex);
      b[at] = (b[at] ?? 0) ^ 1;
      return bytesToHex(b);
    };
    await expect(releaseOnce(ctx, dstack, tampering((r) => ({ ...r, ciphertext: flip(r.ciphertext, 5) })), silentLogger)).rejects.toThrow();
    await expect(releaseOnce(ctx, dstack, tampering((r) => ({ ...r, enc: flip(r.enc, 0) })), silentLogger)).rejects.toThrow();
  });

  it("a payload sealed with another nonce (aad) or to another key", async () => {
    const payload = utf8(canonicalize({ secrets, diskKey: `0x${"11".repeat(32)}`, signerSeed: `0x${"22".repeat(32)}` }));
    const wrongAad = tampering(async (r, req) => {
      const { enc, ciphertext } = await sealKbRelease(hexToBytes(req.ephemeralPub), new Uint8Array(32).fill(7), payload);
      return { ...r, enc: bytesToHex(enc), ciphertext: bytesToHex(ciphertext) };
    });
    await expect(releaseOnce(ctx, dstack, wrongAad, silentLogger)).rejects.toThrow();
    const otherKey = tampering(async (r, req) => {
      const { enc, ciphertext } = await sealKbRelease(new Uint8Array(32).fill(9), hexToBytes(req.nonce), payload);
      return { ...r, enc: bytesToHex(enc), ciphertext: bytesToHex(ciphertext) };
    });
    await expect(releaseOnce(ctx, dstack, otherKey, silentLogger)).rejects.toThrow();
  });

  it("a plaintext that is not the release schema", async () => {
    const b = tampering(async (r, req) => {
      const { enc, ciphertext } = await sealKbRelease(hexToBytes(req.ephemeralPub), hexToBytes(req.nonce), utf8(canonicalize({ secrets: { "../etc": { A: "1" } }, diskKey: "0x00", signerSeed: "0x00" })));
      return { ...r, enc: bytesToHex(enc), ciphertext: bytesToHex(ciphertext) };
    });
    await expect(releaseOnce(ctx, dstack, b, silentLogger)).rejects.toThrow();
  });

  it("keeps retrying with a fresh nonce instead of accepting a bad answer", async () => {
    let calls = 0;
    const real = new HttpKeyBroker(broker.url);
    const flaky: KeyBroker = {
      nonce: () => real.nonce(),
      release: async (req) => {
        const r = await real.release(req);
        return ++calls < 3 ? { ...r, stackHash: `0x${"ee".repeat(32)}` } : r;
      },
    };
    const clock = { now: () => 0, sleep: () => Promise.resolve() };
    const keys = await releaseKeys(ctx, dstack, flaky, { log: silentLogger, clock, attempts: 5 });
    expect(calls).toBe(3);
    expect(keys.secrets).toEqual(secrets);
  });
});
