// The 24-hour re-attestation timer (spec 5.6 step 9, G19). boot.e2e.test.ts covers the evidence sent at
// every boot; this file covers the periodic path that agent.start() sets up. It uses the same harness (dstack
// simulator, fake key broker, fake platform, fake Caddy, FakePayer) with a clock the test moves by hand, so
// a day passes in milliseconds and every loop runs at its real interval.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  bytesToHex,
  decodeSimQuote,
  enclaveSignerAddress,
  type EvidenceBundle,
  evidenceBundleSchema,
  evidenceReportData,
  devSimSealedConfigSchema,
  type Hex,
  hexToBytes,
  loadDefaults,
  quoteHash,
  stackHash,
  usageDomain,
} from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import type { Clock } from "../src/clock.js";
import { DstackClient } from "../src/dstack.js";
import { parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { type AgentSettings, settingsFromEnv } from "../src/settings.js";
import { type FakeBroker, SIGNER_SEED_TAG, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, CUSTOMER, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

interface Sleeper {
  at: number;
  seq: number;
  wake: () => void;
}

/**
 * A clock the test moves by hand. In auto mode (the boot) a sleep returns at once and moves the time on. In
 * manual mode a sleep returns only when advance() passes its deadline. advance() wakes sleepers one at a time in
 * deadline order and waits until the woken task sleeps again, so loop ticks never overlap and time only moves
 * while every loop is asleep.
 */
class ManualClock implements Clock {
  private ms: number;
  private seq = 0;
  private sleepers: Sleeper[] = [];
  auto = true;

  constructor(startSec: number) {
    this.ms = startSec * 1000;
  }

  now(): number {
    return Math.floor(this.ms / 1000);
  }

  get pending(): number {
    return this.sleepers.length;
  }

  sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason);
      if (this.auto) {
        this.ms += ms;
        setImmediate(resolve);
        return;
      }
      const onAbort = () => {
        this.sleepers = this.sleepers.filter((s) => s !== sleeper);
        reject(signal?.reason);
      };
      const sleeper: Sleeper = {
        at: this.ms + ms,
        seq: this.seq++,
        wake: () => {
          signal?.removeEventListener("abort", onAbort);
          resolve();
        },
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.sleepers.push(sleeper);
    });
  }

  async advance(ms: number): Promise<void> {
    const target = this.ms + ms;
    for (;;) {
      const due = this.sleepers.filter((s) => s.at <= target).sort((a, b) => a.at - b.at || a.seq - b.seq)[0];
      if (!due) break;
      const asleep = this.sleepers.length;
      this.sleepers = this.sleepers.filter((s) => s !== due);
      this.ms = Math.max(this.ms, due.at);
      due.wake();
      await until(() => this.sleepers.length >= asleep, "the woken task to sleep again");
    }
    this.ms = target;
  }
}

/** Waits (in real time) until cond holds. */
async function until(cond: () => boolean, what: string, timeoutMs = 20_000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 1));
  }
}

const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });

describe("sealed-agent re-attestation timer", () => {
  let dir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let config: ReturnType<typeof makeConfig>;
  let appCompose: string;
  let settings: AgentSettings;
  let agent: Agent;
  let startedAt: number;
  const clock = new ManualClock(1_800_000_000);
  const secrets = { crm: { APP_SECRET: "crm-secret-value" }, "llm-gateway": { LITELLM_MASTER_KEY: "sk-test" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } };

  const expectedSigner = () => enclaveSignerAddress(broker.derive(SIGNER_SEED_TAG, CUSTOMER, config.salt as Hex));
  // The tests' endpoints are plain http on loopback, which only dev sim mode accepts (as boot.e2e does).
  const bundle = (i: number): EvidenceBundle => evidenceBundleSchema.extend({ config: devSimSealedConfigSchema }).parse(platform.evidence[i]);

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-agent-reattest-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets, approved: () => true, hmacKey: Buffer.alloc(32, 3) });
    platform = await startFakePlatform({ now: () => clock.now() });
    caddy = await startFakeCaddy(join(dir, "caddy-admin.sock"), CADDYFILE);
    config = makeConfig({ endpoints: { keyBroker: broker.url, platformApi: platform.url } });
    appCompose = makeAppCompose(config);
    await writeFile(join(dir, "config.json"), JSON.stringify(config, null, 2));
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    // The interval under test is the production default (SEALED_REATTEST_HOURS unset). The other loops keep running,
    // at intervals long enough that a simulated day stays cheap.
    settings = testSettings(dir, {
      dstackEndpoint: sim.endpoint,
      reattestHours: settingsFromEnv({}).reattestHours,
      pollIntervalSec: 900,
      healthIntervalSec: 3600,
    });
    // The platform knows the deployment from the start, so the boot's ledger rebuild reads at once (no retry sleeps).
    platform.signer = expectedSigner();
    platform.domain = usageDomain(config.contracts.feeSplitter as Hex, config.chainId);
    const payer = new FakePayer();
    agent = new Agent({
      settings,
      clock,
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      payer: () => payer,
      egressStats: async () => ({ since: clock.now(), allowed: {}, blocked: {} }),
      probe: async () => true,
      defaults,
      peerOf: testPeerOf,
      chown: async () => undefined,
    });
    await agent.boot();
    await agent.evidence;
    await until(() => agent.ledger?.verified === true, "the boot's ledger rebuild");
    clock.auto = false;
  });

  afterAll(async () => {
    await agent?.stop();
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  it("uses the 24 hour default", () => {
    expect(settings.reattestHours).toBe(24);
  });

  it("sent one evidence bundle at boot and nothing is pending", () => {
    expect(platform.evidence.length).toBe(1);
    expect(clock.pending).toBe(0);
  });

  it("start() runs the loops; nothing is re-attested before 24 hours have passed", async () => {
    startedAt = clock.now();
    expect(bundle(0).attestedAt).toBeLessThanOrEqual(startedAt);
    agent.start();
    // App health, settlement, health report and re-attestation: each loop sleeps until its next tick.
    await until(() => clock.pending === 4, "every loop to sleep");
    await clock.advance(DAY_MS - 1000);
    expect(platform.evidence.length).toBe(1);
    // The other loops did run in that day.
    expect(platform.health.length).toBe(23);
  });

  it("re-attests after 24 hours with a fresh quote, nonce2 and a newer attestedAt", async () => {
    await clock.advance(1000);
    expect(platform.evidence.length).toBe(2);
    const [first, second] = [bundle(0), bundle(1)];
    expect(second.attestedAt).toBe(startedAt + DAY_MS / 1000);
    expect(second.attestedAt).toBeGreaterThan(first.attestedAt);
    expect(second.nonce2).not.toBe(first.nonce2);
    expect(second.quote).not.toBe(first.quote);
    expect(second.quoteHash).toBe(quoteHash(second.quote as Hex));
    // The new quote binds the same stack, config and signer to the new nonce2 and attestedAt.
    const rd = evidenceReportData(second.stackHash as Hex, second.configHash as Hex, second.enclaveSigner as Hex, second.nonce2 as Hex, second.attestedAt);
    expect(decodeSimQuote(hexToBytes(second.quote)).reportData).toBe(bytesToHex(rd).slice(2));
    expect(second).toMatchObject({
      deploymentId: first.deploymentId,
      stackHash: stackHash(appCompose),
      configHash: first.configHash,
      enclaveSigner: expectedSigner(),
      imageId: first.imageId,
      releaseIds: first.releaseIds,
    });
    expect(agent.lastEvidence?.nonce2).toBe(second.nonce2);
  });

  it("keeps re-attesting every 24 hours, and a refused submission is retried with a fresh quote", async () => {
    platform.failEvidence = 2;
    await clock.advance(DAY_MS - 1000);
    expect(platform.evidence.length).toBe(2);
    // Two refusals, then the retry with backoff (2 s, then up to 4 s) is accepted within the next minute.
    await clock.advance(60_000);
    expect(platform.failEvidence).toBe(0);
    expect(platform.evidence.length).toBe(3);
    const third = bundle(2);
    const due = bundle(1).attestedAt + DAY_MS / 1000;
    expect(third.attestedAt).toBeGreaterThan(due);
    expect(third.attestedAt).toBeLessThanOrEqual(due + 10);
    expect(third.nonce2).not.toBe(bundle(1).nonce2);
    const rd = evidenceReportData(third.stackHash as Hex, third.configHash as Hex, third.enclaveSigner as Hex, third.nonce2 as Hex, third.attestedAt);
    expect(decodeSimQuote(hexToBytes(third.quote)).reportData).toBe(bytesToHex(rd).slice(2));
    // The loop sleeps again once the accepted submission returns (scheduler.ts every), so the next one is due 24
    // hours after it, not 24 hours after the tick that started the retries.
    await clock.advance(DAY_MS - 59_000);
    expect(clock.now()).toBe(due + DAY_MS / 1000);
    expect(platform.evidence.length).toBe(3);
    await clock.advance((third.attestedAt - due) * 1000 + 1000);
    expect(platform.evidence.length).toBe(4);
    expect(bundle(3).attestedAt).toBe(third.attestedAt + DAY_MS / 1000);
  });

  it("stop() ends the loop: no timer is left and no evidence is sent afterwards", async () => {
    const sent = platform.evidence.length;
    await agent.stop();
    expect(clock.pending).toBe(0);
    await clock.advance(3 * DAY_MS);
    expect(platform.evidence.length).toBe(sent);
  });
});
