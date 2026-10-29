// D-062 regression (review ws-int-agent 2): the host rolls the data disk back to an older copy of itself
// and boots the VM again. The rolled-back state still holds, as open usage, tokens that a later report
// already billed and paid. FeeSplitter dedupes per usageHash only, so cutting that usage again into a
// report with another period would pay it twice. The agent must rebuild its ledger from the reports the
// platform stores (verified against its own signer) and onchain usagePaid, and never sign a period that
// overlaps one it already signed.
//
// Two boots of the real agent against the dstack simulator, the fake key broker (same keys both times),
// a fake platform that stores reports and refuses overlapping ones, and one FakePayer whose usagePaid
// map stands for the chain across both boots.
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appId, loadDefaults, periodsOverlap } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import type { AgentSettings } from "../src/settings.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, CUSTOMER, fromPeer, IPS, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });
const LLM = appId("llm-gateway");

describe("D-062: a data disk rolled back to an older copy bills no leg twice", () => {
  let dir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let settings: AgentSettings;
  let now = 1_800_000_000;
  const clock = { now: () => now, sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };
  // The chain: usagePaid and every payment, across both boots.
  const payer = new FakePayer();
  const agents: Agent[] = [];
  let usageIds = 0;

  const newAgent = () => {
    const a = new Agent({
      settings,
      clock,
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      payer: () => payer,
      egressStats: async () => undefined,
      probe: async () => true,
      defaults,
      releaseDeniedDelayMs: 10,
      peerOf: testPeerOf,
    });
    agents.push(a);
    return a;
  };
  const use = async (a: Agent, tokens: number) => {
    const r = await localRequest(parseEndpoint(`http://127.0.0.1:${a.port}`), "/v1/usage-events", {
      body: { app: "llm-gateway", unit: "tokens", quantity: tokens, id: `call-${++usageIds}` },
      headers: fromPeer(IPS.llm),
    });
    return r.status;
  };
  /** Every token the platform stores a report for, and every leg paid onchain. */
  const storedTokens = () =>
    platform.stored.reduce((n, r) => n + r.report.items.filter((i) => i.appId === LLM && i.unit === 1).reduce((m, i) => m + BigInt(i.quantity), 0n), 0n);
  const paidLegs = () => payer.paid.flat().map((l) => `${l.usageHash}:${l.appId}`);
  const storedFees = () => platform.stored.reduce((n, r) => n + r.report.items.reduce((m, i) => m + BigInt(i.fee), 0n), 0n);
  const paidTotal = () => payer.paid.flat().reduce((n, l) => n + l.amount, 0n);

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-rollback-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets: { _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } } });
    platform = await startFakePlatform({ now: () => now });
    caddy = await startFakeCaddy(join(dir, "caddy-admin.sock"), CADDYFILE);
    const config = makeConfig({ endpoints: { keyBroker: broker.url, platformApi: platform.url } });
    const appCompose = makeAppCompose(config);
    await writeFile(join(dir, "config.json"), JSON.stringify(config, null, 2));
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    settings = testSettings(dir, { dstackEndpoint: sim.endpoint });
  });

  afterAll(async () => {
    for (const a of agents) await a.stop().catch(() => undefined);
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  it("rebuilds from the platform's signed reports and onchain usagePaid, drops the covered usage, and bills new usage once", async () => {
    const snapshot = join(dir, "snapshot");
    const first = newAgent();
    await first.boot();
    await first.evidence; // registers the enclave signer with the fake platform
    expect(await first.rebuildLedger()).toBe(true);
    const signer = first.enclaveSigner;

    // U1 sits in the open period when the host takes its copy of the disk.
    expect(await use(first, 1_000_000)).toBe(202);
    await first.store?.save();
    await cp(settings.dataMount, snapshot, { recursive: true });
    const snapState = JSON.parse(await readFile(join(snapshot, ".sealed-agent", "state.json"), "utf8"));
    expect(snapState.ledger.open["llm-gateway"].tokens).toBe("1000000");
    expect(snapState.ledger.reports).toEqual([]);

    // The VM runs on: U1 is billed and paid in R1, then U2 in R2.
    now += 3600;
    expect((await first.settle(now)).apps).toEqual([expect.objectContaining({ app: "llm-gateway", result: "paid" })]);
    expect(await use(first, 400_000)).toBe(202);
    now += 3600;
    expect((await first.settle(now)).apps).toEqual([expect.objectContaining({ app: "llm-gateway", result: "paid" })]);
    expect(platform.stored).toHaveLength(2);
    expect(payer.paid).toHaveLength(2);
    const [r1, r2] = platform.stored as [FakePlatform["stored"][number], FakePlatform["stored"][number]];
    await first.stop();

    // The host restores its copy of the disk and boots again: same deployment, same keys.
    await rm(settings.dataMount, { recursive: true, force: true });
    await cp(snapshot, settings.dataMount, { recursive: true });
    now += 600;
    const bootedAt = now;
    const second = newAgent();
    await second.boot();
    expect(second.enclaveSigner).toBe(signer);
    expect(await second.rebuildLedger()).toBe(true);
    const ledger = second.ledger?.state;
    // U1 is covered by R1, which the platform holds: dropped, not cut again. The open period is the one this boot
    // started (usage from the boot on is new), after R2.
    expect(ledger?.open).toEqual({});
    expect(ledger?.held).toBeUndefined();
    expect(ledger?.signedThrough).toBe(r2.periodEnd);
    expect(ledger?.periodStart).toBe(bootedAt);
    expect(bootedAt).toBeGreaterThan(r2.periodEnd);
    expect(ledger?.reports.map((r) => r.usageHash).sort()).toEqual([r1.usageHash, r2.usageHash].sort());

    // Settlement finds both legs paid onchain (usagePaid) and pays nothing.
    now += 3600;
    const after = await second.settle(now);
    expect(after).toMatchObject({ outcome: "settled", reportCut: false, apps: [] });
    expect(payer.paid).toHaveLength(2);
    expect(second.ledger?.unpaid()).toEqual([]);

    // Usage after the rollback is billed once, in a period after everything already signed.
    expect(await use(second, 250_000)).toBe(202);
    now += 3600;
    expect((await second.settle(now)).apps).toEqual([expect.objectContaining({ app: "llm-gateway", result: "paid" })]);
    const r3 = platform.stored.at(-1) as FakePlatform["stored"][number];
    expect(r3.periodStart).toBe(bootedAt);

    // No leg is billed twice: the agent never even offered an overlapping report, every leg was paid once, and the
    // stored reports hold every token exactly once.
    expect(platform.conflicts).toEqual([]);
    for (let i = 0; i < platform.stored.length; i++) {
      for (let j = i + 1; j < platform.stored.length; j++) expect(periodsOverlap(platform.stored[i] as never, platform.stored[j] as never)).toBe(false);
    }
    expect(new Set(paidLegs()).size).toBe(paidLegs().length);
    expect(storedTokens()).toBe(1_650_000n);
    expect(paidTotal()).toBe(storedFees());
    await second.stop();
  });

  it("without the platform's reports the agent cuts and pays nothing, and catches up once they can be read", async () => {
    // Roll back again, to the same copy, while the platform cannot be reached.
    const snapshot = join(dir, "snapshot");
    await rm(settings.dataMount, { recursive: true, force: true });
    await cp(snapshot, settings.dataMount, { recursive: true });
    platform.down = true;
    const paidBefore = payer.paid.length;
    const storedBefore = platform.stored.length;
    now += 600;
    const third = newAgent();
    await third.boot();
    expect(third.ledger?.verified).toBe(false);
    // New usage is still accepted (it waits in the open period); the held usage from disk is not billed.
    expect(await use(third, 100_000)).toBe(202);
    now += 3600;
    const blind = await third.settle(now);
    expect(blind).toMatchObject({ outcome: "failed", reportCut: false, apps: [{ app: "*", result: "failed", reason: "ledger_unverified" }] });
    // D-073: a platform outage defers settlement; the grace period does not run, however long the outage lasts.
    const deferredAt = now;
    expect(third.store?.state.payments.failingSince).toBeNull();
    expect(third.store?.state.payments.deferredSince).toBe(deferredAt);
    expect(payer.paid).toHaveLength(paidBefore);
    now += 3 * 86_400; // three times the 24 h grace period
    const still = await third.settle(now);
    expect(still).toMatchObject({ paymentNeeded: false, apps: [{ app: "*", result: "failed", reason: "ledger_unverified" }] });
    expect(third.store?.state.payments).toMatchObject({ failingSince: null, deferredSince: deferredAt, paymentNeeded: false });

    // The platform is back. A health report before the next settlement says since when settlement waits.
    platform.down = false;
    const health = await third.reportHealth(now);
    expect(health.body.payments).toMatchObject({ deferredSince: deferredAt, failingSince: null, paymentNeeded: false, lastOutcome: "ledger_unverified" });
    // The rebuild drops U1 again, keeps the new usage and bills only that.
    now += 3600;
    const back = await third.settle(now);
    expect(back.apps).toEqual([expect.objectContaining({ app: "llm-gateway", result: "paid" })]);
    expect(platform.stored).toHaveLength(storedBefore + 1);
    const r = platform.stored.at(-1) as FakePlatform["stored"][number];
    expect(r.report.items).toEqual([expect.objectContaining({ appId: LLM, quantity: "100000" })]);
    expect(platform.conflicts).toEqual([]);
    expect(new Set(paidLegs()).size).toBe(paidLegs().length);
    expect(storedTokens()).toBe(1_750_000n);
    expect(paidTotal()).toBe(storedFees());
    expect(third.store?.state.payments.failingSince).toBeNull();
    expect(third.store?.state.payments.deferredSince).toBeUndefined();
    expect((await third.reportHealth(now)).body.payments).toMatchObject({ deferredSince: null });
  });

  it("a disk copy that boots twice at once (a clone) cannot bill a period twice: the overlapping report is void", async () => {
    // Two VMs on copies of the same disk run side by side. Both hold the same open usage; the first to report
    // it wins, the other's report overlaps a stored one, is refused, voided and never paid.
    for (const a of agents) await a.stop().catch(() => undefined);
    const cloneDir = join(dir, "clone");
    await mkdir(cloneDir, { recursive: true });
    const a = newAgent();
    await a.boot();
    expect(await a.rebuildLedger()).toBe(true);
    expect(await use(a, 300_000)).toBe(202);
    await a.store?.save();
    // The clone starts from a's disk at this point, with its own listener and state directory.
    const cloneSettings = { ...settings, dataMount: join(cloneDir, "data") };
    await cp(settings.dataMount, cloneSettings.dataMount, { recursive: true });
    const b = new Agent({
      settings: cloneSettings,
      clock,
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      payer: () => payer,
      egressStats: async () => undefined,
      probe: async () => true,
      defaults,
      peerOf: testPeerOf,
    });
    agents.push(b);
    await b.boot();
    expect(await b.rebuildLedger()).toBe(true);
    const paidBefore = payer.paid.length;
    now += 3600;
    // b cuts first but has not reported yet; a cuts a minute later and reports first.
    expect((await b.ledger?.closePeriod(now))?.report.items).toEqual([expect.objectContaining({ quantity: "300000" })]);
    now += 60;
    expect((await a.settle(now)).apps).toEqual([expect.objectContaining({ result: "paid" })]);
    const fromB = await b.settle(now);
    expect(platform.conflicts).toHaveLength(1);
    expect(fromB.apps.filter((x) => x.result === "paid")).toEqual([]);
    expect(b.ledger?.state.reports.find((r) => r.void)?.report.periodStart).toBeLessThan(platform.stored.at(-1)?.periodEnd as number);
    expect(payer.paid).toHaveLength(paidBefore + 1);
    expect(new Set(paidLegs()).size).toBe(paidLegs().length);
    expect(paidTotal()).toBe(storedFees());
    // The clone took the stored report over, so its next period starts after it.
    expect(b.ledger?.state.signedThrough).toBeGreaterThanOrEqual(platform.stored.at(-1)?.periodEnd as number);
  });
});
