// payments-8, over the real wire: the payer's ChannelRecovery and AgentSpendBudget (runtime/mpp-payer) against the
// real agent's /v1/spend/reserve. With an access key limit below the app-hour floor, fee priority leaves the payer
// nothing, so before the fix every recovery pass was deferred and an orphaned deposit stayed in escrow. Now the
// recovery's network fee gets a small allowance past reserved_for_fees, and a recovery still waiting for budget is
// reported in the signed health report.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDefaults } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ChannelJournal } from "../../mpp-payer/src/channel-journal.js";
import { ChannelRecovery, type ChannelState, type EscrowChain, type RecoveryCall } from "../../mpp-payer/src/channel-recovery.js";
import { AgentSpendBudget } from "../../mpp-payer/src/shared-budget.js";
import { SpendGuard, SpendLimitError } from "../../mpp-payer/src/spend-guard.js";
import { SpendReporter, spendSnapshot } from "../../mpp-payer/src/spend-reporter.js";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent, NETWORK_FEE_ALLOWANCE } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, CUSTOMER, fromPeer, IPS, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });
const id = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;

describe("payments-8: recovery of an orphaned deposit below the fee floor", () => {
  let dir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let agent: Agent;
  let feeToken: string;
  const now = 1_800_000_000;
  const clock = { now: () => now, sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };
  const payer = new FakePayer();

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-recovery-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets: { _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } } });
    platform = await startFakePlatform({ now: () => now });
    caddy = await startFakeCaddy(join(dir, "caddy-admin.sock"), CADDYFILE);
    const config = makeConfig({ endpoints: { keyBroker: broker.url, platformApi: platform.url } });
    feeToken = config.feeToken;
    await writeFile(join(dir, "config.json"), JSON.stringify(config, null, 2));
    sim = await startSimulator({ appCompose: makeAppCompose(config), socket: join(dir, "dstack.sock") });
    // The access key has 0.03 USD left for a day; crm alone reserves 1.20 USD of app-hours until the period ends.
    payer.limit = { remaining: 30_000n, periodEnd: now + 86_400 };
    agent = new Agent({
      settings: testSettings(dir, { dstackEndpoint: sim.endpoint }),
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
    await agent.boot();
    await agent.evidence;
    expect(await agent.rebuildLedger()).toBe(true);
    await agent.settle(now);
  });

  afterAll(async () => {
    await agent?.stop().catch(() => undefined);
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  const asPayer = (url: string, init?: RequestInit) => fetch(url, { ...init, headers: { ...(init?.headers as Record<string, string>), ...fromPeer(IPS.payer) } });
  const budget = () => new AgentSpendBudget({ agentUrl: `http://127.0.0.1:${agent.port}`, currency: feeToken, retryDelaysMs: [], fetch: asPayer });
  const orphan = (n: number, feeCap: bigint) => {
    const journal = new ChannelJournal(undefined, () => now - 3600);
    journal.recordOpen({
      channelId: id(n),
      chainId: 4217,
      escrow: "0x4d50500000000000000000000000000000000000",
      descriptor: { payer: CUSTOMER as `0x${string}`, payee: `0x${"ab".repeat(20)}`, operator: `0x${"ab".repeat(20)}`, token: feeToken as `0x${string}`, salt: id(n), authorizedSigner: `0x${"22".repeat(20)}`, expiringNonceHash: id(n + 100) },
      deposit: 500_000n,
    });
    const sent: RecoveryCall[] = [];
    const state: ChannelState = { deposit: 500_000n, settled: 0n, closeRequestedAt: 0 };
    const chain: EscrowChain = {
      state: async () => state,
      gracePeriod: async () => 900,
      prepare: async (call) => ({ feeCap, send: async () => (sent.push(call), { status: "success", closeRequestedAt: now }) }),
    };
    const recovery = new ChannelRecovery({ journal, chain, liveChannels: () => new Set<string>(), guard: new SpendGuard(2_000_000n), budget: budget(), now: () => now });
    return { recovery, sent };
  };

  it("sends the requestClose although an ordinary reservation of the same fee is refused", async () => {
    expect(agent.budget?.available(now)).toBe(0n);
    await expect(budget().reserve(2_000n)).rejects.toBeInstanceOf(SpendLimitError);
    const { recovery, sent } = orphan(1, 2_000n);
    await recovery.sweep();
    expect(sent).toEqual(["requestClose"]);
    expect(recovery.snapshot()).toMatchObject({ requestCloses: 1, deferred: 0 });
    // The fee came out of the limit, never past it, and only once from the window's allowance.
    expect(agent.budget?.state.recoveryOverReserve).toBe("2000");
  });

  it("reports a recovery that still waits for budget in the signed health report", async () => {
    // A fee above the per-transaction allowance (a settlement transaction's 0.01 USD on mainnet) stays deferred.
    const { recovery, sent } = orphan(2, NETWORK_FEE_ALLOWANCE + 1n);
    await recovery.sweep();
    expect(sent).toEqual([]);
    expect(recovery.snapshot()).toMatchObject({ deferred: 1, deferredAmount: "500000" });
    const guard = new SpendGuard(2_000_000n, () => now * 1000);
    const reporter = new SpendReporter({
      agentUrl: `http://127.0.0.1:${agent.port}`,
      intervalSeconds: 60,
      fetch: asPayer,
      snapshot: () =>
        spendSnapshot({ mode: "access-key", currency: feeToken, guard, gate: { isOpen: () => true, state: () => ({}) }, relay: { sessionsAvailable: () => true }, recovery }),
    });
    expect(await reporter.send()).toBe(true);
    const h = await agent.reportHealth(now);
    expect(h.body.payments).toMatchObject({ mpp_recoveryDeferred: 1, mpp_recoveryDeferredAmount: "500000" });
  });
});
