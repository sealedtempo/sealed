// D-089 B1 and B2, ported from the billing-soak repros (docs/notes/billing-soak.md). The whole agent runs against
// the dstack simulator, the fake key broker, platform and Caddy, and one FakePayer that stands in for the chain.
//
// B1: a payer that reserves its whole D-048 share must not starve fee settlement on the period tail when callback
//     usage (gateway tokens) keeps accruing, and a lowered access-key limit must not be chargeable against the stale
//     higher value within ONCHAIN_LIMIT_MAX_AGE_SEC.
// B2: usage the agent answered 202 for must still be there after a crash in the batched-save window and a restart.
//
// Each assertion holds with the fix and fails on the pre-fix agent (feeReserve reserving callback accrual only for
// heartbeat apps; reserveSpend refreshing the onchain limit async-only; recordUsage persisting on a 2 s timer).
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDefaults } from "@sealed/core";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
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

describe("D-089 billing fixes B1 and B2", () => {
  let topDir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let configPath: string;
  let caddySock: string;
  const nowRef = { v: 1_800_000_000 };
  const clock = { now: () => nowRef.v, sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };
  const cleanup: Array<() => Promise<void>> = [];

  beforeAll(async () => {
    topDir = await mkdtemp(join(tmpdir(), "sealed-billingfix-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets: { _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } } });
    platform = await startFakePlatform({ now: () => nowRef.v });
    caddySock = join(topDir, "caddy-admin.sock");
    caddy = await startFakeCaddy(caddySock, CADDYFILE);
    const config = makeConfig({ endpoints: { keyBroker: broker.url, platformApi: platform.url } });
    configPath = join(topDir, "config.json");
    await writeFile(configPath, JSON.stringify(config, null, 2));
    sim = await startSimulator({ appCompose: makeAppCompose(config), socket: join(topDir, "dstack.sock") });
    return async () => {
      await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
      await rm(topDir, { recursive: true, force: true });
    };
  });

  afterEach(async () => {
    for (const c of cleanup.splice(0)) await c().catch(() => undefined);
  });

  const makeAgent = (settings: AgentSettings, payer: FakePayer) => {
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
    cleanup.push(() => a.stop().catch(() => undefined));
    return a;
  };

  const settingsIn = async () => {
    const dir = await mkdtemp(join(tmpdir(), "sealed-billingfix-agent-"));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    return { dir, settings: testSettings(dir, { dstackEndpoint: sim.endpoint, configPath, caddyAdminSocket: caddySock }) };
  };

  const boot = async (payer: FakePayer) => {
    const { dir, settings } = await settingsIn();
    const a = makeAgent(settings, payer);
    await a.boot();
    await a.evidence;
    expect(await a.rebuildLedger()).toBe(true);
    return { a, dir, settings };
  };

  /** POST /v1/usage-events as the gateway's own service IP. */
  const useTokens = (a: Agent, quantity: number, id: string) =>
    localRequest(parseEndpoint(`http://127.0.0.1:${a.port}`), "/v1/usage-events", { body: { app: "llm-gateway", unit: "tokens", quantity, id }, headers: fromPeer(IPS.llm) });
  /** POST /v1/spend/reserve as sealed-mpp-payer. Returns the parsed ReserveResult. */
  const reserve = async (a: Agent, amount: bigint): Promise<{ ok: boolean; reservationId?: string; remaining: string; reason?: string }> => {
    const r = await localRequest(parseEndpoint(`http://127.0.0.1:${a.port}`), "/v1/spend/reserve", { body: { amount: amount.toString() }, headers: fromPeer(IPS.payer) });
    return JSON.parse(r.body);
  };
  const release = (a: Agent, reservationId: string, used: bigint) =>
    localRequest(parseEndpoint(`http://127.0.0.1:${a.port}`), "/v1/spend/release", { body: { reservationId, used: used.toString() }, headers: fromPeer(IPS.payer) });

  it("B1: reserving the whole share does not starve settlement when callback usage accrues on the tail", async () => {
    const payer = new FakePayer();
    const T0 = nowRef.v;
    const LIMIT = 3_000_000n;
    payer.limit = { remaining: LIMIT, periodEnd: T0 + 900 };
    const { a } = await boot(payer);

    // Steady gateway token usage for the first 300 s of the period: 100k tokens (20k base-unit fee) every 10 s.
    for (let i = 0; i < 30; i++) {
      nowRef.v = T0 + i * 10;
      expect((await useTokens(a, 100_000, `pre-${i}`)).status).toBe(202);
    }

    // The relay payer reserves and spends its whole offered share, exactly as the soak's P2 burst did.
    nowRef.v = T0 + 300;
    const probe = await reserve(a, LIMIT * 2n); // refused; its `remaining` is the available share
    expect(probe.ok).toBe(false);
    const share = BigInt(probe.remaining);
    expect(share).toBeGreaterThan(0n);
    const grant = await reserve(a, share);
    expect(grant.ok).toBe(true);
    expect((await release(a, grant.reservationId as string, share)).status).toBe(200);

    // Callback usage keeps accruing on the tail; then settlement must pay it.
    for (let i = 0; i < 20; i++) {
      nowRef.v = T0 + 300 + i * 10;
      expect((await useTokens(a, 100_000, `tail-${i}`)).status).toBe(202);
    }
    nowRef.v = T0 + 500;
    await a.settle(nowRef.v);

    // The invariant the chain enforces (D-048): net key spend in the window never exceeds the access-key limit. The
    // fix reserved the callback accrual, so the payer's share was smaller and settlement still fit; pre-fix the share
    // was oversized and payer debits + settled fees exceed the limit (spend_limit on the tail).
    const budget = a.budget!.state;
    expect(BigInt(budget.payer) + BigInt(budget.fees)).toBeLessThanOrEqual(LIMIT);
    // Sanity: real money moved (the payer spent its share and settlement paid the gateway fees).
    expect(BigInt(budget.payer)).toBeGreaterThan(0n);
    expect(BigInt(budget.fees)).toBeGreaterThan(0n);
  });

  it("B1: a lowered access-key limit is not chargeable against the stale higher value", async () => {
    const payer = new FakePayer();
    const T0 = nowRef.v;
    payer.limit = { remaining: 10_000_000n, periodEnd: T0 + 3600 };
    const { a } = await boot(payer);

    // First reservation against the high limit: granted, and it reads the limit onchain.
    nowRef.v = T0;
    const first = await reserve(a, 100_000n);
    expect(first.ok).toBe(true);

    // The customer lowers the key's limit well below the outstanding reservation plus fee reserve.
    payer.limit = { remaining: 200_000n, periodEnd: T0 + 3600 };

    // 5 s later, within ONCHAIN_LIMIT_MAX_AGE_SEC: a reservation that fits the stale 10M but not the fresh 200k.
    nowRef.v = T0 + 5;
    const second = await reserve(a, 500_000n);
    // The fix reads the limit synchronously before authorizing, so the fresh lower value refuses it. Pre-fix the
    // stale reading grants it (the payer keeps charging against the old limit for up to 60 s).
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("budget");
    expect(a.budget!.snapshot(nowRef.v).budget_onchainRemaining).toBe("200000");
  });

  it("B2: usage answered 202 survives a crash in the batched-save window and a restart", async () => {
    const payer = new FakePayer();
    const T0 = nowRef.v;
    payer.limit = { remaining: 10_000_000n, periodEnd: T0 + 3600 };
    const { a, dir } = await boot(payer);

    // One accepted event (1,000,000 tokens -> 200,000 base-unit fee). It is answered 202 and write-ahead-journaled,
    // but the full state save is on a 2 s debounce and has not fired.
    nowRef.v = T0;
    expect((await useTokens(a, 1_000_000, "crash-1")).status).toBe(202);

    // Simulate a SIGKILL/VM crash within the window: copy the data disk now (the journal is on it; the batched save
    // is not yet). The agent keeps running on the original dir; the copy is an independent "rolled-forward" disk.
    const crashDir = await mkdtemp(join(tmpdir(), "sealed-billingfix-crash-"));
    cleanup.push(() => rm(crashDir, { recursive: true, force: true }));
    await cp(join(dir, "data"), join(crashDir, "data"), { recursive: true });

    // The batched state save had not persisted the usage yet (so the test exercises the journal, not a raced save):
    // either no state.json exists at all, or it has no open gateway usage.
    const saved = await readFile(join(crashDir, "data", ".sealed-agent", "state.json"), "utf8")
      .then((t) => JSON.parse(t) as { ledger?: { open?: Record<string, unknown> } })
      .catch(() => undefined);
    expect(saved?.ledger?.open?.["llm-gateway"]).toBeUndefined();

    // Boot a fresh agent on the crashed disk: it replays the journal and the usage is present again.
    const payer2 = new FakePayer();
    payer2.limit = { remaining: 10_000_000n, periodEnd: T0 + 3600 };
    const b = makeAgent(testSettings(crashDir, { dstackEndpoint: sim.endpoint, configPath, caddyAdminSocket: caddySock }), payer2);
    await b.boot();
    await b.evidence;
    expect(await b.rebuildLedger()).toBe(true);
    expect(b.ledger!.openFee("llm-gateway")).toBe(200_000n);
  });
});
