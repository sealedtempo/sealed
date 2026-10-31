// payments-5: a D-058 upgrade (`sealed deploy --replace`: same salt, new stackHash, so a new deploymentId) boots on
// the old data disk. Before the fix the new agent dropped the old deployment's ledger (unpaid legs and the open period)
// and its payment status, so an upgrade wiped unpaid fees and lifted the payment-needed page. Now the old ledger is kept
// under its own deploymentId: its open period is cut and reported, its legs are paid, and the routes stay on the
// payment-needed page while it needs payment. The last settlement at stop cuts the open period before the VM goes away.
//
// Real agents against the dstack simulator, the fake key broker (same keys for both stacks, D-058), a fake platform
// that stores reports per deployment, a fake Caddy admin socket and one FakePayer per deploymentId (FeeSplitter's
// usagePaid is per deployment).
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDefaults } from "@sealed/core";
import { afterEach, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import type { Budget } from "../src/payments/feePayer.js";
import type { AgentSettings } from "../src/settings.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, CADDYFILE_PAYMENT_NEEDED, CUSTOMER, fromPeer, IPS, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });
const LIMIT_SPENT: Budget = { spendable: 0n, problem: "spend_limit" };
const FUNDED: Budget = { spendable: 1_000_000_000n };

interface World {
  dir: string;
  broker: FakeBroker;
  platform: FakePlatform;
  caddy: FakeCaddy;
  sim?: RunningSimulator;
  settings?: AgentSettings;
  agents: Agent[];
  payers: Map<string, FakePayer>;
}

const worlds: World[] = [];
afterEach(async () => {
  for (const w of worlds.splice(0)) {
    for (const a of w.agents) await a.stop().catch(() => undefined);
    await Promise.all([w.broker.close(), w.platform.close(), w.caddy.close(), w.sim?.close()]);
    await rm(w.dir, { recursive: true, force: true });
  }
});

let now = 1_800_000_000;
const clock = { now: () => now, sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };
let ids = 0;

async function world(): Promise<World> {
  const dir = await mkdtemp(join(tmpdir(), "sealed-upgrade-"));
  const w: World = {
    dir,
    broker: await startFakeBroker({ customer: CUSTOMER, secrets: { _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } } }),
    platform: await startFakePlatform({ now: () => now }),
    caddy: await startFakeCaddy(join(dir, "caddy-admin.sock"), CADDYFILE),
    agents: [],
    payers: new Map(),
  };
  worlds.push(w);
  return w;
}

/** Boots the stack whose llm-gateway release is `0x<releaseByte x 32>` (same salt: an upgrade keeps the disk). */
async function boot(w: World, releaseByte: string, o: { finalSettleMs?: number } = {}): Promise<Agent> {
  await w.sim?.close();
  const config = makeConfig({
    endpoints: { keyBroker: w.broker.url, platformApi: w.platform.url },
    apps: [
      { id: "crm", releaseId: `0x${"c1".repeat(32)}` },
      { id: "llm-gateway", releaseId: `0x${releaseByte.repeat(32)}` },
    ],
  });
  await writeFile(join(w.dir, "config.json"), JSON.stringify(config, null, 2));
  w.sim = await startSimulator({ appCompose: makeAppCompose(config), socket: join(w.dir, `dstack-${releaseByte}.sock`) });
  w.settings = testSettings(w.dir, { dstackEndpoint: w.sim.endpoint });
  // A new VM: Caddy starts from the normal Caddyfile.
  w.caddy.current = CADDYFILE;
  const agent = new Agent({
    settings: w.settings,
    clock,
    log: silentLogger,
    dstack: new DstackClient(parseEndpoint(w.sim.endpoint)),
    payer: (_keys, ctx) => payerFor(w, ctx.deploymentId),
    egressStats: async () => undefined,
    probe: async () => true,
    defaults,
    releaseDeniedDelayMs: 10,
    peerOf: testPeerOf,
    ...o,
  });
  w.agents.push(agent);
  await agent.boot();
  await agent.evidence;
  expect(await agent.rebuildLedger()).toBe(true);
  return agent;
}

function payerFor(w: World, deploymentId: string): FakePayer {
  let p = w.payers.get(deploymentId);
  if (!p) {
    p = new FakePayer();
    w.payers.set(deploymentId, p);
  }
  return p;
}

const use = (a: Agent, tokens: number) =>
  localRequest(parseEndpoint(`http://127.0.0.1:${a.port}`), "/v1/usage-events", {
    body: { app: "llm-gateway", unit: "tokens", quantity: tokens, id: `call-${++ids}` },
    headers: fromPeer(IPS.llm),
  });
const owed = (legs: { fee: bigint }[]) => legs.reduce((s, e) => s + e.fee, 0n);
const paidTotal = (p: FakePayer | undefined) => (p?.paid ?? []).flat().reduce((s, l) => s + l.amount, 0n);
const storedFor = (w: World, deploymentId: string) => w.platform.stored.filter((r) => r.report.deploymentId.toLowerCase() === deploymentId.toLowerCase());
const tokensIn = (reports: { report: { items: { unit: number; quantity: string }[] } }[]) =>
  reports.reduce((n, r) => n + r.report.items.filter((i) => i.unit === 1).reduce((m, i) => m + BigInt(i.quantity), 0n), 0n);

/** 26 hourly settlements that fail on the customer's side: past the 24 h grace period, on the payment-needed page. */
async function lockOut(w: World, a: Agent): Promise<void> {
  payerFor(w, a.ctx?.deploymentId as string).budgetResult = LIMIT_SPENT;
  for (let h = 0; h < 26; h++) {
    expect((await use(a, 1_000_000)).status).toBe(202);
    now += 3600;
    await a.settle(now);
  }
  expect(a.store?.state.payments.paymentNeeded).toBe(true);
  expect(w.caddy.current).toBe(CADDYFILE_PAYMENT_NEEDED);
}

describe("payments-5: a same-salt upgrade keeps the old deployment's debt", () => {
  it("keeps the unpaid legs, the open period and the payment-needed page, and settles them under the old id", async () => {
    const w = await world();
    // The old VM is deleted without a last settlement (the repro's case): finalSettleMs 0.
    const first = await boot(w, "11", { finalSettleMs: 0 });
    const oldId = first.ctx?.deploymentId as string;
    await lockOut(w, first);
    const unpaidBefore = first.ledger?.unpaid() ?? [];
    expect(unpaidBefore.length).toBeGreaterThan(0);
    // Usage in the open period, not cut yet, when the instance goes away.
    expect((await use(first, 500_000)).status).toBe(202);
    await first.stop();
    expect(storedFor(w, oldId).length).toBe(unpaidBefore.length);

    // sealed deploy --replace: a new llm-gateway release, same salt, so a new stackHash and deploymentId.
    now += 300;
    const second = await boot(w, "12");
    const newId = second.ctx?.deploymentId as string;
    expect(newId).not.toBe(oldId);
    // The new deployment starts its own ledger and status; the old one is kept beside it.
    expect(second.ledger?.unpaid()).toEqual([]);
    expect(second.store?.state.payments).toMatchObject({ failingSince: null, paymentNeeded: false });
    expect(second.store?.state.previous).toEqual([expect.objectContaining({ deploymentId: oldId })]);
    expect(second.paymentNeeded()).toBe(true);
    expect(w.caddy.current).toBe(CADDYFILE);
    const health = await second.reportHealth(now);
    expect(health.body.payments).toMatchObject({ paymentNeeded: true, previous_deployments: 1, previous_paymentNeeded: true, previous_unpaid: owed(unpaidBefore).toString() });
    // reserved_for_fees keeps room for the old deployment's debt.
    expect(second.feeReserve(now + 3600, now)).toBeGreaterThanOrEqual(owed(unpaidBefore));

    // The customer's limit is still spent: the routes stay on the payment-needed page, and the old open period is cut
    // and reported under the old id.
    payerFor(w, newId).budgetResult = LIMIT_SPENT;
    now += 3600;
    const locked = await second.settle(now);
    expect(locked.paymentNeeded).toBe(true);
    expect(w.caddy.current).toBe(CADDYFILE_PAYMENT_NEEDED);
    expect(tokensIn(storedFor(w, oldId))).toBe(26_500_000n);
    expect(storedFor(w, newId)).toEqual([]);
    expect(w.platform.conflicts).toEqual([]);

    // The new deployment's own usage settles fine once the limit is raised, but its recovery does not open the routes
    // while the old legs are still being paid (at most 10 per transaction).
    expect((await use(second, 200_000)).status).toBe(202);
    payerFor(w, oldId).budgetResult = FUNDED;
    payerFor(w, newId).budgetResult = FUNDED;
    now += 3600;
    // Paying part of a backlog is no recovery (payments-3): one settlement pays at most 10 old legs, so the routes
    // stay on the payment-needed page until a later settlement leaves no old leg overdue.
    expect((await second.settle(now)).paymentNeeded).toBe(true);
    for (let i = 0; i < 3 && second.store?.state.previous; i++) {
      now += 3600;
      await second.settle(now);
    }
    // Every old leg is paid under the old deploymentId, the old ledger is dropped, and the routes are back.
    expect(second.store?.state.previous).toBeUndefined();
    expect(w.caddy.current).toBe(CADDYFILE);
    expect(second.paymentNeeded()).toBe(false);
    expect(paidTotal(payerFor(w, oldId))).toBe(storedFor(w, oldId).reduce((s, r) => s + r.report.items.reduce((m, i) => m + BigInt(i.fee), 0n), 0n));
    expect(paidTotal(payerFor(w, newId))).toBe(storedFor(w, newId).reduce((s, r) => s + r.report.items.reduce((m, i) => m + BigInt(i.fee), 0n), 0n));
    const after = await second.reportHealth(now);
    expect(after.body.payments).toMatchObject({ paymentNeeded: false });
    expect(after.body.payments).not.toHaveProperty("previous_deployments");
    const onDisk = JSON.parse(await readFile(join(w.dir, "data", ".sealed-agent", "state.json"), "utf8"));
    expect(onDisk.deploymentId).toBe(newId);
    expect(onDisk.previous).toBeUndefined();
  });

  it("cuts, reports and pays the open period at stop, so an upgrade has nothing left to carry", async () => {
    const w = await world();
    const first = await boot(w, "21");
    const oldId = first.ctx?.deploymentId as string;
    expect((await use(first, 750_000)).status).toBe(202);
    now += 600;
    await first.stop();
    expect(tokensIn(storedFor(w, oldId))).toBe(750_000n);
    expect(payerFor(w, oldId).paid).toHaveLength(1);
    const state = JSON.parse(await readFile(join(w.dir, "data", ".sealed-agent", "state.json"), "utf8"));
    expect(state.ledger.open).toEqual({});
    // The next boot is an upgrade with nothing owed: no earlier deployment is kept.
    const second = await boot(w, "22");
    expect(second.store?.state.previous).toBeUndefined();
  });

  it("drops an old deployment that is Closed onchain: its legs cannot be paid and it does not hold the new routes", async () => {
    const w = await world();
    const first = await boot(w, "31", { finalSettleMs: 0 });
    const oldId = first.ctx?.deploymentId as string;
    await lockOut(w, first);
    await first.stop();
    payerFor(w, oldId).deployment = "closed";
    now += 300;
    const second = await boot(w, "32");
    expect(second.store?.state.previous).toHaveLength(1);
    now += 3600;
    const r = await second.settle(now);
    expect(r.paymentNeeded).toBe(false);
    expect(second.store?.state.previous).toBeUndefined();
    expect(w.caddy.current).toBe(CADDYFILE);
    expect(payerFor(w, oldId).paid).toEqual([]);
  });

  it("a return to the earlier stack gets that deployment's own ledger and status back", async () => {
    const w = await world();
    const a = await boot(w, "41", { finalSettleMs: 0 });
    const idA = a.ctx?.deploymentId as string;
    await lockOut(w, a);
    const legsA = (a.ledger?.unpaid() ?? []).map((e) => e.usageHash).sort();
    await a.stop();
    now += 300;
    const b = await boot(w, "42", { finalSettleMs: 0 });
    expect(b.store?.state.previous?.map((p) => p.deploymentId)).toEqual([idA]);
    await b.stop();
    // Back to stack A: the same deploymentId, so its ledger is the current one again; B owed nothing and is not kept.
    now += 300;
    const again = await boot(w, "41");
    expect(again.ctx?.deploymentId).toBe(idA);
    expect((again.ledger?.unpaid() ?? []).map((e) => e.usageHash).sort()).toEqual(legsA);
    expect(again.store?.state.payments.paymentNeeded).toBe(true);
    expect(again.store?.state.previous).toBeUndefined();
  });
});
