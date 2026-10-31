// payments-7, through the real agent: once settlement has failed on the customer's side for the grace period and
// Caddy shows the payment-needed page, the agent's health polling stops billing app-hours, and reserved_for_fees
// stops counting app-hours until the window end. The real Agent runs against the dstack simulator, the fake key
// broker, the fake platform, a fake Caddy admin socket and the FakePayer.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDefaults } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CADDYFILE, CADDYFILE_PAYMENT_NEEDED, CUSTOMER, makeAppCompose, makeConfig, testPeerOf, testSettings } from "./helpers/fixtures.js";

const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });
const CRM_PER_HOUR = 50_000n;

describe("payments-7: no app-hours behind the payment-needed page", () => {
  let dir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let agent: Agent;
  let now = 1_800_000_000;
  const clock = { now: () => now, sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };
  const payer = new FakePayer();

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-lockout-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets: { _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } } });
    platform = await startFakePlatform({ now: () => now });
    caddy = await startFakeCaddy(join(dir, "caddy-admin.sock"), CADDYFILE);
    const config = makeConfig({ endpoints: { keyBroker: broker.url, platformApi: platform.url } });
    await writeFile(join(dir, "config.json"), JSON.stringify(config, null, 2));
    sim = await startSimulator({ appCompose: makeAppCompose(config), socket: join(dir, "dstack.sock") });
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
  });

  afterAll(async () => {
    await agent?.stop().catch(() => undefined);
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  /** One hour of health polls (every 60 s, the poller's two-interval cap) and the settlement at its end. */
  const hour = async () => {
    for (let s = 60; s <= 3600; s += 60) await agent.pollApps(now + s);
    now += 3600;
    return agent.settle(now);
  };
  const crmBilled = () => (agent.ledger?.state.reports ?? []).reduce((s, r) => s + BigInt(r.payments.crm?.fee ?? "0"), 0n) + (agent.ledger?.openFee("crm") ?? 0n);

  it("stops billing crm and stops reserving its app-hours once the routes switch, and bills again after", async () => {
    await agent.pollApps(now);
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    let h = 0;
    while (!agent.store?.state.payments.paymentNeeded && h < 30) {
      await hour();
      h++;
    }
    expect(agent.store?.state.payments.paymentNeeded).toBe(true);
    expect(caddy.current).toBe(CADDYFILE_PAYMENT_NEEDED);
    const atLock = crmBilled();
    expect(atLock).toBeLessThanOrEqual(BigInt(h) * CRM_PER_HOUR);

    // Three days behind the payment page: crm stays healthy and is not billed.
    for (let d = 0; d < 72; d++) await hour();
    expect(crmBilled()).toBe(atLock);
    expect((await agent.reportHealth(now)).body.apps).toMatchObject({ crm: "healthy" });

    // reserved_for_fees holds the unpaid legs and the network fees, not a day of app-hours.
    const unpaid = (agent.ledger?.unpaid() ?? []).reduce((s, e) => s + e.fee, 0n);
    const reserve = agent.feeReserve(now + 86_400, now);
    expect(reserve - unpaid).toBeLessThan(CRM_PER_HOUR);

    // The customer raises the limit: the backlog is paid, the routes come back, and crm is billed again from the
    // last poll on.
    payer.budgetResult = { spendable: 1_000_000_000n };
    // Paying part of a backlog is no recovery (payments-3): one settlement pays at most 10 legs, so a backlog of a
    // day of hourly legs takes several settlements, and the routes come back only at the one that leaves none overdue.
    let paid = 0;
    while (agent.store?.state.payments.paymentNeeded && paid < 10) {
      await hour();
      paid++;
    }
    expect(agent.store?.state.payments.paymentNeeded).toBe(false);
    expect(caddy.current).toBe(CADDYFILE);
    expect(agent.feeReserve(now + 86_400, now) - (agent.ledger?.unpaid() ?? []).reduce((s, e) => s + e.fee, 0n)).toBeGreaterThanOrEqual(24n * CRM_PER_HOUR);
    const before = crmBilled();
    await hour();
    const billed = crmBilled() - before;
    expect(billed).toBeGreaterThanOrEqual(CRM_PER_HOUR - 1n);
    expect(billed).toBeLessThanOrEqual(CRM_PER_HOUR + 1n);
  });
});
