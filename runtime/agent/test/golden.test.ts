// The agent against the composer's golden stack (test/fixtures/composer-golden, copied from
// runtime/composer/testdata/golden): the sealed-agent service's environment, mounts and volumes, the
// measured configs, and a full boot on that exact app-compose.json with the dstack simulator, a fake
// key broker and tmpfs checks driven by the compose's own volume list. Review finding: the agent and
// the composer had drifted apart on all of these.
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { canonicalize, loadDefaults, parseCJSON } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { buildContext, checkMountedCopy, parsePublicConfig } from "../src/context.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { HttpKeyBroker } from "../src/keyRelease.js";
import { silentLogger } from "../src/log.js";
import { TMPFS_MAGIC } from "../src/secrets.js";
import { settingsFromEnv } from "../src/settings.js";
import { measuredConfigs } from "../src/stack.js";
import { fixedTlsKey } from "../src/tls.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { fromPeer, makeConfig, makeStackInfo, testPeerOf, testSettings } from "./helpers/fixtures.js";
// The payer's own code builds the /v1/spend body (brief item 21: accept it as payments built it).
import { SpendGuard } from "../../mpp-payer/src/spend-guard.js";
import { SpendReporter, spendSnapshot } from "../../mpp-payer/src/spend-reporter.js";
import { ChannelJournal } from "../../mpp-payer/src/channel-journal.js";
import { ChannelRecovery } from "../../mpp-payer/src/channel-recovery.js";
import { AgentSpendBudget, BudgetUnavailableError } from "../../mpp-payer/src/shared-budget.js";
import { SpendLimitError } from "../../mpp-payer/src/spend-guard.js";

const golden = join(import.meta.dirname, "fixtures/composer-golden");
const read = (f: string) => readFile(join(golden, f), "utf8");
const appCompose = await read("app-compose.json");
const configText = await read("config.json");
const config = JSON.parse(configText) as { feeToken: string };
const compose = JSON.parse(JSON.parse(appCompose).docker_compose_file) as {
  services: Record<string, Record<string, unknown>>;
  volumes: Record<string, { driver_opts?: { type?: string } }>;
};
const agentSvc = compose.services["sealed-agent"] as {
  environment: Record<string, string>;
  configs: { source: string; target: string }[];
  volumes: { type: string; source: string; target: string; bind?: { propagation?: string } }[];
  devices: string[];
  healthcheck: { test: string[] };
};
const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });

describe("sealed-agent against the composer's golden stack", () => {
  // Merge C: ws/harden-composer moved the composer to 1.3.0 and refreshed its goldens while this copy kept 1.2.0's,
  // so these tests checked the agent against a stack the composer no longer writes.
  it("the fixture is the composer's current golden output, byte for byte", async () => {
    const source = join(import.meta.dirname, "../../composer/testdata/golden");
    const files = (await readdir(golden)).filter((f) => f !== "README.md").sort();
    expect(files).toEqual(["Caddyfile", "Caddyfile.payment-needed", "app-compose.json", "config.json", "stack.json"]);
    for (const f of files) expect(await read(f), `${f} differs from runtime/composer/testdata/golden/${f}: copy it again`).toBe(await readFile(join(source, f), "utf8"));
  });

  const settings = settingsFromEnv(agentSvc.environment);
  const configTarget = (name: string) => agentSvc.configs.find((c) => c.source === name)?.target;
  const volumeTarget = (name: string) => agentSvc.volumes.find((v) => v.type === "volume" && v.source === name)?.target;

  // Merge C (final): the unit tests' synthetic stack still put sealed-verifierd at 172.30.0.6 on the apps network, two
  // composer versions after it moved to the verifier network (D-061).
  it("the unit tests' synthetic stack places the sidecars where the composer does", async () => {
    const stack = JSON.parse(await read("stack.json")) as { sidecars: Record<string, string> };
    expect(makeStackInfo(makeConfig()).sidecars).toEqual(stack.sidecars);
  });

  it("the composer's sealed-agent environment and mounts give the agent its paths", () => {
    expect(settings.configPath).toBe(configTarget("sealed-config"));
    expect(settings.stackPath).toBe(configTarget("sealed-stack"));
    expect(settings.caddyfilePath).toBe(configTarget("sealed-caddyfile"));
    expect(settings.caddyfilePaymentNeededPath).toBe(configTarget("sealed-caddyfile-payment-needed"));
    // The ready flag lives in a shared tmpfs volume, a directory, as `<dir>/ok`.
    expect(settings.readyDir).toBe(volumeTarget("sealed-ready"));
    expect(compose.volumes["sealed-ready"]?.driver_opts?.type).toBe("tmpfs");
    expect(dirname(settings.caddyAdminSocket)).toBe(volumeTarget("sealed-caddy-admin"));
    expect(compose.volumes["sealed-caddy-admin"]?.driver_opts?.type).toBe("tmpfs");
    // D-042 (composer 1.2): the agent binds the host's secrets directory (on the CVM's /run tmpfs) and
    // writes the owner directories itself; no Docker volume holds secrets.
    expect(agentSvc.volumes.find((v) => v.type === "bind" && v.target === settings.secretsDir)).toMatchObject({ source: settings.secretsDir });
    expect(Object.keys(compose.volumes).filter((v) => v.startsWith("sealed-secrets"))).toEqual([]);
    const data = agentSvc.volumes.find((v) => v.type === "bind" && v.target === settings.dataMount);
    expect(data).toMatchObject({ source: "/mnt/sealed-data", bind: { propagation: "rshared" } });
    expect(agentSvc.devices).toContain(`/dev/disk/by-id/google-sealed-data:${settings.dataDevice}`);
    expect(agentSvc.volumes.find((v) => v.source === "/var/run/dstack.sock")?.target).toBe(settings.dstackEndpoint);
    expect(agentSvc.healthcheck.test.join(" ")).toContain(`http://127.0.0.1:${settings.listenPort}/v1/ready`);
    expect(settings).toMatchObject({ diskMode: "luks", requireTmpfs: true, devSim: false, egressStatsUrl: "http://172.30.0.2:9100/v1/stats" });
  });

  it("reads the measured configs from app-compose.json exactly as the composer wrote them", async () => {
    const m = measuredConfigs(appCompose);
    expect(m["sealed-stack"]).toBe(await read("stack.json"));
    expect(m["sealed-caddyfile"]).toBe(await read("Caddyfile"));
    expect(m["sealed-caddyfile-payment-needed"]).toBe(await read("Caddyfile.payment-needed"));
    expect(canonicalize(parseCJSON(m["sealed-config"] as string))).toBe(canonicalize(parseCJSON(configText)));
  });

  it("takes metering, healthchecks (by fixed IP), callers and the payer from sealed-stack/v1", () => {
    const { config, json } = parsePublicConfig(configText);
    const ctx = buildContext({ config, configJson: json, appCompose, defaults });
    // Per-app networks (D-041): health probes use the app-network address, callers every address.
    expect(ctx.apps).toEqual([
      expect.objectContaining({ id: "llm-gateway", metering: { unit: "tokens", source: "callback" }, healthcheck: "http://172.30.1.16:4000/health/liveliness", serviceIps: ["172.30.1.16", "172.30.0.16"] }),
      expect.objectContaining({ id: "notes", metering: { unit: "app_hour", source: "heartbeat" }, healthcheck: "http://172.30.2.16:8080/healthz", serviceIps: ["172.30.2.17", "172.30.2.16", "172.30.0.17"] }),
    ]);
    expect(ctx.payerIp).toBe("172.30.0.5");
    expect(ctx.caddyIp).toBe("172.30.0.4");
    expect(ctx.stack.attestHost).toBe("attest.34-1-2-3.sslip.io");
  });

  it("refuses a mounted copy or a config file that differs from the measured one", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sealed-golden-x-"));
    try {
      await writeFile(join(dir, "Caddyfile"), "evil.example { respond 200 }\n");
      await expect(checkMountedCopy(join(dir, "Caddyfile"), measuredConfigs(appCompose)["sealed-caddyfile"] as string, "Caddyfile")).rejects.toThrow("differs from the measured copy");
      await checkMountedCopy(join(dir, "missing"), "x", "Caddyfile");
      const { config, json } = parsePublicConfig(configText.replace('"intervalMinutes":60', '"intervalMinutes":61'));
      expect(() => buildContext({ config, configJson: json, appCompose, defaults })).toThrow("differs from the measured sealed-config");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  describe("boot", () => {
    let dir: string;
    let sim: RunningSimulator;
    let broker: FakeBroker;
    let platform: FakePlatform;
    let caddy: FakeCaddy;
    let agent: Agent;
    let payer: FakePayer;
    let now = 1_800_000_000;
    const tmpfs = new Set<string>();
    const secrets = {
      "llm-gateway": { MASTER_KEY: "sk-master" },
      notes: { APP_SECRET: "notes-app", DB_PASSWORD: "pg" },
      _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" },
    };
    const ep = () => parseEndpoint(`http://127.0.0.1:${agent.port}`);

    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "sealed-golden-"));
      const { config } = parsePublicConfig(configText);
      broker = await startFakeBroker({ customer: config.customer, secrets });
      platform = await startFakePlatform();
      sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
      const base = testSettings(dir);
      // The host secrets directory the compose binds into the agent is on tmpfs, with everything below it.
      for (const v of agentSvc.volumes) {
        if (v.type === "bind" && v.target === settings.secretsDir) {
          await mkdir(base.secretsDir, { recursive: true });
          tmpfs.add(base.secretsDir);
        }
      }
      expect(tmpfs.size).toBe(1);
      await mkdir(join(base.secretsDir, "stray"), { recursive: true });
      await mkdir(base.readyDir, { recursive: true });
      await writeFile(base.configPath, configText);
      for (const f of ["stack.json", "Caddyfile", "Caddyfile.payment-needed"]) await writeFile(join(dir, f), await read(f));
      caddy = await startFakeCaddy(base.caddyAdminSocket, await read("Caddyfile"));
      payer = new FakePayer();
      agent = new Agent({
        settings: {
          ...base,
          stackPath: join(dir, "stack.json"),
          caddyfilePath: join(dir, "Caddyfile"),
          caddyfilePaymentNeededPath: join(dir, "Caddyfile.payment-needed"),
          requireTmpfs: true,
        },
        fsType: async (p) => {
          await stat(p);
          return [...tmpfs].some((t) => p === t || p.startsWith(`${t}/`)) ? TMPFS_MAGIC : 0xef53;
        },
        clock: { now: () => now, sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 20))) },
        log: silentLogger,
        dstack: new DstackClient(parseEndpoint(sim.endpoint)),
        broker: new HttpKeyBroker(broker.url),
        platform: {
          postEvidence: async () => ({ deploymentId: "0x" }),
          postUsage: async () => undefined,
          postHealth: async () => undefined,
        },
        payer: () => payer,
        tls: fixedTlsKey(`0x${"77".repeat(32)}`),
        egressStats: async () => undefined,
        probe: async () => true,
        defaults,
        peerOf: testPeerOf,
      });
      await agent.boot();
    });
    afterAll(async () => {
      await agent?.stop();
      await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
      await rm(dir, { recursive: true, force: true });
    });

    it("opens the ready gate as <SEALED_READY_DIR>/ok and writes exactly the stack's secretFiles", async () => {
      const s = testSettings(dir);
      expect(await readFile(join(s.readyDir, "ok"), "utf8")).toMatch(/^\d+\n$/);
      expect(await readFile(join(s.secretsDir, "notes", "DB_PASSWORD"), "utf8")).toBe("pg");
      expect(await readFile(join(s.secretsDir, "notes", "APP_SECRET"), "utf8")).toBe("notes-app");
      // An optional secret the customer did not set is bound on its own, so it exists, empty.
      expect(await readFile(join(s.secretsDir, "notes", "SMTP_PASSWORD"), "utf8")).toBe("");
      expect(await readFile(join(s.secretsDir, "llm-gateway", "MASTER_KEY"), "utf8")).toBe("sk-master");
      expect(await readFile(join(s.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8")).toBe(agent.keys?.enclaveKey);
      // No container binds the gate hash (Caddy holds no secret), so it stays in the agent's memory.
      await expect(stat(join(s.secretsDir, "_gate"))).rejects.toThrow();
      const stack = JSON.parse(await read("stack.json")) as { secretsRoot: string; secretFiles: string[] };
      const written: string[] = [];
      for (const owner of ["llm-gateway", "notes", "sealed-mpp-payer"]) for (const f of await readdir(join(s.secretsDir, owner))) written.push(`${stack.secretsRoot}/${owner}/${f}`);
      expect(written.sort()).toEqual(stack.secretFiles);
      expect((await localRequest(ep(), "/v1/ready")).status).toBe(200);
    });

    it("created every bind source on the data disk, including Caddy's certificate storage", async () => {
      const data = testSettings(dir).dataMount;
      for (const p of ["notes/pgdata", "notes/uploads", "_caddy/data"]) expect((await stat(join(data, p))).isDirectory()).toBe(true);
    });

    it("accepts usage only from the app's own service IPs and only in the unit the manifest meters", async () => {
      const post = (body: unknown, ip: string) => localRequest(ep(), "/v1/usage-events", { body, headers: fromPeer(ip) });
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000, id: "c1" }, "172.30.0.16")).status).toBe(202);
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 500, id: "c2" }, "172.30.1.16")).status).toBe(202); // its app-network address
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000 }, "172.30.2.16")).status).toBe(403); // notes-web on app-notes
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000 }, "172.30.0.17")).status).toBe(403); // notes-web
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000 }, "172.30.0.5")).status).toBe(403); // the payer
      expect((await post({ app: "notes", unit: "app_hour", quantity: 60 }, "172.30.0.17")).status).toBe(422); // heartbeat-metered
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 50_000_000 }, "172.30.0.16")).status).toBe(422); // per-event limit
      expect(agent.ledger?.state.open["llm-gateway"]?.tokens).toBe("1500");
    });

    it("keeps only sealed-mpp-payer's numeric spend counters", async () => {
      const report = {
        source: "sealed-mpp-payer",
        mode: "access-key",
        currency: "0x20c0000000000000000000000000000000000000",
        counters: { day: "2026-10-28", limit: "2000000", debited: "1200", remaining: "1998800", charges: 3, chargeAmount: "1200", deposits: 0, depositAmount: "0", topUps: 0, topUpAmount: "0", refunded: "0", refused: 0, sessionAuthorized: "0", note: "x".repeat(80) },
        relay: { attested: true, checkedAt: 1_800_000_000, sessionsAvailable: true },
        sentAt: 1_800_000_001,
      };
      expect((await localRequest(ep(), "/v1/spend", { body: report, headers: fromPeer("172.30.0.16") })).status).toBe(403);
      expect((await localRequest(ep(), "/v1/spend", { body: { counters: { day: "a covert message" } }, headers: fromPeer("172.30.0.5") })).status).toBe(400);
      expect((await localRequest(ep(), "/v1/spend", { body: report, headers: fromPeer("172.30.0.5") })).status).toBe(204);
      const h = await agent.reportHealth(now);
      expect(h.body.payments).toMatchObject({ mpp_debited: "1200", mpp_charges: 3, mpp_relayAttested: true, mpp_sentAt: 1_800_000_001 });
      expect(JSON.stringify(h.body)).not.toContain("xxxx");
      expect(JSON.stringify(h.body)).not.toContain("sealed-mpp-payer");
    });

    it("accepts the body the real payer sends (runtime/mpp-payer SpendGuard, ChannelRecovery, spendSnapshot, SpendReporter)", async () => {
      const guard = new SpendGuard(2_000_000n, () => now * 1000);
      guard.reserve(1200n, "charge");
      // The payer's channel recovery after one orphaned channel was closed and withdrawn (refund 487654).
      const channelId = `0x${"0c".repeat(32)}` as const;
      const journal = new ChannelJournal(undefined, () => now);
      journal.recordOpen({
        channelId,
        chainId: 4217,
        escrow: "0x4d50500000000000000000000000000000000000",
        descriptor: { payer: `0x${"11".repeat(20)}`, payee: `0x${"ab".repeat(20)}`, operator: `0x${"ab".repeat(20)}`, token: config.feeToken as `0x${string}`, salt: channelId, authorizedSigner: `0x${"22".repeat(20)}`, expiringNonceHash: channelId },
        deposit: 500_000n,
      });
      const recovery = new ChannelRecovery({
        journal,
        chain: {
          state: async () => ({ deposit: 500_000n, settled: 12_346n, closeRequestedAt: now - 1000 }),
          gracePeriod: async () => 900,
          prepare: async () => ({ feeCap: 100n, send: async () => ({ status: "success", refunded: 487_654n }) }),
        },
        liveChannels: () => new Set<string>(),
        guard,
        now: () => now + 400,
      });
      await recovery.sweep();
      const sources = {
        mode: "access-key",
        currency: config.feeToken,
        guard,
        gate: { isOpen: () => true, state: () => ({ checkedAt: now, stackHash: `0x${"ab".repeat(32)}` }) },
        relay: { sessionsAvailable: () => false },
        recovery,
      };
      const reporter = new SpendReporter({
        agentUrl: `http://127.0.0.1:${agent.port}`,
        intervalSeconds: 60,
        snapshot: () => spendSnapshot(sources),
        fetch: (url, init) => fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), ...fromPeer("172.30.0.5") } }),
      });
      expect(await reporter.send()).toBe(true);
      const h = await agent.reportHealth(now);
      expect(h.body.payments).toMatchObject({
        mpp_day: new Date(now * 1000).toISOString().slice(0, 10),
        mpp_limit: "2000000",
        mpp_budget: "2000000",
        mpp_debited: "1300",
        mpp_charges: 1,
        mpp_relayAttested: true,
        mpp_sessionsAvailable: false,
        // The payer's recovery counters reach the platform in the signed report (rounded, D-065).
        mpp_recoveryRequestCloses: 0,
        mpp_recoveryWithdrawals: 1,
        mpp_recovered: "480000",
        mpp_recoveryFailures: 0,
      });
      expect(JSON.stringify(h.body)).not.toContain("abab");
    });

    it("switches Caddy to the measured Caddyfile.payment-needed after the grace period", async () => {
      payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
      await agent.settle(now);
      now += 1440 * 60;
      const r = await agent.settle(now);
      expect(r.paymentNeeded).toBe(true);
      expect(caddy.current).toBe(await read("Caddyfile.payment-needed"));
      payer.budgetResult = { spendable: 1_000_000_000n };
      now += 60;
      expect((await agent.settle(now)).paymentNeeded).toBe(false);
      expect(caddy.current).toBe(await read("Caddyfile"));
    });

    it("reserves the payer's share of the daily budget after the next settlement's fees (D-048)", async () => {
      const post = (path: string, body: unknown, ip = "172.30.0.5") => localRequest(ep(), path, { body, headers: fromPeer(ip) });
      expect((await post("/v1/spend/reserve", { amount: "1000" }, "172.30.0.16")).status).toBe(403);
      expect((await post("/v1/spend/reserve", { amount: "1000", currency: `0x${"99".repeat(20)}` })).status).toBe(422);
      expect((await post("/v1/spend/reserve", { amount: "-1" })).status).toBe(400);
      expect((await post("/v1/spend/reserve", { amount: "0" })).status).toBe(400);
      expect((await post("/v1/spend/release", { reservationId: `0x${"00".repeat(16)}`, used: "1" })).status).toBe(404);
      // Usage that the next settlement will pay: 2M gateway tokens (0.40 USD).
      expect((await post("/v1/usage-events", { app: "llm-gateway", unit: "tokens", quantity: 2_000_000, id: "budget-1" }, "172.30.0.16")).status).toBe(202);
      // reserved_for_fees: unpaid legs, the open period and a network fee allowance per app transaction.
      const reserved = agent.feeReserve();
      expect(reserved).toBeGreaterThanOrEqual(400_000n + 10_000n);
      // What the payer may take: the limit less what was spent today (earlier settlements) and reserved_for_fees.
      const spent = BigInt(agent.budget?.state.fees ?? "0") + BigInt(agent.budget?.state.payer ?? "0");
      const base = 2_000_000n - spent - reserved;
      expect(agent.budget?.available(now)).toBe(base);
      const first = JSON.parse((await post("/v1/spend/reserve", { amount: "100000", currency: config.feeToken })).body);
      expect(first).toMatchObject({ ok: true, remaining: (base - 100_000n).toString() });
      // On disk before the payer hears of it: an agent restart cannot forget the reservation (review M4).
      const onDisk = JSON.parse(await readFile(join(testSettings(dir).dataMount, ".sealed-agent", "state.json"), "utf8"));
      expect(onDisk.budget.reservations[first.reservationId]).toMatchObject({ amount: "100000" });
      const tooMuch = JSON.parse((await post("/v1/spend/reserve", { amount: base.toString() })).body);
      expect(tooMuch).toEqual({ ok: false, remaining: (base - 100_000n).toString(), reason: "budget" });
      const released = JSON.parse((await post("/v1/spend/release", { reservationId: first.reservationId, used: "40000" })).body);
      expect(released).toEqual({ ok: true, remaining: (base - 40_000n).toString() });
      // Settlement pays the fees (plus the network fee) out of the same limit.
      const before = BigInt(agent.budget?.state.fees ?? "0");
      const r = await agent.settle(now);
      expect(r.apps.filter((a) => a.result === "paid").length).toBeGreaterThan(0);
      const paid = r.apps.reduce((s, a) => s + (a.result === "paid" ? a.amount + payer.networkFee : 0n), 0n);
      expect(BigInt(agent.budget?.state.fees ?? "0") - before).toBe(paid);
      const h = await agent.reportHealth(now);
      expect(h.body.payments).toMatchObject({ budget_limit: "2000000", budget_payer: "40000", budget_fees: (before + paid).toString(), budget_reserved: "0" });
    });

    it("answers the payer's own AgentSpendBudget client (runtime/mpp-payer shared-budget)", async () => {
      const client = (currency?: string) =>
        new AgentSpendBudget({
          agentUrl: `http://127.0.0.1:${agent.port}`,
          ...(currency ? { currency } : {}),
          retryDelaysMs: [],
          fetch: (url, init) => fetch(url, { ...init, headers: { ...(init?.headers as Record<string, string>), ...fromPeer("172.30.0.5") } }),
        });
      const before = agent.budget?.available(now) as bigint;
      const budget = client(config.feeToken);
      const r = await budget.reserve(25_000n);
      expect(r.remaining).toBe(before - 25_000n);
      await budget.release(r, 10_000n);
      expect(agent.budget?.available(now)).toBe(before - 10_000n);
      expect(budget.state()).toMatchObject({ pendingReleases: 0 });
      // Released twice: the agent answers 404, which the payer treats as already released.
      await budget.release(r, 10_000n);
      expect(budget.state()).toMatchObject({ pendingReleases: 0 });
      // More than the budget: the payer gets a shared SpendLimitError, not a payment.
      await expect(budget.reserve(before * 2n)).rejects.toBeInstanceOf(SpendLimitError);
      // Another fee token: the agent refuses it, and the payer treats that as unavailable (fail closed).
      await expect(client(`0x${"99".repeat(20)}`).reserve(1n)).rejects.toBeInstanceOf(BudgetUnavailableError);
    });

    it("follows the access key's limit period for the budget window", async () => {
      payer.limit = { remaining: 1_500_000n, periodEnd: now + 3600 };
      await agent.settle(now);
      expect(agent.budget?.state).toMatchObject({ windowEnd: now + 3600, aligned: true, onchain: { remaining: "1500000", periodEnd: now + 3600 } });
      // The onchain remaining limit, not the config's 2 USD, bounds the payer's share now.
      expect(agent.budget?.available(now)).toBe(1_500_000n - agent.feeReserve(now + 3600, now));
      payer.limit = undefined;
    });

    it("answers the gate only for Caddy, and fails closed on a released hash it cannot use", async () => {
      const gate = (ip: string, route = "tools") => localRequest(ep(), `/v1/gate?route=${route}`, { headers: { ...fromPeer(ip), authorization: `Basic ${Buffer.from("sealed:x").toString("base64")}` } });
      expect((await gate("172.30.0.16")).status).toBe(403);
      const r = await gate("172.30.0.4");
      // The golden secrets carry "$2a$14$hash", which is no bcrypt hash.
      expect(r.status).toBe(503);
      expect(r.body).toBe("gate not configured");
      expect((await gate("172.30.0.4", "attest")).status).toBe(403);
    });
  });
});
