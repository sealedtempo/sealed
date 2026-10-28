// The agent on the composer 1.2.0 golden stack (test/fixtures/composer-golden-1.2, from ws/int-composer):
// review ws-int-agent 1. Composer 1.2 binds the host's /run/sealed/secrets (on the CVM's /run tmpfs) into
// sealed-agent and binds single secret files into each service, so no owner directory exists at boot.
// The agent boots with the production tmpfs checks on, where only the secrets root and the ready volume
// are tmpfs, creates the owner directories, writes every `secretFiles` entry and only then the ready flag.
// The same boot covers the agent sides of D-065 (rounded counts), the payer's spend report fields
// (ws/fix-payments, recovery counters included), review C-6 (`?bearer=1`) and review L2.
import { lstat, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDefaults } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { parsePublicConfig, requireHttpsEndpoints } from "../src/context.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { HttpKeyBroker } from "../src/keyRelease.js";
import { silentLogger } from "../src/log.js";
import { TMPFS_MAGIC } from "../src/secrets.js";
import { settingsFromEnv } from "../src/settings.js";
import { parseStackInfo } from "../src/stack.js";
import { fixedTlsKey } from "../src/tls.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { fromPeer, testPeerOf, testSettings } from "./helpers/fixtures.js";

const golden = join(import.meta.dirname, "fixtures/composer-golden-1.2");
const read = (f: string) => readFile(join(golden, f), "utf8");
const appCompose = await read("app-compose.json");
const configText = await read("config.json");
const stack = parseStackInfo(await read("stack.json"));
const compose = JSON.parse(JSON.parse(appCompose).docker_compose_file) as { services: Record<string, { environment: Record<string, string>; volumes: { type: string; source: string; target: string }[] }> };
const agentSvc = compose.services["sealed-agent"] as (typeof compose.services)[string];
const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });

describe("sealed-agent on the composer 1.2 golden stack (host-bound secrets root)", () => {
  let dir: string;
  let sim: RunningSimulator;
  let broker: FakeBroker;
  let caddy: FakeCaddy;
  let agent: Agent;
  let payer: FakePayer;
  let base: ReturnType<typeof testSettings>;
  const now = 1_800_000_000;
  const health: { body: { egress: { allowed: Record<string, number>; blocked: Record<string, number> }; payments: Record<string, unknown> } }[] = [];
  const secrets = {
    "llm-gateway": { MASTER_KEY: "sk-master" },
    notes: { APP_SECRET: "notes-app", DB_PASSWORD: "pg" },
    _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" },
  };
  const ep = () => parseEndpoint(`http://127.0.0.1:${agent.port}`);
  const local = (p: string) => join(base.secretsDir, p.slice(stack.secretsRoot ? String(stack.secretsRoot).length + 1 : 0));

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-golden12-"));
    const { config } = parsePublicConfig(configText);
    broker = await startFakeBroker({ customer: config.customer, secrets });
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    base = testSettings(dir);
    // The host directory the compose binds (create_host_path: true) exists and is empty; only it, and the ready
    // volume, are tmpfs. Nothing below it exists yet.
    await mkdir(base.secretsDir, { recursive: true });
    await mkdir(base.readyDir, { recursive: true });
    await writeFile(base.configPath, configText);
    for (const f of ["stack.json", "Caddyfile", "Caddyfile.payment-needed"]) await writeFile(join(dir, f), await read(f));
    caddy = await startFakeCaddy(base.caddyAdminSocket, await read("Caddyfile"));
    payer = new FakePayer();
    agent = new Agent({
      settings: { ...base, stackPath: join(dir, "stack.json"), caddyfilePath: join(dir, "Caddyfile"), caddyfilePaymentNeededPath: join(dir, "Caddyfile.payment-needed"), requireTmpfs: true },
      fsType: async (p) => {
        await stat(p);
        const onTmpfs = p === base.secretsDir || p.startsWith(`${base.secretsDir}/`) || p === base.readyDir;
        return onTmpfs ? TMPFS_MAGIC : 0xef53;
      },
      clock: { now: () => now, sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 20))) },
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      broker: new HttpKeyBroker(broker.url),
      platform: {
        postEvidence: async () => ({ deploymentId: "0x" }),
        postUsage: async () => undefined,
        postHealth: async (b) => {
          health.push(b as (typeof health)[number]);
          return { ok: true };
        },
      },
      payer: () => payer,
      tls: fixedTlsKey(`0x${"77".repeat(32)}`),
      // Exact counts as an older sealed-egress serves them (newer ones round already, D-065).
      egressStats: async () => ({ since: 1_799_999_000, allowed: { "api.example.com:443": 98_765 }, blocked: { "unlisted:443": 123, "ip-public:80": 7 } }),
      probe: async () => true,
      defaults,
      peerOf: testPeerOf,
    });
    await agent.boot();
  });
  afterAll(async () => {
    await agent?.stop();
    await Promise.all([broker?.close(), caddy?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  it("is the composer 1.2 layout: the agent binds the host's secrets root, services bind single files", () => {
    expect(stack.composerVersion).toBe("1.2.0");
    const env = settingsFromEnv(agentSvc.environment);
    expect(agentSvc.volumes.find((v) => v.target === env.secretsDir)).toMatchObject({ type: "bind", source: "/run/sealed/secrets" });
    expect(agentSvc.volumes.some((v) => v.type === "volume" && v.source.startsWith("sealed-secrets-"))).toBe(false);
  });

  it("created each owner directory (0755) on the tmpfs root and wrote every secretFiles entry before the ready flag", async () => {
    const files = stack.secretFiles as string[];
    expect(files.length).toBe(6);
    for (const owner of ["llm-gateway", "notes", "sealed-mpp-payer"]) {
      const st = await lstat(join(base.secretsDir, owner));
      expect(st.isDirectory() && !st.isSymbolicLink()).toBe(true);
      expect(st.mode & 0o777).toBe(0o755);
    }
    const readyAt = (await stat(join(base.readyDir, "ok"))).mtimeMs;
    for (const f of files) {
      const st = await stat(local(f));
      expect(st.mode & 0o777, f).toBe(0o444);
      expect(st.mtimeMs, f).toBeLessThanOrEqual(readyAt);
    }
    expect(await readFile(local("/run/sealed/secrets/notes/DB_PASSWORD"), "utf8")).toBe("pg");
    expect(await readFile(local("/run/sealed/secrets/notes/SMTP_PASSWORD"), "utf8")).toBe(""); // optional, not set
    expect(await readFile(local("/run/sealed/secrets/sealed-mpp-payer/ENCLAVE_KEY"), "utf8")).toBe(agent.keys?.enclaveKey);
    // Caddy holds no secret in 1.2: the gate's hash stays in the agent's memory (D-042).
    await expect(stat(join(base.secretsDir, "_gate"))).rejects.toThrow();
    expect((await localRequest(ep(), "/v1/ready")).status).toBe(200);
  });

  it("rounds egress counts and the payer's counters down to two significant figures; usage stays exact (D-065)", async () => {
    const report = {
      source: "sealed-mpp-payer",
      mode: "access-key",
      currency: (JSON.parse(configText) as { feeToken: string }).feeToken,
      counters: { day: "2027-01-15", limit: "2000000", budget: "2000000", debited: "123456", remaining: "1876544", charges: 345, chargeAmount: "123456", deposits: 0, depositAmount: "0", topUps: 0, topUpAmount: "0", refunded: "0", refused: 12, sessionAuthorized: "0" },
      relay: { attested: true, checkedAt: now, stackHash: `0x${"ab".repeat(32)}`, sessionsAvailable: true },
      // ws/fix-payments: ChannelRecovery counters, and a field this agent does not know yet.
      recovery: { requestCloses: 3, withdrawals: 2, recovered: "987654", failures: 0 },
      newerField: { anything: "dropped" },
      sentAt: now,
    };
    expect((await localRequest(ep(), "/v1/spend", { body: report, headers: fromPeer("172.30.0.5") })).status).toBe(204);
    const h = await agent.reportHealth(now);
    expect(h.body.egress).toEqual({ since: 1_799_999_000, allowed: { "api.example.com:443": 98_000 }, blocked: { "unlisted:443": 120, "ip-public:80": 7 } });
    expect(h.body.payments).toMatchObject({
      mpp_charges: 340,
      mpp_debited: "120000",
      mpp_remaining: "1800000",
      mpp_refused: 12,
      mpp_recoveryRequestCloses: 3,
      mpp_recoveryWithdrawals: 2,
      mpp_recovered: "980000",
      mpp_recoveryFailures: 0,
      // Exact: limits and timestamps.
      mpp_limit: "2000000",
      mpp_sentAt: now,
      mpp_relayCheckedAt: now,
    });
    expect(JSON.stringify(h.body)).not.toContain("dropped");
    expect(Object.keys(h.body.payments).length).toBeLessThanOrEqual(64);
    // Usage quantities stay exact: billing needs them.
    expect((await localRequest(ep(), "/v1/usage-events", { body: { app: "llm-gateway", unit: "tokens", quantity: 123_457, id: "u1" }, headers: fromPeer("172.30.0.16") })).status).toBe(202);
    expect(agent.ledger?.state.open["llm-gateway"]?.tokens).toBe("123457");
  });

  it("answers ?bearer=1 for the bearer-passthrough route once the keys are released (review C-6)", async () => {
    const gate = (q: string, authorization?: string) =>
      localRequest(ep(), `/v1/gate?${q}`, { headers: { ...fromPeer("172.30.0.4"), ...(authorization ? { authorization } : {}) } });
    const ok = await gate("route=gateway&bearer=1", "Bearer sk-app");
    expect(ok.status).toBe(200);
    expect((await gate("route=gateway&bearer=1")).status).toBe(401);
    expect((await gate("route=tools&bearer=1", "Bearer sk-app")).status).toBe(403);
  });

  it("leaves legs it cannot pay out of reserved_for_fees (review L2)", async () => {
    const before = agent.feeReserve(now + 3600, now);
    payer.budgetResult = { spendable: 0n, problem: "insufficient_balance" };
    await agent.settle(now);
    const leg = agent.ledger?.unpaid()[0];
    expect(leg).toBeDefined();
    const withLeg = agent.feeReserve(now + 3600, now);
    expect(withLeg).toBeGreaterThanOrEqual(before);
    (agent.store?.state.payments as { unpayable?: Record<string, string> }).unpayable = { [`${leg?.usageHash}:${leg?.app}`]: "over_payment_cap" };
    expect(agent.feeReserve(now + 3600, now)).toBe(withLeg - (leg?.fee ?? 0n) - 10_000n);
  });

  it("refuses plain-http endpoints outside loopback and dev sim mode (review C-4)", () => {
    const { config } = parsePublicConfig(configText);
    expect(() => requireHttpsEndpoints(config.endpoints, false)).not.toThrow();
    for (const name of ["keyBroker", "platformApi", "tempoRpc", "relay", "relayAttest"]) {
      const endpoints = { ...config.endpoints, [name]: "http://broker.example/attest" };
      expect(() => requireHttpsEndpoints(endpoints, false), name).toThrow(`endpoints.${name} must be https`);
      expect(() => requireHttpsEndpoints(endpoints, true), name).not.toThrow();
    }
    expect(() => requireHttpsEndpoints({ ...config.endpoints, keyBroker: "http://127.0.0.1:8080" }, false)).not.toThrow();
    expect(() => requireHttpsEndpoints({ ...config.endpoints, keyBroker: "ftp://x" }, false)).toThrow("must be https");
  });
});

