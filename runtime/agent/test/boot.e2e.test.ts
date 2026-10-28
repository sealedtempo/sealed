// End to end boot flow (spec 5.6) against the dstack simulator, a fake key broker and a fake
// platform API: key release, secrets, evidence, /attest, metering, usage reports and health.
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  attestReportData,
  bytesToHex,
  configHash,
  decodeSimQuote,
  deploymentId as computeDeploymentId,
  enclaveSignerAddress,
  eventLogHash,
  evidenceBundleSchema,
  evidenceReportData,
  type Hex,
  hexToBytes,
  loadDefaults,
  quoteHash,
  recoverCjsonBodySigner,
  recoverUsageReportSigner,
  stackHash,
  usageDomain,
  usageReportDigest,
  usageReportFromJson,
} from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import type { AgentSettings } from "../src/settings.js";
import { CaddyCertSource } from "../src/tls.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { sampleCaddyConfig, startFakeCaddy, type FakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CUSTOMER, makeAppCompose, makeConfig } from "./helpers/fixtures.js";

const fx = JSON.parse(await readFile(join(import.meta.dirname, "fixtures/attest.json"), "utf8"));
const defaults = await loadDefaults(join(import.meta.dirname, "../../../config/defaults.yaml"), { testOverrides: false });

describe("sealed-agent boot flow", () => {
  let dir: string;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let sim: RunningSimulator;
  let config: ReturnType<typeof makeConfig>;
  let appCompose: string;
  let settings: AgentSettings;
  let agent: Agent;
  let payer: FakePayer;
  let approved = false;
  const brokerKey = Buffer.alloc(32, 3);
  const secrets = { crm: { APP_SECRET: "crm-secret-value" }, "llm-gateway": { LITELLM_MASTER_KEY: "sk-test" }, _gate: { GATE_PASSWORD_BCRYPT: "$2a$14$hash" } };
  let now = 1_800_000_000;
  const clock = { now: () => now, sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 20))) };

  function newAgent(p = new FakePayer()) {
    payer = p;
    return new Agent({
      settings,
      clock,
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      payer: () => payer,
      tls: new CaddyCertSource(join(dir, "caddy-data"), fx.host),
      egressStats: async () => ({ since: 1_799_999_000, allowed: { "api.example.com:443": 3 }, blocked: { "evil.example:443": 1 } }),
      probe: async () => true,
      defaults,
      releaseDeniedDelayMs: 10,
      caddy: undefined,
    });
  }

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-agent-e2e-"));
    broker = await startFakeBroker({ customer: CUSTOMER, secrets, approved: () => approved, hmacKey: brokerKey });
    platform = await startFakePlatform();
    platform.failEvidence = 1;
    caddy = await startFakeCaddy(join(dir, "caddy-admin.sock"), sampleCaddyConfig("34-1-2-3"));
    config = makeConfig({ endpoints: { keyBroker: broker.url, platformApi: platform.url } });
    const dataMount = join(dir, "data");
    appCompose = makeAppCompose(config, dataMount);
    await writeFile(join(dir, "config.json"), JSON.stringify(config, null, 2));
    await writeFile(
      join(dir, "agent-apps.json"),
      JSON.stringify({
        schema: "sealed-agent-apps/v1",
        apps: {
          crm: { metering: { unit: "app_hour", source: "heartbeat" }, healthcheck: "http://crm-server:3000/healthz" },
          "llm-gateway": { metering: { unit: "tokens", source: "callback" }, healthcheck: "http://llm-gateway:4000/health/liveliness" },
        },
      }),
    );
    const certDir = join(dir, "caddy-data", "caddy", "certificates", "local", fx.host);
    await mkdir(certDir, { recursive: true });
    await cp(join(import.meta.dirname, "fixtures/attest.crt"), join(certDir, `${fx.host}.crt`));
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    settings = {
      configPath: join(dir, "config.json"),
      appsMetaPath: join(dir, "agent-apps.json"),
      testOverrides: false,
      listenHost: "127.0.0.1",
      listenPort: 0,
      secretsDir: join(dir, "run", "secrets"),
      readyFile: join(dir, "run", "ready"),
      dataMount,
      dataDevice: "/dev/null",
      luksName: "sealed-data",
      diskMode: "dir",
      caddyAdminSocket: join(dir, "caddy-admin.sock"),
      caddyDataDir: join(dir, "caddy-data"),
      egressStatsUrl: "http://127.0.0.1:9/v1/stats",
      reattestHours: 24,
      healthIntervalSec: 60,
      pollIntervalSec: 30,
      devSim: true,
    };
    agent = newAgent();
    setTimeout(() => {
      approved = true;
    }, 100);
    await agent.boot();
  });

  afterAll(async () => {
    await agent?.stop();
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    await rm(dir, { recursive: true, force: true });
  });

  const expectedDeploymentId = () => computeDeploymentId(CUSTOMER, stackHash(appCompose), config.salt as Hex);
  const expectedSigner = () => enclaveSignerAddress(broker.derive("sealed/signer/v1", expectedDeploymentId()));

  it("retried the denied release, then derived the enclave signer from the released seed", () => {
    expect(broker.denials).toContain("stack_not_approved");
    expect(broker.releases).toBe(1);
    expect(agent.ctx?.deploymentId).toBe(expectedDeploymentId());
    expect(agent.enclaveSigner).toBe(expectedSigner());
  });

  it("wrote app secrets, the payer key and the ready flag, and reports healthy", async () => {
    expect(await readFile(join(settings.secretsDir, "crm", "APP_SECRET"), "utf8")).toBe("crm-secret-value");
    expect(await readFile(join(settings.secretsDir, "_gate", "GATE_PASSWORD_BCRYPT"), "utf8")).toBe("$2a$14$hash");
    const payerKey = await readFile(join(settings.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8");
    expect(payerKey).toBe(agent.keys?.enclaveKey);
    expect(await readFile(join(settings.secretsDir, "sealed-mpp-payer", "SPEND_LIMIT_PER_DAY"), "utf8")).toBe("2000000");
    expect(await readFile(settings.readyFile, "utf8")).toMatch(/^\d+\n$/);
    const ep = parseEndpoint(`http://127.0.0.1:${agent.port}`);
    expect((await localRequest(ep, "/healthz")).status).toBe(200);
    const ready = JSON.parse((await localRequest(ep, "/v1/ready")).body);
    expect(ready).toMatchObject({ ready: true, deploymentId: expectedDeploymentId(), enclaveSigner: expectedSigner() });
  });

  it("created the per-app volume directories on the data disk", async () => {
    await readFile(join(settings.dataMount, ".sealed-agent", "state.json"), "utf8").catch(() => undefined);
    const { stat } = await import("node:fs/promises");
    expect((await stat(join(settings.dataMount, "crm", "db"))).isDirectory()).toBe(true);
    expect((await stat(join(settings.dataMount, "crm", "files"))).isDirectory()).toBe(true);
  });

  it("submitted an evidence bundle (after one retry) whose quote binds stack, config, signer and nonce2", async () => {
    await agent.evidence;
    expect(platform.evidence.length).toBe(1);
    const b = evidenceBundleSchema.parse(platform.evidence[0]);
    expect(b.stackHash).toBe(stackHash(appCompose));
    expect(b.appCompose).toBe(appCompose);
    expect(b.configHash).toBe(configHash(config));
    expect(b.deploymentId).toBe(expectedDeploymentId());
    expect(b.enclaveSigner).toBe(expectedSigner());
    expect(b.releaseIds).toEqual(config.apps.map((a) => a.releaseId));
    expect(b.imageId).toBe(config.imageId);
    expect(b.quoteHash).toBe(quoteHash(b.quote as Hex));
    expect(b.eventLogHash).toBe(eventLogHash(b.eventLog));
    expect(b.attestedAt).toBe(now);
    const q = decodeSimQuote(hexToBytes(b.quote));
    const rd = evidenceReportData(b.stackHash as Hex, b.configHash as Hex, b.enclaveSigner as Hex, b.nonce2 as Hex);
    expect(q.reportData).toBe(bytesToHex(rd).slice(2));
  });

  it("serves /attest bound to the nonce, the TLS key and the enclave signer", async () => {
    const nonce = `0x${"9c".repeat(32)}`;
    const ep = parseEndpoint(`http://127.0.0.1:${agent.port}`);
    const res = await localRequest(ep, `/attest?nonce=${nonce}`);
    expect(res.status).toBe(200);
    const a = JSON.parse(res.body);
    expect(a.tlsPubKeyHash).toBe(fx.spkiSha256);
    expect(a.enclaveSigner).toBe(expectedSigner());
    const expected = bytesToHex(attestReportData(nonce as Hex, fx.spkiSha256, expectedSigner()));
    expect(a.reportData).toBe(expected);
    expect(decodeSimQuote(hexToBytes(a.quote)).reportData).toBe(expected.slice(2));
    expect(a.appCompose).toBe(appCompose);
    expect(a.config).toEqual(config);
    expect((await localRequest(ep, "/attest?nonce=0x1234")).status).toBe(400);
  });

  it("meters callback and heartbeat apps into a signed usage report and pays it", async () => {
    const ep = parseEndpoint(`http://127.0.0.1:${agent.port}`);
    const post = (body: unknown) => localRequest(ep, "/v1/usage-events", { body });
    expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 600_000, id: "call-1", meta: { model: "local/qwen3-4b" } })).status).toBe(202);
    expect(JSON.parse((await post({ app: "llm-gateway", unit: "tokens", quantity: 600_000, id: "call-1" })).body).status).toBe("duplicate");
    expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 400_000, id: "call-2" })).status).toBe(202);
    expect((await post({ app: "crm", unit: "app_hour", quantity: 10 })).status).toBe(422);
    expect((await post({ app: "llm-gateway", unit: "pages", quantity: 1 })).status).toBe(422);
    await agent.pollApps(now);
    now += 30;
    await agent.pollApps(now);
    now += 30;
    await agent.pollApps(now);
    now += 600;
    const result = await agent.settle(now);
    expect(result.reportCut).toBe(true);
    expect(result.outcome).toBe("settled");
    expect(platform.usage.length).toBe(1);
    const { report: json, signature } = platform.usage[0] as { report: never; signature: Hex };
    const report = usageReportFromJson(json);
    const domain = usageDomain(config.contracts.feeSplitter as Hex, config.chainId);
    expect((await recoverUsageReportSigner(report, domain, signature)).toLowerCase()).toBe(expectedSigner());
    expect(report.items.map((i) => [i.unit, i.quantity, i.fee])).toEqual([
      [3, 60n, 833n],
      [1, 1_000_000n, 200_000n],
    ]);
    const usageHash = usageReportDigest(report, domain);
    expect(payer.paid.flat().map((l) => [l.amount, l.usageHash])).toEqual([
      [833n, usageHash],
      [200_000n, usageHash],
    ]);
  });

  it("sends a content-free health report signed by the enclave signer", async () => {
    const ep = parseEndpoint(`http://127.0.0.1:${agent.port}`);
    expect((await localRequest(ep, "/v1/spend", { body: { spentToday: "1200", limit: "2000000", "bad key": 1 } })).status).toBe(204);
    await agent.reportHealth(now);
    const h = platform.health.at(-1) as FakePlatform["health"][number];
    expect(h.deploymentId).toBe(expectedDeploymentId());
    expect(await recoverCjsonBodySigner(h.body, h.signature)).toBe(expectedSigner());
    expect(h.body).toMatchObject({
      at: now,
      apps: { crm: "healthy", "llm-gateway": "healthy" },
      egress: { allowed: { "api.example.com:443": 3 }, blocked: { "evil.example:443": 1 } },
      payments: { mode: "access-key", paymentNeeded: false, unpaid: "0", metered: "200833", mpp_spentToday: "1200", mpp_limit: "2000000" },
    });
    expect(JSON.stringify(h.body)).not.toContain("crm-secret-value");
  });

  it("after a reboot the same deployment gets the same signer, disk state and fresh evidence", async () => {
    await agent.stop();
    agent = newAgent();
    await agent.boot();
    await agent.evidence;
    expect(agent.enclaveSigner).toBe(expectedSigner());
    expect(platform.evidence.length).toBe(2);
    expect(platform.evidence[1]?.nonce2).not.toBe(platform.evidence[0]?.nonce2);
    expect(agent.ledger?.totals().metered).toBe(200_833n);
  });
});
