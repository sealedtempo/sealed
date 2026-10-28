// The agent against the composer's golden stack (test/fixtures/composer-golden, copied from
// runtime/composer/testdata/golden): the sealed-agent service's environment, mounts and volumes, the
// measured configs, and a full boot on that exact app-compose.json with the dstack simulator, a fake
// key broker and tmpfs checks driven by the compose's own volume list. Review finding: the agent and
// the composer had drifted apart on all of these.
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
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
import { fromPeer, testPeerOf, testSettings } from "./helpers/fixtures.js";

const golden = join(import.meta.dirname, "fixtures/composer-golden");
const read = (f: string) => readFile(join(golden, f), "utf8");
const appCompose = await read("app-compose.json");
const configText = await read("config.json");
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
  const settings = settingsFromEnv(agentSvc.environment);
  const configTarget = (name: string) => agentSvc.configs.find((c) => c.source === name)?.target;
  const volumeTarget = (name: string) => agentSvc.volumes.find((v) => v.type === "volume" && v.source === name)?.target;

  it("the composer's sealed-agent environment and mounts give the agent its paths", () => {
    expect(settings.configPath).toBe(configTarget("sealed-config"));
    expect(settings.stackPath).toBe(configTarget("sealed-stack"));
    expect(settings.caddyfilePath).toBe(configTarget("sealed-caddyfile"));
    expect(settings.caddyfilePaymentNeededPath).toBe(configTarget("sealed-caddyfile-payment-needed"));
    // The ready flag lives in a shared tmpfs volume, a directory, as `<dir>/ok`.
    expect(settings.readyDir).toBe(volumeTarget("sealed-ready"));
    expect(compose.volumes["sealed-ready"]?.driver_opts?.type).toBe("tmpfs");
    expect(dirname(settings.caddyAdminSocket)).toBe(volumeTarget("sealed-caddy-admin"));
    for (const owner of ["_gate", "llm-gateway", "notes", "sealed-mpp-payer"]) {
      expect(volumeTarget(`sealed-secrets-${owner}`)).toBe(join(settings.secretsDir, owner));
      expect(compose.volumes[`sealed-secrets-${owner}`]?.driver_opts?.type).toBe("tmpfs");
    }
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
    expect(ctx.apps).toEqual([
      expect.objectContaining({ id: "llm-gateway", metering: { unit: "tokens", source: "callback" }, healthcheck: "http://172.30.0.16:4000/health/liveliness", serviceIps: ["172.30.0.16"] }),
      expect.objectContaining({ id: "notes", metering: { unit: "app_hour", source: "heartbeat" }, healthcheck: "http://172.30.0.17:8080/healthz", serviceIps: ["172.30.0.18", "172.30.0.17"] }),
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
      // The secrets tmpfs volumes the compose mounts into the agent, and nothing else, count as tmpfs.
      for (const v of agentSvc.volumes) {
        if (v.type === "volume" && v.source.startsWith("sealed-secrets-")) {
          const local = join(base.secretsDir, v.target.slice(settings.secretsDir.length + 1));
          await mkdir(local, { recursive: true });
          tmpfs.add(local);
        }
      }
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
          return tmpfs.has(p) ? TMPFS_MAGIC : 0xef53;
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

    it("opens the ready gate as <SEALED_READY_DIR>/ok and writes every secret into its own tmpfs volume", async () => {
      const s = testSettings(dir);
      expect(await readFile(join(s.readyDir, "ok"), "utf8")).toMatch(/^\d+\n$/);
      expect(await readFile(join(s.secretsDir, "notes", "DB_PASSWORD"), "utf8")).toBe("pg");
      expect(await readFile(join(s.secretsDir, "llm-gateway", "MASTER_KEY"), "utf8")).toBe("sk-master");
      expect(await readFile(join(s.secretsDir, "_gate", "GATE_PASSWORD_BCRYPT"), "utf8")).toBe("$2a$14$hash");
      expect(await readFile(join(s.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8")).toBe(agent.keys?.enclaveKey);
      expect((await localRequest(ep(), "/v1/ready")).status).toBe(200);
    });

    it("created every bind source on the data disk, including Caddy's certificate storage", async () => {
      const data = testSettings(dir).dataMount;
      for (const p of ["notes/pgdata", "notes/uploads", "_caddy/data"]) expect((await stat(join(data, p))).isDirectory()).toBe(true);
    });

    it("accepts usage only from the app's own service IPs and only in the unit the manifest meters", async () => {
      const post = (body: unknown, ip: string) => localRequest(ep(), "/v1/usage-events", { body, headers: fromPeer(ip) });
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000, id: "c1" }, "172.30.0.16")).status).toBe(202);
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000 }, "172.30.0.17")).status).toBe(403); // notes-web
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1000 }, "172.30.0.5")).status).toBe(403); // the payer
      expect((await post({ app: "notes", unit: "app_hour", quantity: 60 }, "172.30.0.17")).status).toBe(422); // heartbeat-metered
      expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 50_000_000 }, "172.30.0.16")).status).toBe(422); // per-event limit
      expect(agent.ledger?.state.open["llm-gateway"]?.tokens).toBe("1000");
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
  });
});
