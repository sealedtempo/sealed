// End to end on real composer output (brief item 21). The real composer
// (`go run ./runtime/composer/cmd/sealed-compose`) composes the real catalog app packages, with the
// development flags that allow unbuilt (all-zero) image digests and missing SBOMs. The agent then
// boots on exactly that app-compose.json against the dstack simulator, a fake key broker and a fake
// platform API, and the test checks that:
// - secrets land per service: every service sees the secrets it declares, from its own app only
//   (and, once the composer mounts one file per secret, nothing else),
// - every data directory exists before the ready flag,
// - the forward_auth gate works for every gated route the composer emits, bootstrap included,
// - the evidence bundle verifies with the real verifier library in simulator mode,
// - the payment-needed switch loads the composed Caddyfiles.
import { execFile, execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { promisify } from "node:util";
import { type EvidenceBundle, loadDefaults } from "@sealed/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningSimulator, startSimulator } from "../sim/simulator.js";
import { Agent } from "../src/agent.js";
import { DstackClient } from "../src/dstack.js";
import { localRequest, parseEndpoint } from "../src/http.js";
import { HttpKeyBroker } from "../src/keyRelease.js";
import { silentLogger } from "../src/log.js";
import { declaredSecretsFromAppCompose, filesMountedIndividually, secretMountsFromAppCompose, visibleSecrets } from "../src/secretMounts.js";
import { TMPFS_MAGIC } from "../src/secrets.js";
import { settingsFromEnv } from "../src/settings.js";
import { parseStackInfo, type StackInfo } from "../src/stack.js";
import { fixedTlsKey } from "../src/tls.js";
import { type FakeBroker, startFakeBroker } from "./helpers/fakeBroker.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { type FakePlatform, startFakePlatform } from "./helpers/fakePlatform.js";
import { CUSTOMER, fromPeer, testPeerOf, testSettings } from "./helpers/fixtures.js";

const run = promisify(execFile);
const repo = join(import.meta.dirname, "../../..");
/** The customer apps of the catalog (inference-relay is the platform's relay deployment, not a customer app). */
const APPS = ["coding-agent", "crm", "internal-tools", "llm-gateway", "scraper"];
const GATE_PASSWORD = "sealed-gate-password";
/** bcrypt of GATE_PASSWORD made by golang.org/x/crypto/bcrypt (fixtures/bcrypt-go-vectors.jsonl). */
const gateHash = (await readFile(join(import.meta.dirname, "fixtures/bcrypt-go-vectors.jsonl"), "utf8"))
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l) as { password: string; hash: string })
  .find((v) => v.password === Buffer.from(GATE_PASSWORD).toString("hex"))?.hash as string;

function goAvailable(): boolean {
  try {
    execFileSync("go", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const haveGo = goAvailable();
if (!haveGo && (process.env.CI || process.env.SEALED_REQUIRE_CHAIN_TESTS === "1")) {
  throw new Error("the composer end-to-end test needs Go on PATH (CI and SEALED_REQUIRE_CHAIN_TESTS=1 require it)");
}

const basic = (pw: string) => `Basic ${Buffer.from(`sealed:${pw}`).toString("base64")}`;

describe.runIf(haveGo)("sealed-agent on the real composer output for the catalog apps", () => {
  let dir: string;
  let out: string;
  let appCompose: string;
  let stack: StackInfo;
  let config: Record<string, unknown> & { feeToken: string; apps: { id: string; releaseId: string }[] };
  let composerVersion: string;
  let sim: RunningSimulator;
  let broker: FakeBroker;
  let platform: FakePlatform;
  let caddy: FakeCaddy;
  let agent: Agent;
  let settings: ReturnType<typeof testSettings>;
  let caddyIp: string;
  const payer = new FakePayer();
  let now = 1_800_000_000;
  const secrets: Record<string, Record<string, string>> = {};
  const chowns: { path: string; readyFlag: boolean }[] = [];
  const ep = () => parseEndpoint(`http://127.0.0.1:${agent.port}`);
  const gate = (route: string, headers: Record<string, string> = {}, client = "203.0.113.7") =>
    localRequest(ep(), `/v1/gate?route=${encodeURIComponent(route)}`, { headers: { ...fromPeer(caddyIp), "x-forwarded-for": client, ...headers } });

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-catalog-"));
    out = join(dir, "composed");
    composerVersion = (JSON.parse(await readFile(join(repo, "runtime/composer/testdata/config.json"), "utf8")) as { composerVersion: string }).composerVersion;
    const deployed = JSON.parse(await readFile(join(repo, "contracts/deployments/tempo-mainnet.json"), "utf8")) as {
      contracts: Record<string, { address: string }>;
      config: { feeToken: string };
    };
    const addr = (name: string) => (deployed.contracts[name]?.address as string).toLowerCase();
    // A mainnet-shaped config (USDC.e fee token, the deployed registries). No transaction is ever sent:
    // the fee payer is a fake.
    const input = {
      schema: "sealed-config/v1",
      chainId: 4217,
      customer: CUSTOMER,
      salt: `0x${"5a".repeat(32)}`,
      imageId: `0x${"1d".repeat(32)}`,
      composerVersion,
      apps: APPS.map((id) => ({ id, releaseId: `0x${"00".repeat(32)}` })),
      hostnames: { scheme: "sslip", ip: "34.1.2.3" },
      egressAdditions: {},
      allowedVpcRanges: [],
      endpoints: {
        keyBroker: "https://sealed-key-broker-test.a.run.app",
        platformApi: "https://api.sealed.example",
        tempoRpc: "https://rpc.tempo.xyz",
        relay: "https://relay.sealed.example",
        relayAttest: "https://attest.relay.sealed.example/attest",
      },
      contracts: {
        platformRegistry: addr("PlatformRegistry"),
        appRegistry: addr("AppRegistry"),
        deploymentRegistry: addr("DeploymentRegistry"),
        feeSplitter: addr("FeeSplitter"),
      },
      feeToken: deployed.config.feeToken.toLowerCase(),
      settlement: { mode: "access-key", intervalMinutes: 60, gracePeriodMinutes: 1440, spendLimitPerDay: "2000000" },
      relayOwner: `0x${"b1".repeat(20)}`,
    };
    await writeFile(join(dir, "input.json"), JSON.stringify(input));
    // --fill-release-ids and --allow-missing-sbom are the composer's development flags; unbuilt digests
    // are allowed unless --require-built is passed.
    await run(
      "go",
      ["run", "./runtime/composer/cmd/sealed-compose", "compose", "--config", join(dir, "input.json"), "--fill-release-ids", "--allow-missing-sbom", ...APPS.flatMap((a) => ["--app-dir", `catalog/apps/${a}`]), "--out", out, "--print", "summary"],
      { cwd: repo, maxBuffer: 16 * 1024 * 1024 },
    );
    appCompose = await readFile(join(out, "app-compose.json"), "utf8");
    stack = parseStackInfo(await readFile(join(out, "stack.json"), "utf8"));
    config = JSON.parse(await readFile(join(out, "config.json"), "utf8"));
    caddyIp = stack.sidecars.caddy as string;

    // Secrets as the broker would release them: every required secret of every app, no optional ones,
    // and the gate's bcrypt hash.
    for (const app of stack.apps) {
      const values: Record<string, string> = {};
      for (const s of app.secrets) if (!s.optional) values[s.name] = `${app.id}:${s.name}:${Math.random().toString(36).slice(2)}`;
      if (Object.keys(values).length > 0) secrets[app.id] = values;
    }
    secrets._gate = { GATE_PASSWORD_BCRYPT: gateHash };

    const compose = JSON.parse(JSON.parse(appCompose).docker_compose_file) as { services: Record<string, { environment: Record<string, string>; volumes: { type: string; source: string; target: string }[] }> };
    const agentSvc = compose.services["sealed-agent"] as (typeof compose.services)[string];
    const env = settingsFromEnv(agentSvc.environment);
    settings = testSettings(dir);
    // Exactly the secrets tmpfs volumes the compose mounts into the agent count as tmpfs.
    const tmpfs = new Set<string>();
    for (const v of agentSvc.volumes) {
      if (v.type === "volume" && v.source.startsWith("sealed-secrets-")) {
        const local = join(settings.secretsDir, relative(env.secretsDir, v.target));
        await mkdir(local, { recursive: true });
        tmpfs.add(local);
      }
    }
    await mkdir(settings.readyDir, { recursive: true });
    await writeFile(settings.configPath, await readFile(join(out, "config.json"), "utf8"));
    const defaults = await loadDefaults(join(repo, "config/defaults.yaml"), { testOverrides: false });
    broker = await startFakeBroker({ customer: CUSTOMER, secrets });
    platform = await startFakePlatform();
    sim = await startSimulator({ appCompose, socket: join(dir, "dstack.sock") });
    caddy = await startFakeCaddy(settings.caddyAdminSocket, await readFile(join(out, "Caddyfile"), "utf8"));
    const platformUrl = platform.url;
    agent = new Agent({
      settings: {
        ...settings,
        stackPath: join(out, "stack.json"),
        caddyfilePath: join(out, "Caddyfile"),
        caddyfilePaymentNeededPath: join(out, "Caddyfile.payment-needed"),
        requireTmpfs: true,
      },
      fsType: async (p) => {
        await stat(p);
        return tmpfs.has(p) ? TMPFS_MAGIC : 0xef53;
      },
      chown: async (path) => {
        chowns.push({ path, readyFlag: await stat(join(settings.readyDir, "ok")).then(() => true, () => false) });
      },
      clock: { now: () => now, sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 20))) },
      log: silentLogger,
      dstack: new DstackClient(parseEndpoint(sim.endpoint)),
      broker: new HttpKeyBroker(broker.url),
      platform: {
        postEvidence: async (b) => {
          await fetch(`${platformUrl}/v1/evidence`, { method: "POST", body: JSON.stringify(b), headers: { "content-type": "application/json" } });
          return { deploymentId: b.deploymentId as `0x${string}` };
        },
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
    await agent.evidence;
  }, 600_000);

  afterAll(async () => {
    await agent?.stop();
    await Promise.all([broker?.close(), platform?.close(), caddy?.close(), sim?.close()]);
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("boots on the composed stack: all catalog apps, the payer, the composer's own paths", () => {
    expect(stack.composerVersion).toBe(composerVersion);
    expect(agent.ctx?.apps.map((a) => a.id)).toEqual(APPS);
    expect(agent.ctx?.payerIp).toBe(stack.sidecars["sealed-mpp-payer"]);
    expect(config.feeToken).toBe("0x20c000000000000000000000b9537d11c60e8b50");
    expect(broker.releases).toBe(1);
  });

  it("lands each secret where only the services that declare it can read it", async () => {
    const mounts = secretMountsFromAppCompose(appCompose);
    const individually = filesMountedIndividually(mounts);
    const written: Record<string, string[]> = {};
    for (const owner of await readdir(settings.secretsDir)) written[owner] = (await readdir(join(settings.secretsDir, owner))).sort();
    const declared = declaredSecretsFromAppCompose(appCompose);
    const services = [...new Set(declared.map((d) => d.service))];
    expect(services.length).toBeGreaterThanOrEqual(APPS.length);
    for (const service of services) {
      const mine = declared.filter((d) => d.service === service);
      const owner = (mine[0] as (typeof mine)[number]).app;
      const visible = visibleSecrets(mounts, service, written);
      // Isolation: a service only ever sees its own app's secrets.
      for (const v of visible) expect(v.split("/")[0], `${service} sees ${v}`).toBe(owner);
      for (const d of mine) {
        const released = secrets[d.app]?.[d.name];
        const path = join(settings.secretsDir, d.app, d.name);
        if (released !== undefined) {
          expect(visible, `${service} must see ${d.app}/${d.name}`).toContain(`${d.app}/${d.name}`);
          expect(await readFile(path, "utf8")).toBe(released);
        } else if (individually.get(d.app)?.has(d.name)) {
          expect(await readFile(path, "utf8")).toBe(""); // an optional secret mounted on its own
        } else {
          expect(visible).not.toContain(`${d.app}/${d.name}`);
        }
      }
      const own = mine.filter((d) => secrets[d.app]?.[d.name] !== undefined || individually.get(d.app)?.has(d.name)).map((d) => `${d.app}/${d.name}`);
      if (individually.has(owner)) {
        // D-042: one mount per declared secret, so a service sees exactly what it declares.
        expect(visible.sort()).toEqual([...new Set(own)].sort());
      } else {
        // Composer 1.1 still mounts the app's whole secrets directory into each such service.
        expect(composerVersion).toMatch(/^1\.1\./);
        expect(visible).toEqual(expect.arrayContaining(own));
      }
    }
    // The payer's key, only with the payer.
    expect(await readFile(join(settings.secretsDir, "sealed-mpp-payer", "ENCLAVE_KEY"), "utf8")).toBe(agent.keys?.enclaveKey);
    expect(visibleSecrets(mounts, "sealed-mpp-payer", written)).toEqual(["sealed-mpp-payer/ENCLAVE_KEY", "sealed-mpp-payer/SPEND_LIMIT_PER_DAY"]);
  });

  it("created every data directory of the stack before the ready flag", async () => {
    expect(stack.dataDirs?.length).toBeGreaterThan(APPS.length);
    for (const d of stack.dataDirs ?? []) {
      const local = join(settings.dataMount, relative(stack.dataRoot ?? "/mnt/sealed-data", d));
      expect((await stat(local)).isDirectory(), d).toBe(true);
    }
    expect(chowns.length).toBeGreaterThan(0);
    expect(chowns.every((c) => !c.readyFlag)).toBe(true);
    expect(await readFile(join(settings.readyDir, "ok"), "utf8")).toMatch(/^\d+\n$/);
  });

  it("gates every gated route the composer emits, and only for Caddy", async () => {
    const gated = stack.apps.flatMap((a) => a.routes.filter((r) => r.auth !== "public").map((r) => ({ route: r.name, app: a })));
    expect(gated.map((g) => g.route).sort()).toEqual(["code", "crm", "gateway", "scraper", "tools"]);
    // When the Caddyfile already uses forward_auth (composer 1.2), each route it asks about is one the agent gates.
    const caddyfile = await readFile(join(out, "Caddyfile"), "utf8");
    for (const m of caddyfile.matchAll(/uri \/v1\/gate\?route=([a-z0-9-]+)/g)) expect(gated.map((g) => g.route)).toContain(m[1]);
    if (!caddyfile.includes("forward_auth")) expect(composerVersion).toMatch(/^1\.1\./);

    expect((await localRequest(ep(), "/v1/gate?route=scraper", { headers: { ...fromPeer(stack.apps[0]?.services[0]?.ip as string), authorization: basic(GATE_PASSWORD) } })).status).toBe(403);
    expect((await gate("attest")).status).toBe(403);

    const none = await gate("scraper");
    expect(none.status).toBe(401);
    expect(none.body).toBe("unauthorized");
    expect((await gate("scraper", { authorization: basic("wrong") })).status).toBe(401);
    const ok = await localRequestWithHeaders(ep(), "/v1/gate?route=scraper", { ...fromPeer(caddyIp), authorization: basic(GATE_PASSWORD) });
    expect(ok.status).toBe(200);
    expect(ok.headers["x-sealed-gate"]).toBe("basic");
    expect(ok.headers["x-sealed-gate-strip-authorization"]).toBe("1");
    const setCookie = String(ok.headers["set-cookie"]);
    expect(setCookie).toMatch(/^sealed_gate=v1\.[^;]+; Path=\/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax$/);
    const cookie = setCookie.split(";")[0] as string;
    // The cookie admits on every route, and the app's own bearer token passes untouched.
    const viaCookie = await localRequestWithHeaders(ep(), "/v1/gate?route=gateway", { ...fromPeer(caddyIp), cookie, authorization: "Bearer sk-litellm" });
    expect(viaCookie.status).toBe(200);
    expect(viaCookie.headers["x-sealed-gate"]).toBe("cookie");
    expect(viaCookie.headers["x-sealed-gate-strip-authorization"]).toBeUndefined();
    expect(viaCookie.headers["set-cookie"]).toBeUndefined();
    // A browser navigation gets the cookie with a 303 back to where it was going.
    const nav = await localRequestWithHeaders(ep(), "/v1/gate?route=scraper", {
      ...fromPeer(caddyIp),
      authorization: basic(GATE_PASSWORD),
      "x-forwarded-method": "GET",
      "x-forwarded-uri": "/jobs?page=2",
      "sec-fetch-mode": "navigate",
    });
    expect([nav.status, nav.headers.location]).toEqual([303, "/jobs?page=2"]);
    expect(String(nav.headers["set-cookie"])).toMatch(/^sealed_gate=v1\./);
    const challenge = await localRequestWithHeaders(ep(), "/v1/gate?route=gateway", { ...fromPeer(caddyIp), authorization: "Bearer sk-litellm" });
    expect(challenge.status).toBe(401);
    expect(challenge.headers["www-authenticate"]).toBe('Basic realm="sealed"');

    // Apps with a bootstrap job stay at 503 starting until its done file exists on the data disk.
    for (const { route, app } of gated.filter((g) => g.app.bootstrap)) {
      const b = app.bootstrap as NonNullable<StackInfo["apps"][number]["bootstrap"]>;
      expect(b.donePath, `${app.id} done file`).not.toBe("");
      const starting = await gate(route, { cookie });
      expect([starting.status, starting.body]).toEqual([503, "starting"]);
      const done = join(settings.dataMount, relative(stack.dataRoot ?? "/mnt/sealed-data", b.donePath));
      await mkdir(dirname(done), { recursive: true });
      await writeFile(done, "{}");
      now += 2;
      expect((await gate(route, { cookie })).status, route).toBe(200);
    }
    expect(gated.filter((g) => g.app.bootstrap).map((g) => g.route).sort()).toEqual(["code", "crm", "tools"]);
  });

  it("rate limits a client that keeps guessing", async () => {
    const client = "198.51.100.9";
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await gate("scraper", { authorization: basic(`guess-${i}`) }, client)).status);
    expect(statuses.slice(0, 10)).toEqual(Array(10).fill(401));
    const limited = await localRequestWithHeaders(ep(), "/v1/gate?route=scraper", { ...fromPeer(caddyIp), "x-forwarded-for": client, authorization: basic("one-more") });
    expect(statuses[10]).toBe(429);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
    // Credentials that already passed (cached for a few minutes) cost no bcrypt and are not guesses.
    expect((await gate("scraper", { authorization: basic(GATE_PASSWORD) }, client)).status).toBe(200);
    // Another client is not affected.
    expect((await gate("scraper", { authorization: basic(GATE_PASSWORD) }, "192.0.2.1")).status).toBe(200);
  });

  it("produces evidence that the real verifier accepts in simulator mode", async () => {
    expect(platform.evidence.length).toBe(1);
    const bundle = platform.evidence[0] as EvidenceBundle;
    expect(bundle.appCompose).toBe(appCompose);
    await writeFile(join(dir, "evidence.json"), JSON.stringify(bundle));
    const defaults = (await loadDefaults(join(repo, "config/defaults.yaml"), { testOverrides: false })) as unknown as { catalog: { registry: string } };
    const registry = defaults.catalog.registry;
    const { stdout } = await run(
      "go",
      ["run", "./runtime/agent/test/tools/verify-evidence.go", "--evidence", join(dir, "evidence.json"), "--registry", registry, ...APPS.flatMap((a) => ["--app-dir", `catalog/apps/${a}`])],
      { cwd: repo, maxBuffer: 16 * 1024 * 1024 },
    );
    const { report, d047ReportData } = JSON.parse(stdout) as { report: { ok: boolean; simulated: boolean; checks: { name: string; ok: boolean; detail: string }[] }; d047ReportData: boolean };
    // SEALED_DEBUG_VERIFY=<file> keeps the verifier's full report for inspection.
    if (process.env.SEALED_DEBUG_VERIFY) await writeFile(process.env.SEALED_DEBUG_VERIFY, stdout);
    expect(report.simulated).toBe(true);
    // The quote binds attestedAt (D-047) whatever the verifier checks.
    expect(d047ReportData).toBe(true);
    const failed = report.checks.filter((c) => !c.ok);
    const rd = report.checks.find((c) => c.name === "report_data");
    if (rd && !rd.ok) {
      // A verifier from before D-047 still expects the construction without attestedAt (verifier owners, item 20).
      expect(rd.detail).not.toContain("attestedAt");
      expect(failed.map((c) => c.name)).toEqual(["report_data"]);
    } else {
      expect(failed).toEqual([]);
      expect(report.ok).toBe(true);
    }
    for (const name of ["quote", "rtmr3", "compose_hash", "config_hash", "deployment_id", "stack_recompute", "stack_approved", "approval_releases", "image_measurements", "freshness"]) {
      expect(report.checks.find((c) => c.name === name)?.ok, name).toBe(true);
    }
  }, 600_000);

  it("switches Caddy between the two composed Caddyfiles when fees cannot be paid", async () => {
    const gateway = stack.apps.find((a) => a.id === "llm-gateway") as StackInfo["apps"][number];
    const usage = await localRequest(ep(), "/v1/usage-events", {
      body: { app: "llm-gateway", unit: "tokens", quantity: 1_000_000, id: "e2e-1" },
      headers: fromPeer(gateway.services.find((x) => x.primary)?.ip as string),
    });
    expect(usage.status).toBe(202);
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    await agent.settle(now);
    now += 1440 * 60;
    expect((await agent.settle(now)).paymentNeeded).toBe(true);
    expect(caddy.current).toBe(await readFile(join(out, "Caddyfile.payment-needed"), "utf8"));
    payer.budgetResult = { spendable: 1_000_000_000n };
    now += 60;
    expect((await agent.settle(now)).paymentNeeded).toBe(false);
    expect(caddy.current).toBe(await readFile(join(out, "Caddyfile"), "utf8"));
  });

  it("takes the payer's reservations from its fixed IP in the composed stack", async () => {
    const payerIp = stack.sidecars["sealed-mpp-payer"] as string;
    const reserve = () => localRequest(ep(), "/v1/spend/reserve", { body: { amount: "1000", currency: config.feeToken }, headers: fromPeer(payerIp) });
    // 16 hours of crm, coding-agent and internal-tools app-hours until the window ends (2.40 USD) do not fit the
    // 2 USD config limit: fee settlement keeps all of it (review M5).
    expect(JSON.parse((await reserve()).body)).toEqual({ ok: false, remaining: "0", reason: "budget" });
    // The customer's key allows 20 USD for the period onchain: the payer gets what the fees leave (review M4).
    payer.limit = { remaining: 20_000_000n, periodEnd: now + 16 * 3600 };
    await agent.settle(now);
    const r = await reserve();
    expect(JSON.parse(r.body)).toMatchObject({ ok: true });
    const other = await localRequest(ep(), "/v1/spend/reserve", { body: { amount: "1000" }, headers: fromPeer(caddyIp) });
    expect(other.status).toBe(403);
  });
});

/** localRequest with the response headers (the gate's answers are all in headers). */
async function localRequestWithHeaders(endpoint: ReturnType<typeof parseEndpoint>, path: string, headers: Record<string, string>) {
  const http = await import("node:http");
  const base = "baseUrl" in endpoint ? new URL(endpoint.baseUrl) : undefined;
  return new Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }>((resolve, reject) => {
    const req = http.request({ hostname: base?.hostname, port: base?.port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8"), headers: res.headers }));
    });
    req.on("error", reject);
    req.end();
  });
}
