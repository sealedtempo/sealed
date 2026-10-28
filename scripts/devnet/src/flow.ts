// The devnet end to end: every step of the Sealed trust and payment flow on one machine, with real components as
// processes and an assertion after each step. See ../README.md for the step list and what is simulated.
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  type Address,
  appId as computeAppId,
  canonicalize,
  deploymentId as computeDeploymentId,
  type Hex,
  imageId as computeImageId,
  measurementsHash,
  releaseId as computeReleaseId,
  SIM_DEBUG_MRTD,
  SIM_MEASUREMENTS,
} from "@sealed/core";
import { http as viemHttp, parseEventLogs, toFunctionSelector } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Abis, Account, Addresses, createClient } from "viem/tempo";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { tempoChain } from "@sealed/core";
import { type AssetServer, sha256Hex, startAssetServer } from "./assets.ts";
import { type AttestFront, selfSignedCert, startAttestFront } from "./attestFront.ts";
import { ABIS, ADDR, Chain, CHAIN_ID, deployContracts, KEYS, REGISTRAR_ROLE, startAnvil, TOKENS } from "./chain.ts";
import { check, checkEq, type StepLog } from "./log.ts";
import { freePorts, http } from "./net.ts";
import { type Proc, sleep, type Supervisor, waitFor } from "./procs.ts";
import { planSecrets, type SecretPlan } from "./secrets.ts";
import {
  type AgentPaths,
  agentPaths,
  type Bins,
  type KeyBroker,
  type Postgres,
  startAgent,
  startApi,
  startKeyBroker,
  startPostgres,
  startSimulator,
  startVerifierd,
} from "./services.ts";

/** The five catalog apps a customer stack runs, plus the platform's relay app (registered and released only). */
export const STACK_APPS = ["coding-agent", "crm", "internal-tools", "llm-gateway", "scraper"] as const;
export const CATALOG_APPS = [...STACK_APPS, "inference-relay"] as const;
export const MAINTAINER_SHARE_BPS = 2000;
const IMAGE_VERSION = "1.0.0-devnet";
const PEER_HEADER = "x-devnet-peer";

export interface DevnetOptions {
  repo: string;
  apiDir: string;
  pgBin: string;
  bins: Bins;
  runDir: string;
  runId: string;
  sup: Supervisor;
  log: StepLog;
  /** Seconds between the agent's settlements (test_overrides.settlement_interval_seconds). */
  settleSeconds: number;
}

interface ReleaseAssetUrls {
  tag: string;
  bundle: string;
  signature: string;
  certificate: string;
  provenance: string;
  sbom: Record<string, string>;
}

interface Release {
  app: string;
  appId: Hex;
  version: string;
  bundleHash: Hex;
  egressPolicyHash: Hex;
  sbomHash: Hex;
  releaseId: Hex;
  bundle: Uint8Array;
  unbuilt: string[];
  /** Where release CI publishes this release's assets (runtime/composer's rule, printed by sealed release build). */
  assets: ReleaseAssetUrls;
}

/** The SLSA builder id the devnet's provenance names (release CI uses the slsa-github-generator). */
const DEVNET_BUILDER = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0";

/** A one-line .intoto.jsonl: a DSSE envelope around an in-toto statement with a SLSA v1 predicate (unsigned). */
function provenanceJsonl(name: string, sha256: Hex): Uint8Array {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name, digest: { sha256: sha256.slice(2) } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
        externalParameters: { workflow: { repository: "https://github.com/sealedtempo/sealed", ref: "refs/heads/main", path: ".github/workflows/release.yml" } },
        resolvedDependencies: [{ uri: "git+https://github.com/sealedtempo/sealed@refs/heads/main", digest: { gitCommit: "0".repeat(40) } }],
      },
      runDetails: { builder: { id: DEVNET_BUILDER } },
    },
  };
  const env = { payloadType: "application/vnd.in-toto+json", payload: Buffer.from(JSON.stringify(statement)).toString("base64"), signatures: [] };
  return new TextEncoder().encode(`${JSON.stringify(env)}\n`);
}

interface Composed {
  name: string;
  dir: string;
  config: Record<string, unknown>;
  appCompose: string;
  stackHash: Hex;
  configHash: Hex;
  deploymentId: Hex;
  releaseIds: Hex[];
  imageId: Hex;
  stack: StackInfo;
}

interface StackInfo {
  apps: Array<{ id: string; metering: { unit: string; source: string }; services: Array<{ name: string; ips: string[] }>; secrets: Array<{ name: string; optional?: boolean }> }>;
  secretFiles?: string[];
  secretsRoot: string;
  dataRoot: string;
  dataDirs: string[];
  [k: string]: unknown;
}

interface AgentRun {
  name: string;
  paths: AgentPaths;
  port: number;
  proc: Proc;
  composed: Composed;
  env?: Record<string, string>;
}

interface VerifyReport {
  ok: boolean;
  simulated?: boolean;
  checks: Array<{ name: string; ok: boolean; detail?: string }>;
}

interface Ready {
  deploymentId: Hex;
  stackHash: Hex;
  enclaveSigner: Address;
  port: number;
  disk: string[];
}

const lower = <T extends string>(s: T) => s.toLowerCase() as T;
const hex0 = (bare: string) => `0x${bare}` as Hex;
const readJson = <T>(p: string) => JSON.parse(readFileSync(p, "utf8")) as T;

export class Devnet {
  private readonly ports: number[] = [];
  chain!: Chain;
  assets!: AssetServer;
  pg!: Postgres;
  broker!: KeyBroker;
  verifierdUrl!: string;
  apiUrl!: string;
  plan!: SecretPlan;
  releases = new Map<string, Release>();
  images!: { prod: Hex; debug: Hex; prodMh: Hex; debugMh: Hex };
  defaultsPath!: string;
  private readonly simEndpoints = new Map<string, string>();
  front?: AttestFront;
  private agentPort = 0;
  private brokerPort = 0;
  private apiPort = 0;
  private readonly agents: AgentRun[] = [];

  private readonly o: DevnetOptions;

  constructor(o: DevnetOptions) {
    this.o = o;
  }

  private get log() {
    return this.o.log;
  }
  private get sup() {
    return this.o.sup;
  }
  private port(): number {
    const p = this.ports.shift();
    if (p === undefined) throw new Error("out of reserved ports");
    return p;
  }
  private path(...p: string[]) {
    return join(this.o.runDir, ...p);
  }

  async run(): Promise<void> {
    this.ports.push(...(await freePorts(24)));
    await this.stepChain();
    await this.stepImages();
    await this.stepReleases();
    const a = await this.stepComposeAndApprove();
    await this.stepServices(a);
    const agentA = await this.stepBoot(a);
    await this.stepVerify(a, agentA);
    await this.stepUsageAccessKey(agentA);
    await this.stepUsageEnclaveAccount();
    await this.stepReboot(agentA);
    await this.stepTamperCompose(a);
    await this.stepTamperDebugImage();
    await this.stepTamperNoQuote(a);
    await this.stepRevokeStack(agentA);
    await this.stepRevokeRelease(agentA);
    await this.front?.close();
  }

  // --- 1. chain ------------------------------------------------------------------------------------------------

  private async stepChain(): Promise<void> {
    this.log.step("Local Tempo node and contracts (anvil --network tempo T4, script/Deploy.s.sol)");
    const node = await startAnvil(this.sup, this.port());
    this.log.ok(`anvil at ${node.rpcUrl}, chain ${CHAIN_ID}, block gas limit ${(await node.client.getBlock()).gasLimit}`);
    const c = await deployContracts(this.sup, { contractsDir: join(this.o.repo, "contracts"), rpcUrl: node.rpcUrl, runDir: this.o.runDir, runId: this.o.runId });
    this.chain = new Chain(node, c);
    for (const [name, a] of Object.entries({ PlatformRegistry: c.platformRegistry, AppRegistry: c.appRegistry, OracleSignatureVerifier: c.oracleVerifier, DeploymentRegistry: c.deploymentRegistry, FeeSplitter: c.feeSplitter })) {
      check((await node.client.getCode({ address: a })) !== undefined, `${name} has code`);
    }
    this.log.ok(`deployed PlatformRegistry ${c.platformRegistry}, AppRegistry ${c.appRegistry}, DeploymentRegistry ${c.deploymentRegistry}, FeeSplitter ${c.feeSplitter} (block ${c.deployBlock})`);
    checkEq(await this.chain.read<Address>("AppRegistry", "owner"), ADDR.owner, "AppRegistry owner");
    check(await this.chain.read<boolean>("AppRegistry", "hasRole", [REGISTRAR_ROLE, ADDR.ops]), "ops holds REGISTRAR_ROLE");
    check(await this.chain.read<boolean>("OracleSignatureVerifier", "isSigner", [ADDR.oracle]), "the local test oracle key is an allowed signer");
    checkEq(await this.chain.read<Address>("DeploymentRegistry", "verifiers", [1]), c.oracleVerifier, "verifier method 1");
    checkEq(await this.chain.read<Address>("FeeSplitter", "treasury"), ADDR.treasury, "treasury");
    check(await this.chain.read<boolean>("FeeSplitter", "isTokenAllowed", [TOKENS.pathUsd]), "FEE_TOKEN (local pathUSD) allowlisted");
    this.log.ok(`owner, registrar ${ADDR.ops}, oracle signer ${ADDR.oracle}, method 1, treasury and FEE_TOKEN pathUSD wired`);
    this.defaultsPath = this.writeDefaults();
  }

  /** config/defaults.yaml with the devnet's settlement interval in test_overrides (agent) and the local chain (CLI). */
  private writeDefaults(): string {
    const doc = parseYaml(readFileSync(join(this.o.repo, "config", "defaults.yaml"), "utf8")) as Record<string, unknown> & {
      test_overrides: Record<string, unknown>;
    };
    doc.test_overrides = { ...doc.test_overrides, settlement_interval_seconds: this.o.settleSeconds };
    const p = this.path("defaults.yaml");
    writeFileSync(p, stringifyYaml(doc));
    return p;
  }

  // --- 2. images -----------------------------------------------------------------------------------------------

  private async stepImages(): Promise<void> {
    this.log.step("Register the simulated OS images (INTERFACES 15: sealed-sim and sealed-sim-debug)");
    const m = { mrtd: hex0(SIM_MEASUREMENTS.mrtd), rtmr0: hex0(SIM_MEASUREMENTS.rtmr0), rtmr1: hex0(SIM_MEASUREMENTS.rtmr1), rtmr2: hex0(SIM_MEASUREMENTS.rtmr2) };
    const prodMh = measurementsHash(m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2);
    const debugMh = measurementsHash(hex0(SIM_DEBUG_MRTD), m.rtmr0, m.rtmr1, m.rtmr2);
    const prod = computeImageId("sealed-sim", IMAGE_VERSION, prodMh);
    const debug = computeImageId("sealed-sim-debug", IMAGE_VERSION, debugMh);
    await this.chain.write(KEYS.owner, "PlatformRegistry", "addImage", [prod, "sealed-sim", IMAGE_VERSION, m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2, false, "https://example.invalid/sealed-sim"]);
    await this.chain.write(KEYS.owner, "PlatformRegistry", "addImage", [debug, "sealed-sim-debug", IMAGE_VERSION, hex0(SIM_DEBUG_MRTD), m.rtmr0, m.rtmr1, m.rtmr2, true, "https://example.invalid/sealed-sim-debug"]);
    const pi = await this.chain.read<{ measurementsHash: Hex; isDebug: boolean }>("PlatformRegistry", "getImage", [prod]);
    const di = await this.chain.read<{ measurementsHash: Hex; isDebug: boolean }>("PlatformRegistry", "getImage", [debug]);
    checkEq(pi.measurementsHash, prodMh, "sealed-sim measurementsHash = keccak256(mrtd||rtmr0||rtmr1||rtmr2)");
    checkEq(di.measurementsHash, debugMh, "sealed-sim-debug measurementsHash");
    check(!pi.isDebug && di.isDebug, "isDebug flags");
    check(await this.chain.read<boolean>("PlatformRegistry", "isApprovedImage", [prod]), "sealed-sim approved");
    check(!(await this.chain.read<boolean>("PlatformRegistry", "isApprovedImage", [debug])), "a debug image is never approved");
    this.images = { prod, debug, prodMh, debugMh };
    this.log.ok(`sealed-sim ${prod} (isDebug false, approved), sealed-sim-debug ${debug} (isDebug true, not approved)`);
  }

  // --- 3. apps, bundles, releases ------------------------------------------------------------------------------

  private async stepReleases(): Promise<void> {
    this.log.step("Register the catalog apps, build bundles with sealed release build, serve them, publishRelease");
    this.assets = await startAssetServer(this.port());
    this.log.ok(`release asset host ${this.assets.base}`);
    const bundleDir = this.path("bundles");
    mkdirSync(bundleDir, { recursive: true });
    for (const app of CATALOG_APPS) {
      const out = join(bundleDir, `${app}.tar`);
      // The catalog's images are not built yet (all-zero digests, D-028): only a dev build of the bundle is possible.
      const json = await this.sup.runOk(`release-build-${app}`, this.o.bins.sealed, [
        "release", "build", app, "--catalog", join(this.o.repo, "catalog", "apps"), "--out", out, "--allow-missing-sbom", "--dev-allow-unbuilt",
        "--release-asset-base", this.assets.base, "--json",
      ], { cleanEnv: true, env: { PATH: process.env.PATH, HOME: this.path("home"), SEALED_DEV_SIM: "1" } });
      const doc = JSON.parse(json) as {
        release: { appId: Hex; slug: string; version: string; bundleHash: Hex; egressPolicyHash: Hex; sbomHash: Hex; releaseId: Hex };
        unbuilt?: string[];
        assets: ReleaseAssetUrls;
      };
      const r = doc.release;
      const bundle = new Uint8Array(readFileSync(out));
      checkEq(sha256Hex(bundle), r.bundleHash, `${app} bundleHash = sha256(bundle.tar)`);
      checkEq(r.appId, computeAppId(app), `${app} appId`);
      checkEq(r.releaseId, computeReleaseId(r.appId, r.version, r.bundleHash), `${app} releaseId`);
      // The composer's asset rule (Go) and the devnet's copy agree; the bundle is served where the Go rule says.
      checkEq(doc.assets.bundle, this.assets.url(app, r.version), `${app} bundle URL (D-046)`);
      checkEq(doc.assets.provenance, `${doc.assets.bundle}.intoto.jsonl`, `${app} provenance URL`);
      this.releases.set(app, { app, appId: r.appId, version: r.version, bundleHash: r.bundleHash, egressPolicyHash: r.egressPolicyHash, sbomHash: r.sbomHash, releaseId: r.releaseId, bundle, unbuilt: doc.unbuilt ?? [], assets: doc.assets });
    }
    this.log.ok(`built ${this.releases.size} bundles (${[...this.releases.values()].map((r) => `${r.app} ${r.version}`).join(", ")})`);
    const unbuilt = [...this.releases.values()].filter((r) => r.unbuilt.length > 0).map((r) => r.app);
    this.log.ok(`apps with unbuilt images, built only with --dev-allow-unbuilt: ${unbuilt.join(", ") || "none"}`);

    for (const r of this.releases.values()) {
      await this.chain.write(KEYS.owner, "AppRegistry", "registerApp", [r.appId, r.app, `${r.app} (devnet)`, "Apache-2.0", ADDR.maintainer, MAINTAINER_SHARE_BPS, `https://example.invalid/${r.app}`]);
      // The release's assets where release CI publishes them: bundle, provenance, one (empty) SBOM per image.
      this.assets.addUrl(r.assets.bundle, r.bundle);
      this.assets.addUrl(r.assets.provenance, provenanceJsonl(`${r.app}-${r.version}.bundle.tar`, r.bundleHash));
      for (const [image, url] of Object.entries(r.assets.sbom)) {
        this.assets.addUrl(url, new TextEncoder().encode(JSON.stringify({ spdxVersion: "SPDX-2.3", name: image, packages: [] })));
      }
      await this.chain.write(KEYS.ops, "AppRegistry", "publishRelease", [r.appId, r.version, r.bundleHash, r.egressPolicyHash, r.sbomHash, r.assets.provenance, r.assets.signature]);
      checkEq(await this.chain.read<Hex>("AppRegistry", "latestRelease", [r.appId]), r.releaseId, `${r.app} latestRelease`);
      check(await this.chain.read<boolean>("AppRegistry", "isApprovableRelease", [r.releaseId]), `${r.app} release approvable`);
      const app = await this.chain.read<{ maintainer: Address; maintainerShareBps: number }>("AppRegistry", "getApp", [r.appId]);
      checkEq(app.maintainer, ADDR.maintainer, `${r.app} maintainer`);
      checkEq(Number(app.maintainerShareBps), MAINTAINER_SHARE_BPS, `${r.app} maintainer share`);
    }
    this.log.ok(`registered ${this.releases.size} apps (maintainer ${ADDR.maintainer}, share ${MAINTAINER_SHARE_BPS} bps) and published every release from the registrar key`);
    const r0 = this.releases.get("crm") as Release;
    check(await this.chain.reverts(KEYS.customer, "AppRegistry", "publishRelease", [r0.appId, "9.9.9", hex0("ab".repeat(32)), r0.egressPolicyHash, r0.sbomHash, "", ""]), "publishRelease from a non-registrar reverts");
    this.log.ok("publishRelease from a key without REGISTRAR_ROLE reverts");
  }

  // --- 4. compose and approve ----------------------------------------------------------------------------------

  /** The customer fetches each bundle by the asset rule and checks it against the onchain bundleHash. */
  private async fetchBundle(app: string): Promise<{ path: string; bytes: Uint8Array }> {
    const r = this.releases.get(app) as Release;
    const onchain = await this.chain.read<{ bundleHash: Hex; version: string }>("AppRegistry", "getRelease", [r.releaseId]);
    const res = await fetch(this.assets.url(app, onchain.version));
    check(res.ok, `GET ${this.assets.url(app, onchain.version)} answered ${res.status}`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    checkEq(sha256Hex(bytes), onchain.bundleHash, `${app} fetched bundle sha256 = onchain bundleHash`);
    const path = this.path("customer-bundles", `${app}.tar`);
    mkdirSync(this.path("customer-bundles"), { recursive: true });
    writeFileSync(path, bytes);
    return { path, bytes };
  }

  private baseConfig(o: { apps: readonly string[]; mode: "access-key" | "enclave-account"; imageId: Hex; salt: Hex; graceMinutes?: number }): Record<string, unknown> {
    return {
      schema: "sealed-config/v1",
      chainId: CHAIN_ID,
      customer: ADDR.customer,
      salt: o.salt,
      imageId: o.imageId,
      composerVersion: "1.2.0",
      apps: [...o.apps].sort().map((id) => ({ id, releaseId: (this.releases.get(id) as Release).releaseId })),
      hostnames: { scheme: "sslip", ip: "203.0.113.10" },
      egressAdditions: {},
      allowedVpcRanges: [],
      // The composer refuses loopback endpoints; the agent host resolves *.devnet.test to 127.0.0.1.
      endpoints: {
        keyBroker: `http://key-broker.devnet.test:${this.brokerPort}`,
        platformApi: `http://api.devnet.test:${this.apiPort}`,
        tempoRpc: `http://rpc.devnet.test:${new URL(this.chain.node.rpcUrl).port}`,
        relay: "https://attest.relay.devnet.example",
        relayAttest: "https://attest.relay.devnet.example/attest",
      },
      contracts: {
        platformRegistry: this.chain.c.platformRegistry,
        appRegistry: this.chain.c.appRegistry,
        deploymentRegistry: this.chain.c.deploymentRegistry,
        feeSplitter: this.chain.c.feeSplitter,
      },
      feeToken: TOKENS.pathUsd,
      settlement: { mode: o.mode, intervalMinutes: 1, gracePeriodMinutes: o.graceMinutes ?? 5, spendLimitPerDay: "2000000" },
      relayOwner: ADDR.treasury,
      debug: false,
    };
  }

  /** sealed-compose over the fetched bundles: app-compose.json, the normalized config, sealed-stack/v1, Caddyfiles. */
  private async compose(name: string, config: Record<string, unknown>, apps: readonly string[], mutate?: (appCompose: string) => string): Promise<Composed> {
    const dir = this.path("compose", name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "input-config.json"), canonicalize(config as never));
    const bundles: string[] = [];
    for (const a of apps) bundles.push((await this.fetchBundle(a)).path);
    const args = ["compose", "--config", join(dir, "input-config.json"), ...bundles.flatMap((b) => ["--bundle", b]), "--out", dir];
    const summary = JSON.parse(await this.sup.runOk(`compose-${name}`, this.o.bins.compose, args, { cleanEnv: true, env: { PATH: process.env.PATH, HOME: dir } })) as {
      stackHash: Hex;
      configHash: Hex;
      deploymentId: Hex;
      unbuilt?: string[];
    };
    let appCompose = readFileSync(join(dir, "app-compose.json"), "utf8");
    if (mutate) {
      appCompose = mutate(appCompose);
      writeFileSync(join(dir, "app-compose.json"), appCompose);
    }
    const normalized = readJson<Record<string, unknown>>(join(dir, "config.json"));
    return {
      name,
      dir,
      config: normalized,
      appCompose,
      stackHash: lower(mutate ? (`0x${createHash("sha256").update(appCompose).digest("hex")}` as Hex) : summary.stackHash),
      configHash: lower(summary.configHash),
      deploymentId: lower(mutate ? computeDeploymentId(ADDR.customer, `0x${createHash("sha256").update(appCompose).digest("hex")}` as Hex, config.salt as Hex) : summary.deploymentId),
      releaseIds: (normalized.apps as Array<{ releaseId: Hex }>).map((a) => lower(a.releaseId)),
      imageId: lower(config.imageId as Hex),
      stack: readJson<StackInfo>(join(dir, "stack.json")),
    };
  }

  private salt(label: string): Hex {
    return `0x${createHash("sha256").update(`sealed/devnet-salt/v1\0${this.o.runId}\0${label}`).digest("hex")}` as Hex;
  }

  private async approve(c: Composed): Promise<void> {
    await this.chain.write(KEYS.customer, "DeploymentRegistry", "approveStack", [c.stackHash, c.releaseIds, c.imageId, 0n]);
    check(await this.chain.read<boolean>("DeploymentRegistry", "isStackApproved", [ADDR.customer, c.stackHash]), `${c.name} stack approved`);
    const [ids, image] = await this.chain.read<[Hex[], Hex]>("DeploymentRegistry", "getStackApproval", [ADDR.customer, c.stackHash]);
    checkEq(ids.map(lower).join(","), c.releaseIds.join(","), `${c.name} approval releaseIds`);
    checkEq(image, c.imageId, `${c.name} approval imageId`);
  }

  private async stepComposeAndApprove(): Promise<Composed> {
    this.log.step("Customer composes the five-app stack with the composer and approves it onchain");
    this.brokerPort = this.port();
    this.apiPort = this.port();
    this.agentPort = this.port();
    const config = this.baseConfig({ apps: STACK_APPS, mode: "access-key", imageId: this.images.prod, salt: this.salt("a") });
    const a = await this.compose("a", config, STACK_APPS);
    this.log.ok(`fetched ${STACK_APPS.length} bundles by the release asset rule; each sha256 equals its onchain bundleHash`);
    checkEq(a.deploymentId, computeDeploymentId(ADDR.customer, a.stackHash, config.salt as Hex), "deploymentId = keccak256(abi.encode(customer, stackHash, salt))");
    checkEq(`0x${createHash("sha256").update(a.appCompose).digest("hex")}`, a.stackHash, "stackHash = sha256(app-compose.json)");
    this.log.ok(`composed stack a: stackHash ${a.stackHash}, configHash ${a.configHash}, ${a.appCompose.length} bytes of app-compose.json`);
    await this.approve(a);
    this.log.ok(`approveStack by the customer ${ADDR.customer}: releases and image match getStackApproval`);
    return a;
  }

  // --- 5. services ---------------------------------------------------------------------------------------------

  private async stepServices(a: Composed): Promise<void> {
    this.log.step("Start the key broker, sealed-verifierd, the platform api (oracle) with PostgreSQL, and the dstack simulator");
    const bundles = STACK_APPS.map((app) => (this.releases.get(app) as Release).bundle);
    this.plan = planSecrets(bundles);
    const n = Object.keys(this.plan.store).length;
    this.broker = await startKeyBroker(this.sup, {
      bin: this.o.bins.keyBroker,
      port: this.brokerPort,
      dir: this.path("key-broker"),
      rpcUrl: this.chain.node.rpcUrl,
      contracts: this.chain.c,
      customer: ADDR.customer,
      assetBase: this.assets.base,
      secrets: this.plan.store,
    });
    this.log.ok(`key broker ${this.broker.url} (dev build, SEALED_DEV_SIM=1, in-memory store with ${n} secrets, file-backed HMAC key, JSON-lines decision log)`);
    const v = await startVerifierd(this.sup, { bin: this.o.bins.verifierd, port: this.port(), dir: this.path("verifierd"), rpcUrl: this.chain.node.rpcUrl, contracts: this.chain.c, assetBase: this.assets.base });
    this.verifierdUrl = v.url;
    const health = (await http<Record<string, unknown>>(`${v.url}/healthz`)).body;
    check(health && (health as { composer?: unknown }).composer !== false, `sealed-verifierd has the composer wired: ${JSON.stringify(health)}`);
    this.log.ok(`sealed-verifierd ${v.url} (simulated quotes allowed, composer ${String((health as { composerVersion?: string }).composerVersion ?? "wired")})`);
    this.pg = await startPostgres(this.sup, { pgBin: this.o.pgBin, dir: this.path("postgres"), port: this.port() });
    this.log.ok(`PostgreSQL 17 throwaway cluster ${this.pg.url}`);
    const api = await startApi(this.sup, {
      apiDir: this.o.apiDir,
      port: this.apiPort,
      dir: this.path("api"),
      rpcUrl: this.chain.node.rpcUrl,
      contracts: this.chain.c,
      databaseUrl: this.pg.url,
      verifierdUrl: v.url,
      assetBase: this.assets.base,
      imageId: this.images.prod,
      defaultsPath: join(this.o.repo, "config", "defaults.yaml"),
    });
    this.apiUrl = api.url;
    this.log.ok(`platform api ${api.url} (oracle key = the local test oracle signer, OPS = the registrar key, indexer from block ${this.chain.c.deployBlock})`);
    void a;
    await this.checkCatalog();
  }

  /** The api's catalog (indexer plus release assets by the D-046 rule) as the console shows it. */
  private async checkCatalog(): Promise<void> {
    await waitFor("the api indexer has every release", async () => (await this.pg.psql("SELECT count(*) FROM releases WHERE status = 'active'")) === String(CATALOG_APPS.length) || undefined, { timeoutMs: 30_000 });
    checkEq(await this.pg.psql("SELECT count(*) || ' ' || count(*) FILTER (WHERE is_debug) FROM images"), "2 1", "indexed images (one debug)");
    const list = await http<Array<{ id: string; latestRelease: { releaseId: Hex } | null }>>(`${this.apiUrl}/v1/catalog/apps`);
    checkEq(list.status, 200, "GET /v1/catalog/apps");
    checkEq(list.body.map((x) => x.id).sort().join(","), [...STACK_APPS].sort().join(","), "the customer catalog lists the five apps (the relay stays hidden)");
    for (const app of list.body) checkEq(app.latestRelease?.releaseId ?? "", (this.releases.get(app.id) as Release).releaseId, `${app.id} latest release in the catalog`);
    for (const r of this.releases.values()) {
      const rels = await http<Array<{ releaseId: Hex; assetsError?: string; provenance: { url: string; builder: string; sourceRepo: string }; sbom: { url: string } }>>(`${this.apiUrl}/v1/catalog/apps/${r.app}/releases`);
      const rel = rels.body.find((x) => lower(x.releaseId) === r.releaseId);
      check(rel, `${r.app} release listed`);
      check(rel.assetsError === undefined, `${r.app}: the api fetched the bundle by the asset rule and checked bundleHash (${rel.assetsError})`);
      checkEq(rel.provenance.url, r.assets.provenance, `${r.app} provenance link`);
      checkEq(rel.provenance.builder, DEVNET_BUILDER, `${r.app}: the api read the provenance where release CI publishes it`);
      checkEq(rel.provenance.sourceRepo, "https://github.com/sealedtempo/sealed", `${r.app} provenance source`);
      check(Object.values(r.assets.sbom).includes(rel.sbom.url), `${r.app}: the SBOM link is a published asset (${rel.sbom.url})`);
      checkEq((await fetch(rel.sbom.url)).status, 200, `${r.app} SBOM link resolves`);
    }
    this.log.ok(`the api indexed ${CATALOG_APPS.length} releases and 2 images; GET /v1/catalog/apps lists the five apps; every release's bundle, provenance (builder, source) and SBOM link resolve at the composer's asset URLs`);
  }

  // --- 6. boot ---------------------------------------------------------------------------------------------------

  private async startSim(c: Composed, name: string, debug = false): Promise<string> {
    const file = join(c.dir, "served-app-compose.json");
    writeFileSync(file, c.appCompose);
    const sim = await startSimulator(this.sup, { agentDir: join(this.o.repo, "runtime", "agent"), name, appComposeFile: file, port: this.port(), debug });
    const info = (await http<{ tcb_info: string }>(`${sim.endpoint}/Info`)).body;
    const served = (JSON.parse(info.tcb_info) as { app_compose: string }).app_compose;
    check(served === c.appCompose, `${name} serves the exact app-compose.json`);
    this.simEndpoints.set(c.name, sim.endpoint);
    return sim.endpoint;
  }

  private launchAgent(c: Composed, name: string, dstack: string, paths: AgentPaths, port: number, env?: Record<string, string>): AgentRun {
    mkdirSync(join(paths.root, "etc"), { recursive: true });
    writeFileSync(paths.config, canonicalize(c.config as never));
    cpSync(join(c.dir, "stack.json"), paths.stack);
    cpSync(join(c.dir, "Caddyfile"), paths.caddyfile);
    cpSync(join(c.dir, "Caddyfile.payment-needed"), paths.caddyfilePaymentNeeded);
    rmSync(join(paths.out, "ready.json"), { force: true });
    rmSync(join(paths.out, "evidence.json"), { force: true });
    const proc = startAgent(this.sup, { name, hostScript: join(this.o.repo, "scripts", "devnet", "src", "agentHost.ts"), paths, dstack, port, defaultsPath: this.defaultsPath, env });
    const run = { name, paths, port, proc, composed: c, env };
    this.agents.push(run);
    return run;
  }

  private async waitReady(run: AgentRun, timeoutMs = 90_000): Promise<Ready> {
    return waitFor(`${run.name} ready`, () => (existsSync(join(run.paths.out, "ready.json")) ? readJson<Ready>(join(run.paths.out, "ready.json")) : undefined), { proc: run.proc, timeoutMs });
  }

  private async waitEvidence(run: AgentRun, timeoutMs = 90_000): Promise<{ result: { deploymentId: Hex; txHash: Hex; kind: string }; bundle: Record<string, unknown> }> {
    return waitFor(
      `${run.name} evidence recorded`,
      () => {
        const err = join(run.paths.out, "evidence-error.json");
        if (existsSync(err)) throw new Error(`evidence submission failed: ${readFileSync(err, "utf8")}`);
        const p = join(run.paths.out, "evidence.json");
        return existsSync(p) ? readJson<{ result: { deploymentId: Hex; txHash: Hex; kind: string }; bundle: Record<string, unknown> }>(p) : undefined;
      },
      { proc: run.proc, timeoutMs },
    );
  }

  private secretFile(paths: AgentPaths, owner: string, name: string): string {
    return join(paths.secrets, owner, name);
  }

  private async checkSecrets(run: AgentRun): Promise<number> {
    let n = 0;
    for (const app of run.composed.stack.apps) {
      for (const [name, value] of Object.entries(this.plan.expected[app.id] ?? {})) {
        const f = this.secretFile(run.paths, app.id, name);
        check(existsSync(f), `secret file ${app.id}/${name} written`);
        check(readFileSync(f, "utf8") === value, `secret ${app.id}/${name} holds the value from the customer's store`);
        n++;
      }
    }
    return n;
  }

  /**
   * Per service (D-042): every secret file the composed compose binds into a service exists on the agent's tmpfs,
   * with the customer's value, or empty for an unset optional secret. Returns the number of service binds.
   */
  private checkServiceBinds(run: AgentRun): { services: number; binds: number } {
    const doc = JSON.parse(JSON.parse(run.composed.appCompose).docker_compose_file) as { services: Record<string, { volumes?: Array<{ type?: string; source?: string; target?: string; read_only?: boolean }> }> };
    const root = run.composed.stack.secretsRoot;
    let services = 0;
    let binds = 0;
    for (const [svc, def] of Object.entries(doc.services)) {
      const files = (def.volumes ?? []).filter((v) => v.type === "bind" && v.source?.startsWith(`${root}/`) && v.source !== root);
      if (svc === "sealed-agent" || files.length === 0) continue;
      services++;
      for (const v of files) {
        const rel = (v.source as string).slice(root.length + 1);
        const [owner, name] = rel.split("/") as [string, string];
        check(v.target === v.source && v.read_only === true, `${svc} mounts ${rel} read-only at the same path`);
        const f = join(run.paths.secrets, rel);
        check(existsSync(f), `${svc}: ${rel} exists on the tmpfs`);
        const want = owner === "sealed-mpp-payer" ? undefined : (this.plan.expected[owner]?.[name] ?? "");
        if (want !== undefined) check(readFileSync(f, "utf8") === want, `${svc}: ${rel} holds the released value`);
        binds++;
      }
    }
    const declared = (run.composed.stack.secretFiles ?? []).map((p) => p.slice(root.length + 1)).sort();
    const written = this.listFiles(run.paths.secrets).sort();
    checkEq(written.join(","), declared.join(","), "the agent wrote exactly the secret files sealed-stack declares");
    return { services, binds };
  }

  private listFiles(dir: string): string[] {
    if (!existsSync(dir)) return [];
    const out: string[] = [];
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) out.push(...this.listFiles(p).map((x) => `${e}/${x}`));
      else out.push(e);
    }
    return out;
  }

  /**
   * The broker's decisions for a stack since index `since`. A denial before the compose checks has no stackHash
   * yet; it is matched by the request's imageId and releaseIds.
   */
  private decisionsFor(c: Pick<Composed, "stackHash" | "imageId" | "releaseIds">, since = 0): Array<Record<string, unknown>> {
    return this.broker.decisions().filter((d, i) => {
      if (i < since) return false;
      const h = (d.hashes ?? {}) as { stackHash?: string; imageId?: string; releaseIds?: string[] };
      if (h.stackHash) return lower(h.stackHash) === c.stackHash;
      return lower(h.imageId ?? "") === c.imageId && (h.releaseIds ?? []).map(lower).join(",") === c.releaseIds.join(",");
    });
  }

  private async onchainRecord(id: Hex) {
    return this.chain.read<{ status: number; customer: Address; stackHash: Hex; imageId: Hex; configHash: Hex; quoteHash: Hex; enclaveSigner: Address; attestedAt: bigint; lastAttestedAt: bigint }>(
      "DeploymentRegistry",
      "getDeployment",
      [id],
    );
  }

  private async deploymentStatus(id: Hex): Promise<number> {
    const [status] = await this.chain.read<[number, Address, Address]>("DeploymentRegistry", "deploymentParties", [id]);
    return Number(status);
  }

  private async stepBoot(a: Composed): Promise<AgentRun> {
    this.log.step("Boot sealed-agent against them (fake LUKS runner, temp /run/sealed and /mnt/sealed-data)");
    const sim = await this.startSim(a, "dstack-sim-a");
    this.log.ok(`dstack simulator ${sim} serves app-compose.json of stack a byte for byte`);
    const attestHost = a.stack.attestHost as string;
    const cert = await selfSignedCert(this.sup, this.path("attest-front"), attestHost);
    this.front = await startAttestFront({ port: this.port(), ...cert, agentPort: this.agentPort, caddyIp: (a.stack.sidecars as Record<string, string>).caddy as string, peerHeader: PEER_HEADER });
    this.log.ok(`attest TLS front ${this.front.url} for ${attestHost} (self-signed, in place of Caddy's attest route)`);
    const decisionsBefore = this.broker.decisions().length;
    const run = this.launchAgent(a, "agent-a", sim, agentPaths(this.path("agent-a")), this.agentPort, { DEVNET_TLS_TARGET: `127.0.0.1:${new URL(this.front.url).port}` });
    const ready = await this.waitReady(run);
    checkEq(ready.deploymentId, a.deploymentId, "agent deploymentId");
    checkEq(ready.stackHash, a.stackHash, "agent stackHash");
    this.log.ok(`agent ready: deploymentId ${ready.deploymentId}, enclave signer ${ready.enclaveSigner}`);

    const decisions = this.decisionsFor(a, decisionsBefore);
    const allowed = decisions.find((d) => d.decision === "allowed");
    check(allowed, `the key broker logged an allowed release for stack a: ${JSON.stringify(decisions.map((d) => d.reason))}`);
    check(allowed.simulated === true, "the decision is flagged simulated");
    const checks = (allowed.checks as Array<{ name?: string; check?: string; ok: boolean }>) ?? [];
    check(checks.length > 0 && checks.every((c) => c.ok), `every broker check passed: ${JSON.stringify(checks)}`);
    check(!JSON.stringify(allowed).includes(Object.values(this.plan.store)[0] as string), "the decision log holds no secret values");
    this.log.ok(`key broker: nonce, quote (simulated), report_data, image, RTMR3 replay, compose recomputation and approval all passed (${checks.length} checks: ${checks.map((c) => c.name ?? c.check).join(", ")})`);

    check(ready.disk.join(",") === "luksFormat,open,mkfs.ext4,mount", `first boot formats, opens, creates ext4 and mounts: ${ready.disk.join(",")}`);
    const mountinfo = readFileSync(run.paths.mountinfo, "utf8");
    check(mountinfo.includes("ext4 /dev/mapper/sealed-data"), "mountinfo shows the encrypted filesystem at the data mount");
    this.log.ok("data disk: LUKS2 formatted with the diskKey-derived volume key, opened, ext4 created and mounted (fake LUKS runner)");

    const n = await this.checkSecrets(run);
    const unset = Object.entries(this.plan.unset).flatMap(([app, names]) => names.map((x) => `${app}/${x}`));
    for (const u of unset) {
      const [app, name] = u.split("/") as [string, string];
      const f = this.secretFile(run.paths, app, name);
      if (existsSync(f)) check(readFileSync(f, "utf8") === "", `unset optional secret ${u} is an empty placeholder`);
    }
    this.log.ok(`${n} secrets written per service, each equal to the customer's value (same_as resolved); ${unset.length} optional secrets left unset`);
    const sb = this.checkServiceBinds(run);
    this.log.ok(`${sb.services} services bind ${sb.binds} secret files read-only, each present with its value; nothing else on the tmpfs (D-042)`);
    for (const d of a.stack.dataDirs) check(existsSync(join(run.paths.data, d.slice(a.stack.dataRoot.length + 1))), `data dir ${d} created`);
    this.log.ok(`${a.stack.dataDirs.length} volume directories created on the data disk before the ready flag`);
    const payerKey = this.secretFile(run.paths, "sealed-mpp-payer", "ENCLAVE_KEY");
    check(existsSync(payerKey), "the payer key file exists");
    checkEq(privateKeyToAccount(readFileSync(payerKey, "utf8").trim() as Hex).address, ready.enclaveSigner, "the payer key belongs to the enclave signer");
    checkEq(readFileSync(this.secretFile(run.paths, "sealed-mpp-payer", "SPEND_LIMIT_PER_DAY"), "utf8").trim(), "2000000", "payer daily limit");
    this.log.ok("sealed-mpp-payer got the enclave key and the daily spend limit");
    check(existsSync(join(run.paths.ready, "ok")), "ready flag written");
    this.log.ok(`ready flag ${join("run", "sealed", "ready", "ok")} written after the secrets`);
    await this.checkGate(run);

    const ev = await this.waitEvidence(run);
    checkEq(ev.result.kind, "register", "evidence kind");
    const receipt = await this.chain.client.getTransactionReceipt({ hash: ev.result.txHash });
    const [reg] = parseEventLogs({ abi: ABIS.DeploymentRegistry, logs: receipt.logs, eventName: "DeploymentRegistered" }) as Array<{ args: { deploymentId: Hex; customer: Address; stackHash: Hex } }>;
    check(reg, "registerDeployment emitted DeploymentRegistered");
    checkEq(reg.args.deploymentId, a.deploymentId, "registered deploymentId");
    checkEq(receipt.from, ADDR.ops, "the platform's OPS key submitted the record");
    const rec = await this.onchainRecord(a.deploymentId);
    checkEq(Number(rec.status), 1, "deployment Active");
    checkEq(rec.customer, ADDR.customer, "record customer");
    checkEq(rec.stackHash, a.stackHash, "record stackHash");
    checkEq(rec.imageId, this.images.prod, "record imageId");
    checkEq(rec.configHash, a.configHash, "record configHash");
    checkEq(rec.enclaveSigner, ready.enclaveSigner, "record enclaveSigner");
    for (const app of STACK_APPS) check(await this.chain.read<boolean>("DeploymentRegistry", "appInDeployment", [a.deploymentId, computeAppId(app)]), `${app} in deployment`);
    const row = await this.pg.psql(`SELECT status || ' ' || kind FROM evidence WHERE deployment_id = '${a.deploymentId}'`);
    checkEq(row, "confirmed register", "api evidence row");
    const indexed = await waitFor("the api indexer sees the deployment", async () => (await this.pg.psql(`SELECT enclave_signer FROM onchain_deployments WHERE deployment_id = '${a.deploymentId}'`)) || undefined, { timeoutMs: 20_000 });
    checkEq(indexed, ready.enclaveSigner, "indexed enclave signer");
    const health = await waitFor("a signed health report", async () => (await this.pg.psql(`SELECT body::text FROM health_reports WHERE deployment_id = '${a.deploymentId}'`)) || undefined, { timeoutMs: 20_000 });
    check(health.includes("payments") && health.includes("coding-agent"), "health report body names the apps and payments");
    this.log.ok("the api indexer recorded the deployment and accepted a signed health report from the agent");
    this.log.ok(`evidence sent; the oracle verified it with sealed-verifierd and registered the deployment onchain (tx ${ev.result.txHash}, block ${receipt.blockNumber})`);
    this.log.ok(`onchain record: Active, customer, stackHash, imageId, configHash and enclave signer match; all five apps in the deployment`);
    writeFileSync(this.path("evidence-a.json"), `${JSON.stringify(ev.bundle, null, 2)}\n`);
    return run;
  }

  /** The password gate (D-044) answers Caddy's forward_auth with the bcrypt hash the broker released as _gate. */
  private async checkGate(run: AgentRun): Promise<void> {
    const caddy = (run.composed.stack.sidecars as Record<string, string>).caddy as string;
    const gate = (route: string, headers: Record<string, string> = {}, peer = caddy) =>
      http(`http://127.0.0.1:${run.port}/v1/gate?route=${route}`, { headers: { [PEER_HEADER]: peer, ...headers } });
    const basic = (pw: string) => `Basic ${Buffer.from(`sealed:${pw}`).toString("base64")}`;
    const none = await gate("scraper");
    checkEq(none.status, 401, "gate without credentials");
    checkEq(none.headers.get("www-authenticate") ?? "", 'Basic realm="sealed"', "gate challenge");
    checkEq((await gate("scraper", { authorization: basic("not-the-password") })).status, 401, "gate with a wrong password");
    const good = await gate("scraper", { authorization: basic(this.plan.gatePassword) });
    checkEq(good.status, 200, "gate with the customer's gate password");
    const cookie = (good.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    check(cookie.startsWith("sealed_gate="), "a Basic success sets the sealed_gate cookie");
    checkEq((await gate("scraper", { cookie })).status, 200, "gate with the cookie");
    checkEq((await gate("crm", { cookie })).status, 503, "crm stays closed until its bootstrap is done");
    checkEq((await gate("scraper", { cookie }, "172.30.0.99")).status, 403, "only Caddy may ask the gate");
    this.log.ok("password gate: 401 without or with a wrong password, 200 and a cookie with the released bcrypt hash, 503 until bootstrap, 403 for anyone but Caddy");
  }

  // --- 7. verify -----------------------------------------------------------------------------------------------

  /** sealed verify in an empty directory with an empty environment: only the evidence file and the chain. */
  private async sealedVerify(
    id: string,
    evidence: Record<string, unknown> | null,
    label: string,
    extra: string[] = [],
  ): Promise<{ code: number | null; report: { ok: boolean; evidence?: VerifyReport; live?: VerifyReport } }> {
    const dir = this.path("verify", label);
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(join(dir, "home"), { recursive: true });
    if (evidence) writeFileSync(join(dir, "evidence.json"), JSON.stringify(evidence));
    // A local chain has no embedded defaults: its public description (chain id, release asset base, addresses).
    const defaults = parseYaml(readFileSync(join(this.o.repo, "config", "defaults.yaml"), "utf8")) as { chain: Record<string, unknown>; catalog: Record<string, unknown> };
    defaults.chain = { ...defaults.chain, name: "devnet", chain_id: CHAIN_ID, public_rpc_url: this.chain.node.rpcUrl, fee_token: TOKENS.pathUsd };
    defaults.catalog = { ...defaults.catalog, release_asset_base: this.assets.base };
    writeFileSync(join(dir, "defaults.yaml"), stringifyYaml(defaults));
    cpSync(this.chain.c.file, join(dir, "deployments.json"));
    const r = await this.sup.run(`sealed-verify-${label}`, this.o.bins.sealed, [
      "verify", "--deployment", id, ...(evidence ? ["--evidence", "evidence.json"] : []), "--rpc", this.chain.node.rpcUrl, "--deployments", "deployments.json", "--defaults", "defaults.yaml",
      "--dev-allow-simulated", "--dev-allow-http-assets", "--json", "--report", "report.json", "--bundle-cache", "cache/bundles", "--collateral-cache", "cache/pcs", ...extra,
    ], { cwd: dir, cleanEnv: true, env: { PATH: "/usr/bin:/bin", HOME: join(dir, "home"), SEALED_DEV_SIM: "1" } });
    const report = existsSync(join(dir, "report.json")) ? readJson<{ ok: boolean }>(join(dir, "report.json")) : { ok: false };
    if (!existsSync(join(dir, "report.json"))) this.log.warn(`sealed verify wrote no report (exit ${r.code}): ${r.output.slice(-1500)}`);
    return { code: r.code, report: report as never };
  }

  private async stepVerify(a: Composed, run: AgentRun): Promise<void> {
    this.log.step("sealed verify --deployment --evidence from a clean environment (bundle and RPC only)");
    const evidence = readJson<Record<string, unknown>>(this.path("evidence-a.json"));
    const r = await this.sealedVerify(a.deploymentId, evidence, "a");
    checkEq(r.code, 0, "sealed verify exit code");
    check(r.report.ok && r.report.evidence?.ok, "verify report ok");
    check(r.report.evidence?.simulated === true, "the report flags the simulated quote");
    const checks = r.report.evidence?.checks ?? [];
    check(checks.length > 0 && checks.every((c) => c.ok), "every verify check passed");
    this.log.ok(`sealed verify passed ${checks.length} checks (${checks.map((c) => c.name).join(", ")}); simulated: true`);
    void run;

    // The platform's public check (POST /v1/verify, anyone) and the dep_ alias the console shows (D-032).
    const alias = await this.pg.psql(`SELECT alias FROM deployment_aliases WHERE deployment_id = '${a.deploymentId}'`);
    check(/^dep_[0-9A-Za-z]{8}$/.test(alias), `the api assigned a dep_ alias (${alias})`);
    const pub = await http<{ result: string; simulated: boolean; deploymentId: string; checks: Array<{ ok: boolean }> }>(`${this.apiUrl}/v1/verify`, { body: { deploymentId: alias } });
    checkEq(pub.status, 200, "POST /v1/verify status");
    checkEq(pub.body.result, "verified", "the api's verify result");
    checkEq(pub.body.deploymentId, a.deploymentId, "the alias resolves to the deployment");
    check(pub.body.simulated === true, "the api's report flags the simulated quote");
    this.log.ok(`POST /v1/verify {deploymentId: ${alias}} answers verified (simulated) from the stored evidence`);
    const viaAlias = await this.sealedVerify(alias, evidence, "a-alias", ["--api", this.apiUrl]);
    checkEq(viaAlias.code, 0, "sealed verify with the alias");
    this.log.ok(`sealed verify --deployment ${alias} --api resolves the alias through the api, then checks everything against the chain`);

    // A5 --live: a fresh nonce over TLS to the attest host; the quote must bind that connection's key.
    const front = this.front as AttestFront;
    const live = await this.sealedVerify(a.deploymentId, null, "a-live", ["--live", front.url, "--dev-insecure-live-tls", "--dev-live-allow-private"]);
    checkEq(live.code, 0, "sealed verify --live exit code");
    const lchecks = live.report.live?.checks ?? [];
    check(live.report.live?.ok === true && lchecks.length > 0 && lchecks.every((c) => c.ok), `every live check passed: ${JSON.stringify(lchecks.filter((c) => !c.ok))}`);
    check(lchecks.some((c) => c.name.includes("tls")), "the live report checks the TLS key binding");
    this.log.ok(`sealed verify --live ${front.url} passed ${lchecks.length} checks (${lchecks.map((c) => c.name).join(", ")})`);

    // A man in the middle with its own certificate for the attest host: the quote binds the real front's key.
    const mitmCert = await selfSignedCert(this.sup, this.path("attest-mitm"), a.stack.attestHost as string);
    const mitm = await startAttestFront({ port: this.port(), ...mitmCert, agentPort: front.target.port, caddyIp: (a.stack.sidecars as Record<string, string>).caddy as string, peerHeader: PEER_HEADER });
    try {
      const bad = await this.sealedVerify(a.deploymentId, null, "a-live-mitm", ["--live", mitm.url, "--dev-insecure-live-tls", "--dev-live-allow-private"]);
      checkEq(bad.code, 1, "sealed verify --live through another certificate");
      const failed = (bad.report.live?.checks ?? []).filter((c) => !c.ok).map((c) => c.name);
      check(failed.includes("tls_binding"), `the TLS key binding fails (${failed.join(", ")})`);
      this.log.ok(`through a front with another certificate for the same host, --live fails: ${failed.join(", ")}`);
    } finally {
      await mitm.close();
    }
  }

  // --- 8. usage and fees ---------------------------------------------------------------------------------------

  private serviceIp(c: Composed, app: string): string {
    const a = c.stack.apps.find((x) => x.id === app);
    const ip = a?.services[0]?.ips[0];
    if (!ip) throw new Error(`no service IP for ${app} in sealed-stack`);
    return ip;
  }

  private async postUsage(run: AgentRun, app: string, unit: string, quantity: number, peer: string, id?: string) {
    return http(`http://127.0.0.1:${run.port}/v1/usage-events`, { body: { app, unit, quantity, ...(id ? { id } : {}) }, headers: { [PEER_HEADER]: peer } });
  }

  private async feesPaid(deploymentId: Hex) {
    const logs = await this.chain.client.getLogs({ address: this.chain.c.feeSplitter, fromBlock: this.chain.c.deployBlock, toBlock: "latest" });
    return (parseEventLogs({ abi: ABIS.FeeSplitter, logs, eventName: "FeesPaid" }) as unknown as Array<{
      args: { deploymentId: Hex; appId: Hex; payer: Address; token: Address; amount: bigint; maintainerAmount: bigint; usageHash: Hex };
      transactionHash: Hex;
    }>).filter((e) => lower(e.args.deploymentId) === lower(deploymentId));
  }

  private async authorizeAccessKey(keyId: Address): Promise<Hex> {
    const chain = tempoChain({ chainId: CHAIN_ID, rpcUrl: this.chain.node.rpcUrl, feeToken: TOKENS.pathUsd });
    const wallet = createClient({ chain: chain as never, transport: viemHttp(this.chain.node.rpcUrl), pollingInterval: 100 });
    const fs = this.chain.c.feeSplitter;
    const hash = await wallet.writeContract({
      account: Account.fromSecp256k1(KEYS.customer),
      address: Addresses.accountKeychain,
      abi: Abis.accountKeychain,
      functionName: "authorizeKey",
      args: [
        keyId,
        0,
        {
          expiry: 2n ** 64n - 1n,
          enforceLimits: true,
          limits: [{ token: TOKENS.pathUsd, amount: 2_000_000n, period: 86_400n }],
          allowAnyCalls: false,
          allowedCalls: [
            { target: TOKENS.pathUsd, selectorRules: [{ selector: toFunctionSelector("approve(address,uint256)"), recipients: [fs] }] },
            {
              target: fs,
              selectorRules: [
                { selector: toFunctionSelector("payFees(bytes32,bytes32,address,uint256,bytes32)"), recipients: [] },
                { selector: toFunctionSelector("topUpFees(bytes32,bytes32,address,uint256,bytes32)"), recipients: [] },
              ],
            },
          ],
        },
      ],
      feeToken: TOKENS.alphaUsd,
      gas: 12_000_000n,
    } as never);
    const receipt = await this.chain.client.waitForTransactionReceipt({ hash, timeout: 20_000 });
    check(receipt.status === "success", `authorizeKey ${hash} succeeded`);
    return hash;
  }

  /** Posts usage, waits for the agent's settlement loop to pay every leg, and checks report, legs and split. */
  private async settleAndCheck(run: AgentRun, usage: Array<{ app: string; unit: string; quantity: number; fee: bigint }>, payer: Address): Promise<{ total: bigint; maintainer: bigint }> {
    const c = run.composed;
    const m0 = await this.chain.read<bigint>("FeeSplitter", "credited", [TOKENS.pathUsd, ADDR.maintainer]);
    const t0 = await this.chain.read<bigint>("FeeSplitter", "credited", [TOKENS.pathUsd, ADDR.treasury]);
    const s0 = await this.chain.balance(TOKENS.pathUsd, this.chain.c.feeSplitter);
    for (const u of usage) {
      const r = await this.postUsage(run, u.app, u.unit, u.quantity, this.serviceIp(c, u.app), `devnet-${c.name}-${u.app}`);
      checkEq(r.status, 202, `usage event ${u.app} ${u.quantity} ${u.unit} accepted`);
    }
    this.log.ok(`posted usage events from the apps' own service IPs: ${usage.map((u) => `${u.app} ${u.quantity} ${u.unit}`).join(", ")}`);
    const want = new Map(usage.map((u) => [lower(computeAppId(u.app)), u.fee]));
    const events = await waitFor(
      `${run.name} settlement`,
      async () => {
        const evs = await this.feesPaid(c.deploymentId);
        const sum = new Map<string, bigint>();
        for (const e of evs) sum.set(lower(e.args.appId), (sum.get(lower(e.args.appId)) ?? 0n) + e.args.amount);
        return [...want].every(([k, v]) => (sum.get(k) ?? 0n) >= v) ? evs : undefined;
      },
      { proc: run.proc, timeoutMs: 120_000, intervalMs: 500 },
    );
    let total = 0n;
    let maintainer = 0n;
    for (const e of events) {
      checkEq(e.args.payer, payer, `FeesPaid payer (${e.args.usageHash.slice(0, 10)})`);
      checkEq(e.args.token, TOKENS.pathUsd, "FeesPaid token");
      checkEq(e.args.maintainerAmount, (e.args.amount * BigInt(MAINTAINER_SHARE_BPS)) / 10_000n, "maintainer amount = amount * 2000 / 10000");
      checkEq(await this.chain.read<bigint>("FeeSplitter", "usagePaid", [c.deploymentId, e.args.usageHash, e.args.appId]), e.args.amount, "usagePaid for the leg");
      total += e.args.amount;
      maintainer += e.args.maintainerAmount;
    }
    for (const [app, fee] of want) {
      const paid = events.filter((e) => lower(e.args.appId) === app).reduce((s, e) => s + e.args.amount, 0n);
      checkEq(paid, fee, `fees paid for ${app}`);
    }
    this.log.ok(`agent settled every ${this.o.settleSeconds} s: ${events.length} FeesPaid legs, ${total} base units, payer ${payer}`);
    const usageHashes = [...new Set(events.map((e) => lower(e.args.usageHash)))];
    const stored = await this.pg.psql(`SELECT count(*) || ' ' || coalesce(sum(fee::numeric), 0) FROM usage_items WHERE deployment_id = '${c.deploymentId}' AND usage_hash IN (${usageHashes.map((h) => `'${h}'`).join(",")})`);
    checkEq(stored, `${events.length} ${total}`, "api stored the signed usage reports behind every paid leg");
    const signers = await this.pg.psql(`SELECT DISTINCT signer FROM usage_reports WHERE deployment_id = '${c.deploymentId}'`);
    const [, , enclaveSigner] = await this.chain.read<[number, Address, Address]>("DeploymentRegistry", "deploymentParties", [c.deploymentId]);
    checkEq(signers, lower(enclaveSigner), "usage reports signed by the onchain enclave signer");
    const indexedFees = await waitFor(
      "the api indexer sees every FeesPaid leg",
      async () => {
        const r = await this.pg.psql(`SELECT count(*) || ' ' || coalesce(sum(amount), 0) FROM fees_paid WHERE deployment_id = '${c.deploymentId}'`);
        return r === `${events.length} ${total}` ? r : undefined;
      },
      { timeoutMs: 20_000 },
    );
    void indexedFees;
    this.log.ok(`the api accepted ${usageHashes.length} usage report(s) signed by the enclave signer; every usageHash matches a paid leg`);
    const m1 = await this.chain.read<bigint>("FeeSplitter", "credited", [TOKENS.pathUsd, ADDR.maintainer]);
    const t1 = await this.chain.read<bigint>("FeeSplitter", "credited", [TOKENS.pathUsd, ADDR.treasury]);
    const s1 = await this.chain.balance(TOKENS.pathUsd, this.chain.c.feeSplitter);
    checkEq(m1 - m0, maintainer, "maintainer credit");
    checkEq(t1 - t0, total - maintainer, "treasury credit");
    checkEq(s1 - s0, total, "FeeSplitter balance");
    checkEq((m1 - m0) * 4n, t1 - t0, "split 20/80");
    this.log.ok(`FeeSplitter split 80/20 by maintainer share ${MAINTAINER_SHARE_BPS}: maintainer +${m1 - m0}, treasury +${t1 - t0}`);
    return { total, maintainer };
  }

  private async stepUsageAccessKey(run: AgentRun): Promise<void> {
    this.log.step("Usage and fees, access-key mode: usage events, signed report, settlement every few seconds, split, withdraw");
    const ready = readJson<Ready>(join(run.paths.out, "ready.json"));
    const hash = await this.authorizeAccessKey(ready.enclaveSigner);
    this.log.ok(`customer authorized the enclave signer as an access key on the AccountKeychain precompile (limit 2.00 pathUSD per day, approve/payFees/topUpFees only; tx ${hash})`);
    const llmIp = this.serviceIp(run.composed, "llm-gateway");
    const wrong = await this.postUsage(run, "scraper", "pages", 5, llmIp);
    checkEq(wrong.status, 403, "usage for another app's service IP is refused");
    const bad = await this.postUsage(run, "crm", "tokens", 5, this.serviceIp(run.composed, "crm"));
    check(bad.status >= 400 && bad.status < 500, `crm meters app_hour by heartbeat, a tokens callback is refused (${bad.status})`);
    this.log.ok("usage from another app's address and usage in a unit the app does not meter are refused");
    const c0 = await this.chain.balance(TOKENS.pathUsd, ADDR.customer);
    const { total, maintainer } = await this.settleAndCheck(
      run,
      [
        { app: "llm-gateway", unit: "tokens", quantity: 2_500_000, fee: 500_000n },
        { app: "scraper", unit: "pages", quantity: 100, fee: 20_000n },
      ],
      ADDR.customer,
    );
    const c1 = await this.chain.balance(TOKENS.pathUsd, ADDR.customer);
    check(c0 - c1 >= total, `the customer's balance paid the fees (and the network fee in pathUSD): -${c0 - c1}`);
    this.log.ok(`the customer account paid ${total} in fees plus ${c0 - c1 - total} in network fees, signed by the access key`);
    await this.checkSharedBudget(run, c0 - c1);

    const b0 = await this.chain.balance(TOKENS.pathUsd, ADDR.maintainer);
    const credit = await this.chain.read<bigint>("FeeSplitter", "credited", [TOKENS.pathUsd, ADDR.maintainer]);
    check(credit >= maintainer, "maintainer has a credit to withdraw");
    await this.chain.write(KEYS.maintainer, "FeeSplitter", "withdraw", [TOKENS.pathUsd]);
    const b1 = await this.chain.balance(TOKENS.pathUsd, ADDR.maintainer);
    checkEq(b1 - b0, credit, "maintainer received the whole credit");
    checkEq(await this.chain.read<bigint>("FeeSplitter", "credited", [TOKENS.pathUsd, ADDR.maintainer]), 0n, "maintainer credit after withdraw");
    check(await this.chain.reverts(KEYS.maintainer, "FeeSplitter", "withdraw", [TOKENS.pathUsd]), "a second withdraw reverts");
    this.log.ok(`maintainer withdrew ${credit} base units of pathUSD to its own address`);
  }

  /** D-048: the payer reserves from the same daily budget as fee settlement, which comes first. */
  private async checkSharedBudget(run: AgentRun, feesSpent: bigint): Promise<void> {
    const payer = (run.composed.stack.sidecars as Record<string, string>)["sealed-mpp-payer"] as string;
    const call = (path: string, body: unknown, peer = payer) => http<{ ok: boolean; remaining: string; reservationId?: string; reason?: string }>(`http://127.0.0.1:${run.port}${path}`, { body, headers: { [PEER_HEADER]: peer } });
    checkEq((await call("/v1/spend/reserve", { amount: "1" }, this.serviceIp(run.composed, "llm-gateway"))).status, 403, "only sealed-mpp-payer may reserve");
    checkEq((await call("/v1/spend/reserve", { amount: "1", currency: TOKENS.alphaUsd })).status, 422, "a reservation in another token");
    const probe = await call("/v1/spend/reserve", { amount: "2000001", currency: TOKENS.pathUsd });
    check(probe.status === 200 && probe.body.ok === false && probe.body.reason === "budget", `more than the daily limit is refused: ${probe.text}`);
    const remaining = BigInt(probe.body.remaining);
    check(remaining > 0n && remaining <= 2_000_000n - feesSpent, `the payer's share excludes the fees already paid (${remaining} <= 2000000 - ${feesSpent})`);
    const r = await call("/v1/spend/reserve", { amount: "100000", currency: TOKENS.pathUsd });
    check(r.body.ok && r.body.reservationId, "a reservation within the budget");
    checkEq(BigInt(r.body.remaining), remaining - 100_000n, "remaining after the reservation");
    const rel = await call("/v1/spend/release", { reservationId: r.body.reservationId, used: "60000" });
    checkEq(BigInt(rel.body.remaining), remaining - 60_000n, "remaining after releasing with 60000 used");
    checkEq((await call("/v1/spend/release", { reservationId: r.body.reservationId, used: "0" })).status, 404, "a reservation releases once");
    this.log.ok(`shared spend budget (D-048): the payer could reserve ${remaining} of 2000000 after ${feesSpent} of fees, and a release counts only what was used`);
  }

  private async stepUsageEnclaveAccount(): Promise<void> {
    this.log.step("Usage and fees, enclave-account mode: a second deployment pays from the enclave signer's own balance");
    const apps = ["llm-gateway", "scraper"] as const;
    // No grace period: the first failed settlement switches to the payment-needed page (A9 in seconds).
    const b = await this.compose("b", this.baseConfig({ apps, mode: "enclave-account", imageId: this.images.prod, salt: this.salt("b"), graceMinutes: 0 }), apps);
    await this.approve(b);
    this.log.ok(`stack b (llm-gateway, scraper, settlement enclave-account, grace period 0) composed and approved: ${b.stackHash}`);
    const sim = await this.startSim(b, "dstack-sim-b");
    const run = this.launchAgent(b, "agent-b", sim, agentPaths(this.path("agent-b")), this.port());
    const ready = await this.waitReady(run);
    checkEq(ready.deploymentId, b.deploymentId, "agent b deploymentId");
    const ev = await this.waitEvidence(run);
    checkEq(ev.result.kind, "register", "agent b evidence kind");
    checkEq(Number((await this.onchainRecord(b.deploymentId)).status), 1, "deployment b Active");
    this.log.ok(`deployment b registered onchain (tx ${ev.result.txHash}); enclave signer ${ready.enclaveSigner}`);
    await this.chain.transfer(KEYS.funder, TOKENS.pathUsd, ready.enclaveSigner, 1_000_000n);
    this.log.ok("funded the enclave signer with 1.00 pathUSD");
    const e0 = await this.chain.balance(TOKENS.pathUsd, ready.enclaveSigner);
    const { total } = await this.settleAndCheck(run, [{ app: "llm-gateway", unit: "tokens", quantity: 1_000_000, fee: 200_000n }], ready.enclaveSigner);
    const e1 = await this.chain.balance(TOKENS.pathUsd, ready.enclaveSigner);
    check(e0 - e1 >= total, "the enclave signer's balance paid");
    this.log.ok(`the enclave account paid ${total} in fees plus ${e0 - e1 - total} in network fees`);

    // Over the balance: the settlement fails, so with grace 0 the routes switch to the payment-needed page; a top-up
    // restores them (A9: grace period, payment-needed page, recovery).
    const caddyLog = join(run.paths.out, "caddy.log");
    const variants = () => (existsSync(caddyLog) ? readFileSync(caddyLog, "utf8").trim().split("\n").map((l) => l.split(" ")[1]) : []);
    const llm = lower(computeAppId("llm-gateway"));
    const paidFor = async () => (await this.feesPaid(b.deploymentId)).filter((e) => lower(e.args.appId) === llm).reduce((s, e) => s + e.args.amount, 0n);
    const paidBefore = await paidFor();
    const big = await this.postUsage(run, "llm-gateway", "tokens", 5_000_000, this.serviceIp(b, "llm-gateway"), "devnet-b-over-balance");
    checkEq(big.status, 202, "usage over the balance accepted");
    await waitFor("payment-needed after a failed settlement", () => variants().includes("payment-needed"), { proc: run.proc, timeoutMs: 30_000 });
    checkEq(await paidFor(), paidBefore, "nothing paid while the balance is short");
    const health = await waitFor(
      "a health report saying payment needed",
      async () => {
        const body = await this.pg.psql(`SELECT body::text FROM health_reports WHERE deployment_id = '${b.deploymentId}'`);
        return body.includes('"paymentNeeded": true') || body.includes('"paymentNeeded":true') ? body : undefined;
      },
      { timeoutMs: 30_000 },
    );
    check(health.includes("insufficient_balance"), "the health report names the content-free failure reason");
    this.log.ok("5,000,000 more tokens (1.00 pathUSD) exceed the enclave balance: the settlement fails, Caddy switches to the payment-needed page, the signed health report says so");
    await this.chain.transfer(KEYS.funder, TOKENS.pathUsd, ready.enclaveSigner, 2_000_000n);
    await waitFor("recovery after the top-up", async () => (await paidFor()) === paidBefore + 1_000_000n && variants().at(-1) === "normal", { proc: run.proc, timeoutMs: 30_000 });
    this.log.ok("after a 2.00 pathUSD top-up the next settlement pays the 1.00 leg and restores the normal Caddyfile");

    await this.chain.write(KEYS.customer, "DeploymentRegistry", "closeDeployment", [b.deploymentId]);
    checkEq(await this.deploymentStatus(b.deploymentId), 2, "deployment b Closed");
    const switches = variants().length;
    await waitFor("agent b switches Caddy to the payment-needed page", () => variants().length > switches && variants().at(-1) === "payment-needed", { proc: run.proc, timeoutMs: 30_000 });
    this.log.ok("customer closed deployment b onchain; at its next settlement the agent switched Caddy to the measured payment-needed Caddyfile");
    await run.proc.stop();
    this.log.ok("agent b stopped");
  }

  // --- 9. reboot -----------------------------------------------------------------------------------------------

  /** A reboot clears the tmpfs mounts (secrets, ready flag); the data disk stays. */
  private clearTmpfs(paths: AgentPaths): void {
    rmSync(paths.secrets, { recursive: true, force: true });
    rmSync(paths.ready, { recursive: true, force: true });
    mkdirSync(paths.secrets, { recursive: true });
    mkdirSync(paths.ready, { recursive: true });
  }

  /** Stops the agent, clears its tmpfs and boots it again on the same data disk and simulator. */
  private async restart(run: AgentRun): Promise<void> {
    await run.proc.stop();
    this.clearTmpfs(run.paths);
    const sim = this.simEndpoints.get(run.composed.name);
    if (!sim) throw new Error(`no simulator for stack ${run.composed.name}`);
    Object.assign(run, this.launchAgent(run.composed, run.name, sim, run.paths, run.port, run.env));
  }

  private async stepReboot(run: AgentRun): Promise<void> {
    this.log.step("Reboot: restart the agent with the same data disk");
    const a = run.composed;
    const before = await this.onchainRecord(a.deploymentId);
    const ready0 = readJson<Ready>(join(run.paths.out, "ready.json"));
    const stateFile = join(run.paths.data, ".sealed-agent", "state.json");
    check(existsSync(stateFile), "the agent keeps its state on the data disk");
    await this.restart(run);
    const ready = await this.waitReady(run);
    checkEq(ready.deploymentId, ready0.deploymentId, "same deploymentId after reboot");
    checkEq(ready.enclaveSigner, ready0.enclaveSigner, "same enclave signer after reboot (signerSeed from the broker's HMAC key)");
    this.log.ok(`same deploymentId ${ready.deploymentId} and enclave signer ${ready.enclaveSigner}`);
    check(ready.disk.join(",") === "luksFormat,open,mkfs.ext4,mount,open,mount", `reboot opens and mounts the existing volume without formatting: ${ready.disk.join(",")}`);
    this.log.ok("data disk opened with the same diskKey (a different key would not open it) and mounted; nothing reformatted");
    const n = await this.checkSecrets(run);
    const sb = this.checkServiceBinds(run);
    this.log.ok(`${n} secrets (${sb.binds} service binds) written again to the fresh tmpfs`);
    const ev = await this.waitEvidence(run);
    checkEq(ev.result.kind, "heartbeat", "evidence after reboot is a heartbeat");
    const receipt = await this.chain.client.getTransactionReceipt({ hash: ev.result.txHash });
    const [hb] = parseEventLogs({ abi: ABIS.DeploymentRegistry, logs: receipt.logs, eventName: "DeploymentHeartbeat" }) as Array<{ args: { deploymentId: Hex; quoteHash: Hex } }>;
    check(hb && lower(hb.args.deploymentId) === a.deploymentId, "DeploymentHeartbeat emitted for the deployment");
    const after = await this.onchainRecord(a.deploymentId);
    check(after.quoteHash !== before.quoteHash, "the heartbeat carries a new quote");
    check(after.lastAttestedAt > before.lastAttestedAt, "lastAttestedAt advanced");
    checkEq(Number(after.status), 1, "still Active");
    this.log.ok(`heartbeat landed onchain (tx ${ev.result.txHash}): new quoteHash, lastAttestedAt ${before.lastAttestedAt} -> ${after.lastAttestedAt}`);
    writeFileSync(this.path("evidence-a.json"), `${JSON.stringify(ev.bundle, null, 2)}\n`);
  }

  // --- 10. tamper matrix ---------------------------------------------------------------------------------------

  /** Boots an agent that must be denied: waits for the broker's denial and checks nothing was released. */
  private async deniedBoot(c: Composed, name: string, dstack: string, reason: string, paths = agentPaths(this.path(name)), port = this.port(), env?: Record<string, string>): Promise<AgentRun> {
    const since = this.broker.decisions().length;
    const run = this.launchAgent(c, name, dstack, paths, port, env);
    const denial = await waitFor(
      `${name}: key broker denial`,
      () => this.decisionsFor(c, since).find((d) => d.decision === "denied"),
      { proc: run.proc, timeoutMs: 60_000 },
    );
    checkEq(String(denial.reason), reason, `${name} denial reason`);
    await sleep(1500);
    check(run.proc.running, `${name} keeps waiting for a release instead of starting apps`);
    check(this.listFiles(paths.secrets).length === 0, `${name}: no secret written (${this.listFiles(paths.secrets).join(", ")})`);
    check(!existsSync(join(paths.ready, "ok")), `${name}: no ready flag`);
    check(!existsSync(join(paths.out, "ready.json")), `${name}: the agent never became ready`);
    check(!this.decisionsFor(c, since).some((d) => d.decision === "allowed"), `${name}: no allowed release`);
    return run;
  }

  private async stepTamperCompose(a: Composed): Promise<void> {
    this.log.step("Tamper: one changed byte in app-compose.json");
    const flip = (s: string) => {
      const m = /"name":"sealed-([0-9a-f]{8})"/.exec(s);
      if (!m || m.index === undefined) throw new Error("app-compose.json has no sealed-<hash> name");
      const at = m.index + `"name":"sealed-`.length + 7;
      const ch = s[at] === "0" ? "1" : "0";
      return s.slice(0, at) + ch + s.slice(at + 1);
    };
    const t = await this.compose("tamper-compose", a.config, STACK_APPS, flip);
    let diff = 0;
    for (let i = 0; i < a.appCompose.length; i++) if (a.appCompose[i] !== t.appCompose[i]) diff++;
    checkEq(diff, 1, "exactly one byte differs");
    checkEq(t.appCompose.length, a.appCompose.length, "same length");
    const sim = await this.startSim(t, "dstack-sim-tamper-compose");
    const run = await this.deniedBoot(t, "agent-tamper-compose", sim, "compose_mismatch");
    checkEq(await this.deploymentStatus(t.deploymentId), 0, "no record for the tampered stack");
    this.log.ok(`a one-byte change (stackHash ${t.stackHash}) is denied with compose_mismatch: no secrets, no ready flag, no record`);
    await run.proc.stop();
  }

  private async stepTamperDebugImage(): Promise<void> {
    this.log.step("Tamper: the debug image gets no production secrets");
    const apps = ["llm-gateway", "scraper"] as const;
    const d = await this.compose("debug", this.baseConfig({ apps, mode: "access-key", imageId: this.images.debug, salt: this.salt("debug") }), apps);
    check(await this.chain.reverts(KEYS.customer, "DeploymentRegistry", "approveStack", [d.stackHash, d.releaseIds, d.imageId, 0n]), "approveStack with a debug image reverts");
    this.log.ok("approveStack naming the debug image reverts (ImageNotApproved)");
    const sim = await this.startSim(d, "dstack-sim-debug", true);
    const run = await this.deniedBoot(d, "agent-debug", sim, "image_debug");
    checkEq(await this.deploymentStatus(d.deploymentId), 0, "no record for the debug stack");
    this.log.ok("a debug TD (mrtd 0x55..) is denied with image_debug: no secrets, no record");
    await run.proc.stop();
  }

  private async stepTamperNoQuote(a: Composed): Promise<void> {
    this.log.step("Tamper: a release request with no quote (a non-confidential VM)");
    const since = this.broker.decisions().length;
    const { body: n } = await http<{ nonce: Hex }>(`${this.broker.url}/v1/nonce`);
    const req = {
      nonce: n.nonce,
      ephemeralPub: hex0("09".repeat(32)),
      quote: "0x",
      eventLog: [],
      config: a.config,
      appCompose: a.appCompose,
      releaseIds: a.releaseIds,
      imageId: a.imageId,
    };
    const r = await http<{ decision: string; reason: string }>(`${this.broker.url}/v1/release`, { body: req });
    checkEq(r.status, 403, "status");
    checkEq(r.body.decision, "denied", "decision");
    checkEq(r.body.reason, "quote_invalid", "reason");
    const logged = this.broker.decisions().slice(since);
    check(logged.some((d) => d.reason === "quote_invalid"), "the denial is in the decision log");
    const replay = await http<{ reason: string }>(`${this.broker.url}/v1/release`, { body: req });
    checkEq(replay.body.reason, "bad_nonce", "the burned nonce cannot be reused");
    this.log.ok("403 quote_invalid, logged; the nonce was consumed (a retry is bad_nonce)");
  }

  private async stepRevokeStack(run: AgentRun): Promise<void> {
    this.log.step("Tamper: revoke the stack approval, then the next boot is denied");
    const a = run.composed;
    await this.chain.write(KEYS.customer, "DeploymentRegistry", "revokeStack", [a.stackHash]);
    check(!(await this.chain.read<boolean>("DeploymentRegistry", "isStackApproved", [ADDR.customer, a.stackHash])), "stack no longer approved");
    await waitFor("the api indexer sees the revoked approval", async () => (await this.pg.psql(`SELECT revoked FROM stack_approvals WHERE stack_hash = '${a.stackHash}'`)) === "t" || undefined, { timeoutMs: 20_000 });
    await run.proc.stop();
    this.clearTmpfs(run.paths);
    const denied = await this.deniedBoot(a, run.name, this.simEndpoints.get(a.name) as string, "stack_not_approved", run.paths, run.port, run.env);
    this.log.ok("after revokeStack the reboot is denied with stack_not_approved: no secrets, no ready flag");
    const v = await this.sealedVerify(a.deploymentId, readJson(this.path("evidence-a.json")), "revoked-stack");
    checkEq(v.code, 1, "sealed verify fails while the approval is revoked");
    this.log.ok(`sealed verify fails: ${(v.report.evidence?.checks ?? []).filter((c) => !c.ok).map((c) => c.name).join(", ")}`);
    await denied.proc.stop();
    await this.approve(a);
    this.log.ok("the customer re-approves the same stack (same releases and image), which clears the revocation");
    this.clearTmpfs(run.paths);
    const again = this.launchAgent(a, run.name, this.simEndpoints.get(a.name) as string, run.paths, run.port, run.env);
    Object.assign(run, again);
    await this.waitReady(run);
    const ev = await this.waitEvidence(run);
    checkEq(ev.result.kind, "heartbeat", "after re-approval the boot attests again");
    this.log.ok(`after re-approval the agent boots and its heartbeat lands (tx ${ev.result.txHash})`);
    writeFileSync(this.path("evidence-a.json"), `${JSON.stringify(ev.bundle, null, 2)}\n`);
  }

  private async stepRevokeRelease(run: AgentRun): Promise<void> {
    this.log.step("Tamper: revoke a release, then the next boot is denied and sealed verify fails");
    const a = run.composed;
    const ok = await this.sealedVerify(a.deploymentId, readJson(this.path("evidence-a.json")), "before-revoke");
    checkEq(ok.code, 0, "sealed verify passes before the revocation");
    const rel = this.releases.get("llm-gateway") as Release;
    await this.chain.write(KEYS.owner, "AppRegistry", "revokeRelease", [rel.releaseId, "devnet incident drill"]);
    check(!(await this.chain.read<boolean>("AppRegistry", "isApprovableRelease", [rel.releaseId])), "release revoked");
    check(!(await this.chain.read<boolean>("DeploymentRegistry", "isStackApproved", [ADDR.customer, a.stackHash])), "a stack with a revoked release is no longer approved");
    check(await this.chain.reverts(KEYS.customer, "DeploymentRegistry", "approveStack", [a.stackHash, a.releaseIds, a.imageId, 0n]), "re-approving cannot undo a revoked release");
    const indexed = await waitFor("the api indexer sees the revoked release", async () => (await this.pg.psql(`SELECT status || ' ' || revoke_reason FROM releases WHERE release_id = '${rel.releaseId}'`)).startsWith("revoked") ? true : undefined, { timeoutMs: 20_000 });
    check(indexed, "release indexed as revoked");
    const listed = await http<Array<{ releaseId: Hex; revocation?: { reason: string } }>>(`${this.apiUrl}/v1/catalog/apps/llm-gateway/releases`);
    checkEq(listed.body.find((x) => lower(x.releaseId) === rel.releaseId)?.revocation?.reason ?? "", "devnet incident drill", "the catalog shows the revocation and its reason");
    this.log.ok(`owner revoked llm-gateway ${rel.version} (${rel.releaseId}); the approval cannot be restored; the api's catalog shows the revocation`);
    await run.proc.stop();
    this.clearTmpfs(run.paths);
    const denied = await this.deniedBoot(a, run.name, this.simEndpoints.get(a.name) as string, "stack_not_approved", run.paths, run.port, run.env);
    this.log.ok("the next boot is denied: no secrets, no ready flag");
    const v = await this.sealedVerify(a.deploymentId, readJson(this.path("evidence-a.json")), "revoked-release");
    checkEq(v.code, 1, "sealed verify exit code after the revocation");
    const failed = (v.report.evidence?.checks ?? []).filter((c) => !c.ok).map((c) => c.name);
    check(failed.length > 0, "verify names the failing checks");
    this.log.ok(`sealed verify fails after the revocation: ${failed.join(", ")}`);
    const pub = await http<{ result: string }>(`${this.apiUrl}/v1/verify`, { body: { bundle: readJson(this.path("evidence-a.json")) } });
    checkEq(pub.body.result, "mismatch", "the api's public check of the same evidence after the revocation");
    this.log.ok("POST /v1/verify {bundle} answers mismatch for the same evidence");
    await denied.proc.stop();
  }
}
