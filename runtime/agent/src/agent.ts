// sealed-agent: the boot sequence of spec 5.6 and the long-running loops (metering, settlement,
// health reports, re-attestation). Dependencies are injectable so the whole flow runs against
// the dstack simulator, a fake key broker and a fake platform in tests.
import { mkdir, readFile } from "node:fs/promises";
import type http from "node:http";
import { join } from "node:path";
import { type Address, type Defaults, type EvidenceBundle, type Hex, loadDefaults, settlementDefaults, type UsageEvent, usageDomain } from "@sealed/core";
import { type CaddySwitch, DirectCaddySwitch, HelperCaddySwitch } from "./caddy.js";
import { type Clock, systemClock } from "./clock.js";
import { buildContext, checkMountedCopy, type DeploymentContext, readPublicConfig } from "./context.js";
import { DirDisk, type DataDisk, LuksDisk } from "./disk.js";
import { DstackClient, type QuoteProvider } from "./dstack.js";
import { attestAndSubmit, type EvidenceResult, HttpPlatformClient, type PlatformClient, buildEvidence } from "./evidence.js";
import { type EgressStatsSource, httpEgressStats, sendHealthReport } from "./healthReport.js";
import { parseEndpoint } from "./http.js";
import { HttpKeyBroker, type KeyBroker, type ReleasedKeys, releaseKeys } from "./keyRelease.js";
import { createLogger, errorFields, type Logger } from "./log.js";
import { AppHealthPoller, type Probe } from "./metering/appHealth.js";
import { Ledger, TooManyReportsError } from "./metering/ledger.js";
import { UsageLimiter, UsageLimitError } from "./metering/limits.js";
import { type FeePayer, TempoFeePayer } from "./payments/feePayer.js";
import { type SettlementResult, Settler } from "./payments/settler.js";
import { liveAttestation } from "./attest.js";
import { dropPrivileges, parseRunAs } from "./privileges.js";
import { every } from "./scheduler.js";
import {
  AGENT_SERVICE,
  checkSecretMounts,
  declaredSecretsFromAppCompose,
  filesMountedIndividually,
  secretMountsFromAppCompose,
} from "./secretMounts.js";
import { type SecretsLayout, writePayerSecrets, writeReadyFlag, writeSecrets } from "./secrets.js";
import { type ApiHandlers, createApiServer, listen, UsageRejected } from "./server.js";
import type { AgentSettings } from "./settings.js";
import { parseSpendReport, type SpendCounters } from "./spend.js";
import { COMPOSE_CONFIGS, measuredConfigs, requireMeasured } from "./stack.js";
import { StateStore } from "./state.js";
import { ServedCertSource, type TlsKeySource } from "./tls.js";
import { createVolumeDirs, volumeDirsFromStack } from "./volumes.js";

export interface AgentDeps {
  settings: AgentSettings;
  clock?: Clock;
  log?: Logger;
  dstack?: QuoteProvider;
  broker?: KeyBroker;
  platform?: PlatformClient;
  disk?: DataDisk;
  caddy?: CaddySwitch;
  tls?: TlsKeySource;
  payer?: (keys: ReleasedKeys, ctx: DeploymentContext) => FeePayer;
  egressStats?: EgressStatsSource;
  probe?: Probe;
  defaults?: Defaults;
  /** statfs f_type override for the tmpfs checks (tests). */
  fsType?: (path: string) => Promise<number>;
  /** chown for the data-disk volume directories (tests record it; production uses fs.chown as root). */
  chown?: (path: string, uid: number, gid: number) => Promise<void>;
  /** Caller address of a local API request (tests; production uses the socket peer). */
  peerOf?: (req: http.IncomingMessage) => string;
  /** Delay between denied release attempts (tests use a short one). */
  releaseDeniedDelayMs?: number;
  /** Called when something the agent cannot recover from in-process fails (main exits so Docker restarts it). */
  onFatal?: (err: Error) => void;
}

/** Caddy's HTTPS port on its apps-network IP, where the agent reads the served certificate. */
const CADDY_TLS_PORT = 443;

export class Agent {
  readonly clock: Clock;
  readonly log: Logger;
  private readonly abort = new AbortController();
  private server?: http.Server;
  private ready = false;
  private loops: Promise<void>[] = [];
  private spend: SpendCounters = {};
  private attesting?: Promise<EvidenceResult>;
  private caddy?: CaddySwitch;
  private tls?: TlsKeySource;
  private readonly limiter = new UsageLimiter();
  /** min(defaults cap, last onchain FeeSplitter perPaymentCap): reports are cut at it. */
  private perPaymentCap = 0n;

  ctx?: DeploymentContext;
  keys?: ReleasedKeys;
  store?: StateStore;
  ledger?: Ledger;
  poller?: AppHealthPoller;
  settler?: Settler;
  payer?: FeePayer;
  dstack?: QuoteProvider;
  evidence?: Promise<EvidenceResult>;
  lastEvidence?: EvidenceBundle;
  port?: number;

  constructor(private readonly deps: AgentDeps) {
    this.clock = deps.clock ?? systemClock;
    this.log = deps.log ?? createLogger({ svc: "sealed-agent" });
  }

  get enclaveSigner(): Address | undefined {
    return this.keys?.enclaveSigner;
  }

  /** Spec 5.6 steps 1-4. Resolves once secrets are written and the agent reports healthy. */
  async boot(): Promise<void> {
    const s = this.deps.settings;
    const { config, json } = await readPublicConfig(s.configPath);
    const defaults = this.deps.defaults ?? (await loadDefaults(s.defaultsPath, { testOverrides: s.testOverrides }));
    const dstack = this.deps.dstack ?? new DstackClient(parseEndpoint(s.dstackEndpoint));
    this.dstack = dstack;
    const appCompose = s.appComposePath ? await readFile(s.appComposePath, "utf8") : await dstack.appCompose();
    const ctx = buildContext({ config, configJson: json, appCompose, defaults });
    await checkMountedCopy(s.stackPath, requireMeasured(measuredConfigs(appCompose), COMPOSE_CONFIGS.stack), "stack file");
    await checkMountedCopy(s.caddyfilePath, ctx.caddyfiles.normal, "Caddyfile");
    await checkMountedCopy(s.caddyfilePaymentNeededPath, ctx.caddyfiles.paymentNeeded, "payment-needed Caddyfile");
    // D-042: no service may see another owner's secrets; checked before any secret is released.
    const secretMounts = secretMountsFromAppCompose(appCompose);
    checkSecretMounts(secretMounts, ctx.stack);
    this.ctx = ctx;
    const log = this.log.child({ deploymentId: ctx.deploymentId });
    log.info("booting", { stackHash: ctx.stackHash, configHash: ctx.configHash, apps: ctx.apps.map((a) => a.id), devSim: s.devSim });

    this.server = createApiServer(this.handlers(), log, { trustedProxy: () => this.ctx?.caddyIp, peerOf: this.deps.peerOf });
    this.port = (await listen(this.server, s.listenHost, s.listenPort)).port;

    const broker = this.deps.broker ?? new HttpKeyBroker(config.endpoints.keyBroker);
    const keys = await releaseKeys(ctx, dstack, broker, {
      log,
      clock: this.clock,
      signal: this.abort.signal,
      deniedDelayMs: this.deps.releaseDeniedDelayMs,
    });
    this.keys = keys;

    const disk =
      this.deps.disk ??
      (s.diskMode === "dir"
        ? new DirDisk(s.dataMount)
        : new LuksDisk({ device: s.dataDevice, name: s.luksName, mountPoint: s.dataMount, log }));
    try {
      await disk.open(keys.diskKey);
    } finally {
      keys.diskKey.fill(0);
    }
    // Brief item 11: every data bind source exists with its declared owner before the ready flag.
    await createVolumeDirs(volumeDirsFromStack(ctx.stack, appCompose, s.dataMount), { chownFn: this.deps.chown });

    const stateDir = s.stateDir ?? join(s.dataMount, ".sealed-agent");
    await mkdir(stateDir, { recursive: true, mode: 0o700 });
    this.store = await StateStore.open(join(stateDir, "state.json"), this.clock.now());

    const layout: SecretsLayout = { secretsDir: s.secretsDir, readyDir: s.readyDir, requireTmpfs: s.requireTmpfs, fsType: this.deps.fsType };
    const optional = new Map(ctx.stack.apps.map((a) => [a.id, new Set(a.secrets.filter((x) => x.optional).map((x) => x.name))]));
    const written = await writeSecrets(layout, keys.secrets, new Set(["_gate", ...ctx.apps.map((a) => a.id)]), {
      individually: filesMountedIndividually(secretMounts),
      isOptional: (owner, name) => optional.get(owner)?.has(name) ?? false,
      onDisk: new Set(secretMounts.filter((m) => m.service === AGENT_SERVICE && m.name === undefined).map((m) => m.owner)),
    });
    for (const d of declaredSecretsFromAppCompose(appCompose)) {
      if (!d.optional && keys.secrets[d.app]?.[d.name] === undefined) {
        log.error("a required secret was not released; the service that declares it cannot start", { app: d.app, secret: d.name, service: d.service });
      }
    }
    if (written.placeholders.length > 0) log.info("optional secrets not released, mounted empty", { secrets: written.placeholders });
    if (written.skipped.length > 0) log.info("released secrets that no container mounts were not written", { owners: written.skipped });
    if (ctx.payerIp) await writePayerSecrets(layout, keys.enclaveKey, config.settlement.spendLimitPerDay);

    const runAs = parseRunAs(s.runAs);
    const dropping = runAs !== undefined && process.getuid?.() === 0;
    this.caddy =
      this.deps.caddy ??
      (dropping
        ? new HelperCaddySwitch(s.caddyAdminSocket, ctx.caddyfiles, {
            onLost: (err) => {
              log.error("caddy helper lost; the payment-needed switch no longer works", errorFields(err));
              this.deps.onFatal?.(err);
            },
          })
        : new DirectCaddySwitch(parseEndpoint(s.caddyAdminSocket), ctx.caddyfiles));
    await writeReadyFlag(layout, this.clock.now());
    await dropPrivileges(runAs, [stateDir], log);
    await this.setupMetering(ctx, keys, defaults, log);
    this.ready = true;
    log.info("secrets written, apps may start", { enclaveSigner: keys.enclaveSigner, secretApps: Object.keys(keys.secrets).length });

    this.evidence = this.attest(log);
  }

  private async setupMetering(ctx: DeploymentContext, keys: ReleasedKeys, defaults: Defaults, log: Logger): Promise<void> {
    const store = this.store as StateStore;
    const s = this.deps.settings;
    const defaultCap = settlementDefaults(defaults).perPaymentCap;
    const payer =
      this.deps.payer?.(keys, ctx) ??
      new TempoFeePayer({
        mode: ctx.config.settlement.mode,
        enclaveKey: keys.enclaveKey,
        customer: ctx.customer,
        chainId: ctx.config.chainId,
        rpcUrl: ctx.config.endpoints.tempoRpc,
        feeToken: ctx.config.feeToken as Address,
        feeSplitter: ctx.config.contracts.feeSplitter as Address,
        deploymentRegistry: ctx.config.contracts.deploymentRegistry as Address,
        deploymentId: ctx.deploymentId,
        // Local Tempo nodes (anvil 1.7.1, T4 rules) under-estimate these batches; mainnet uses the node's estimate.
        minGas: ctx.config.chainId === 4217 ? 0n : 5_000_000n,
      });
    this.payer = payer;
    // Reports must never be cut above the onchain cap, or a leg could never be paid: read it before
    // accepting usage, and refresh it at every settlement.
    const setCap = (onchain: bigint | undefined) => {
      this.perPaymentCap = onchain !== undefined && onchain > 0n && onchain < defaultCap ? onchain : defaultCap;
    };
    setCap(undefined);
    try {
      setCap(await withTimeout(payer.perPaymentCap(), 15_000));
    } catch (err) {
      log.warn("could not read the FeeSplitter per-payment cap, using the defaults until the next settlement", errorFields(err));
    }

    let saveTimer: NodeJS.Timeout | undefined;
    const scheduleSave = () => {
      saveTimer ??= setTimeout(() => {
        saveTimer = undefined;
        void store.save().catch((err) => log.error("state save failed", errorFields(err)));
      }, 2000);
      saveTimer.unref?.();
    };
    this.ledger = new Ledger(store.state.ledger, {
      deploymentId: ctx.deploymentId,
      apps: ctx.apps.map((a) => a.id),
      schedule: ctx.schedule,
      domain: usageDomain(ctx.config.contracts.feeSplitter as Address, ctx.config.chainId),
      enclaveKey: keys.enclaveKey,
      perPaymentCap: () => this.perPaymentCap,
      onChange: scheduleSave,
    });
    this.poller = new AppHealthPoller(ctx.apps, { ledger: this.ledger, log, intervalSec: s.pollIntervalSec, probe: this.deps.probe });
    this.settler = new Settler({
      ledger: this.ledger,
      payer,
      platform: this.platform(),
      gate: this.caddy,
      status: store.state.payments,
      graceSec: ctx.config.settlement.gracePeriodMinutes * 60,
      save: () => store.save(),
      log: log.child({ part: "settlement" }),
      onPerPaymentCap: setCap,
    });
  }

  private platform(): PlatformClient {
    return this.deps.platform ?? new HttpPlatformClient((this.ctx as DeploymentContext).config.endpoints.platformApi);
  }

  /**
   * Builds evidence and submits it, retrying with backoff until accepted. While one submission is
   * still retrying, a second call joins it instead of starting another retry loop.
   */
  attest(log: Logger = this.log): Promise<EvidenceResult> {
    if (this.attesting) return this.attesting;
    const ctx = this.ctx as DeploymentContext;
    const signer = this.enclaveSigner as Address;
    const platform = this.platform();
    const recording: PlatformClient = {
      postEvidence: async (b) => {
        this.lastEvidence = b;
        return platform.postEvidence(b);
      },
      postUsage: (b) => platform.postUsage(b),
      postHealth: (b) => platform.postHealth(b),
    };
    const p: Promise<EvidenceResult> = attestAndSubmit(ctx, this.dstack as QuoteProvider, recording, signer, {
      clock: this.clock,
      log,
      signal: this.abort.signal,
    }).finally(() => {
      if (this.attesting === p) this.attesting = undefined;
    });
    this.attesting = p;
    p.catch((err) => {
      if (!this.abort.signal.aborted) log.error("evidence submission gave up", errorFields(err));
    });
    return p;
  }

  /** Starts the periodic loops (call after boot). */
  start(): void {
    const s = this.deps.settings;
    const ctx = this.ctx as DeploymentContext;
    const opts = { clock: this.clock, log: this.log, signal: this.abort.signal };
    this.loops.push(
      every("app health poll", s.pollIntervalSec * 1000, () => this.pollApps(), { ...opts, runFirst: true }),
      every("settlement", ctx.config.settlement.intervalMinutes * 60_000, () => this.settle(), opts),
      every("health report", s.healthIntervalSec * 1000, () => this.reportHealth(), opts),
      every("re-attestation", s.reattestHours * 3_600_000, () => this.attest(), opts),
    );
  }

  pollApps(now = this.clock.now()): Promise<void> {
    return (this.poller as AppHealthPoller).pollOnce(now);
  }

  settle(now = this.clock.now()): Promise<SettlementResult> {
    return (this.settler as Settler).tick(now);
  }

  async reportHealth(now = this.clock.now()) {
    const ctx = this.ctx as DeploymentContext;
    const store = this.store as StateStore;
    const st = store.state.payments;
    const totals = (this.ledger as Ledger).totals();
    const egress = await (this.deps.egressStats ?? httpEgressStats(this.deps.settings.egressStatsUrl))();
    return sendHealthReport(this.platform(), ctx.deploymentId, (this.keys as ReleasedKeys).enclaveKey, {
      at: now,
      apps: (this.poller as AppHealthPoller).status(),
      egress,
      payments: {
        mode: ctx.config.settlement.mode,
        paymentNeeded: st.paymentNeeded,
        failingSince: st.failingSince,
        lastPaidAt: st.lastPaidAt ?? null,
        lastAttemptAt: st.lastAttemptAt ?? null,
        lastOutcome: st.lastOutcome ?? null,
        metered: totals.metered.toString(),
        unpaid: totals.unpaid.toString(),
        overCap: st.overCap ?? 0,
        ...this.spend,
      },
    });
  }

  /** A fresh evidence bundle without submitting it (sealed verify tests, debugging). */
  buildEvidence(): Promise<EvidenceBundle> {
    return buildEvidence(this.ctx as DeploymentContext, this.dstack as QuoteProvider, this.enclaveSigner as Address, this.clock);
  }

  /**
   * POST /v1/usage-events. Fails closed: the caller must be one of the app's own services (fixed
   * IPs from the stack), the app must meter this unit by callback, and the event must fit the limits.
   */
  private async recordUsage(ev: UsageEvent, peer: string): Promise<"accepted" | "duplicate"> {
    const ledger = this.ledger as Ledger;
    const app = this.ctx?.apps.find((a) => a.id === ev.app);
    if (!app || !ledger.hasApp(ev.app)) throw new UsageRejected(`unknown app ${ev.app}`);
    if (!app.serviceIps.includes(peer)) throw new UsageRejected(`usage for ${ev.app} must come from its own services`, 403);
    if (app.metering.source !== "callback" || app.metering.unit !== ev.unit) {
      throw new UsageRejected(`${ev.app} meters ${app.metering.unit} by ${app.metering.source}`);
    }
    const key = ev.id ?? (typeof ev.meta?.call_id === "string" ? ev.meta.call_id : undefined);
    if (key && ledger.seen(`${ev.app}:${key}`)) return "duplicate";
    const now = this.clock.now();
    const quantity = BigInt(ev.quantity);
    try {
      this.limiter.admit(ev.app, ev.unit, quantity, now);
    } catch (err) {
      if (err instanceof UsageLimitError) throw new UsageRejected(err.message, err.status);
      throw err;
    }
    try {
      await ledger.record(ev.app, ev.unit, quantity, now);
    } catch (err) {
      this.limiter.release(ev.app, ev.unit, quantity, now);
      if (err instanceof TooManyReportsError) throw new UsageRejected(err.message, 422);
      throw err;
    }
    return "accepted";
  }

  /** POST /v1/spend: only from sealed-mpp-payer's fixed IP, only the known numeric counters. */
  private recordSpend(body: unknown, peer: string): void {
    const payerIp = this.ctx?.payerIp;
    if (!payerIp || peer !== payerIp) throw new UsageRejected("spend counters are accepted from sealed-mpp-payer only", 403);
    const counters = parseSpendReport(body);
    if (!counters) throw new UsageRejected("invalid spend report", 400);
    this.spend = counters;
  }

  private handlers(): ApiHandlers {
    return {
      isReady: () => this.ready,
      readyInfo: () =>
        this.ready ? { deploymentId: this.ctx?.deploymentId, enclaveSigner: this.enclaveSigner, stackHash: this.ctx?.stackHash } : {},
      recordUsage: (ev, peer) => this.recordUsage(ev, peer),
      recordSpend: (body, peer) => this.recordSpend(body, peer),
      attest: (nonce) => {
        const ctx = this.ctx as DeploymentContext;
        this.tls ??= this.deps.tls ?? new ServedCertSource({ host: ctx.caddyIp, port: CADDY_TLS_PORT }, ctx.stack.attestHost);
        return liveAttestation(ctx, this.dstack as QuoteProvider, this.tls, this.enclaveSigner as Address, nonce);
      },
    };
  }

  async stop(): Promise<void> {
    this.abort.abort(new Error("agent stopping"));
    await Promise.allSettled(this.loops);
    await this.store?.save().catch(() => undefined);
    if (this.caddy instanceof HelperCaddySwitch) this.caddy.close();
    await new Promise<void>((ok) => {
      if (!this.server) return ok();
      this.server.close(() => ok());
      this.server.closeAllConnections();
    });
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((ok, fail) => {
    const t = setTimeout(() => fail(new Error(`timed out after ${ms} ms`)), ms);
    t.unref?.();
    p.then(
      (v) => {
        clearTimeout(t);
        ok(v);
      },
      (e) => {
        clearTimeout(t);
        fail(e);
      },
    );
  });
}

export type { Hex };
