// sealed-agent: the boot sequence of spec 5.6 and the long-running loops (metering, settlement,
// health reports, re-attestation). Dependencies are injectable so the whole flow runs against
// the dstack simulator, a fake key broker and a fake platform in tests.
import type http from "node:http";
import { join } from "node:path";
import {
  type Address,
  type Defaults,
  type EvidenceBundle,
  type Hex,
  loadDefaults,
  routeHostname,
  settlementDefaults,
  type UsageEvent,
  usageDomain,
} from "@sealed/core";
import { type CaddyAdmin, PaymentGate, SocketCaddyAdmin } from "./caddy.js";
import { type Clock, systemClock } from "./clock.js";
import { buildContext, type DeploymentContext, readAppsMeta, readPublicConfig } from "./context.js";
import { DirDisk, type DataDisk, LuksDisk } from "./disk.js";
import { DstackClient, type QuoteProvider } from "./dstack.js";
import { attestAndSubmit, type EvidenceResult, HttpPlatformClient, type PlatformClient, buildEvidence } from "./evidence.js";
import { type EgressStatsSource, httpEgressStats, sendHealthReport } from "./healthReport.js";
import { parseEndpoint } from "./http.js";
import { HttpKeyBroker, type KeyBroker, type ReleasedKeys, releaseKeys } from "./keyRelease.js";
import { createLogger, errorFields, type Logger } from "./log.js";
import { AppHealthPoller, type Probe } from "./metering/appHealth.js";
import { Ledger } from "./metering/ledger.js";
import { type FeePayer, TempoFeePayer } from "./payments/feePayer.js";
import { type SettlementResult, Settler } from "./payments/settler.js";
import { liveAttestation } from "./attest.js";
import { every } from "./scheduler.js";
import { writePayerSecrets, writeReadyFlag, writeSecrets } from "./secrets.js";
import { type ApiHandlers, createApiServer, listen, UsageRejected } from "./server.js";
import type { AgentSettings } from "./settings.js";
import { StateStore } from "./state.js";
import { CaddyCertSource, type TlsKeySource } from "./tls.js";
import { createVolumeDirs, volumeDirsFromAppCompose } from "./volumes.js";

export interface AgentDeps {
  settings: AgentSettings;
  clock?: Clock;
  log?: Logger;
  dstack?: QuoteProvider;
  broker?: KeyBroker;
  platform?: PlatformClient;
  disk?: DataDisk;
  caddy?: CaddyAdmin;
  tls?: TlsKeySource;
  payer?: (keys: ReleasedKeys, ctx: DeploymentContext) => FeePayer;
  egressStats?: EgressStatsSource;
  probe?: Probe;
  defaults?: Defaults;
  /** Delay between denied release attempts (tests use a short one). */
  releaseDeniedDelayMs?: number;
}

export class Agent {
  readonly clock: Clock;
  readonly log: Logger;
  private readonly abort = new AbortController();
  private server?: http.Server;
  private ready = false;
  private loops: Promise<void>[] = [];
  private spend: Record<string, string | number> = {};

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
    const dstack = this.deps.dstack ?? new DstackClient();
    this.dstack = dstack;
    const appCompose = s.appComposePath
      ? await (await import("node:fs/promises")).readFile(s.appComposePath, "utf8")
      : await dstack.appCompose();
    const ctx = buildContext({ config, configJson: json, appCompose, defaults, appsMeta: await readAppsMeta(s.appsMetaPath) });
    this.ctx = ctx;
    const log = this.log.child({ deploymentId: ctx.deploymentId });
    log.info("booting", { stackHash: ctx.stackHash, configHash: ctx.configHash, apps: ctx.apps.map((a) => a.id), devSim: s.devSim });

    this.server = createApiServer(this.handlers(), log);
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
    await disk.open(keys.diskKey);
    keys.diskKey.fill(0);
    await createVolumeDirs(volumeDirsFromAppCompose(appCompose, s.dataMount));

    this.store = await StateStore.open(join(s.stateDir ?? join(s.dataMount, ".sealed-agent"), "state.json"), this.clock.now());

    const layout = { secretsDir: s.secretsDir, readyFile: s.readyFile };
    await writeSecrets(layout, keys.secrets);
    await writePayerSecrets(layout, keys.enclaveKey, config.settlement.spendLimitPerDay);

    this.setupMetering(ctx, keys, defaults, log);
    await writeReadyFlag(layout, this.clock.now());
    this.ready = true;
    log.info("secrets written, apps may start", { enclaveSigner: keys.enclaveSigner, secretApps: Object.keys(keys.secrets).length });

    this.evidence = this.attest(log);
  }

  private setupMetering(ctx: DeploymentContext, keys: ReleasedKeys, defaults: Defaults, log: Logger): void {
    const store = this.store as StateStore;
    const s = this.deps.settings;
    const sd = settlementDefaults(defaults);
    let cap = sd.perPaymentCap;
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
    void payer
      .perPaymentCap()
      .then((c) => {
        if (c > 0n) cap = c;
      })
      .catch((err) => log.warn("could not read FeeSplitter caps, using defaults", errorFields(err)));

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
      perPaymentCap: () => cap,
      onChange: scheduleSave,
    });
    this.poller = new AppHealthPoller(ctx.apps, { ledger: this.ledger, log, intervalSec: s.pollIntervalSec, probe: this.deps.probe });

    const attestHost = routeHostname(ctx.config, "attest");
    const appHosts = APP_ROUTES.map((r) => routeHostname(ctx.config, r)).filter((h): h is string => !!h && h !== attestHost);
    const gate = new PaymentGate(this.deps.caddy ?? new SocketCaddyAdmin(parseEndpoint(s.caddyAdminSocket)), [...new Set(appHosts)], {
      getOriginal: () => store.state.caddyOriginal,
      setOriginal: async (c) => {
        store.state.caddyOriginal = c;
        await store.save();
      },
    });
    this.settler = new Settler({
      ledger: this.ledger,
      payer,
      platform: this.platform(),
      gate,
      status: store.state.payments,
      graceSec: ctx.config.settlement.gracePeriodMinutes * 60,
      save: () => store.save(),
      log: log.child({ part: "settlement" }),
    });
  }

  private platform(): PlatformClient {
    return this.deps.platform ?? new HttpPlatformClient((this.ctx as DeploymentContext).config.endpoints.platformApi);
  }

  /** Builds evidence and submits it, retrying with backoff until accepted. */
  attest(log: Logger = this.log): Promise<EvidenceResult> {
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
    const p = attestAndSubmit(ctx, this.dstack as QuoteProvider, recording, signer, { clock: this.clock, log, signal: this.abort.signal });
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
        ...Object.fromEntries(Object.entries(this.spend).map(([k, v]) => [`mpp_${k}`, v])),
      },
    });
  }

  /** A fresh evidence bundle without submitting it (sealed verify tests, debugging). */
  buildEvidence(): Promise<EvidenceBundle> {
    return buildEvidence(this.ctx as DeploymentContext, this.dstack as QuoteProvider, this.enclaveSigner as Address, this.clock);
  }

  private handlers(): ApiHandlers {
    return {
      isReady: () => this.ready,
      readyInfo: () =>
        this.ready ? { deploymentId: this.ctx?.deploymentId, enclaveSigner: this.enclaveSigner, stackHash: this.ctx?.stackHash } : {},
      recordUsage: async (ev: UsageEvent) => {
        const ledger = this.ledger as Ledger;
        if (!ledger.hasApp(ev.app)) throw new UsageRejected(`unknown app ${ev.app}`);
        const meta = this.ctx?.apps.find((a) => a.id === ev.app)?.metering;
        if (meta && (meta.unit !== ev.unit || meta.source !== "callback")) {
          throw new UsageRejected(`${ev.app} meters ${meta.unit} by ${meta.source}`);
        }
        const key = ev.id ?? (typeof ev.meta?.call_id === "string" ? ev.meta.call_id : undefined);
        if (key && ledger.seen(`${ev.app}:${key}`)) return "duplicate";
        await ledger.record(ev.app, ev.unit, BigInt(ev.quantity), this.clock.now());
        return "accepted";
      },
      recordSpend: (body) => {
        const out: Record<string, string | number> = {};
        for (const [k, v] of Object.entries(body).slice(0, 10)) {
          if (/^[A-Za-z][A-Za-z0-9_]{0,40}$/.test(k) && (typeof v === "number" || (typeof v === "string" && v.length <= 80))) out[k] = v;
        }
        this.spend = out;
      },
      attest: (nonce) =>
        liveAttestation(
          this.ctx as DeploymentContext,
          this.dstack as QuoteProvider,
          this.deps.tls ?? new CaddyCertSource(this.deps.settings.caddyDataDir, routeHostname((this.ctx as DeploymentContext).config, "attest")),
          this.enclaveSigner as Address,
          nonce,
        ),
    };
  }

  async stop(): Promise<void> {
    this.abort.abort(new Error("agent stopping"));
    await Promise.allSettled(this.loops);
    await this.store?.save().catch(() => undefined);
    await new Promise<void>((ok) => {
      if (!this.server) return ok();
      this.server.close(() => ok());
      this.server.closeAllConnections();
    });
  }
}

/** Caddy app route names (manifest routes[].name); `attest` is never switched. */
export const APP_ROUTES = ["gateway", "scraper", "crm", "code", "tools", "relay"] as const;

export type { Hex };
