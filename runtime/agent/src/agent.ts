// sealed-agent: the boot sequence of spec 5.6 and the long-running loops (metering, settlement,
// health reports, re-attestation). Dependencies are injectable so the whole flow runs against
// the dstack simulator, a fake key broker and a fake platform in tests.
import { mkdir, readFile } from "node:fs/promises";
import type http from "node:http";
import { join } from "node:path";
import {
  type Address,
  type Defaults,
  type EvidenceBundle,
  type Hex,
  loadDefaults,
  priceRuleFor,
  settlementDefaults,
  type UsageEvent,
  usageDomain,
} from "@sealed/core";
import { type CaddySwitch, DirectCaddySwitch, HelperCaddySwitch } from "./caddy.js";
import { type Clock, systemClock } from "./clock.js";
import { buildContext, checkMountedCopy, type DeploymentContext, readPublicConfig } from "./context.js";
import { DirDisk, type DataDisk, LuksDisk } from "./disk.js";
import { DstackClient, type QuoteProvider } from "./dstack.js";
import { attestAndSubmit, type EvidenceResult, HttpPlatformClient, type PlatformClient, buildEvidence } from "./evidence.js";
import { type EgressStatsSource, httpEgressStats, sendHealthReport } from "./healthReport.js";
import { parseEndpoint } from "./http.js";
import { BcryptWorker } from "./gate/bcrypt.js";
import { BootstrapError, BootstrapTracker } from "./gate/bootstrap.js";
import { Gate, type GateDecision, type GateRequest, type GateRoute } from "./gate/gate.js";
import { HttpKeyBroker, type KeyBroker, type ReleasedKeys, releaseKeys } from "./keyRelease.js";
import { createLogger, errorFields, type Logger } from "./log.js";
import { AppHealthPoller, type Probe } from "./metering/appHealth.js";
import { Ledger, TooManyReportsError } from "./metering/ledger.js";
import { UsageLimiter, UsageLimitError } from "./metering/limits.js";
import { emptyBudgetState, SpendBudget } from "./payments/budget.js";
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
import { parseSpendReport, releaseRequestSchema, reserveRequestSchema, type SpendCounters } from "./spend.js";
import { COMPOSE_CONFIGS, GATE_DEFAULTS, measuredConfigs, requireMeasured, type StackInfo } from "./stack.js";
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
  /** bcrypt check for the gate (tests may substitute a fast one; production uses a worker thread). */
  gateVerify?: (password: Uint8Array, hash: string) => Promise<boolean>;
  /** Per-boot key for the gate cookie (tests fix it; production draws a random one at every boot). */
  gateKey?: Uint8Array;
  /** Called when something the agent cannot recover from in-process fails (main exits so Docker restarts it). */
  onFatal?: (err: Error) => void;
}

/** Caddy's HTTPS port on its apps-network IP, where the agent reads the served certificate. */
const CADDY_TLS_PORT = 443;
/**
 * Network fee allowance per settlement transaction, in fee-token base units (0.01 USD). A batch costs
 * about 3.6M gas, a fraction of a cent at mainnet's base fee (tempo-viem notes); self-paid fees count
 * against an access-key limit, so the payer must leave room for them.
 */
export const NETWORK_FEE_ALLOWANCE = 10_000n;

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
  private bcrypt?: BcryptWorker;
  gate?: Gate;
  bootstrap?: BootstrapTracker;
  budget?: SpendBudget;

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

    // Answers 503 `starting` until the gate hash is released and the app's bootstrap is done.
    this.gate = this.createGate(ctx.stack, log);
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
    const store = this.store;
    this.bootstrap = new BootstrapTracker(ctx.stack, s.dataMount, {
      log,
      now: () => this.clock.now() * 1000,
      reported: store.state.bootstrapDone,
      onReported: (app) => {
        store.state.bootstrapDone = [...new Set([...(store.state.bootstrapDone ?? []), app])].sort();
        void store.save().catch((err) => log.error("state save failed", errorFields(err)));
      },
    });

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
    const g = ctx.stack.gate ?? GATE_DEFAULTS;
    this.gate.setHash(keys.secrets[g.secretApp]?.[g.secret]);
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
    store.state.budget ??= emptyBudgetState(this.clock.now());
    this.budget = new SpendBudget({
      limit: BigInt(ctx.config.settlement.spendLimitPerDay),
      state: store.state.budget,
      feeReserve: () => this.feeReserve(),
      onChange: scheduleSave,
    });
    await this.alignBudget(log);
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
      onSpent: (amount, now) => this.budget?.recordFees(amount, now),
    });
  }

  /** The gate in front of every gated route (Caddy forward_auth to GET /v1/gate). */
  private createGate(stack: StackInfo, log: Logger): Gate {
    const routes = new Map<string, GateRoute>();
    for (const app of stack.apps) {
      for (const r of app.routes) {
        if (r.auth === "public") continue;
        const prev = routes.get(r.name);
        if (prev && prev.app !== app.id) throw new Error(`sealed-stack: route ${r.name} belongs to both ${prev.app} and ${app.id}`);
        routes.set(r.name, { app: app.id });
      }
    }
    const verify =
      this.deps.gateVerify ??
      ((password: Uint8Array, hash: string) => {
        this.bcrypt ??= new BcryptWorker();
        return this.bcrypt.verify(password, hash);
      });
    return new Gate({
      routes,
      username: (stack.gate ?? GATE_DEFAULTS).username,
      bootstrapDone: (app) => this.bootstrap?.done(app) ?? Promise.resolve(false),
      verify,
      key: this.deps.gateKey,
      now: () => this.clock.now() * 1000,
      onProblem: (problem) => log.error("the password gate cannot authenticate anyone", { problem }),
    });
  }

  /**
   * reserved_for_fees (D-048): what the next settlement is expected to take from the spend limit. Unpaid
   * legs, the open period so far, app-hours of heartbeat apps until the next settlement, and a network
   * fee allowance per app transaction.
   */
  feeReserve(): bigint {
    const ctx = this.ctx;
    const ledger = this.ledger;
    if (!ctx || !ledger) return 0n;
    const intervalSec = BigInt(ctx.config.settlement.intervalMinutes * 60);
    const apps = new Set<string>();
    let total = 0n;
    for (const e of ledger.unpaid()) {
      total += e.fee;
      apps.add(e.app);
    }
    for (const a of ctx.apps) {
      let fee = ledger.openFee(a.id);
      if (a.metering.source === "heartbeat") {
        const rule = priceRuleFor(ctx.schedule, a.id, "app_hour");
        fee += (rule.price * intervalSec + rule.per - 1n) / rule.per;
      }
      if (fee > 0n) apps.add(a.id);
      total += fee;
    }
    return total + NETWORK_FEE_ALLOWANCE * BigInt(apps.size);
  }

  /** Follows the access key's spending-limit period, when the chain reports one. */
  private async alignBudget(log: Logger): Promise<void> {
    const payer = this.payer;
    if (!payer?.limitPeriodEnd || !this.budget) return;
    try {
      const end = await withTimeout(payer.limitPeriodEnd(), 15_000);
      if (end !== undefined) this.budget.alignWindow(end, this.clock.now());
    } catch (err) {
      log.warn("could not read the access key's limit period; the spend budget keeps its window", errorFields(err));
    }
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

  async settle(now = this.clock.now()): Promise<SettlementResult> {
    const result = await (this.settler as Settler).tick(now);
    await this.alignBudget(this.log);
    return result;
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
        ...(this.budget?.snapshot(now) ?? {}),
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

  private requirePayer(peer: string): void {
    const payerIp = this.ctx?.payerIp;
    if (!payerIp || peer !== payerIp) throw new UsageRejected("spend calls are accepted from sealed-mpp-payer only", 403);
  }

  /** POST /v1/spend: only from sealed-mpp-payer's fixed IP, only the known numeric counters. */
  private recordSpend(body: unknown, peer: string): void {
    this.requirePayer(peer);
    const report = parseSpendReport(body);
    if (!report) throw new UsageRejected("invalid spend report", 400);
    this.spend = report.counters;
  }

  /** POST /v1/spend/reserve {amount}: the payer's share of the daily budget, after fees (D-048). */
  private reserveSpend(body: unknown, peer: string) {
    this.requirePayer(peer);
    const r = reserveRequestSchema.safeParse(body);
    if (!r.success) throw new UsageRejected(`invalid reservation: ${r.error.issues[0]?.message ?? "bad body"}`, 400);
    const feeToken = (this.ctx as DeploymentContext).config.feeToken.toLowerCase();
    if (r.data.currency && r.data.currency.toLowerCase() !== feeToken) throw new UsageRejected("the reservation's currency is not the deployment's fee token", 422);
    return (this.budget as SpendBudget).reserve(r.data.amount, this.clock.now());
  }

  /** POST /v1/spend/release {reservationId, used}. */
  private releaseSpend(body: unknown, peer: string) {
    this.requirePayer(peer);
    const r = releaseRequestSchema.safeParse(body);
    if (!r.success) throw new UsageRejected(`invalid release: ${r.error.issues[0]?.message ?? "bad body"}`, 400);
    return (this.budget as SpendBudget).release(r.data.reservationId, r.data.used, this.clock.now());
  }

  /** GET /v1/gate: only Caddy asks (fixed IP); everyone else gets 403 so the gate is no password oracle. */
  private async checkGate(req: GateRequest, peer: string): Promise<GateDecision> {
    const ctx = this.ctx;
    if (!ctx || peer !== ctx.caddyIp) return { status: 403, reason: "the gate answers Caddy only" };
    return (this.gate as Gate).check(req);
  }

  private bootstrapDone(body: unknown, peer: string): void {
    const app = (body as { app?: unknown } | null)?.app;
    if (typeof app !== "string") throw new BootstrapError(400, "body must be {\"app\": \"<appId>\"}");
    (this.bootstrap as BootstrapTracker).report(app, peer);
  }

  private handlers(): ApiHandlers {
    return {
      isReady: () => this.ready,
      readyInfo: () =>
        this.ready ? { deploymentId: this.ctx?.deploymentId, enclaveSigner: this.enclaveSigner, stackHash: this.ctx?.stackHash } : {},
      recordUsage: (ev, peer) => this.recordUsage(ev, peer),
      recordSpend: (body, peer) => this.recordSpend(body, peer),
      reserveSpend: (body, peer) => this.reserveSpend(body, peer),
      releaseSpend: (body, peer) => this.releaseSpend(body, peer),
      gate: (req, peer) => this.checkGate(req, peer),
      bootstrapDone: (body, peer) => this.bootstrapDone(body, peer),
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
    await this.bcrypt?.close();
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
