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
  recoverUsageReportSigner,
  settlementDefaults,
  signUsageReportsRead,
  type StoredUsageReport,
  TEMPO_MAINNET_ID,
  type UsageEvent,
  usageDomain,
  usageReportDigest,
  usageReportFromJson,
  usageReportsPageSchema,
} from "@sealed/core";
import { adminSocketReachable, type CaddySwitch, DirectCaddySwitch } from "./caddy.js";
import { type Clock, systemClock } from "./clock.js";
import { buildContext, checkMountedCopy, type DeploymentContext, readPublicConfig, requireHttpsEndpoints } from "./context.js";
import { DirDisk, type DataDisk, LuksDisk } from "./disk.js";
import { DstackClient, type QuoteProvider } from "./dstack.js";
import { attestAndSubmit, type EvidenceResult, HttpPlatformClient, type PlatformClient, buildEvidence } from "./evidence.js";
import { type EgressStatsSource, httpEgressStats, sendHealthReport } from "./healthReport.js";
import { HttpError, parseEndpoint } from "./http.js";
import { BcryptWorker } from "./gate/bcrypt.js";
import { BootstrapError, BootstrapTracker } from "./gate/bootstrap.js";
import { Gate, type GateDecision, type GateRequest, type GateRoute } from "./gate/gate.js";
import { HttpKeyBroker, type KeyBroker, type ReleasedKeys, releaseKeys } from "./keyRelease.js";
import { createLogger, errorFields, type Logger } from "./log.js";
import { AppHealthPoller, type Probe } from "./metering/appHealth.js";
import { Ledger, LedgerUnverifiedError, TooManyReportsError, type VerifiedReport } from "./metering/ledger.js";
import { UsageJournal } from "./metering/usageJournal.js";
import { UsageLimiter, UsageLimitError } from "./metering/limits.js";
import { emptyBudgetState, SpendBudget } from "./payments/budget.js";
import { type FeePayer, feeUnitsReserved, LOCAL_MIN_GAS, TempoFeePayer } from "./payments/feePayer.js";
import { MAX_PREVIOUS_DEPLOYMENTS, ledgerApps, outstanding, switchDeployment } from "./payments/previous.js";
import { type SettlementResult, Settler } from "./payments/settler.js";
import { liveAttestation } from "./attest.js";
import { dropPrivileges, parseRunAs } from "./privileges.js";
import { withRetry } from "./retry.js";
import { every } from "./scheduler.js";
import {
  agentSecretOwners,
  checkSecretMounts,
  declaredSecretsFromAppCompose,
  filesMountedIndividually,
  secretFilesFromStack,
  secretMountsFromAppCompose,
} from "./secretMounts.js";
import { type SecretsLayout, writePayerSecrets, writeReadyFlag, writeSecrets } from "./secrets.js";
import { type ApiHandlers, createApiServer, listen, UsageRejected } from "./server.js";
import type { AgentSettings } from "./settings.js";
import { parseSpendReport, releaseRequestSchema, reserveRequestSchema, type SpendCounters } from "./spend.js";
import { COMPOSE_CONFIGS, GATE_DEFAULTS, measuredConfigs, requireMeasured, type StackInfo } from "./stack.js";
import { type PreviousDeployment, StateStore } from "./state.js";
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
  /** How long stop() waits for the last settlement (payments-5); 0 skips it, like a VM that is cut off. */
  finalSettleMs?: number;
}

/** Caddy's HTTPS port on its apps-network IP, where the agent reads the served certificate. */
const CADDY_TLS_PORT = 443;
/**
 * Network fee allowance per settlement transaction on mainnet, in fee-token base units (0.01 USD). A batch costs
 * about 3.6M gas, a fraction of a cent at mainnet's base fee (tempo-viem notes); self-paid fees count
 * against an access-key limit, so the payer must leave room for them.
 */
export const NETWORK_FEE_ALLOWANCE = 10_000n;
/**
 * The highest gas price a local Tempo node charges, in attodollars per gas: TIP-1067 caps the base fee at 1.2e10
 * (a fresh anvil starts there and falls as blocks are mined), plus the 1e9 priority fee anvil suggests.
 */
export const LOCAL_MAX_GAS_PRICE = 13_000_000_000n;

/**
 * The network fee allowance per settlement transaction (D-048 reserved_for_fees). Off mainnet every settlement
 * transaction has at least LOCAL_MIN_GAS, and the settler only sends one when its own reserve for that gas
 * (feeUnitsReserved) fits the limit, so the allowance is that reserve at the highest local gas price: 0.13 USD
 * instead of mainnet's 0.01, which a local settlement's reserve far exceeds.
 */
export function networkFeeAllowance(chainId: number): bigint {
  if (chainId === TEMPO_MAINNET_ID) return NETWORK_FEE_ALLOWANCE;
  const local = feeUnitsReserved(LOCAL_MIN_GAS, LOCAL_MAX_GAS_PRICE);
  return local > NETWORK_FEE_ALLOWANCE ? local : NETWORK_FEE_ALLOWANCE;
}
/** Recovery transactions per budget window that may go past reserved_for_fees (payments-8: 0.05 USD on mainnet). */
export const RECOVERY_TXS_PER_WINDOW = 5n;
/** A reservation older than this since the last read of the access key's limit triggers a new read. */
export const ONCHAIN_LIMIT_MAX_AGE_SEC = 60;
/** A ledger rebuild reads at most this many pages of stored reports (500 each) before it gives up (D-062). */
export const MAX_REBUILD_PAGES = 2000;
/**
 * The last settlement at stop() gets this long (payments-5): Docker stops the agent 10 s after SIGTERM, so it cuts,
 * reports and pays what it can before then. What it cannot finish stays on the disk for the next boot.
 */
export const FINAL_SETTLE_MS = 8_000;

/** A deployment this disk ran before a same-salt upgrade, settled beside the current one (payments-5). */
interface PreviousSettlement {
  state: PreviousDeployment;
  ledger: Ledger;
  settler: Settler;
  apps: string[];
  rebuilding?: Promise<boolean>;
}

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
  private limitRead?: Promise<void>;
  private rebuilding?: Promise<boolean>;
  /** When the last ledger rebuild read the platform's stored reports (D-062). */
  private ledgerReadAt?: number;
  /** Earlier deployments on this disk still owing something (payments-5). */
  private previous: PreviousSettlement[] = [];
  /** The routes show the payment-needed page because an earlier deployment needs payment (payments-5). */
  private heldByPrevious = false;
  private stopping = false;
  private stopped = false;
  private saveTimer?: NodeJS.Timeout;
  gate?: Gate;
  bootstrap?: BootstrapTracker;
  budget?: SpendBudget;
  /** B2 (D-089): write-ahead journal for accepted usage, so a crash in the batched-save window loses none. */
  usageJournal?: UsageJournal;
  /** B2 (D-089): highest journal seq whose ledger.record() has fully completed, so is reflected in the next save. */
  private appliedWalSeq = 0;
  /** B2 (D-089): serializes journal-append + ledger.record + applied-marker, so a save never stamps a half-applied event. */
  private usageApply: Promise<void> = Promise.resolve();

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
    const { config, json } = await readPublicConfig(s.configPath, { devSim: s.devSim });
    requireHttpsEndpoints(config.endpoints, s.devSim);
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
    const secretFiles = secretFilesFromStack(ctx.stack, secretMounts);
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
    // D-058: a stack upgrade keeps the data disk and the enclave signer but is a new deployment, with its own ledger.
    // The previous deployment's usage can only be reported and paid under its own id, so its ledger and payment
    // status are kept beside the new ones until it is paid (payments-5).
    const switched = switchDeployment(store.state, ctx.deploymentId, this.clock.now());
    if (switched.previous !== undefined) {
      log.warn("the agent state on the data disk belongs to another deployment; starting a new usage ledger", {
        previous: switched.previous,
        keptUntilPaid: switched.kept,
        unpaidLegsKept: switched.keptUnpaidLegs,
        restored: switched.restored,
      });
    }
    for (const d of switched.dropped) log.error(`more than ${MAX_PREVIOUS_DEPLOYMENTS} earlier deployments owe fees; the oldest is dropped`, d);
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
      ...(secretFiles ? { files: secretFiles } : {}),
      individually: filesMountedIndividually(secretMounts),
      isOptional: (owner, name) => optional.get(owner)?.has(name) ?? false,
      onDisk: agentSecretOwners(secretMounts),
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
    // Brief item 15, review ws-int-agent 9: Caddy creates its admin socket with mode 0660 on a tmpfs owned by
    // 10001:10001 (setgid), so the agent reaches it after dropping to 10001:10001 and keeps no root process.
    // When the dropped user could not reach it (a socket the stack does not describe that way), the
    // payment-needed switch would silently never work, so the boot fails before the ready flag instead.
    const dropping = runAs !== undefined && process.getuid?.() === 0;
    if (dropping && !(await adminSocketReachable(runAs, s.caddyAdminSocket, ctx.stack.caddy))) {
      throw new Error(`caddy admin socket ${s.caddyAdminSocket} is not reachable as ${runAs.uid}:${runAs.gid} (sealed-stack/v1 caddy.adminSocketMode and adminSocketOwner); refusing to boot without the payment-needed switch`);
    }
    this.caddy = this.deps.caddy ?? new DirectCaddySwitch(parseEndpoint(s.caddyAdminSocket), ctx.caddyfiles);
    await writeReadyFlag(layout, this.clock.now());
    await dropPrivileges(runAs, [stateDir], log);
    await this.setupMetering(ctx, keys, defaults, log);
    // D-062: nothing is cut until the platform's stored reports are merged; keep trying in the background.
    void withRetry(
      async () => {
        if (!(await this.rebuildLedger(log))) throw new Error("the platform's stored usage reports could not be read");
      },
      { attempts: Number.POSITIVE_INFINITY, initialDelayMs: 2000, maxDelayMs: 300_000, signal: this.abort.signal, clock: this.clock, log, what: "usage ledger rebuild" },
    ).catch(() => undefined);
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
    const payer = this.feePayer(keys, ctx, ctx.deploymentId);
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

    const scheduleSave = () => {
      // After stop() the last save is its own (no timer may write into a disk being torn down).
      if (this.stopped) return;
      this.saveTimer ??= setTimeout(() => {
        this.saveTimer = undefined;
        void store.save().catch((err) => log.error("state save failed", errorFields(err)));
      }, 2000);
      this.saveTimer.unref?.();
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
    // B2 (D-089): replay usage that was answered 202 but not yet in a full state save, then let the normal D-062
    // hold/adopt flow reconcile it. Only entries past what the saved snapshot covers, and for this deployment, are
    // applied; a client retry of a replayed event is deduped by its recorded id. The journal is then kept consistent
    // with every save (walThrough stamping and compaction).
    const stateDir = s.stateDir ?? join(s.dataMount, ".sealed-agent");
    const { journal, entries } = await UsageJournal.load(join(stateDir, "usage-wal.jsonl"));
    this.usageJournal = journal;
    const through = store.state.walThrough ?? 0;
    for (const e of entries) {
      if (e.seq <= through || e.deploymentId !== ctx.deploymentId || !this.ledger.hasApp(e.app)) continue;
      if (e.id && this.ledger.seen(e.id)) continue;
      this.ledger.restoreOpen(e.app, e.unit, BigInt(e.quantity));
    }
    // Everything in the journal is now reflected in the in-memory ledger (entries up to `through` were in the saved
    // snapshot; the rest were just replayed), so the next full save covers all of it.
    this.appliedWalSeq = journal.seq;
    store.attachJournal({ seq: () => this.appliedWalSeq, truncateThrough: (n) => journal.truncateThrough(n) });
    // The state came from a disk the host may have rolled back (D-062).
    this.ledger.holdForRebuild(this.clock.now());
    store.state.budget ??= emptyBudgetState(this.clock.now());
    this.budget = new SpendBudget({
      limit: BigInt(ctx.config.settlement.spendLimitPerDay),
      // access-key mode: the customer's onchain authorization sets the limit and period, not the config (review M4).
      onchainLimit: ctx.config.settlement.mode === "access-key",
      state: store.state.budget,
      feeReserve: (windowEnd, now) => this.feeReserve(windowEnd, now),
      // payments-8: the payer's recovery of an orphaned escrow deposit may use a settlement transaction's network fee
      // allowance past reserved_for_fees, for a few transactions per window.
      recoveryAllowance: { perTx: networkFeeAllowance(ctx.config.chainId), perWindow: RECOVERY_TXS_PER_WINDOW * networkFeeAllowance(ctx.config.chainId) },
      onChange: scheduleSave,
    });
    // In the background: a blocked RPC must not delay boot (every settlement and stale reservation reads again).
    void this.refreshSpendLimit(log);
    this.poller = new AppHealthPoller(ctx.apps, {
      ledger: this.ledger,
      log,
      intervalSec: s.pollIntervalSec,
      probe: this.deps.probe,
      billable: () => !this.paymentNeeded(),
    });
    // While an earlier deployment needs payment, this deployment's own recovery does not open the routes (payments-5).
    const caddy = this.caddy;
    const gate = caddy && { apply: (v: Parameters<typeof caddy.apply>[0]) => caddy.apply(v === "normal" && this.previousNeedsPayment() ? "payment-needed" : v) };
    this.settler = new Settler({
      ledger: this.ledger,
      payer,
      platform: this.platform(),
      gate,
      status: store.state.payments,
      graceSec: ctx.config.settlement.gracePeriodMinutes * 60,
      save: () => store.save(),
      log: log.child({ part: "settlement" }),
      onPerPaymentCap: setCap,
      spend: this.budget,
      feeLimit: (now) => this.budget?.feeHeadroom(now),
      rebuild: () => this.rebuildLedger(log),
    });
    for (const state of store.state.previous ?? []) {
      const id = state.deploymentId as Hex;
      const plog = log.child({ part: "settlement", previousDeployment: id });
      const apps = ledgerApps(state.ledger, ctx.apps.map((a) => a.id));
      const ledger = new Ledger(state.ledger, {
        deploymentId: id,
        apps,
        schedule: ctx.schedule,
        domain: usageDomain(ctx.config.contracts.feeSplitter as Address, ctx.config.chainId),
        enclaveKey: keys.enclaveKey,
        perPaymentCap: () => this.perPaymentCap,
        onChange: scheduleSave,
      });
      // Its open period is cut only once the platform's stored reports for it are read (D-062).
      ledger.holdForRebuild(this.clock.now());
      let prev: PreviousSettlement | undefined;
      const settler = new Settler({
        ledger,
        payer: this.feePayer(keys, ctx, id),
        platform: this.platform(),
        status: state.payments,
        graceSec: ctx.config.settlement.gracePeriodMinutes * 60,
        save: () => store.save(),
        log: plog,
        onPerPaymentCap: setCap,
        spend: this.budget,
        feeLimit: (now) => this.budget?.feeHeadroom(now),
        rebuild: () => this.rebuildPrevious(prev as PreviousSettlement, plog),
      });
      prev = { state, ledger, settler, apps };
      this.previous.push(prev);
      plog.info("an earlier deployment on this disk still owes fees; it is settled under its own id until paid", { since: state.since, unpaidLegs: ledger.unpaid().length });
    }
  }

  /** The FeePayer for a deployment of this disk: this one, or an earlier one still being settled (payments-5). */
  private feePayer(keys: ReleasedKeys, ctx: DeploymentContext, deploymentId: Hex): FeePayer {
    return (
      this.deps.payer?.(keys, deploymentId === ctx.deploymentId ? ctx : { ...ctx, deploymentId }) ??
      new TempoFeePayer({
        mode: ctx.config.settlement.mode,
        enclaveKey: keys.enclaveKey,
        customer: ctx.customer,
        chainId: ctx.config.chainId,
        rpcUrl: ctx.config.endpoints.tempoRpc,
        feeToken: ctx.config.feeToken as Address,
        feeSplitter: ctx.config.contracts.feeSplitter as Address,
        deploymentRegistry: ctx.config.contracts.deploymentRegistry as Address,
        deploymentId,
        // Headroom on local Tempo nodes in tests; mainnet uses the node's estimate and the per-line floors.
        minGas: ctx.config.chainId === TEMPO_MAINNET_ID ? 0n : LOCAL_MIN_GAS,
      })
    );
  }

  /** The D-062 rebuild of an earlier deployment's ledger from the platform's stored reports for its id. */
  private rebuildPrevious(p: PreviousSettlement, log: Logger): Promise<boolean> {
    if (p.rebuilding) return p.rebuilding;
    const r = this.readStoredReports(log, { deploymentId: p.state.deploymentId as Hex, ledger: p.ledger }).finally(() => {
      if (p.rebuilding === r) p.rebuilding = undefined;
    });
    p.rebuilding = r;
    return r;
  }

  /**
   * D-062: reads the reports the platform stores for this deployment (signed read, one page at a time from the
   * ledger's cursor), keeps those whose signature recovers to this enclave signer, and merges them into the ledger.
   * One rebuild at a time. Resolves false when the listing could not be read (the ledger keeps its state).
   */
  rebuildLedger(log: Logger = this.log): Promise<boolean> {
    if (this.rebuilding) return this.rebuilding;
    const p = this.readStoredReports(log).finally(() => {
      if (this.rebuilding === p) this.rebuilding = undefined;
    });
    this.rebuilding = p;
    return p;
  }

  private async readStoredReports(log: Logger, of?: { deploymentId: Hex; ledger: Ledger }): Promise<boolean> {
    const ctx = this.ctx as DeploymentContext;
    const keys = this.keys as ReleasedKeys;
    const ledger = of?.ledger ?? (this.ledger as Ledger);
    const deploymentId = (of?.deploymentId ?? ctx.deploymentId).toLowerCase() as Hex;
    const platform = this.platform();
    const domain = usageDomain(ctx.config.contracts.feeSplitter as Address, ctx.config.chainId);
    const signer = keys.enclaveSigner.toLowerCase();
    const known = new Set(ledger.state.reports.map((r) => r.usageHash.toLowerCase()));
    const verified: VerifiedReport[] = [];
    let cursor = ledger.state.platformCursor;
    let rejected = 0;
    try {
      for (let page = 0; platform.usageReports; page++) {
        if (page >= MAX_REBUILD_PAGES) throw new Error(`more than ${MAX_REBUILD_PAGES} pages of stored usage reports`);
        const read = await signUsageReportsRead(deploymentId, this.clock.now(), keys.enclaveKey);
        let raw: unknown;
        try {
          raw = await platform.usageReports(deploymentId, read, cursor);
        } catch (err) {
          // Not registered (yet): the platform cannot hold a report for it.
          if (err instanceof HttpError && err.status === 404) break;
          throw err;
        }
        const parsed = usageReportsPageSchema.safeParse(raw);
        if (!parsed.success) throw new Error("the platform's stored usage reports page is malformed");
        if (parsed.data.deploymentId.toLowerCase() !== deploymentId) throw new Error("the platform answered for another deployment");
        for (const e of parsed.data.reports) {
          const v = await verifyStoredReport(e, deploymentId, domain, signer, known);
          if (v) verified.push(v);
          else rejected++;
        }
        const last = parsed.data.reports.at(-1);
        if (parsed.data.next) {
          if (parsed.data.next === cursor) throw new Error("the platform's listing does not advance");
          cursor = parsed.data.next;
          continue;
        }
        if (last) cursor = `${last.periodStart}:${last.usageHash.toLowerCase()}`;
        break;
      }
    } catch (err) {
      log.warn("could not read the platform's stored usage reports; no report is cut until they are read", errorFields(err));
      return false;
    }
    const wasVerified = ledger.verified;
    const r = ledger.adopt(verified, cursor);
    if (!of) this.ledgerReadAt = this.clock.now();
    if (!wasVerified || r.adopted > 0 || r.droppedUsage > 0 || rejected > 0) {
      const fields = { adopted: r.adopted, confirmed: r.confirmed, droppedUsage: r.droppedUsage, keptUsage: r.keptUsage, rejected, signedThrough: r.signedThrough };
      if (r.adopted > 0 || r.droppedUsage > 0) log.warn("the platform holds signed reports this state did not (a rolled back data disk?); merged them, usage they cover is not billed again", fields);
      else log.info("usage ledger rebuilt from the platform's stored reports", fields);
    }
    return true;
  }

  /** The gate in front of every gated route (Caddy forward_auth to GET /v1/gate). */
  private createGate(stack: StackInfo, log: Logger): Gate {
    const routes = new Map<string, GateRoute>();
    for (const app of stack.apps) {
      for (const r of app.routes) {
        if (r.auth === "public") continue;
        const prev = routes.get(r.name);
        if (prev && prev.app !== app.id) throw new Error(`sealed-stack: route ${r.name} belongs to both ${prev.app} and ${app.id}`);
        routes.set(r.name, { app: app.id, ...(prev?.bearer || r.auth === "bearer-passthrough" ? { bearer: true } : {}) });
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

  /** Whether the routes show the payment-needed page: this deployment, or an earlier one on this disk, needs payment. */
  paymentNeeded(): boolean {
    return this.store?.state.payments.paymentNeeded === true || this.previousNeedsPayment();
  }

  /** An earlier deployment on this disk is past its grace period with fees unpaid (payments-5). */
  private previousNeedsPayment(): boolean {
    return this.previous.some((p) => p.state.payments.paymentNeeded);
  }

  /**
   * reserved_for_fees (D-048): what settlement will still take from the spend limit before `windowEnd`, the end of
   * the limit's period (review M5: the whole window, not only the next settlement). Unpaid legs, the open period so
   * far, app-hours of heartbeat apps until the window ends (none while the payment-needed page is shown, when no
   * app-hour is billed, payments-7), the network fee allowance per app transaction of the next settlement, and the
   * later settlements' transactions at twice the last network fee seen.
   */
  feeReserve(windowEnd?: number, now = this.clock.now()): bigint {
    const ctx = this.ctx;
    const ledger = this.ledger;
    if (!ctx || !ledger) return 0n;
    const intervalSec = ctx.config.settlement.intervalMinutes * 60;
    const end = windowEnd ?? this.budget?.windowEnd(now) ?? now + intervalSec;
    const horizon = this.paymentNeeded() ? 0 : Math.max(0, end - now);
    const apps = new Set<string>();
    let total = 0n;
    // Legs the last settlement found it cannot pay (over the cap, another token, an app outside the deployment) are
    // left out, so they do not shrink the payer's share for good (review L2).
    const unpayable = this.store?.state.payments.unpayable ?? {};
    for (const e of ledger.unpaid()) {
      if (unpayable[`${e.usageHash}:${e.app}`]) continue;
      total += e.fee;
      apps.add(e.app);
    }
    // D-089 B1: reserve the fees each metered app will still accrue before the window ends, not only heartbeat
    // app-hours. Heartbeat accrual is known from the price; callback apps (gateway tokens, scraper pages) are
    // projected from their recent observed rate (ledger.projectedFee). Without this a payer that spends its whole
    // share takes the budget that settlement needs for callback usage accruing later in the window, and settlement
    // trips spend_limit on the period tail.
    let accruing = 0;
    for (const a of ctx.apps) {
      let fee = ledger.openFee(a.id);
      let projected = 0n;
      if (a.metering.source === "heartbeat") {
        const rule = priceRuleFor(ctx.schedule, a.id, "app_hour");
        if (rule.price > 0n) projected = (rule.price * BigInt(horizon) + rule.per - 1n) / rule.per;
      } else {
        projected = ledger.projectedFee(a.id, horizon, now);
      }
      if (projected > 0n) {
        fee += projected;
        // This app will have its own settlement transactions in the later settlements of the window.
        accruing++;
      }
      if (fee > 0n) apps.add(a.id);
      total += fee;
    }
    // Earlier deployments on this disk (payments-5): their unpaid legs and the period still open, one transaction each.
    let previousTxs = 0;
    for (const p of this.previous) {
      const skip = p.state.payments.unpayable ?? {};
      const owing = new Set<string>();
      for (const e of p.ledger.unpaid()) {
        if (skip[`${e.usageHash}:${e.app}`]) continue;
        total += e.fee;
        owing.add(e.app);
      }
      for (const app of p.apps) {
        const fee = p.ledger.openFee(app);
        if (fee > 0n) owing.add(app);
        total += fee;
      }
      previousTxs += owing.size;
    }
    const later = BigInt(Math.max(0, Math.ceil(horizon / intervalSec) - 1) * accruing);
    const seen = this.budget?.state.networkFeePerTx;
    // Later transactions are counted at what they will pay (not at the next one's reserve): twice the last network
    // fee, or the mainnet allowance until one is seen (a floor-sized guess for every settlement of a short local
    // interval would leave the payer nothing before the first payment).
    const perTx = seen !== undefined ? 2n * BigInt(seen) : NETWORK_FEE_ALLOWANCE;
    return total + networkFeeAllowance(ctx.config.chainId) * BigInt(apps.size + previousTxs) + later * perTx;
  }

  /**
   * Reads the access key's remaining limit and period end into the spend budget (access-key mode). One read at a
   * time; a failed read keeps the last reading, which only gets more conservative as spends are counted.
   */
  private refreshSpendLimit(log: Logger = this.log): Promise<void> {
    const payer = this.payer;
    const budget = this.budget;
    if (!payer?.spendLimit || !budget?.followsOnchain) return Promise.resolve();
    if (this.limitRead) return this.limitRead;
    const mark = budget.beginOnchainRead();
    const read = withTimeout(payer.spendLimit(), 15_000)
      .then((limit) => budget.setOnchain(limit, mark, this.clock.now()))
      .catch((err) => log.warn("could not read the access key's spending limit; the spend budget keeps the last reading", errorFields(err)))
      .finally(() => {
        if (this.limitRead === read) this.limitRead = undefined;
      });
    this.limitRead = read;
    return read;
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
      ...(platform.usageReports ? { usageReports: platform.usageReports.bind(platform) } : {}),
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
      every("settlement", settlementIntervalMs(ctx.config, ctx.defaults, s), () => this.settle(), opts),
      every("health report", s.healthIntervalSec * 1000, () => this.reportHealth(), opts),
      every("re-attestation", s.reattestHours * 3_600_000, () => this.attest(), opts),
    );
  }

  pollApps(now = this.clock.now()): Promise<void> {
    return (this.poller as AppHealthPoller).pollOnce(now);
  }

  async settle(now = this.clock.now()): Promise<SettlementResult> {
    // The oldest debt first: earlier deployments on this disk, then this one (payments-5).
    await this.settlePrevious(now);
    const result = await (this.settler as Settler).tick(now);
    await this.holdForPrevious();
    await this.refreshSpendLimit(this.log);
    return this.previousNeedsPayment() ? { ...result, paymentNeeded: true } : result;
  }

  /**
   * One settlement for each earlier deployment (payments-5): cut and report its open period, pay its legs. One that
   * is fully reported and paid is dropped, and so is one that is Closed onchain, since FeeSplitter takes no fee for a
   * closed deployment.
   */
  private async settlePrevious(now: number): Promise<void> {
    for (const p of [...this.previous]) {
      let r: SettlementResult;
      try {
        r = await p.settler.tick(now);
      } catch (err) {
        this.log.warn("settlement of an earlier deployment failed", { previousDeployment: p.state.deploymentId, ...errorFields(err) });
        continue;
      }
      const closed = r.outcome === "deployment_closed";
      const done = p.ledger.verified && !outstanding(p.ledger.state);
      if (!closed && !done) continue;
      if (closed && !done) {
        const unpaid = p.ledger.unpaid();
        this.log.error("an earlier deployment on this disk is closed onchain with fees unpaid; they can no longer be paid", {
          previousDeployment: p.state.deploymentId,
          unpaidLegs: unpaid.length,
          unpaid: unpaid.reduce((s, e) => s + e.fee, 0n).toString(),
        });
      } else {
        this.log.info("an earlier deployment on this disk is reported and paid", { previousDeployment: p.state.deploymentId });
      }
      this.previous = this.previous.filter((x) => x !== p);
      const store = this.store as StateStore;
      const kept = (store.state.previous ?? []).filter((x) => x !== p.state);
      if (kept.length > 0) store.state.previous = kept;
      else delete store.state.previous;
      await store.save().catch((err) => this.log.error("state save failed", errorFields(err)));
    }
  }

  /** Keeps the routes on the payment-needed page while an earlier deployment needs payment, and lifts that hold. */
  private async holdForPrevious(): Promise<void> {
    const own = this.store?.state.payments.paymentNeeded === true;
    try {
      if (this.previousNeedsPayment()) {
        // Re-applied every tick: Caddy restarts from the normal Caddyfile.
        if (!this.heldByPrevious) this.log.warn("an earlier deployment on this disk needs payment; the routes show the payment-needed page");
        this.heldByPrevious = true;
        await this.caddy?.apply("payment-needed");
      } else if (this.heldByPrevious) {
        this.heldByPrevious = false;
        if (!own) {
          await this.caddy?.apply("normal");
          this.log.info("the earlier deployment's fees are paid, app routes restored");
        }
      }
    } catch (err) {
      this.log.error("could not update Caddy routes", errorFields(err));
    }
  }

  async reportHealth(now = this.clock.now()) {
    const ctx = this.ctx as DeploymentContext;
    const store = this.store as StateStore;
    const st = store.state.payments;
    const totals = (this.ledger as Ledger).totals();
    const egress = await (this.deps.egressStats ?? httpEgressStats(this.deps.settings.egressStatsUrl))();
    const sent = await sendHealthReport(this.platform(), ctx.deploymentId, (this.keys as ReleasedKeys).enclaveKey, {
      at: now,
      apps: (this.poller as AppHealthPoller).status(),
      egress,
      payments: {
        mode: ctx.config.settlement.mode,
        // What the routes show: also true while an earlier deployment on this disk needs payment (payments-5).
        paymentNeeded: st.paymentNeeded || this.previousNeedsPayment(),
        failingSince: st.failingSince,
        // D-073: settlement waits for the platform (its stored reports, a report it has not accepted, registration).
        deferredSince: st.deferredSince ?? null,
        lastPaidAt: st.lastPaidAt ?? null,
        lastAttemptAt: st.lastAttemptAt ?? null,
        lastOutcome: st.lastOutcome ?? null,
        metered: totals.metered.toString(),
        unpaid: totals.unpaid.toString(),
        overCap: st.overCap ?? 0,
        unpayableLegs: Object.keys(st.unpayable ?? {}).length,
        ledger_verified: (this.ledger as Ledger).verified,
        ...(this.ledgerReadAt !== undefined ? { ledger_verifiedAt: this.ledgerReadAt } : {}),
        ledger_signedThrough: (this.ledger as Ledger).state.signedThrough ?? 0,
        ...this.previousFields(),
        ...(this.budget?.snapshot(now) ?? {}),
        ...this.spend,
      },
    });
    if (sent.reattest) {
      // The customer asked for a re-attestation (D-068): fresh evidence now, not at the next 24 h one.
      this.log.info("re-attestation requested through the platform");
      void this.attest();
    }
    return sent;
  }

  /** Health fields for earlier deployments on this disk that still owe fees (payments-5); none when there are none. */
  private previousFields(): Record<string, string | number | boolean> {
    if (this.previous.length === 0) return {};
    const unpaid = this.previous.reduce((s, p) => s + p.ledger.totals().unpaid, 0n);
    return { previous_deployments: this.previous.length, previous_unpaid: unpaid.toString(), previous_paymentNeeded: this.previousNeedsPayment() };
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
    const dedupId = key ? `${ev.app}:${key}` : undefined;
    if (dedupId && ledger.seen(dedupId)) return "duplicate";
    const now = this.clock.now();
    const quantity = BigInt(ev.quantity);
    try {
      this.limiter.admit(ev.app, ev.unit, quantity, now);
    } catch (err) {
      if (err instanceof UsageLimitError) throw new UsageRejected(err.message, err.status);
      throw err;
    }
    try {
      // B2 (D-089): write the accepted event to the journal (durably) before 202, so a crash before the batched
      // save does not lose it. The journal append, the ledger.record and the applied-marker update run serialized as
      // one step, so a concurrent save never stamps walThrough over a half-applied event. Journal only once the
      // ledger is accepting cuts (verified); checkAcceptable rejects an oversized event before it is journaled, so
      // once it passes ledger.record cannot fail for capacity reasons.
      const run = this.usageApply.then(async () => {
        const journal = this.usageJournal;
        if (journal && ledger.verified) {
          ledger.checkAcceptable(ev.app, ev.unit, quantity);
          const seq = await journal.append({ deploymentId: this.ctx?.deploymentId as string, app: ev.app, unit: ev.unit, quantity: quantity.toString(), at: now, ...(dedupId ? { id: dedupId } : {}) });
          await ledger.record(ev.app, ev.unit, quantity, now);
          // Set only after record fully returns: until then a save keeps walThrough below this seq, so a crash
          // replays the event instead of dropping it.
          this.appliedWalSeq = seq;
        } else {
          await ledger.record(ev.app, ev.unit, quantity, now);
        }
      });
      this.usageApply = run.then(
        () => undefined,
        () => undefined,
      );
      await run;
    } catch (err) {
      this.limiter.release(ev.app, ev.unit, quantity, now);
      if (err instanceof TooManyReportsError) throw new UsageRejected(err.message, 422);
      if (err instanceof LedgerUnverifiedError) throw new UsageRejected(err.message, 503);
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

  /**
   * POST /v1/spend/reserve {amount}: the payer's share of the shared budget, after fees (D-048). The reservation is
   * on disk before the payer hears of it, so a restart cannot forget money the payer is about to spend.
   */
  private async reserveSpend(body: unknown, peer: string) {
    this.requirePayer(peer);
    const r = reserveRequestSchema.safeParse(body);
    if (!r.success) throw new UsageRejected(`invalid reservation: ${r.error.issues[0]?.message ?? "bad body"}`, 400);
    const feeToken = (this.ctx as DeploymentContext).config.feeToken.toLowerCase();
    if (r.data.currency && r.data.currency.toLowerCase() !== feeToken) throw new UsageRejected("the reservation's currency is not the deployment's fee token", 422);
    const budget = this.budget as SpendBudget;
    if (budget.followsOnchain) {
      const now = this.clock.now();
      const age = budget.onchainAge(now);
      // D-089 B1: a decreased access-key limit must bite at once, not after up to ONCHAIN_LIMIT_MAX_AGE_SEC of
      // charging against the stale higher value. Read the chain synchronously before authorizing a reservation the
      // cached reading would grant (so the fresh, possibly lower limit is the one applied), and when nothing has been
      // read yet. A reservation the cache already refuses is left to the periodic async refresh: refusing on a stale
      // reading is safe, and a stale increase it misses only defers the next grant briefly.
      if (age === Number.POSITIVE_INFINITY || budget.wouldGrant(r.data.amount, now, r.data.purpose)) await this.refreshSpendLimit();
      else if (age >= ONCHAIN_LIMIT_MAX_AGE_SEC) void this.refreshSpendLimit();
    }
    const result = budget.reserve(r.data.amount, this.clock.now(), r.data.purpose);
    if (result.ok) {
      try {
        await (this.store as StateStore).save();
      } catch (err) {
        budget.cancel(result.reservationId);
        this.log.error("could not save a spend reservation; refused", errorFields(err));
        throw new UsageRejected("the reservation could not be recorded", 503);
      }
    }
    return result;
  }

  /** POST /v1/spend/release {reservationId, used}. */
  private async releaseSpend(body: unknown, peer: string) {
    this.requirePayer(peer);
    const r = releaseRequestSchema.safeParse(body);
    if (!r.success) throw new UsageRejected(`invalid release: ${r.error.issues[0]?.message ?? "bad body"}`, 400);
    const result = (this.budget as SpendBudget).release(r.data.reservationId, r.data.used, this.clock.now());
    // A lost release only makes the reservation expire and count as spent, so a failed save is logged, not refused.
    await (this.store as StateStore).save().catch((err) => this.log.error("state save failed", errorFields(err)));
    return result;
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
    const first = !this.stopping;
    this.stopping = true;
    this.abort.abort(new Error("agent stopping"));
    await Promise.allSettled(this.loops);
    // payments-5: one bounded last settlement, so the open period is cut, reported and paid before the VM goes away
    // (D-068: the last period settles before closeDeployment). Whatever does not finish stays on the disk.
    const finalMs = this.deps.finalSettleMs ?? FINAL_SETTLE_MS;
    if (first && finalMs > 0 && this.settler && this.ledger?.verified) {
      await withTimeout(this.settle(), finalMs).catch((err) => this.log.warn("the last settlement before stopping did not finish", errorFields(err)));
    }
    this.stopped = true;
    clearTimeout(this.saveTimer);
    this.saveTimer = undefined;
    await this.store?.save().catch(() => undefined);
    await this.bcrypt?.close();
    await new Promise<void>((ok) => {
      if (!this.server) return ok();
      this.server.close(() => ok());
      this.server.closeAllConnections();
    });
  }
}

/**
 * The settlement timer: the measured config's intervalMinutes. Only a dev simulator agent with
 * SEALED_TEST_OVERRIDES=1 may settle faster, when defaults.yaml test_overrides sets
 * settlement_interval_seconds (local devnets settle in seconds instead of minutes). Periods are cut at
 * each tick, so the timer is the only thing that changes.
 */
export function settlementIntervalMs(
  config: { settlement: { intervalMinutes: number } },
  defaults: Defaults,
  settings: Pick<AgentSettings, "devSim" | "testOverrides">,
): number {
  const sec = (defaults as { settlement_interval_seconds?: unknown }).settlement_interval_seconds;
  if (settings.devSim && settings.testOverrides && typeof sec === "number" && Number.isInteger(sec) && sec > 0) return sec * 1000;
  return config.settlement.intervalMinutes * 60_000;
}

/**
 * A stored report as the agent signed it, or undefined: the report must be for this deployment, have a period, and
 * its EIP-712 signature must recover to this enclave signer. Reports the local state already holds (by digest) skip
 * the signature check. The platform's own usageHash is not trusted; the digest is recomputed.
 */
async function verifyStoredReport(e: StoredUsageReport, deploymentId: Hex, domain: ReturnType<typeof usageDomain>, signer: string, known: ReadonlySet<string>): Promise<VerifiedReport | undefined> {
  let report: ReturnType<typeof usageReportFromJson>;
  try {
    report = usageReportFromJson(e.report as Parameters<typeof usageReportFromJson>[0]);
  } catch {
    return undefined;
  }
  if (report.deploymentId.toLowerCase() !== deploymentId.toLowerCase() || report.periodEnd <= report.periodStart) return undefined;
  const usageHash = usageReportDigest(report, domain).toLowerCase() as Hex;
  if (!known.has(usageHash)) {
    try {
      if ((await recoverUsageReportSigner(report, domain, e.signature as Hex)).toLowerCase() !== signer) return undefined;
    } catch {
      return undefined;
    }
  }
  return { report, signature: e.signature as Hex, usageHash, receivedAt: e.receivedAt };
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
