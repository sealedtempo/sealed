// Agent settings from the environment the composer gives the sealed-agent service (runtime/composer,
// "Contract for the sidecars"). Everything security relevant (endpoints, contracts, settlement,
// stack facts) comes from the measured config and app-compose instead; these are paths and timings.
export interface AgentSettings {
  /** SEALED_CONFIG_FILE: the public config, checked against the measured copy in app-compose. */
  configPath: string;
  /** SEALED_STACK_FILE, SEALED_CADDYFILE, SEALED_CADDYFILE_PAYMENT_NEEDED: optional cross-checks of the measured copies. */
  stackPath?: string;
  caddyfilePath?: string;
  caddyfilePaymentNeededPath?: string;
  appComposePath?: string;
  defaultsPath?: string;
  testOverrides: boolean;
  listenHost: string;
  listenPort: number;
  secretsDir: string;
  /** SEALED_READY_DIR: the shared tmpfs volume; the gate opens when `<readyDir>/ok` exists. */
  readyDir: string;
  dataMount: string;
  dataDevice: string;
  luksName: string;
  diskMode: "luks" | "dir";
  stateDir?: string;
  caddyAdminSocket: string;
  egressStatsUrl: string;
  /** DSTACK_SOCKET, or DSTACK_SIMULATOR_ENDPOINT when SEALED_DEV_SIM=1. */
  dstackEndpoint: string;
  reattestHours: number;
  healthIntervalSec: number;
  pollIntervalSec: number;
  devSim: boolean;
  /** Secrets, the payer key and the ready flag must sit on tmpfs mounts (always, except in dev sim mode). */
  requireTmpfs: boolean;
  /** uid[:gid] to switch to once the root-only boot steps are done. */
  runAs?: string;
}

const num = (v: string | undefined, d: number, min = 1) => {
  if (v === undefined || v === "") return d;
  const n = Number(v);
  if (!Number.isFinite(n) || n < min) throw new Error(`invalid number ${v}`);
  return n;
};

export function settingsFromEnv(env: NodeJS.ProcessEnv = process.env): AgentSettings {
  const devSim = env.SEALED_DEV_SIM === "1";
  const diskMode = env.SEALED_DISK_MODE ?? "luks";
  if (diskMode !== "luks" && diskMode !== "dir") throw new Error("SEALED_DISK_MODE must be luks or dir");
  if (diskMode === "dir" && !devSim) throw new Error("SEALED_DISK_MODE=dir is only allowed with SEALED_DEV_SIM=1");
  if (env.DSTACK_SIMULATOR_ENDPOINT && !devSim) throw new Error("DSTACK_SIMULATOR_ENDPOINT is only honored with SEALED_DEV_SIM=1");
  const port = num(env.PORT, 7070, 0);
  if (!Number.isInteger(port) || port > 65535) throw new Error(`invalid PORT ${env.PORT}`);
  return {
    configPath: env.SEALED_CONFIG_FILE ?? "/etc/sealed/config.json",
    stackPath: env.SEALED_STACK_FILE ?? "/etc/sealed/stack.json",
    caddyfilePath: env.SEALED_CADDYFILE ?? "/etc/sealed/caddy/Caddyfile",
    caddyfilePaymentNeededPath: env.SEALED_CADDYFILE_PAYMENT_NEEDED ?? "/etc/sealed/caddy/Caddyfile.payment-needed",
    appComposePath: env.SEALED_APP_COMPOSE_PATH || undefined,
    defaultsPath: env.SEALED_DEFAULTS_PATH || undefined,
    testOverrides: env.SEALED_TEST_OVERRIDES === "1",
    listenHost: env.SEALED_LISTEN_HOST || "0.0.0.0",
    listenPort: port,
    secretsDir: env.SEALED_SECRETS_DIR ?? "/run/sealed/secrets",
    readyDir: env.SEALED_READY_DIR ?? "/run/sealed/ready",
    dataMount: env.SEALED_DATA_DIR ?? "/mnt/sealed-data",
    dataDevice: env.SEALED_DATA_DEVICE ?? "/dev/sealed-data",
    luksName: env.SEALED_LUKS_NAME ?? "sealed-data",
    diskMode,
    stateDir: env.SEALED_STATE_DIR || undefined,
    caddyAdminSocket: env.SEALED_CADDY_ADMIN_SOCKET ?? "/run/sealed/caddy-admin/admin.sock",
    egressStatsUrl: env.SEALED_EGRESS_STATS_URL ?? "http://172.30.0.2:9100/v1/stats",
    dstackEndpoint: (devSim && env.DSTACK_SIMULATOR_ENDPOINT) || env.DSTACK_SOCKET || "/var/run/dstack.sock",
    reattestHours: num(env.SEALED_REATTEST_HOURS, 24),
    healthIntervalSec: num(env.SEALED_HEALTH_INTERVAL_S, 60),
    pollIntervalSec: num(env.SEALED_POLL_INTERVAL_S, 30),
    devSim,
    requireTmpfs: !devSim,
    runAs: env.SEALED_RUN_AS || undefined,
  };
}
