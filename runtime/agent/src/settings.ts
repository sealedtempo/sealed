// Agent settings from the environment. Everything security relevant (endpoints, contracts,
// settlement) comes from the measured public config instead; these are paths and timings.
export interface AgentSettings {
  configPath: string;
  appsMetaPath: string;
  appComposePath?: string;
  defaultsPath?: string;
  testOverrides: boolean;
  listenHost: string;
  listenPort: number;
  secretsDir: string;
  readyFile: string;
  dataMount: string;
  dataDevice: string;
  luksName: string;
  diskMode: "luks" | "dir";
  stateDir?: string;
  caddyAdminSocket: string;
  caddyDataDir: string;
  egressStatsUrl: string;
  reattestHours: number;
  healthIntervalSec: number;
  pollIntervalSec: number;
  devSim: boolean;
}

const num = (v: string | undefined, d: number) => {
  if (v === undefined || v === "") return d;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`invalid number ${v}`);
  return n;
};

export function settingsFromEnv(env: NodeJS.ProcessEnv = process.env): AgentSettings {
  const [host, port] = (env.SEALED_LISTEN ?? "0.0.0.0:7070").split(":");
  const diskMode = env.SEALED_DISK_MODE ?? "luks";
  if (diskMode !== "luks" && diskMode !== "dir") throw new Error("SEALED_DISK_MODE must be luks or dir");
  return {
    configPath: env.SEALED_CONFIG_PATH ?? "/etc/sealed/config.json",
    appsMetaPath: env.SEALED_AGENT_APPS_PATH ?? "/etc/sealed/agent-apps.json",
    appComposePath: env.SEALED_APP_COMPOSE_PATH || undefined,
    defaultsPath: env.SEALED_DEFAULTS_PATH || undefined,
    testOverrides: env.SEALED_TEST_OVERRIDES === "1",
    listenHost: host || "0.0.0.0",
    listenPort: num(port, 7070),
    secretsDir: env.SEALED_SECRETS_DIR ?? "/run/sealed/secrets",
    readyFile: env.SEALED_READY_FILE ?? "/run/sealed/ready",
    dataMount: env.SEALED_DATA_MOUNT ?? "/mnt/sealed-data",
    dataDevice: env.SEALED_DATA_DEVICE ?? "/dev/disk/by-id/google-sealed-data",
    luksName: env.SEALED_LUKS_NAME ?? "sealed-data",
    diskMode,
    stateDir: env.SEALED_STATE_DIR || undefined,
    caddyAdminSocket: env.SEALED_CADDY_ADMIN_SOCKET ?? "/run/caddy-admin/admin.sock",
    caddyDataDir: env.SEALED_CADDY_DATA_DIR ?? "/caddy-data",
    egressStatsUrl: env.SEALED_EGRESS_STATS_URL ?? "http://172.30.0.2:9100/v1/stats",
    reattestHours: num(env.SEALED_REATTEST_HOURS, 24),
    healthIntervalSec: num(env.SEALED_HEALTH_INTERVAL_S, 60),
    pollIntervalSec: num(env.SEALED_POLL_INTERVAL_S, 30),
    devSim: env.SEALED_DEV_SIM === "1",
  };
}
