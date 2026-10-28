// Starting the off-chain components as processes: a throwaway PostgreSQL 17 cluster, the key broker (dev build,
// simulator mode), sealed-verifierd, the platform api (oracle and indexer), the dstack simulator and sealed-agent.
// Every endpoint is 127.0.0.1 on a port chosen at run start; nothing reaches a cloud API (the api's Google and
// Rekor endpoints point at a closed local port).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Address } from "@sealed/core";
import { ADDR, CHAIN_ID, type Contracts, KEYS, TOKENS } from "./chain.ts";
import { answers, http } from "./net.ts";
import { type Proc, type Supervisor, waitFor } from "./procs.ts";

/** A port nothing listens on: the api's cloud and Rekor endpoints point here, so a stray call fails at once. */
export const DEAD_URL = "http://127.0.0.1:9";

export interface Bins {
  sealed: string;
  keyBroker: string;
  verifierd: string;
  compose: string;
}

// --- PostgreSQL ------------------------------------------------------------------------------------------------

export interface Postgres {
  url: string;
  proc: Proc;
  psql(sql: string): Promise<string>;
}

export async function startPostgres(sup: Supervisor, o: { pgBin: string; dir: string; port: number }): Promise<Postgres> {
  const data = join(o.dir, "data");
  await sup.runOk("initdb", join(o.pgBin, "initdb"), ["-D", data, "-U", "postgres", "--auth=trust", "-E", "UTF8", "--no-instructions"], { env: { LC_ALL: "C" } });
  // TCP on loopback only; no unix socket (worktree paths can exceed the 104-byte sun_path limit).
  const proc = sup.spawn("postgres", join(o.pgBin, "postgres"), ["-D", data, "-p", String(o.port), "-c", "listen_addresses=127.0.0.1", "-c", "unix_socket_directories=", "-c", "fsync=off"], {
    env: { LC_ALL: "C" },
  });
  const psqlArgs = ["-h", "127.0.0.1", "-p", String(o.port), "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-At"];
  const psql = (db: string) => async (sql: string) => (await sup.runOk("psql", join(o.pgBin, "psql"), [...psqlArgs, "-d", db, "-c", sql])).trim();
  await waitFor("postgres", async () => (await sup.run("pg_isready", join(o.pgBin, "pg_isready"), ["-h", "127.0.0.1", "-p", String(o.port)])).code === 0, { proc, timeoutMs: 30_000 });
  await psql("postgres")("CREATE DATABASE sealed");
  return { url: `postgres://postgres@127.0.0.1:${o.port}/sealed`, proc, psql: psql("sealed") };
}

// --- Key broker ------------------------------------------------------------------------------------------------

export interface KeyBroker {
  url: string;
  proc: Proc;
  decisionLog: string;
  /** Decisions written so far (JSON lines). */
  decisions(): Array<Record<string, unknown>>;
}

export async function startKeyBroker(
  sup: Supervisor,
  o: { bin: string; port: number; dir: string; rpcUrl: string; contracts: Contracts; customer: Address; assetBase: string; secrets: Record<string, string> },
): Promise<KeyBroker> {
  mkdirSync(o.dir, { recursive: true });
  const secretsFile = join(o.dir, "secrets.json");
  writeFileSync(secretsFile, JSON.stringify(o.secrets), { mode: 0o600 });
  const decisionLog = join(o.dir, "decisions.jsonl");
  const proc = sup.spawn(
    "key-broker",
    o.bin,
    [
      "--listen",
      `127.0.0.1:${o.port}`,
      "--dev-allow-simulated",
      "--dev-secrets-file",
      secretsFile,
      "--dev-kms-key-file",
      join(o.dir, "hmac.key"),
      "--dev-decision-log",
      decisionLog,
    ],
    {
      cleanEnv: true,
      env: {
        PATH: process.env.PATH,
        HOME: o.dir,
        SEALED_DEV_SIM: "1",
        SEALED_CUSTOMER_ADDRESS: o.customer,
        TEMPO_RPC_URL: o.rpcUrl,
        TEMPO_CHAIN_ID: String(CHAIN_ID),
        SEALED_PLATFORM_REGISTRY: o.contracts.platformRegistry,
        SEALED_APP_REGISTRY: o.contracts.appRegistry,
        SEALED_DEPLOYMENT_REGISTRY: o.contracts.deploymentRegistry,
        SEALED_RELEASE_ASSET_BASE: o.assetBase,
        GCE_METADATA_HOST: "127.0.0.1:9",
      },
    },
  );
  const url = `http://127.0.0.1:${o.port}`;
  await waitFor("key broker /healthz", async () => (await http(`${url}/healthz`)).status === 200, { proc, timeoutMs: 20_000 });
  return {
    url,
    proc,
    decisionLog,
    decisions() {
      try {
        return readFileSync(decisionLog, "utf8")
          .split("\n")
          .filter((l) => l.trim() !== "")
          .map((l) => JSON.parse(l) as Record<string, unknown>);
      } catch {
        return [];
      }
    },
  };
}

// --- sealed-verifierd ------------------------------------------------------------------------------------------

export async function startVerifierd(sup: Supervisor, o: { bin: string; port: number; dir: string; rpcUrl: string; contracts: Contracts; assetBase: string }): Promise<{ url: string; proc: Proc }> {
  mkdirSync(o.dir, { recursive: true });
  const proc = sup.spawn(
    "sealed-verifierd",
    o.bin,
    [
      "--listen",
      `127.0.0.1:${o.port}`,
      "--tempo-rpc",
      o.rpcUrl,
      "--chain-id",
      String(CHAIN_ID),
      "--deployments",
      o.contracts.file,
      "--release-asset-base",
      o.assetBase,
      "--bundle-cache-dir",
      join(o.dir, "bundles"),
      "--dev-allow-simulated",
    ],
    { cleanEnv: true, env: { PATH: process.env.PATH, HOME: o.dir, SEALED_DEV_SIM: "1" } },
  );
  const url = `http://127.0.0.1:${o.port}`;
  await waitFor("sealed-verifierd", () => answers(`${url}/healthz`), { proc, timeoutMs: 20_000 });
  return { url, proc };
}

// --- Platform api ----------------------------------------------------------------------------------------------

export async function startApi(
  sup: Supervisor,
  o: { apiDir: string; port: number; dir: string; rpcUrl: string; contracts: Contracts; databaseUrl: string; verifierdUrl: string; assetBase: string; imageId: string; defaultsPath: string },
): Promise<{ url: string; proc: Proc }> {
  mkdirSync(o.dir, { recursive: true });
  const url = `http://127.0.0.1:${o.port}`;
  const proc = sup.spawn("api", process.execPath, [join(o.apiDir, "dist", "main.js"), "serve"], {
    cwd: o.apiDir,
    cleanEnv: true,
    env: {
      PATH: process.env.PATH,
      HOME: o.dir,
      NODE_ENV: "development",
      DATABASE_URL: o.databaseUrl,
      TEMPO_RPC_URL: o.rpcUrl,
      TEMPO_PUBLIC_RPC_URL: o.rpcUrl,
      TEMPO_CHAIN_ID: String(CHAIN_ID),
      TEMPO_HARDFORK: "t4",
      SEALED_DEPLOYMENTS_FILE: o.contracts.file,
      INDEXER_START_BLOCK: String(o.contracts.deployBlock),
      INDEXER_POLL_MS: "500",
      FEE_TOKEN_ADDRESS: TOKENS.pathUsd,
      SEALED_DEFAULTS_PATH: o.defaultsPath,
      SEALED_VERIFIERD_URL: o.verifierdUrl,
      // anvil's public dev keys (ORACLE is the signer Deploy.s.sol allowed; OPS sends).
      ORACLE_KEY_REF: "env:DEVNET_ORACLE_KEY",
      OPS_KEY_REF: "env:DEVNET_OPS_KEY",
      DEVNET_ORACLE_KEY: KEYS.oracle,
      DEVNET_OPS_KEY: KEYS.ops,
      SEALED_ORACLE_SIGNER: ADDR.oracle,
      SEALED_OPS_ADDRESS: ADDR.ops,
      SEALED_PUBLIC_API_URL: url,
      SEALED_API_LISTEN: `127.0.0.1:${o.port}`,
      SEALED_RELEASE_ASSET_BASE: o.assetBase,
      SEALED_IMAGE_ID: o.imageId,
      SEALED_DEV_SIM: "1",
      SEALED_REKOR_URL: DEAD_URL,
      SEALED_GCP_METADATA_URL: DEAD_URL,
      SEALED_GCP_IAMCREDENTIALS_URL: DEAD_URL,
      SEALED_GCP_COMPUTE_URL: DEAD_URL,
      SEALED_GCP_SECRETMANAGER_URL: DEAD_URL,
      SEALED_GCP_RESOURCEMANAGER_URL: DEAD_URL,
    },
  });
  await waitFor("platform api", () => answers(`${url}/v1/catalog/apps`), { proc, timeoutMs: 60_000 });
  return { url, proc };
}

// --- dstack simulator ------------------------------------------------------------------------------------------

export async function startSimulator(sup: Supervisor, o: { agentDir: string; name: string; appComposeFile: string; port: number; debug?: boolean }): Promise<{ endpoint: string; proc: Proc }> {
  const proc = sup.spawn(o.name, process.execPath, [join(o.agentDir, "dist", "sim.js"), "--app-compose", o.appComposeFile, "--host", "127.0.0.1", "--port", String(o.port), ...(o.debug ? ["--debug"] : [])]);
  const endpoint = `http://127.0.0.1:${o.port}`;
  await waitFor("dstack simulator", () => answers(`${endpoint}/Info`), { proc, timeoutMs: 15_000 });
  return { endpoint, proc };
}

// --- sealed-agent ----------------------------------------------------------------------------------------------

export interface AgentPaths {
  root: string;
  config: string;
  stack: string;
  caddyfile: string;
  caddyfilePaymentNeeded: string;
  secrets: string;
  ready: string;
  data: string;
  device: string;
  luksState: string;
  mountinfo: string;
  out: string;
}

export function agentPaths(root: string): AgentPaths {
  return {
    root,
    config: join(root, "etc", "config.json"),
    stack: join(root, "etc", "stack.json"),
    caddyfile: join(root, "etc", "Caddyfile"),
    caddyfilePaymentNeeded: join(root, "etc", "Caddyfile.payment-needed"),
    secrets: join(root, "run", "sealed", "secrets"),
    ready: join(root, "run", "sealed", "ready"),
    data: join(root, "mnt", "sealed-data"),
    device: join(root, "dev", "sealed-data"),
    luksState: join(root, "dev", "sealed-data.luks.json"),
    mountinfo: join(root, "proc", "mountinfo"),
    out: join(root, "out"),
  };
}

export function startAgent(sup: Supervisor, o: { name: string; hostScript: string; paths: AgentPaths; dstack: string; port: number; defaultsPath: string }): Proc {
  const p = o.paths;
  for (const d of [join(p.root, "etc"), p.secrets, p.ready, p.data, join(p.root, "dev"), p.out]) mkdirSync(d, { recursive: true });
  writeFileSync(p.device, ""); // the data disk the host attaches (its content is the fake runner's state file)
  return sup.spawn(o.name, process.execPath, [o.hostScript], {
    env: {
      SEALED_DEV_SIM: "1",
      SEALED_TEST_OVERRIDES: "1",
      SEALED_DEFAULTS_PATH: o.defaultsPath,
      SEALED_CONFIG_FILE: p.config,
      SEALED_STACK_FILE: p.stack,
      SEALED_CADDYFILE: p.caddyfile,
      SEALED_CADDYFILE_PAYMENT_NEEDED: p.caddyfilePaymentNeeded,
      SEALED_SECRETS_DIR: p.secrets,
      SEALED_READY_DIR: p.ready,
      SEALED_DATA_DIR: p.data,
      SEALED_DATA_DEVICE: p.device,
      SEALED_DISK_MODE: "luks",
      SEALED_LISTEN_HOST: "127.0.0.1",
      PORT: String(o.port),
      DSTACK_SIMULATOR_ENDPOINT: o.dstack,
      SEALED_HEALTH_INTERVAL_S: "5",
      SEALED_POLL_INTERVAL_S: "5",
      DEVNET_LUKS_STATE: p.luksState,
      DEVNET_MOUNTINFO: p.mountinfo,
      DEVNET_OUT: p.out,
    },
  });
}
