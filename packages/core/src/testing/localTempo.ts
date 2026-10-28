// Test harness: a local Tempo node (anvil --network tempo, chain 31337) with the Sealed contracts
// deployed from the Foundry artifacts. Node only; uses anvil's public dev keys; never touches a
// public network.
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type Abi,
  type Chain,
  type Client,
  createClient,
  encodeAbiParameters,
  type Hash,
  type HttpTransport,
  http,
  type PublicActions,
  publicActions,
  type WalletActions,
  walletActions,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { tempoChain } from "../chain.js";
import { type DeploymentRecord, recordDigest, registryDomain } from "../eip712.js";
import type { Address, Hex } from "../hex.js";
import { measurementsHash as computeMeasurementsHash } from "../ids.js";

/** anvil's default dev keys (mnemonic "test test ... junk"). Public; local use only. */
export const DEV_KEYS = {
  owner: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  ops: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  oracle: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  customer: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  maintainer: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  treasury: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  funder: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
} as const satisfies Record<string, Hex>;

/** Genesis TIP-20 tokens of a local Tempo node. Every dev account holds u64::MAX of each. */
export const LOCAL_TOKENS = {
  pathUsd: "0x20c0000000000000000000000000000000000000",
  alphaUsd: "0x20c0000000000000000000000000000000000001",
} as const satisfies Record<string, Address>;

export const LOCAL_CHAIN_ID = 31337;

async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolvePort(port));
    });
  });
}

export type LocalClient = Client<HttpTransport, Chain, undefined, undefined, PublicActions<HttpTransport, Chain> & WalletActions<Chain, undefined>>;

export function localClient(rpcUrl: string): LocalClient {
  const chain = tempoChain({ chainId: LOCAL_CHAIN_ID, rpcUrl, hardfork: "t4" });
  return createClient({ chain, transport: http(rpcUrl), pollingInterval: 100 }).extend(publicActions).extend(walletActions);
}

export interface LocalTempo {
  rpcUrl: string;
  chainId: number;
  client: LocalClient;
  stop(): Promise<void>;
  /** Moves the node clock forward and mines a block. */
  increaseTime(seconds: number): Promise<void>;
}

export interface StartOptions {
  hardfork?: string;
  port?: number;
}

/** Starts `anvil --network tempo` on a free port and waits until it answers. */
export async function startLocalTempo(opts: StartOptions = {}): Promise<LocalTempo> {
  const port = opts.port ?? (await freePort());
  const args = ["--network", "tempo", "--hardfork", opts.hardfork ?? "T4", "--port", String(port), "--gas-limit", "500000000", "--silent"];
  const child: ChildProcess = spawn("anvil", args, { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr?.on("data", (d) => (stderr += String(d)));
  const rpcUrl = `http://127.0.0.1:${port}`;
  const client = localClient(rpcUrl);
  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      if ((await client.getChainId()) === LOCAL_CHAIN_ID) break;
    } catch {
      // not up yet
    }
    if (child.exitCode !== null) throw new Error(`anvil exited: ${stderr}`);
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error(`anvil did not start: ${stderr}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  const onExit = () => child.kill("SIGKILL");
  process.once("exit", onExit);
  return {
    rpcUrl,
    chainId: LOCAL_CHAIN_ID,
    client,
    async stop() {
      process.removeListener("exit", onExit);
      if (child.exitCode !== null) return;
      await new Promise<void>((r) => {
        child.once("exit", () => r());
        child.kill("SIGTERM");
      });
    },
    async increaseTime(seconds: number) {
      await client.request({ method: "evm_increaseTime" as never, params: [seconds] as never });
      await client.request({ method: "evm_mine" as never, params: [] as never });
    },
  };
}

// --- Contracts ----------------------------------------------------------------------------------

export const SEALED_CONTRACT_NAMES = [
  "PlatformRegistry",
  "AppRegistry",
  "OracleSignatureVerifier",
  "DeploymentRegistry",
  "FeeSplitter",
] as const;
type ContractName = (typeof SEALED_CONTRACT_NAMES)[number];

interface Artifact {
  abi: Abi;
  bytecode: Hex;
}

/**
 * Finds the Foundry project: SEALED_CONTRACTS_DIR, then <repo>/contracts (merged layout), then the
 * sibling contracts worktree used during the parallel build.
 */
export function findContractsDir(): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(here, "../../../..");
  const candidates = [
    process.env.SEALED_CONTRACTS_DIR,
    join(repoRoot, "contracts"),
    resolve(repoRoot, "../contracts/contracts"),
  ].filter((p): p is string => !!p);
  return candidates.find((p) => existsSync(join(p, "foundry.toml")));
}

/**
 * Whether the local-chain suites can run (anvil on PATH and the Foundry project found). With
 * SEALED_REQUIRE_CHAIN_TESTS=1 (CI) a missing prerequisite throws instead, so the suites fail
 * rather than report green while skipped.
 */
export function chainTestsEnabled(): boolean {
  let anvil = true;
  try {
    execFileSync("anvil", ["--version"], { stdio: "ignore" });
  } catch {
    anvil = false;
  }
  const contracts = !!findContractsDir();
  if ((!anvil || !contracts) && process.env.SEALED_REQUIRE_CHAIN_TESTS === "1") {
    throw new Error(`SEALED_REQUIRE_CHAIN_TESTS=1 but ${!anvil ? "anvil is not on PATH" : "the Foundry contracts project was not found (SEALED_CONTRACTS_DIR)"}`);
  }
  return anvil && contracts;
}

async function run(cmd: string, args: string[], cwd: string): Promise<void> {
  await new Promise<void>((ok, fail) => {
    const p = spawn(cmd, args, { cwd, stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    p.stderr?.on("data", (d) => (err += String(d)));
    p.on("exit", (code) => (code === 0 ? ok() : fail(new Error(`${cmd} ${args.join(" ")} failed: ${err}`))));
  });
}

let builtOutDir: string | undefined;

/** Reads artifacts from <contracts>/out, building into a temp dir (read-only for the source) if absent. */
export async function loadArtifacts(contractsDir = findContractsDir()): Promise<Record<ContractName, Artifact>> {
  if (!contractsDir) throw new Error("Sealed contracts not found; set SEALED_CONTRACTS_DIR");
  let outDir = join(contractsDir, "out");
  if (!existsSync(join(outDir, "FeeSplitter.sol", "FeeSplitter.json"))) {
    if (!builtOutDir) {
      const tmp = await mkdtemp(join(tmpdir(), "sealed-forge-"));
      await run("forge", ["build", "--root", contractsDir, "--out", join(tmp, "out"), "--cache-path", join(tmp, "cache"), "--skip", "test", "script"], contractsDir);
      builtOutDir = join(tmp, "out");
    }
    outDir = builtOutDir;
  }
  const result = {} as Record<ContractName, Artifact>;
  for (const name of SEALED_CONTRACT_NAMES) {
    const json = JSON.parse(await readFile(join(outDir, `${name}.sol`, `${name}.json`), "utf8"));
    result[name] = { abi: json.abi as Abi, bytecode: json.bytecode.object as Hex };
  }
  return result;
}

export interface SealedDeployment {
  platformRegistry: Address;
  appRegistry: Address;
  oracleVerifier: Address;
  deploymentRegistry: Address;
  feeSplitter: Address;
  feeToken: Address;
  abis: Record<ContractName, Abi>;
}

export interface DeployOptions {
  feeToken?: Address;
  perPaymentCap?: bigint;
  perDeploymentDailyCap?: bigint;
}

const devAccount = (k: Hex) => privateKeyToAccount(k);
export const devAddress = (k: Hex) => devAccount(k).address.toLowerCase() as Address;

/** Sends a contract write as a Tempo tx paying gas in AlphaUSD, waits, and throws on revert. */
export async function send(
  client: LocalClient,
  key: Hex,
  address: Address,
  abi: Abi,
  functionName: string,
  args: readonly unknown[],
): Promise<Hash> {
  const account = devAccount(key);
  const request = { account, address, abi, functionName, args, feeToken: LOCAL_TOKENS.alphaUsd } as const;
  // anvil 1.7.1 (Tempo T4 rules) under-estimates storage-heavy calls, so leave wide headroom.
  const estimate = await client.estimateContractGas(request as never);
  const gas = [estimate * 3n + 1_000_000n, 3_000_000n].reduce((a, b) => (a > b ? a : b));
  const hash = await client.writeContract({ ...request, gas: gas > 25_000_000n ? 25_000_000n : gas } as never);
  const receipt = await client.waitForTransactionReceipt({ hash, timeout: 10_000 });
  if (receipt.status !== "success") throw new Error(`${functionName} reverted (${hash})`);
  return hash;
}

/** Deploys and wires the five contracts exactly like script/Deploy.s.sol. */
export async function deploySealedContracts(node: LocalTempo, opts: DeployOptions = {}): Promise<SealedDeployment> {
  const artifacts = await loadArtifacts();
  const { client } = node;
  const owner = devAccount(DEV_KEYS.owner);
  const deploy = async (name: ContractName, args: readonly unknown[]): Promise<Address> => {
    const { abi, bytecode } = artifacts[name];
    const hash = await client.deployContract({
      abi,
      bytecode,
      args,
      account: owner,
      feeToken: LOCAL_TOKENS.alphaUsd,
      gas: 60_000_000n,
    } as never);
    const receipt = await client.waitForTransactionReceipt({ hash, timeout: 10_000 });
    if (receipt.status !== "success" || !receipt.contractAddress) throw new Error(`deploy ${name} failed`);
    return receipt.contractAddress.toLowerCase() as Address;
  };
  const feeToken = opts.feeToken ?? LOCAL_TOKENS.pathUsd;
  const ownerAddr = owner.address;
  const platformRegistry = await deploy("PlatformRegistry", [ownerAddr]);
  const appRegistry = await deploy("AppRegistry", [ownerAddr]);
  const oracleVerifier = await deploy("OracleSignatureVerifier", [ownerAddr]);
  const deploymentRegistry = await deploy("DeploymentRegistry", [ownerAddr, platformRegistry, appRegistry]);
  const feeSplitter = await deploy("FeeSplitter", [
    ownerAddr,
    deploymentRegistry,
    appRegistry,
    feeToken,
    devAddress(DEV_KEYS.treasury),
    opts.perPaymentCap ?? 5_000_000n,
    opts.perDeploymentDailyCap ?? 20_000_000n,
  ]);
  const abis = Object.fromEntries(SEALED_CONTRACT_NAMES.map((n) => [n, artifacts[n].abi])) as Record<ContractName, Abi>;
  await send(client, DEV_KEYS.owner, appRegistry, abis.AppRegistry, "grantRegistrar", [devAddress(DEV_KEYS.ops)]);
  await send(client, DEV_KEYS.owner, oracleVerifier, abis.OracleSignatureVerifier, "addSigner", [devAddress(DEV_KEYS.oracle)]);
  await send(client, DEV_KEYS.owner, deploymentRegistry, abis.DeploymentRegistry, "setVerifier", [1, oracleVerifier]);
  return { platformRegistry, appRegistry, oracleVerifier, deploymentRegistry, feeSplitter, feeToken, abis };
}

// --- Lifecycle helpers ------------------------------------------------------------------------------

export interface Measurements {
  mrtd: Hex;
  rtmr0: Hex;
  rtmr1: Hex;
  rtmr2: Hex;
}

export async function addImage(
  node: LocalTempo,
  d: SealedDeployment,
  image: { imageId: Hex; name: string; version: string; isDebug?: boolean } & Measurements,
): Promise<Hex> {
  await send(node.client, DEV_KEYS.owner, d.platformRegistry, d.abis.PlatformRegistry, "addImage", [
    image.imageId, image.name, image.version, image.mrtd, image.rtmr0, image.rtmr1, image.rtmr2, image.isDebug ?? false,
    "https://example.invalid/image",
  ]);
  return computeMeasurementsHash(image.mrtd, image.rtmr0, image.rtmr1, image.rtmr2);
}

export async function registerApp(node: LocalTempo, d: SealedDeployment, app: { appId: Hex; slug: string; shareBps: number }) {
  await send(node.client, DEV_KEYS.owner, d.appRegistry, d.abis.AppRegistry, "registerApp", [
    app.appId, app.slug, app.slug, "MIT", devAddress(DEV_KEYS.maintainer), app.shareBps, "https://example.invalid/app",
  ]);
}

export async function publishRelease(
  node: LocalTempo,
  d: SealedDeployment,
  rel: { appId: Hex; version: string; bundleHash: Hex },
): Promise<void> {
  const zero32 = `0x${"00".repeat(31)}01` as Hex;
  await send(node.client, DEV_KEYS.ops, d.appRegistry, d.abis.AppRegistry, "publishRelease", [
    rel.appId, rel.version, rel.bundleHash, zero32, zero32, "", "",
  ]);
}

export async function approveStack(
  node: LocalTempo,
  d: SealedDeployment,
  customerKey: Hex,
  stack: { stackHash: Hex; releaseIds: Hex[]; imageId: Hex; expiry?: bigint },
): Promise<void> {
  await send(node.client, customerKey, d.deploymentRegistry, d.abis.DeploymentRegistry, "approveStack", [
    stack.stackHash, stack.releaseIds, stack.imageId, stack.expiry ?? 0n,
  ]);
}

/** Registers a deployment the way the platform oracle does: oracle-signed record, method 1, sent by ops. */
export async function registerDeployment(node: LocalTempo, d: SealedDeployment, record: DeploymentRecord): Promise<Hex> {
  const digest = recordDigest(record, registryDomain(d.deploymentRegistry, node.chainId));
  const signature = await devAccount(DEV_KEYS.oracle).sign({ hash: digest });
  const evidence = encodeAbiParameters([{ type: "bytes" }], [signature]);
  await send(node.client, DEV_KEYS.ops, d.deploymentRegistry, d.abis.DeploymentRegistry, "registerDeployment", [
    record, 1, evidence,
  ]);
  return digest;
}

/** Closes a deployment (terminal), as its customer or the owner would. */
export async function closeDeployment(node: LocalTempo, d: SealedDeployment, key: Hex, deploymentId: Hex): Promise<void> {
  await send(node.client, key, d.deploymentRegistry, d.abis.DeploymentRegistry, "closeDeployment", [deploymentId]);
}

/** Transfers TIP-20 tokens from the funder dev account. */
export async function fund(node: LocalTempo, token: Address, to: Address, amount: bigint): Promise<void> {
  const tip20 = [
    { type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ type: "bool" }] },
  ] as const satisfies Abi;
  await send(node.client, DEV_KEYS.funder, token, tip20, "transfer", [to, amount]);
}

export async function tokenBalance(node: LocalTempo, token: Address, holder: Address): Promise<bigint> {
  const abi = [
    { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ name: "a", type: "address" }], outputs: [{ type: "uint256" }] },
  ] as const satisfies Abi;
  return node.client.readContract({ address: token, abi, functionName: "balanceOf", args: [holder] });
}
