// The local Tempo node and the Sealed contracts: anvil --network tempo (hardfork T12, mainnet's, D-053) and script/Deploy.s.sol
// broadcast with forge, as contracts/script/local-e2e.sh does. Only anvil's public dev keys sign, and the chain id
// is anvil's 31337, so nothing signed here is valid on Tempo mainnet (4217).
import { copyFileSync, existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import {
  type Address,
  appRegistryAbi,
  deploymentRegistryAbi,
  feeSplitterAbi,
  type Hex,
  LOCAL_HARDFORK,
  oracleSignatureVerifierAbi,
  platformRegistryAbi,
} from "@sealed/core";
import { DEV_KEYS, devAddress, LOCAL_CHAIN_ID, LOCAL_TOKENS, type LocalClient, localClient, send } from "@sealed/core/testing";
import { type Abi, keccak256, toBytes } from "viem";
import { type Proc, type Supervisor, waitFor } from "./procs.ts";

export const KEYS = DEV_KEYS;
export const ADDR = Object.fromEntries(Object.entries(DEV_KEYS).map(([k, v]) => [k, devAddress(v)])) as Record<keyof typeof DEV_KEYS, Address>;
export const TOKENS = LOCAL_TOKENS;
export const CHAIN_ID = LOCAL_CHAIN_ID;

export const ABIS = {
  PlatformRegistry: platformRegistryAbi as Abi,
  AppRegistry: appRegistryAbi as Abi,
  DeploymentRegistry: deploymentRegistryAbi as Abi,
  FeeSplitter: feeSplitterAbi as Abi,
  OracleSignatureVerifier: oracleSignatureVerifierAbi as Abi,
};

export interface Contracts {
  platformRegistry: Address;
  appRegistry: Address;
  oracleVerifier: Address;
  deploymentRegistry: Address;
  feeSplitter: Address;
  deployBlock: bigint;
  /** The deployments file (contracts/deployments/<network>.json format) in the run directory. */
  file: string;
}

export interface Node {
  rpcUrl: string;
  client: LocalClient;
  proc: Proc;
}

export async function startAnvil(sup: Supervisor, port: number): Promise<Node> {
  // The hardfork the contracts and every other local node use (D-053, @sealed/core LOCAL_HARDFORK); block gas
  // limit 500M as on mainnet.
  const proc = sup.spawn("anvil", "anvil", ["--network", "tempo", "--hardfork", LOCAL_HARDFORK.toUpperCase(), "--host", "127.0.0.1", "--port", String(port), "--gas-limit", "500000000"]);
  const rpcUrl = `http://127.0.0.1:${port}`;
  const client = localClient(rpcUrl);
  await waitFor("anvil", async () => (await client.getChainId()) === CHAIN_ID, { proc, timeoutMs: 20_000 });
  return { rpcUrl, client, proc };
}

/** Broadcasts script/Deploy.s.sol (local network profile) and copies its deployments file into `runDir`. */
export async function deployContracts(sup: Supervisor, o: { contractsDir: string; rpcUrl: string; runDir: string; runId: string }): Promise<Contracts> {
  const name = `anvil-devnet-${o.runId}`; // contracts/.gitignore covers deployments/anvil*.json
  const rel = `deployments/${name}.json`;
  const env = {
    OWNER_PRIVATE_KEY: KEYS.owner,
    OPS_ADDRESS: ADDR.ops,
    ORACLE_ADDRESS: ADDR.oracle,
    TREASURY_ADDRESS: ADDR.treasury,
    FEE_TOKEN_ADDRESS: TOKENS.pathUsd,
    DEPLOYMENTS_NETWORK: name,
    DEPLOYMENTS_FILE: rel,
  };
  const abs = join(o.contractsDir, rel);
  try {
    // Gas is paid in AlphaUSD (a Tempo transaction with fee_token), so pathUSD balances move only by what the
    // contracts transfer.
    await sup.runOk("forge-deploy", "forge", ["script", "script/Deploy.s.sol:Deploy", "--rpc-url", o.rpcUrl, "--broadcast", "--slow", "--tempo.fee-token", TOKENS.alphaUsd], {
      cwd: o.contractsDir,
      env,
    });
    await sup.runOk("record-deployment", "script/record-deployment.sh", [rel, `broadcast/Deploy.s.sol/${CHAIN_ID}/run-latest.json`], { cwd: o.contractsDir });
    const file = join(o.runDir, "deployments.json");
    copyFileSync(abs, file);
    const d = JSON.parse(readFileSync(file, "utf8")) as { chainId: number; deployBlock: number; contracts: Record<string, { address: Address }> };
    const a = (n: string) => (d.contracts[n]?.address ?? "").toLowerCase() as Address;
    return {
      platformRegistry: a("PlatformRegistry"),
      appRegistry: a("AppRegistry"),
      oracleVerifier: a("OracleSignatureVerifier"),
      deploymentRegistry: a("DeploymentRegistry"),
      feeSplitter: a("FeeSplitter"),
      deployBlock: BigInt(d.deployBlock ?? 0),
      file,
    };
  } finally {
    if (existsSync(abs)) rmSync(abs);
  }
}

export class Chain {
  readonly node: Node;
  readonly c: Contracts;

  constructor(node: Node, c: Contracts) {
    this.node = node;
    this.c = c;
  }

  get client() {
    return this.node.client;
  }

  read<T = unknown>(contract: keyof typeof ABIS, fn: string, args: readonly unknown[] = []): Promise<T> {
    const address = {
      PlatformRegistry: this.c.platformRegistry,
      AppRegistry: this.c.appRegistry,
      DeploymentRegistry: this.c.deploymentRegistry,
      FeeSplitter: this.c.feeSplitter,
      OracleSignatureVerifier: this.c.oracleVerifier,
    }[contract];
    return this.client.readContract({ address, abi: ABIS[contract], functionName: fn, args } as never) as Promise<T>;
  }

  async write(key: Hex, contract: keyof typeof ABIS, fn: string, args: readonly unknown[]): Promise<Hex> {
    const address = {
      PlatformRegistry: this.c.platformRegistry,
      AppRegistry: this.c.appRegistry,
      DeploymentRegistry: this.c.deploymentRegistry,
      FeeSplitter: this.c.feeSplitter,
      OracleSignatureVerifier: this.c.oracleVerifier,
    }[contract];
    return send(this.client, key, address, ABIS[contract], fn, args);
  }

  /** True when the call reverts (estimate or receipt). */
  async reverts(key: Hex, contract: keyof typeof ABIS, fn: string, args: readonly unknown[]): Promise<boolean> {
    try {
      await this.write(key, contract, fn, args);
      return false;
    } catch {
      return true;
    }
  }

  async balance(token: Address, holder: Address): Promise<bigint> {
    const abi = [{ type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ name: "a", type: "address" }], outputs: [{ type: "uint256" }] }] as const;
    return this.client.readContract({ address: token, abi, functionName: "balanceOf", args: [holder] });
  }

  async transfer(key: Hex, token: Address, to: Address, amount: bigint): Promise<Hex> {
    const abi = [
      { type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ type: "bool" }] },
    ] as const satisfies Abi;
    return send(this.client, key, token, abi, "transfer", [to, amount]);
  }

  async blockTime(): Promise<bigint> {
    return (await this.client.getBlock()).timestamp;
  }
}

export const REGISTRAR_ROLE = keccak256(toBytes("REGISTRAR_ROLE"));
