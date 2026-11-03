// Tempo chain helpers. Always start from viem's `tempo` chain so clients get the 0x76 serializer,
// Tempo formatters and prepare hooks (tempo-viem notes, G1).
import type { Chain } from "viem";
import { tempo } from "viem/chains";
import { Addresses, type Hardfork } from "viem/tempo";
import type { Address } from "./hex.js";

export const TEMPO_MAINNET_ID = 4217;
export const LOCAL_ANVIL_ID = 31337;
export const PATH_USD: Address = "0x20c0000000000000000000000000000000000000";
/** Bridged USDC (Stargate), the mainnet FEE_TOKEN (D-035, config/defaults.yaml chain.fee_token). */
export const USDC_E: Address = "0x20c000000000000000000000b9537d11c60e8b50";
export const ACCOUNT_KEYCHAIN: Address = "0xaaaaaaaa00000000000000000000000000000000";
export const FEE_TOKEN_DECIMALS = 6;
/** The Tempo hardfork local nodes run (anvil --network tempo --hardfork T13), mainnet's active hardfork (D-053). */
export const LOCAL_HARDFORK = "t13" satisfies Hardfork.Hardfork;

export { tempo as tempoMainnet };

export interface TempoChainOptions {
  /** 4217 (default) for mainnet; any other id gives a local/dev chain with the same Tempo config. */
  chainId?: number;
  rpcUrl?: string;
  /**
   * Default fee token for transactions. Callers pass the deployment's configured feeToken; without one,
   * mainnet uses USDC.e (D-035) and local nodes use pathUSD (what anvil --network tempo funds).
   */
  feeToken?: Address;
  /**
   * Tempo hardfork the node runs. Local nodes default to t13, mainnet's active hardfork (D-053; Foundry 1.8.6 knows t0..t14).
   * Change it to t13 together with contracts/foundry.toml once T13 activates (2026-11-03 15:00 UTC).
   */
  hardfork?: Hardfork.Hardfork;
}

/** The fee token a chain falls back to when the config names none: USDC.e on mainnet, pathUSD elsewhere. */
export function defaultFeeToken(chainId: number): Address {
  return chainId === TEMPO_MAINNET_ID ? USDC_E : (Addresses.pathUsd as Address);
}

/** A viem Chain for Tempo mainnet or a local Tempo node (anvil --network tempo). */
export function tempoChain(opts: TempoChainOptions = {}): Chain {
  const chainId = opts.chainId ?? TEMPO_MAINNET_ID;
  const feeToken = opts.feeToken ?? defaultFeeToken(chainId);
  if (chainId === TEMPO_MAINNET_ID) {
    return tempo.extend({
      feeToken,
      ...(opts.rpcUrl ? { rpcUrls: { default: { http: [opts.rpcUrl] } } } : {}),
    }) as unknown as Chain;
  }
  return tempo.extend({
    id: chainId,
    name: `Tempo local ${chainId}`,
    testnet: true,
    feeToken,
    hardfork: opts.hardfork ?? LOCAL_HARDFORK,
    blockExplorers: undefined,
    rpcUrls: { default: { http: [opts.rpcUrl ?? "http://127.0.0.1:8545"] } },
  }) as unknown as Chain;
}

export const explorerTxUrl = (hash: string) => `https://explore.tempo.xyz/tx/${hash}`;
export const explorerAddressUrl = (addr: string) => `https://explore.tempo.xyz/address/${addr}`;
