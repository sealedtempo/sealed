// The customer's access-key authorization for a deployment's enclave signer (D-026, D-034, D-054). One helper
// builds it for the console and the api, so the key can make exactly the calls fee settlement and the relay
// payer need, within the customer's limit, and nothing else. It is never `allowAnyCalls`.
//
// What the key may call (top-level calls of a Tempo transaction signed by the key, sender = the customer):
// - FEE_TOKEN approve(spender = FeeSplitter): the agent batches approve(exact) with payFees or topUpFees, and
//   resets the allowance with approve(FeeSplitter, 0) after a top-up.
// - FeeSplitter payFees and topUpFees.
// - FEE_TOKEN transferWithMemo(recipient = the FeeSplitter's treasury): MPP charges to the relay.
// - The TIP-1034 escrow precompile open, topUp, requestClose and withdraw: MPP sessions with the relay. The
//   keychain refuses recipient rules on these selectors (InvalidCallScope, checked on a T13 node), so the
//   chain does not bind the channel payee. The payer's firewall enforces the attested treasury payee, and
//   every deposit counts against the key's limit (the precompile pulls from the customer).
//
// Limits: one periodic limit in FEE_TOKEN with the customer's amount and period. Once limits are set, every
// other token has a limit of zero, and network fees the customer's account pays count against the limit too.
import { encodeFunctionData, isAddress, maxUint64 } from "viem";
import { Abis } from "viem/tempo";
import { ACCOUNT_KEYCHAIN } from "./chain.js";
import type { Address, Hex } from "./hex.js";

/** The TIP-1034 TIP-20 channel escrow precompile that MPP sessions use (mppx 0.15.0, D-027). */
export const TIP1034_ESCROW: Address = "0x4d50500000000000000000000000000000000000";
/** The mainnet FeeSplitter's treasury (contracts/deployments/tempo-mainnet.json), the relay's payee (D-054). */
export const MAINNET_TREASURY: Address = "0x755a1e289503c7109d01a74ed253ba0f724ca3eb";

/** The periods the console offers (seconds; a month is 30 days, as Tempo periods are fixed lengths). */
export const SPEND_PERIOD_SECONDS = { day: 86_400, week: 604_800, month: 2_592_000 } as const;
export type SpendPeriod = keyof typeof SPEND_PERIOD_SECONDS;

/** Selectors the key may call. Tests check each against its signature and the contract ABIs. */
export const ACCESS_KEY_SELECTORS = {
  /** TIP-20 approve(address,uint256), recipient = FeeSplitter. */
  approve: "0x095ea7b3",
  /** TIP-20 transferWithMemo(address,uint256,bytes32), recipient = treasury. */
  transferWithMemo: "0x95777d59",
  /** FeeSplitter payFees(bytes32,bytes32,address,uint256,bytes32). */
  payFees: "0xa1e03ecd",
  /** FeeSplitter topUpFees(bytes32,bytes32,address,uint256,bytes32) (CR-7). */
  topUpFees: "0x01571ecd",
  /** Escrow open(address,address,address,uint96,bytes32,address). */
  escrowOpen: "0xedc53b00",
  /** Escrow topUp(descriptor,uint96). */
  escrowTopUp: "0xdc48471e",
  /** Escrow requestClose(descriptor). */
  escrowRequestClose: "0x675402e5",
  /** Escrow withdraw(descriptor). */
  escrowWithdraw: "0x41e2c664",
} as const satisfies Record<string, Hex>;

export interface SelectorRule {
  selector: Hex;
  /** Allowed first-argument addresses (transfer, transferWithMemo and approve only); empty = any. */
  recipients: Address[];
}

export interface AllowedCall {
  target: Address;
  selectorRules: SelectorRule[];
}

export interface TokenLimit {
  token: Address;
  amount: bigint;
  /** Seconds; the first period starts at authorization time, not at a calendar boundary. */
  period: bigint;
}

/** The KeyRestrictions tuple of AccountKeychain.authorizeKey (T3+). */
export interface KeyConfig {
  expiry: bigint;
  enforceLimits: true;
  limits: TokenLimit[];
  allowAnyCalls: false;
  allowedCalls: AllowedCall[];
}

export interface AccessKeyAuthorizationParams {
  /** The deployment's enclave signer (secp256k1, signature type 0). */
  keyId: Address;
  /** The deployment's FEE_TOKEN (config feeToken; USDC.e on mainnet, D-035). */
  feeToken: Address;
  feeSplitter: Address;
  /** The FeeSplitter's treasury, the only payee of MPP charges (MAINNET_TREASURY on mainnet). */
  treasury: Address;
  /** The customer's limit per period in FEE_TOKEN base units. Fees, network fees and relay spend share it (D-048). */
  limit: bigint;
  /** The customer's period: day, week, month, or seconds. */
  period: SpendPeriod | number | bigint;
  /** Unix seconds after which the key stops working; default never (type(uint64).max). Expiry cannot be extended later. */
  expiry?: bigint;
  /** The escrow precompile; default TIP1034_ESCROW. */
  escrow?: Address;
}

export interface NamedCall {
  name:
    | "feeToken.approve"
    | "feeToken.transferWithMemo"
    | "feeSplitter.payFees"
    | "feeSplitter.topUpFees"
    | "escrow.open"
    | "escrow.topUp"
    | "escrow.requestClose"
    | "escrow.withdraw";
  target: Address;
  selector: Hex;
  recipients: Address[];
}

export interface AccessKeyAuthorization {
  keyId: Address;
  signatureType: 0;
  config: KeyConfig;
  /** authorizeKey(keyId, 0, config): the args for writeContract with Abis.accountKeychain. */
  args: readonly [Address, 0, KeyConfig];
  /** The standard transaction an injected wallet sends (D-026): AccountKeychain.authorizeKey. */
  call: { to: Address; data: Hex };
  /** Every allowed call by name, in `config.allowedCalls` order (for display and checks). */
  calls: NamedCall[];
}

const U64_MAX = maxUint64;
const U128_MAX = (1n << 128n) - 1n;
const ZERO: Address = "0x0000000000000000000000000000000000000000";

function addr(name: string, v: string): Address {
  if (!isAddress(v, { strict: false }) || v.toLowerCase() === ZERO) throw new Error(`${name} must be a nonzero address`);
  return v.toLowerCase() as Address;
}

/** Period in seconds for a named period or a positive number of seconds. */
export function spendPeriodSeconds(period: SpendPeriod | number | bigint): bigint {
  const s = typeof period === "string" ? SPEND_PERIOD_SECONDS[period] : period;
  if (s === undefined) throw new Error(`unknown period ${String(period)}`);
  const n = BigInt(s);
  if (n <= 0n || n > U64_MAX) throw new Error("period must be a positive number of seconds");
  return n;
}

/**
 * The exact D-054 authorization for a deployment's enclave signer: FEE_TOKEN limited to `limit` per `period`,
 * and the eight allowed calls above. Sent by the customer's root account, either as the returned `call` in a
 * standard transaction (any injected wallet) or with writeContract and `args`.
 */
export function buildAccessKeyAuthorization(p: AccessKeyAuthorizationParams): AccessKeyAuthorization {
  const keyId = addr("keyId", p.keyId);
  const feeToken = addr("feeToken", p.feeToken);
  const feeSplitter = addr("feeSplitter", p.feeSplitter);
  const treasury = addr("treasury", p.treasury);
  const escrow = addr("escrow", p.escrow ?? TIP1034_ESCROW);
  if (new Set([keyId, feeToken, feeSplitter, treasury, escrow]).size !== 5) throw new Error("keyId, feeToken, feeSplitter, treasury and escrow must differ");
  if (p.limit <= 0n || p.limit > U128_MAX) throw new Error("limit must be positive and fit in 128 bits");
  const period = spendPeriodSeconds(p.period);
  const expiry = p.expiry ?? U64_MAX;
  if (expiry <= 0n || expiry > U64_MAX) throw new Error("expiry must be a positive uint64 (type(uint64).max for none)");

  const s = ACCESS_KEY_SELECTORS;
  const calls: NamedCall[] = [
    { name: "feeToken.approve", target: feeToken, selector: s.approve, recipients: [feeSplitter] },
    { name: "feeToken.transferWithMemo", target: feeToken, selector: s.transferWithMemo, recipients: [treasury] },
    { name: "feeSplitter.payFees", target: feeSplitter, selector: s.payFees, recipients: [] },
    { name: "feeSplitter.topUpFees", target: feeSplitter, selector: s.topUpFees, recipients: [] },
    { name: "escrow.open", target: escrow, selector: s.escrowOpen, recipients: [] },
    { name: "escrow.topUp", target: escrow, selector: s.escrowTopUp, recipients: [] },
    { name: "escrow.requestClose", target: escrow, selector: s.escrowRequestClose, recipients: [] },
    { name: "escrow.withdraw", target: escrow, selector: s.escrowWithdraw, recipients: [] },
  ];
  const allowedCalls: AllowedCall[] = [];
  for (const c of calls) {
    let entry = allowedCalls.find((a) => a.target === c.target);
    if (!entry) allowedCalls.push((entry = { target: c.target, selectorRules: [] }));
    entry.selectorRules.push({ selector: c.selector, recipients: [...c.recipients] });
  }
  const config: KeyConfig = {
    expiry,
    enforceLimits: true,
    limits: [{ token: feeToken, amount: p.limit, period }],
    allowAnyCalls: false,
    allowedCalls,
  };
  const args = [keyId, 0, config] as const;
  const data = encodeFunctionData({ abi: Abis.accountKeychain, functionName: "authorizeKey", args: args as never });
  return { keyId, signatureType: 0, config, args, call: { to: ACCOUNT_KEYCHAIN, data }, calls };
}

/**
 * AccountKeychain.updateSpendingLimit for a key that already exists: sets the FEE_TOKEN limit (remaining and
 * maximum) to `limit` at once. The period stays what the authorization set; a different period needs a new key,
 * because a revoked key id can never be authorized again.
 */
export function buildSpendingLimitUpdate(p: { keyId: Address; feeToken: Address; limit: bigint }): { to: Address; data: Hex } {
  const keyId = addr("keyId", p.keyId);
  const feeToken = addr("feeToken", p.feeToken);
  if (p.limit < 0n || p.limit > U128_MAX) throw new Error("limit must fit in 128 bits");
  return { to: ACCOUNT_KEYCHAIN, data: encodeFunctionData({ abi: Abis.accountKeychain, functionName: "updateSpendingLimit", args: [keyId, feeToken, p.limit] }) };
}

export interface AccessKeyRevocation {
  /** AccountKeychain.revokeKey(keyId): permanent, the key id can never be authorized again. */
  revokeKey: { to: Address; data: Hex };
  /** FEE_TOKEN approve(FeeSplitter, 0): revocation does not reset allowances the key granted (D-026). */
  resetAllowance: { to: Address; data: Hex };
  /** Both, in order: one Tempo batch from a Tempo-aware root, or two standard transactions from an injected wallet. */
  calls: [{ to: Address; data: Hex }, { to: Address; data: Hex }];
}

/** Revokes the enclave signer's key and resets any allowance it left to FeeSplitter (A12, D-026). */
export function buildAccessKeyRevocation(p: { keyId: Address; feeToken: Address; feeSplitter: Address }): AccessKeyRevocation {
  const keyId = addr("keyId", p.keyId);
  const feeToken = addr("feeToken", p.feeToken);
  const feeSplitter = addr("feeSplitter", p.feeSplitter);
  const revokeKey = { to: ACCOUNT_KEYCHAIN, data: encodeFunctionData({ abi: Abis.accountKeychain, functionName: "revokeKey", args: [keyId] }) };
  const resetAllowance = { to: feeToken, data: encodeFunctionData({ abi: Abis.tip20, functionName: "approve", args: [feeSplitter, 0n] }) };
  return { revokeKey, resetAllowance, calls: [revokeKey, resetAllowance] };
}

type OnchainAllowedCalls = readonly { target: string; selectorRules: readonly { selector: string; recipients: readonly string[] }[] }[];

function canonicalCalls(calls: OnchainAllowedCalls): string[] {
  const out: string[] = [];
  for (const c of calls) {
    for (const r of c.selectorRules) {
      const recipients = r.recipients.map((x) => x.toLowerCase()).sort();
      out.push(`${c.target.toLowerCase()}:${r.selector.toLowerCase()}:${recipients.join(",")}`);
    }
  }
  return out.sort();
}

/**
 * True when the allowed calls the chain reports (AccountKeychain.getAllowedCalls of a scoped key) are exactly
 * `expected`, ignoring order and address case. The api uses it to confirm what a customer authorized.
 */
export function sameAllowedCalls(expected: readonly AllowedCall[] | AccessKeyAuthorization, onchain: OnchainAllowedCalls): boolean {
  const want = canonicalCalls("config" in expected ? expected.config.allowedCalls : expected);
  const got = canonicalCalls(onchain);
  return want.length === got.length && want.every((v, i) => v === got[i]);
}

/**
 * App-hour fees a stack accrues over one period, in FEE_TOKEN base units: the least a limit must cover for fee
 * settlement alone (review M5). Usage-metered fees, network fees and relay spend come on top, so the console and
 * the api should warn below this plus a margin. `appHourPrices` maps app id to the price per hour in base units.
 */
export function appHourFeeFloor(appHourPrices: Record<string, bigint>, apps: readonly string[], period: SpendPeriod | number | bigint): bigint {
  const seconds = spendPeriodSeconds(period);
  let total = 0n;
  for (const a of apps) total += ((appHourPrices[a] ?? 0n) * seconds + 3599n) / 3600n;
  return total;
}
