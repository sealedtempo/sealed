// Fee payments on Tempo (spec 7.2-7.3, D-026). One Tempo transaction per app batches
// TIP-20 approve(FeeSplitter, exact) and one FeeSplitter call per unpaid report: payFees for a leg
// nobody paid yet, topUpFees(total = the report's fee) for a leg someone paid short.
// access-key mode: the enclave key signs as an access key of the customer account, so
// msg.sender is the customer. enclave-account mode: the enclave signer pays from its own balance.
import {
  type Address,
  feeSplitterAbi,
  deploymentRegistryAbi,
  type Hex,
  tempoChain,
} from "@sealed/core";
import {
  BaseError,
  createClient,
  encodeFunctionData,
  http,
  keccak256,
  publicActions,
  RpcRequestError,
  TransactionReceiptNotFoundError,
  walletActions,
} from "viem";
import { Account, Actions, tempoActions } from "viem/tempo";

export type SettlementMode = "access-key" | "enclave-account";

export interface PaymentLine {
  appId: Hex;
  /** What this line pulls: the report's fee minus `paid`. */
  amount: bigint;
  usageHash: Hex;
  /** usagePaid already recorded onchain for (deploymentId, usageHash, appId); > 0 makes the line a top-up. */
  paid: bigint;
}

export interface Budget {
  /** Spendable by the payer before limits and balance run out, after `reserve`. */
  spendable: bigint;
  /** Content-free reason when nothing can be spent. */
  problem?: "access_key_missing" | "access_key_revoked" | "access_key_expired" | "spend_limit" | "insufficient_balance";
  /** Which limit `spendable` comes from: the access key's remaining spending limit or the token balance. */
  binding?: "spend_limit" | "balance";
}

/** The access key's FEE_TOKEN limit as the chain reports it (getRemainingLimit); 0 for a missing, revoked or expired key. */
export interface SpendLimit {
  remaining: bigint;
  /** End of the current period (unix seconds); 0 for a one-time limit or no key. */
  periodEnd: number;
}

/** The receipt of a settlement transaction: what it paid in network fees, and whether its calls ran. */
export interface PaymentReceipt {
  status: "success" | "reverted";
  networkFee: bigint;
}

/**
 * A payment that did not complete. `not_sent`: the node refused it, nothing left the limit. `reverted`: it was
 * mined and reverted, its network fee was paid. `unknown`: it may have been broadcast (lost response, receipt
 * timeout); `txHash` is set so the caller can count it and look for the receipt later.
 */
export class PaymentError extends Error {
  constructor(
    message: string,
    readonly outcome: "not_sent" | "reverted" | "unknown",
    readonly txHash?: Hex,
    readonly networkFee?: bigint,
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}

/** DeploymentRegistry status: None (not registered yet), Active, Closed (terminal). */
export type DeploymentStatus = "none" | "active" | "closed";

/** At most this many legs per transaction, so the gas floor below stays far under the 30M per-tx cap. */
export const MAX_LINES_PER_TX = 10;

export interface FeePayer {
  readonly mode: SettlementMode;
  /** Address whose tokens pay (customer in access-key mode). */
  readonly payer: Address;
  /** The token every payment uses (config feeToken), lowercase. */
  readonly feeToken: Address;
  deploymentStatus(): Promise<DeploymentStatus>;
  appInDeployment(appId: Hex): Promise<boolean>;
  perPaymentCap(): Promise<bigint>;
  dailyRemaining(): Promise<bigint>;
  /** usagePaid(deploymentId, usageHash, appId): the amount paid onchain for this leg, 0 when unpaid. */
  paidAmount(usageHash: Hex, appId: Hex): Promise<bigint>;
  /** usageToken(deploymentId, usageHash, appId): the token a leg was opened in (topUpFees must match it). */
  legToken(usageHash: Hex, appId: Hex): Promise<Address>;
  /** Estimated network fee in token base units for exactly this batch; rejects when the node's estimate reverts. */
  feeReserve(lines: PaymentLine[]): Promise<bigint>;
  budget(reserve: bigint): Promise<Budget>;
  /**
   * `networkFee` is what the transaction paid in fee-token base units (it counts against an access-key limit).
   * Rejects with a PaymentError when the payment did not complete.
   */
  pay(lines: PaymentLine[]): Promise<{ txHash: Hex; gasUsed: bigint; networkFee?: bigint }>;
  /** The access key's limit onchain; undefined in enclave-account mode or for a key without limits. */
  spendLimit?(): Promise<SpendLimit | undefined>;
  /** The receipt of an earlier payment transaction, undefined while none is mined. */
  paymentReceipt?(txHash: Hex): Promise<PaymentReceipt | undefined>;
  /** FeeSplitter.paused(): while the owner has paused it, payFees and topUpFees revert EnforcedPause (payments-4). */
  splitterPaused?(): Promise<boolean>;
}

/** OpenZeppelin Pausable's EnforcedPause() selector, the revert of FeeSplitter.payFees and topUpFees while paused. */
export const ENFORCED_PAUSE_SELECTOR = "0xd93c0665";

/**
 * Whether an estimate or payment error is FeeSplitter's EnforcedPause() revert, anywhere in the error's cause chain.
 * The selector is matched only as revert data (`data`, a decoded error's `data`, `raw`, `signature`) or as viem's
 * decoded error name; it is never read from the free-text `message` or `details`, which carry the request (`from:`
 * is the customer's root wallet in access-key mode), so a customer address starting with the selector would turn any
 * failure into the operator's pause (D-073) and the grace period would never run. The `EnforcedPause()` name, which
 * cannot be an address, is matched in `shortMessage` and `details`.
 */
export function isEnforcedPause(err: unknown): boolean {
  const seen = new Set<unknown>();
  for (let e: unknown = err; typeof e === "object" && e !== null && !seen.has(e); e = (e as { cause?: unknown }).cause) {
    seen.add(e);
    const x = e as { data?: unknown; raw?: unknown; signature?: unknown; shortMessage?: unknown; details?: unknown };
    const decoded = typeof x.data === "object" && x.data !== null ? (x.data as { errorName?: unknown; data?: unknown }) : undefined;
    if (decoded?.errorName === "EnforcedPause") return true;
    for (const v of [x.data, decoded?.data, x.raw, x.signature]) {
      if (typeof v === "string" && v.toLowerCase().startsWith(ENFORCED_PAUSE_SELECTOR)) return true;
    }
    for (const v of [x.shortMessage, x.details]) {
      if (typeof v === "string" && /\bEnforcedPause\(\)/.test(v)) return true;
    }
  }
  return false;
}

const tip20Abi = [
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ name: "a", type: "address" }], outputs: [{ type: "uint256" }] },
] as const;

export interface TempoFeePayerOptions {
  mode: SettlementMode;
  enclaveKey: Hex;
  customer: Address;
  chainId: number;
  rpcUrl: string;
  feeToken: Address;
  feeSplitter: Address;
  deploymentRegistry: Address;
  deploymentId: Hex;
  /** Extra gas on top of the node's estimate (keychain signatures are estimated low). */
  gasHeadroomPct?: number;
  /** Lower bound for the gas limit (local nodes in tests). */
  minGas?: bigint;
  receiptTimeoutMs?: number;
}

/**
 * Gas floor per batch. Each new storage slot costs 250k gas on Tempo (tempo-chain notes): a leg can
 * create usagePaid, usageToken, the day's dailyPaid and two credit slots; approve can create the
 * allowance slot and a fresh account pays 271k for its first transaction.
 */
export const BASE_GAS_FLOOR = 600_000n;
export const PER_LINE_GAS_FLOOR = 1_300_000n;
/** Lowest gas limit of a settlement transaction off mainnet (headroom on local Tempo nodes); mainnet uses the floors above. */
export const LOCAL_MIN_GAS = 5_000_000n;

/**
 * Fee units the settler reserves for a transaction of `gas` at `price` attodollars per gas: gas * price / 1e12,
 * doubled for base fee movement, rounded up.
 */
export function feeUnitsReserved(gas: bigint, price: bigint): bigint {
  return (gas * price * 2n + 999_999_999_999n) / 1_000_000_000_000n;
}

export class TempoFeePayer implements FeePayer {
  readonly mode: SettlementMode;
  readonly payer: Address;
  readonly feeToken: Address;
  private readonly client;
  private readonly account;

  constructor(private readonly o: TempoFeePayerOptions) {
    this.mode = o.mode;
    const chain = tempoChain({ chainId: o.chainId, rpcUrl: o.rpcUrl, feeToken: o.feeToken });
    this.client = createClient({ chain, transport: http(o.rpcUrl, { timeout: 30_000 }), pollingInterval: o.chainId === 4217 ? 1000 : 200 })
      .extend(publicActions)
      .extend(walletActions)
      .extend(tempoActions());
    this.account =
      o.mode === "access-key" ? Account.fromSecp256k1(o.enclaveKey, { access: o.customer }) : Account.fromSecp256k1(o.enclaveKey);
    this.payer = (o.mode === "access-key" ? o.customer : this.account.address).toLowerCase() as Address;
    this.feeToken = o.feeToken.toLowerCase() as Address;
  }

  /** The access key id (enclave signer address); equals `payer` in enclave-account mode. */
  get keyId(): Address {
    const a = this.account as { accessKeyAddress?: Address; address: Address };
    return (a.accessKeyAddress ?? a.address).toLowerCase() as Address;
  }

  async deploymentStatus(): Promise<DeploymentStatus> {
    const [status] = await this.client.readContract({
      address: this.o.deploymentRegistry,
      abi: deploymentRegistryAbi,
      functionName: "deploymentParties",
      args: [this.o.deploymentId],
    });
    if (status === 0) return "none";
    if (status === 1) return "active";
    if (status === 2) return "closed";
    throw new Error(`unknown deployment status ${status}`);
  }

  async appInDeployment(appId: Hex): Promise<boolean> {
    return this.client.readContract({
      address: this.o.deploymentRegistry,
      abi: deploymentRegistryAbi,
      functionName: "appInDeployment",
      args: [this.o.deploymentId, appId],
    });
  }

  async perPaymentCap(): Promise<bigint> {
    const cfg = await this.client.readContract({
      address: this.o.feeSplitter,
      abi: feeSplitterAbi,
      functionName: "tokenConfig",
      args: [this.o.feeToken],
    });
    return cfg.perPaymentCap;
  }

  async splitterPaused(): Promise<boolean> {
    return this.client.readContract({ address: this.o.feeSplitter, abi: feeSplitterAbi, functionName: "paused" });
  }

  async dailyRemaining(): Promise<bigint> {
    return this.client.readContract({
      address: this.o.feeSplitter,
      abi: feeSplitterAbi,
      functionName: "remainingDailyAllowance",
      args: [this.o.deploymentId, this.o.feeToken],
    });
  }

  /**
   * usagePaid(deploymentId, usageHash, appId): the amount paid for the leg (0 = unpaid). FeeSplitter does not
   * see the signed report, so the deployment's own payer can pay a leg with less than its fee; the settler
   * compares this with the fee and tops a short leg up (contract review logic-F1 b / funds-F-02).
   */
  async paidAmount(usageHash: Hex, appId: Hex): Promise<bigint> {
    return this.client.readContract({
      address: this.o.feeSplitter,
      abi: feeSplitterAbi,
      functionName: "usagePaid",
      args: [this.o.deploymentId, usageHash, appId],
    });
  }

  async legToken(usageHash: Hex, appId: Hex): Promise<Address> {
    const t = await this.client.readContract({
      address: this.o.feeSplitter,
      abi: feeSplitterAbi,
      functionName: "usageToken",
      args: [this.o.deploymentId, usageHash, appId],
    });
    return t.toLowerCase() as Address;
  }

  private calls(lines: PaymentLine[]) {
    const total = lines.reduce((s, l) => s + l.amount, 0n);
    const approve = (amount: bigint) => Actions.token.approve.call({ token: this.o.feeToken, spender: this.o.feeSplitter, amount });
    const topUps = lines.some((l) => l.paid > 0n);
    return [
      approve(total),
      ...lines.map((l) => ({
        to: this.o.feeSplitter,
        data:
          l.paid > 0n
            ? encodeFunctionData({
                abi: feeSplitterAbi,
                functionName: "topUpFees",
                args: [this.o.deploymentId, l.appId, this.o.feeToken, l.paid + l.amount, l.usageHash],
              })
            : encodeFunctionData({
                abi: feeSplitterAbi,
                functionName: "payFees",
                args: [this.o.deploymentId, l.appId, this.o.feeToken, l.amount, l.usageHash],
              }),
      })),
      // topUpFees pulls total - usagePaid at execution time, which is less than `amount` if the payer topped the
      // leg up in between: reset what is left of the approval (D-026).
      ...(topUps ? [approve(0n)] : []),
    ];
  }

  private async gasFor(lines: PaymentLine[]): Promise<bigint> {
    const estimate = await this.client.estimateGas({ account: this.account, calls: this.calls(lines), feeToken: this.o.feeToken } as never);
    const pct = BigInt(this.o.gasHeadroomPct ?? 50);
    let gas = estimate + (estimate * pct) / 100n + 50_000n;
    const floor = BASE_GAS_FLOOR + PER_LINE_GAS_FLOOR * BigInt(lines.length);
    for (const min of [floor, this.o.minGas ?? 0n]) if (gas < min) gas = min;
    return gas;
  }

  async feeReserve(lines: PaymentLine[]): Promise<bigint> {
    const [gas, price] = await Promise.all([this.gasFor(lines), this.client.getGasPrice()]);
    return feeUnitsReserved(gas, price);
  }

  async budget(reserve: bigint): Promise<Budget> {
    const balance = await this.client.readContract({ address: this.o.feeToken, abi: tip20Abi, functionName: "balanceOf", args: [this.payer] });
    let spendable = balance - reserve;
    let binding: Budget["binding"] = "balance";
    if (this.mode === "access-key") {
      const meta = await this.client.accessKey.getMetadata({ account: this.o.customer, accessKey: this.keyId });
      if (meta.address.toLowerCase() !== this.keyId) return { spendable: 0n, problem: meta.isRevoked ? "access_key_revoked" : "access_key_missing" };
      if (meta.isRevoked) return { spendable: 0n, problem: "access_key_revoked" };
      if (meta.expiry <= BigInt(Math.floor(Date.now() / 1000))) return { spendable: 0n, problem: "access_key_expired" };
      if (meta.spendPolicy === "limited") {
        const { remaining } = await this.client.accessKey.getRemainingLimit({ account: this.o.customer, accessKey: this.keyId, token: this.o.feeToken });
        // Self-paid fees count against the limit too (tempo-viem notes, section 0).
        const byLimit = remaining - reserve;
        if (byLimit < spendable) {
          if (byLimit <= 0n) return { spendable: 0n, problem: "spend_limit", binding: "spend_limit" };
          spendable = byLimit;
          binding = "spend_limit";
        }
      }
    }
    if (spendable <= 0n) return { spendable: 0n, problem: "insufficient_balance", binding };
    return { spendable, binding };
  }

  async spendLimit(): Promise<SpendLimit | undefined> {
    if (this.mode !== "access-key") return undefined;
    const meta = await this.client.accessKey.getMetadata({ account: this.o.customer, accessKey: this.keyId });
    const active = meta.address.toLowerCase() === this.keyId && !meta.isRevoked && meta.expiry > BigInt(Math.floor(Date.now() / 1000));
    if (!active) return { remaining: 0n, periodEnd: 0 };
    if (meta.spendPolicy !== "limited") return undefined;
    const { remaining, periodEnd } = await this.client.accessKey.getRemainingLimit({ account: this.o.customer, accessKey: this.keyId, token: this.o.feeToken });
    return { remaining, periodEnd: periodEnd !== undefined && periodEnd > 0n && periodEnd <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(periodEnd) : 0 };
  }

  async paymentReceipt(txHash: Hex): Promise<PaymentReceipt | undefined> {
    try {
      const r = await this.client.getTransactionReceipt({ hash: txHash });
      return { status: r.status === "success" ? "success" : "reverted", networkFee: networkFeeOf(r) ?? 0n };
    } catch (err) {
      if (err instanceof TransactionReceiptNotFoundError) return undefined;
      throw err;
    }
  }

  /**
   * Signs locally first, so the hash is known before anything is sent: a payment whose broadcast or receipt is
   * lost is reported as `unknown` with its hash, and the settler counts it against the limit (review M4).
   */
  async pay(lines: PaymentLine[]): Promise<{ txHash: Hex; gasUsed: bigint; networkFee?: bigint }> {
    if (lines.length === 0) throw new Error("nothing to pay");
    if (lines.length > MAX_LINES_PER_TX) throw new Error(`at most ${MAX_LINES_PER_TX} legs per transaction`);
    const gas = await this.gasFor(lines);
    const request = await this.client.prepareTransactionRequest({ account: this.account, calls: this.calls(lines), feeToken: this.o.feeToken, gas } as never);
    const serializer = this.client.chain.serializers?.transaction;
    const signed = (await this.account.signTransaction(request as never, { serializer } as never)) as Hex;
    let hash: Hex = keccak256(signed);
    try {
      hash = await this.client.sendRawTransaction({ serializedTransaction: signed });
    } catch (err) {
      // A JSON-RPC error answer means the node refused it; anything else (timeout, dropped connection) may have
      // reached the node.
      const refused = err instanceof BaseError && err.walk((e) => e instanceof RpcRequestError) !== null;
      if (refused) throw new PaymentError("the node refused the payment transaction", "not_sent", undefined, undefined, { cause: err });
      throw new PaymentError("the payment transaction may have been sent; no answer from the node", "unknown", hash, undefined, { cause: err });
    }
    let receipt;
    try {
      receipt = await this.client.waitForTransactionReceipt({ hash, timeout: this.o.receiptTimeoutMs ?? 120_000 });
    } catch (err) {
      throw new PaymentError("no receipt for the payment transaction", "unknown", hash, undefined, { cause: err });
    }
    const networkFee = networkFeeOf(receipt);
    if (receipt.status !== "success") {
      throw new PaymentError(`payment transaction reverted (gas used ${receipt.gasUsed} of ${gas})`, "reverted", hash, networkFee ?? 0n);
    }
    return { txHash: hash, gasUsed: receipt.gasUsed, ...(networkFee !== undefined ? { networkFee } : {}) };
  }
}

/** Fee units = gas * attodollars-per-gas / 1e12, rounded up (as feeReserve). */
function networkFeeOf(receipt: { gasUsed: bigint }): bigint | undefined {
  const price = (receipt as { effectiveGasPrice?: bigint }).effectiveGasPrice;
  return price === undefined ? undefined : (receipt.gasUsed * price + 999_999_999_999n) / 1_000_000_000_000n;
}
