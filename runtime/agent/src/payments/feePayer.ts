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
import { createClient, encodeFunctionData, http, publicActions, walletActions } from "viem";
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
  /** `networkFee` is what the transaction paid in fee-token base units (it counts against an access-key limit). */
  pay(lines: PaymentLine[]): Promise<{ txHash: Hex; gasUsed: bigint; networkFee?: bigint }>;
  /** End of the access key's current spending-limit period (unix seconds); undefined without a periodic limit. */
  limitPeriodEnd?(): Promise<number | undefined>;
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
  /** Lower bound for the gas limit. Local anvil 1.7.1 (Tempo T4 rules) under-estimates batches with new storage slots. */
  minGas?: bigint;
  receiptTimeoutMs?: number;
}

/**
 * Gas floor per batch: unvalidated against a real Tempo node (anvil 1.7.1 returns a constant estimate
 * for 0x76 batches). Each new storage slot costs 250k gas on Tempo (tempo-chain notes): a leg can
 * create usagePaid, usageToken, the day's dailyPaid and two credit slots; approve can create the
 * allowance slot and a fresh account pays 271k for its first transaction.
 */
export const BASE_GAS_FLOOR = 600_000n;
export const PER_LINE_GAS_FLOOR = 1_300_000n;

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
    // Fee units = gas * attodollars-per-gas / 1e12, doubled for base fee movement.
    return (gas * price * 2n + 999_999_999_999n) / 1_000_000_000_000n;
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

  async limitPeriodEnd(): Promise<number | undefined> {
    if (this.mode !== "access-key") return undefined;
    const { periodEnd } = await this.client.accessKey.getRemainingLimit({ account: this.o.customer, accessKey: this.keyId, token: this.o.feeToken });
    return periodEnd !== undefined && periodEnd > 0n ? Number(periodEnd) : undefined;
  }

  async pay(lines: PaymentLine[]): Promise<{ txHash: Hex; gasUsed: bigint; networkFee?: bigint }> {
    if (lines.length === 0) throw new Error("nothing to pay");
    if (lines.length > MAX_LINES_PER_TX) throw new Error(`at most ${MAX_LINES_PER_TX} legs per transaction`);
    const gas = await this.gasFor(lines);
    const hash = await this.client.sendTransaction({ account: this.account, calls: this.calls(lines), feeToken: this.o.feeToken, gas } as never);
    const receipt = await this.client.waitForTransactionReceipt({ hash, timeout: this.o.receiptTimeoutMs ?? 120_000 });
    if (receipt.status !== "success") {
      throw Object.assign(new Error(`payment transaction reverted (gas used ${receipt.gasUsed} of ${gas})`), { txHash: hash });
    }
    // Fee units = gas * attodollars-per-gas / 1e12, rounded up (as feeReserve).
    const price = (receipt as { effectiveGasPrice?: bigint }).effectiveGasPrice;
    const networkFee = price === undefined ? undefined : (receipt.gasUsed * price + 999_999_999_999n) / 1_000_000_000_000n;
    return { txHash: hash, gasUsed: receipt.gasUsed, ...(networkFee !== undefined ? { networkFee } : {}) };
  }
}
