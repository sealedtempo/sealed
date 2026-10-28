// Fee payments on Tempo (spec 7.2-7.3, D-026). One Tempo transaction per app batches
// TIP-20 approve(FeeSplitter, exact) and one FeeSplitter.payFees per unpaid report.
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
  amount: bigint;
  usageHash: Hex;
}

export interface Budget {
  /** Spendable by the payer before limits and balance run out, after `reserve`. */
  spendable: bigint;
  /** Content-free reason when nothing can be spent. */
  problem?: "access_key_missing" | "access_key_revoked" | "access_key_expired" | "spend_limit" | "insufficient_balance";
}

export interface FeePayer {
  readonly mode: SettlementMode;
  /** Address whose tokens pay (customer in access-key mode). */
  readonly payer: Address;
  deploymentActive(): Promise<boolean>;
  appInDeployment(appId: Hex): Promise<boolean>;
  perPaymentCap(): Promise<bigint>;
  dailyRemaining(): Promise<bigint>;
  isPaid(usageHash: Hex, appId: Hex): Promise<boolean>;
  /** Estimated network fee in token base units for a batch of `lines`. */
  feeReserve(lines: PaymentLine[]): Promise<bigint>;
  budget(reserve: bigint): Promise<Budget>;
  pay(lines: PaymentLine[]): Promise<{ txHash: Hex; gasUsed: bigint }>;
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
  receiptTimeoutMs?: number;
}

export class TempoFeePayer implements FeePayer {
  readonly mode: SettlementMode;
  readonly payer: Address;
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
  }

  /** The access key id (enclave signer address); equals `payer` in enclave-account mode. */
  get keyId(): Address {
    const a = this.account as { accessKeyAddress?: Address; address: Address };
    return (a.accessKeyAddress ?? a.address).toLowerCase() as Address;
  }

  async deploymentActive(): Promise<boolean> {
    const [status] = await this.client.readContract({
      address: this.o.deploymentRegistry,
      abi: deploymentRegistryAbi,
      functionName: "deploymentParties",
      args: [this.o.deploymentId],
    });
    return status === 1;
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

  async isPaid(usageHash: Hex, appId: Hex): Promise<boolean> {
    return this.client.readContract({ address: this.o.feeSplitter, abi: feeSplitterAbi, functionName: "usagePaid", args: [usageHash, appId] });
  }

  private calls(lines: PaymentLine[]) {
    const total = lines.reduce((s, l) => s + l.amount, 0n);
    return [
      Actions.token.approve.call({ token: this.o.feeToken, spender: this.o.feeSplitter, amount: total }),
      ...lines.map((l) => ({
        to: this.o.feeSplitter,
        data: encodeFunctionData({
          abi: feeSplitterAbi,
          functionName: "payFees",
          args: [this.o.deploymentId, l.appId, this.o.feeToken, l.amount, l.usageHash],
        }),
      })),
    ];
  }

  private async gasFor(lines: PaymentLine[]): Promise<bigint> {
    const estimate = await this.client.estimateGas({ account: this.account, calls: this.calls(lines), feeToken: this.o.feeToken } as never);
    const pct = BigInt(this.o.gasHeadroomPct ?? 50);
    return estimate + (estimate * pct) / 100n + 50_000n;
  }

  async feeReserve(lines: PaymentLine[]): Promise<bigint> {
    const [gas, price] = await Promise.all([this.gasFor(lines), this.client.getGasPrice()]);
    // Fee units = gas * attodollars-per-gas / 1e12, doubled for base fee movement.
    return (gas * price * 2n + 999_999_999_999n) / 1_000_000_000_000n;
  }

  async budget(reserve: bigint): Promise<Budget> {
    const balance = await this.client.readContract({ address: this.o.feeToken, abi: tip20Abi, functionName: "balanceOf", args: [this.payer] });
    let spendable = balance - reserve;
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
          if (byLimit <= 0n) return { spendable: 0n, problem: "spend_limit" };
          spendable = byLimit;
        }
      }
    }
    if (spendable <= 0n) return { spendable: 0n, problem: "insufficient_balance" };
    return { spendable };
  }

  async pay(lines: PaymentLine[]): Promise<{ txHash: Hex; gasUsed: bigint }> {
    if (lines.length === 0) throw new Error("nothing to pay");
    const gas = await this.gasFor(lines);
    const hash = await this.client.sendTransaction({ account: this.account, calls: this.calls(lines), feeToken: this.o.feeToken, gas } as never);
    const receipt = await this.client.waitForTransactionReceipt({ hash, timeout: this.o.receiptTimeoutMs ?? 120_000 });
    if (receipt.status !== "success") throw Object.assign(new Error(`payment transaction reverted`), { txHash: hash });
    return { txHash: hash, gasUsed: receipt.gasUsed };
  }
}
