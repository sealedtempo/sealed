import type { Address, Hex } from "@sealed/core";
import { type Budget, type DeploymentStatus, type FeePayer, PaymentError, type PaymentLine, type PaymentReceipt, type SpendLimit } from "../../src/payments/feePayer.js";

export const PATH_USD = "0x20c0000000000000000000000000000000000000" as Address;

/**
 * In-memory FeePayer for flows that do not need a chain. `onchain` models FeeSplitter.usagePaid and
 * usageToken with the contract's rules: payFees opens an unpaid leg, topUpFees raises an opened leg
 * in the same token to a higher total, every leg total is at most `cap` and a batch at most `daily`.
 * Unlike anvil, the estimate reverts whenever the batch would.
 */
export class FakePayer implements FeePayer {
  readonly mode = "access-key" as const;
  readonly payer = "0x90f79bf6eb2c4f870365e785982e1f101e93b906" as const;
  readonly feeToken = PATH_USD;
  paid: PaymentLine[][] = [];
  estimates: PaymentLine[][] = [];
  onchain = new Map<string, bigint>();
  tokens = new Map<string, Address>();
  deployment: DeploymentStatus = "active";
  /** Makes deploymentStatus() throw, like an RPC outage or a blocked firewall. */
  rpcDown = false;
  inDeployment = true;
  cap = 5_000_000n;
  daily = 20_000_000n;
  budgetResult: Budget = { spendable: 1_000_000_000n };
  reserve = 1000n;
  /** What each payment transaction paid in network fees (counts against the spend limit, D-048). */
  networkFee = 2_000n;
  /** The access key's limit as the chain reports it; undefined = a key without limits (config applies). */
  limit: SpendLimit | undefined;
  failNext = 0;
  /** The next payment fails like a mined revert (`reverted`) or a lost broadcast or receipt (`unknown`). */
  failNextAs: "reverted" | "unknown" | undefined;
  /** Receipts paymentReceipt() reports, by transaction hash. */
  receipts = new Map<string, PaymentReceipt>();
  private key(usageHash: Hex, appId: Hex) {
    return `${usageHash}:${appId}`;
  }
  /** A payment made outside the agent (the customer from its wallet, or a console payment). */
  payDirectly(usageHash: Hex, appId: Hex, amount: bigint, token: Address = PATH_USD) {
    const k = this.key(usageHash, appId);
    this.onchain.set(k, (this.onchain.get(k) ?? 0n) + amount);
    if (!this.tokens.has(k)) this.tokens.set(k, token);
  }
  private chainRead() {
    if (this.rpcDown) throw new Error("fetch failed: connect ETIMEDOUT rpc.tempo.xyz:443");
  }
  async deploymentStatus() {
    this.chainRead();
    return this.deployment;
  }
  async appInDeployment() {
    this.chainRead();
    return this.inDeployment;
  }
  async perPaymentCap() {
    this.chainRead();
    return this.cap;
  }
  async dailyRemaining() {
    this.chainRead();
    return this.daily;
  }
  async paidAmount(usageHash: Hex, appId: Hex) {
    this.chainRead();
    return this.onchain.get(this.key(usageHash, appId)) ?? 0n;
  }
  async legToken(usageHash: Hex, appId: Hex) {
    this.chainRead();
    return this.tokens.get(this.key(usageHash, appId)) ?? ("0x0000000000000000000000000000000000000000" as Address);
  }
  /** FeeSplitter's checks for a batch, as the contract would revert on them. */
  private check(lines: PaymentLine[]) {
    let total = 0n;
    for (const l of lines) {
      const k = this.key(l.usageHash, l.appId);
      const now = this.onchain.get(k) ?? 0n;
      if (l.paid + l.amount > this.cap) throw new Error("execution reverted: PerPaymentCapExceeded");
      if (l.paid === 0n && now !== 0n) throw new Error("execution reverted: UsageAlreadyPaid");
      if (l.paid > 0n && now === 0n) throw new Error("execution reverted: UsageNotPaid");
      if (l.paid > 0n && l.paid + l.amount <= now) throw new Error("execution reverted: NothingToTopUp");
      if (l.paid > 0n && this.tokens.get(k) !== this.feeToken) throw new Error("execution reverted: UsageTokenMismatch");
      total += l.paid + l.amount - now;
    }
    if (total > this.daily) throw new Error("execution reverted: DailyCapExceeded");
  }
  async feeReserve(lines: PaymentLine[]) {
    this.estimates.push(lines);
    this.check(lines);
    return this.reserve * BigInt(lines.length);
  }
  async budget(reserve: bigint): Promise<Budget> {
    if (this.budgetResult.problem) return this.budgetResult;
    const spendable = this.budgetResult.spendable - reserve;
    return spendable > 0n ? { spendable } : { spendable: 0n, problem: "insufficient_balance" };
  }
  async pay(lines: PaymentLine[]) {
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("execution reverted");
    }
    if (this.failNextAs) {
      const outcome = this.failNextAs;
      this.failNextAs = undefined;
      const txHash = `0x${"ee".repeat(31)}${String(this.paid.length).padStart(2, "0")}` as Hex;
      throw new PaymentError(`payment ${outcome}`, outcome, txHash, outcome === "reverted" ? this.networkFee : undefined);
    }
    // The batch is atomic: check every line against FeeSplitter's rules before recording any.
    this.check(lines);
    for (const l of lines) {
      const k = this.key(l.usageHash, l.appId);
      this.daily -= l.paid + l.amount - (this.onchain.get(k) ?? 0n);
      this.onchain.set(k, l.paid + l.amount);
      if (!this.tokens.has(k)) this.tokens.set(k, this.feeToken);
    }
    this.paid.push(lines);
    return { txHash: `0x${String(this.paid.length).padStart(64, "0")}` as Hex, gasUsed: 100_000n, networkFee: this.networkFee };
  }
  async spendLimit() {
    this.chainRead();
    return this.limit;
  }
  async paymentReceipt(txHash: Hex) {
    this.chainRead();
    return this.receipts.get(txHash);
  }
}
