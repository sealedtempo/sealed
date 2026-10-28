import type { Hex } from "@sealed/core";
import type { Budget, FeePayer, PaymentLine } from "../../src/payments/feePayer.js";

/**
 * In-memory FeePayer for flows that do not need a chain. `onchain` models FeeSplitter.usagePaid with
 * the contract's rules: payFees opens an unpaid leg, topUpFees raises an opened leg to a higher total.
 */
export class FakePayer implements FeePayer {
  readonly mode = "access-key" as const;
  readonly payer = "0x90f79bf6eb2c4f870365e785982e1f101e93b906" as const;
  paid: PaymentLine[][] = [];
  onchain = new Map<string, bigint>();
  active = true;
  cap = 5_000_000n;
  daily = 20_000_000n;
  budgetResult: Budget = { spendable: 1_000_000_000n };
  failNext = 0;
  private key(usageHash: Hex, appId: Hex) {
    return `${usageHash}:${appId}`;
  }
  /** A payment made outside the agent (the customer from its wallet, or a console payment). */
  payDirectly(usageHash: Hex, appId: Hex, amount: bigint) {
    const k = this.key(usageHash, appId);
    this.onchain.set(k, (this.onchain.get(k) ?? 0n) + amount);
  }
  async deploymentActive() {
    return this.active;
  }
  async appInDeployment() {
    return true;
  }
  async perPaymentCap() {
    return this.cap;
  }
  async dailyRemaining() {
    return this.daily;
  }
  async paidAmount(usageHash: Hex, appId: Hex) {
    return this.onchain.get(this.key(usageHash, appId)) ?? 0n;
  }
  async feeReserve() {
    return 1000n;
  }
  async budget() {
    return this.budgetResult;
  }
  async pay(lines: PaymentLine[]) {
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("execution reverted");
    }
    // The batch is atomic: check every line against FeeSplitter's rules before recording any.
    for (const l of lines) {
      const now = this.onchain.get(this.key(l.usageHash, l.appId)) ?? 0n;
      if (l.paid === 0n && now !== 0n) throw new Error("execution reverted: UsageAlreadyPaid");
      if (l.paid > 0n && now === 0n) throw new Error("execution reverted: UsageNotPaid");
      if (l.paid > 0n && l.paid + l.amount <= now) throw new Error("execution reverted: NothingToTopUp");
    }
    for (const l of lines) this.onchain.set(this.key(l.usageHash, l.appId), l.paid + l.amount);
    this.paid.push(lines);
    this.daily -= lines.reduce((s, l) => s + l.amount, 0n);
    return { txHash: `0x${String(this.paid.length).padStart(64, "0")}` as Hex, gasUsed: 100_000n };
  }
}
