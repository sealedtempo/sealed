import type { Hex } from "@sealed/core";
import type { Budget, FeePayer, PaymentLine } from "../../src/payments/feePayer.js";

/** In-memory FeePayer for flows that do not need a chain. */
export class FakePayer implements FeePayer {
  readonly mode = "access-key" as const;
  readonly payer = "0x90f79bf6eb2c4f870365e785982e1f101e93b906" as const;
  paid: PaymentLine[][] = [];
  active = true;
  cap = 5_000_000n;
  daily = 20_000_000n;
  budgetResult: Budget = { spendable: 1_000_000_000n };
  failNext = 0;
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
  async isPaid(usageHash: Hex, appId: Hex) {
    return this.paid.some((b) => b.some((l) => l.usageHash === usageHash && l.appId === appId));
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
    this.paid.push(lines);
    this.daily -= lines.reduce((s, l) => s + l.amount, 0n);
    return { txHash: `0x${String(this.paid.length).padStart(64, "0")}` as Hex, gasUsed: 100_000n };
  }
}
