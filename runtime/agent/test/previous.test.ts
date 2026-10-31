// payments-5: what a boot does with the state of another deployment on the same data disk (D-058 upgrades).
import { describe, expect, it } from "vitest";
import { emptyLedgerState, type LedgerState } from "../src/metering/ledger.js";
import { ledgerApps, MAX_PREVIOUS_DEPLOYMENTS, outstanding, switchDeployment } from "../src/payments/previous.js";
import { type AgentState, emptyState } from "../src/state.js";

const T = 1_800_000_000;
const id = (n: number) => `0x${n.toString(16).padStart(64, "0")}`;

function owing(fee = "1000"): LedgerState {
  const l = emptyLedgerState(T);
  l.reports.push({
    report: { deploymentId: id(1), periodStart: T, periodEnd: T + 3600, items: [] } as never,
    signature: "0x",
    usageHash: `0x${"aa".repeat(32)}`,
    createdAt: T + 3600,
    submitted: true,
    payments: { "llm-gateway": { appId: `0x${"bb".repeat(32)}`, fee, status: "unpaid" } },
  });
  return l;
}

const at = (deploymentId: string, ledger: LedgerState, paymentNeeded = false): AgentState => ({
  ...emptyState(T),
  deploymentId,
  ledger,
  payments: { failingSince: paymentNeeded ? T : null, paymentNeeded },
});

describe("payments-5: switching the disk's state to another deployment", () => {
  it("keeps a deployment that owes fees, with its status, and starts the new one fresh", () => {
    const old = owing();
    const s = at(id(1), old, true);
    const r = switchDeployment(s, id(2), T + 10);
    expect(r).toMatchObject({ previous: id(1), kept: true, keptUnpaidLegs: 1, restored: false, dropped: [] });
    expect(s.deploymentId).toBe(id(2));
    expect(s.previous).toEqual([{ deploymentId: id(1), since: T + 10, ledger: old, payments: { failingSince: T, paymentNeeded: true } }]);
    expect(s.ledger).toEqual(emptyLedgerState(T + 10));
    expect(s.payments).toEqual({ failingSince: null, paymentNeeded: false });
  });

  it("keeps a period that was still open, and drops a deployment that owes nothing", () => {
    const open = emptyLedgerState(T);
    open.open = { crm: { app_hour: "1200" } };
    expect(outstanding(open)).toBe(true);
    const held = emptyLedgerState(T);
    held.held = [{ periodStart: T, open: { crm: { app_hour: "60" } } }];
    expect(outstanding(held)).toBe(true);
    expect(outstanding(emptyLedgerState(T))).toBe(false);
    const s = at(id(1), emptyLedgerState(T));
    expect(switchDeployment(s, id(2), T)).toMatchObject({ previous: id(1), kept: false });
    expect(s.previous).toBeUndefined();
  });

  it("gives a returning deployment its own ledger back, and is a no-op for the same deployment", () => {
    const a = owing("7");
    const s = at(id(1), a);
    switchDeployment(s, id(2), T);
    s.ledger = owing("9");
    const r = switchDeployment(s, id(1), T + 5);
    expect(r).toMatchObject({ restored: true, kept: true });
    expect(s.ledger).toBe(a);
    expect(s.previous?.map((p) => p.deploymentId)).toEqual([id(2)]);
    const same = switchDeployment(s, id(1), T + 6);
    expect(same).toMatchObject({ kept: false, restored: false });
    expect(same.previous).toBeUndefined();
    expect(s.ledger).toBe(a);
  });

  it(`keeps at most ${MAX_PREVIOUS_DEPLOYMENTS} earlier deployments, dropping the oldest`, () => {
    const s = at(id(1), owing());
    for (let n = 2; n <= MAX_PREVIOUS_DEPLOYMENTS + 2; n++) {
      const r = switchDeployment(s, id(n), T + n);
      if (n === MAX_PREVIOUS_DEPLOYMENTS + 2) expect(r.dropped).toEqual([{ deploymentId: id(1), unpaidLegs: 1 }]);
      s.ledger = owing();
    }
    expect(s.previous).toHaveLength(MAX_PREVIOUS_DEPLOYMENTS);
  });

  it("knows the apps of a kept ledger, the current ones included, in report order", () => {
    const l = owing();
    l.open = { crm: { app_hour: "5" } };
    l.carry = { "internal-tools:app_hour": "3" };
    expect(ledgerApps(l, ["scraper"])).toEqual(["crm", "internal-tools", "llm-gateway", "scraper"]);
  });
});
