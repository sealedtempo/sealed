// payments-5: a same-salt stack upgrade (D-058, `sealed deploy --replace`) boots on the old data disk as a new
// deployment, with a new deploymentId. The old deployment's usage can only be reported and paid under its own id,
// and it stays Active onchain, so the agent keeps its ledger and payment status beside the new ones instead of
// dropping them: it cuts and reports the period that was still open, keeps paying the legs, and keeps the routes on
// the payment-needed page while the old deployment needs payment. Otherwise an upgrade would wipe unpaid fees and a
// payment-needed page.
import { emptyLedgerState, type LedgerState } from "../metering/ledger.js";
import type { AgentState, PaymentStatus, PreviousDeployment } from "../state.js";

/** At most this many earlier deployments are kept (the oldest is dropped beyond it, with an error log). */
export const MAX_PREVIOUS_DEPLOYMENTS = 8;

const isEmpty = (open: LedgerState["open"]) => Object.values(open).every((units) => Object.values(units).every((q) => !q || q === "0"));

/** Whether a ledger still has usage to report or legs to pay. */
export function outstanding(ledger: LedgerState): boolean {
  if (!isEmpty(ledger.open)) return true;
  if ((ledger.held ?? []).some((h) => !isEmpty(h.open))) return true;
  return ledger.reports.some((r) => !r.void && (!r.submitted || Object.values(r.payments).some((p) => p.status === "unpaid")));
}

/** The app slugs a kept ledger knows, with the current deployment's, in report order (sorted by id). */
export function ledgerApps(ledger: LedgerState, current: string[]): string[] {
  const apps = new Set(current);
  const addOpen = (open: LedgerState["open"]) => {
    for (const app of Object.keys(open)) apps.add(app);
  };
  addOpen(ledger.open);
  for (const h of ledger.held ?? []) addOpen(h.open);
  for (const key of Object.keys(ledger.carry)) apps.add(key.slice(0, key.lastIndexOf(":")));
  for (const r of ledger.reports) for (const app of Object.keys(r.payments)) apps.add(app);
  return [...apps].sort();
}

export interface DeploymentSwitch {
  /** The deployment whose state was moved aside (kept when it still owes something). */
  previous?: string;
  kept: boolean;
  /** Unpaid legs of the deployment kept aside. */
  keptUnpaidLegs: number;
  /** The deployment booting now was one of the kept ones: its own ledger and status came back. */
  restored: boolean;
  /** Kept deployments dropped beyond MAX_PREVIOUS_DEPLOYMENTS, with their unpaid legs. */
  dropped: { deploymentId: string; unpaidLegs: number }[];
}

const unpaidLegs = (l: LedgerState) => l.reports.filter((r) => !r.void).flatMap((r) => Object.values(r.payments)).filter((p) => p.status === "unpaid").length;

/**
 * At boot, when the state on the disk belongs to another deployment: keeps that deployment's ledger and payment
 * status aside while it still owes something, and starts the booting deployment from its own kept state (a return
 * to an earlier stack) or from a fresh one.
 */
export function switchDeployment(state: AgentState, deploymentId: string, now: number): DeploymentSwitch {
  const result: DeploymentSwitch = { kept: false, keptUnpaidLegs: 0, restored: false, dropped: [] };
  const prior = state.deploymentId;
  if (prior === undefined || prior === deploymentId) {
    state.deploymentId = deploymentId;
    return result;
  }
  result.previous = prior;
  const kept = state.previous ?? [];
  const back = kept.find((p) => p.deploymentId === deploymentId);
  const rest: PreviousDeployment[] = kept.filter((p) => p !== back && p.deploymentId !== prior);
  if (outstanding(state.ledger)) {
    rest.push({ deploymentId: prior, since: now, ledger: state.ledger, payments: state.payments });
    result.kept = true;
    result.keptUnpaidLegs = unpaidLegs(state.ledger);
  }
  while (rest.length > MAX_PREVIOUS_DEPLOYMENTS) {
    const old = rest.shift() as PreviousDeployment;
    result.dropped.push({ deploymentId: old.deploymentId, unpaidLegs: unpaidLegs(old.ledger) });
  }
  if (rest.length > 0) state.previous = rest;
  else delete state.previous;
  const fresh: PaymentStatus = { failingSince: null, paymentNeeded: false };
  state.ledger = back?.ledger ?? emptyLedgerState(now);
  state.payments = back?.payments ?? fresh;
  result.restored = back !== undefined;
  state.deploymentId = deploymentId;
  return result;
}
