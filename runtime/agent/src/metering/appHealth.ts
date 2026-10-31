// Polls each app's healthcheck URL. The results feed the content-free health report, and for
// `metering.source: heartbeat` apps every healthy interval is billed as app-hour seconds, except while the
// routes show the payment-needed page (payments-7): the customer cannot reach the apps then, so that time
// is never billed, then or later.
import type { AppMeta } from "../context.js";
import { localRequest, parseEndpoint } from "../http.js";
import { errorFields, type Logger } from "../log.js";
import type { Ledger } from "./ledger.js";

export type AppStatus = "healthy" | "unhealthy" | "unknown";
export type Probe = (url: string) => Promise<boolean>;

export const httpProbe: Probe = async (url) => {
  const u = new URL(url);
  try {
    const res = await localRequest(parseEndpoint(u.origin), `${u.pathname}${u.search}`, { timeoutMs: 5000 });
    return res.status >= 200 && res.status < 400;
  } catch {
    return false;
  }
};

interface AppPollState {
  status: AppStatus;
  lastHealthyAt?: number;
}

export class AppHealthPoller {
  private readonly states = new Map<string, AppPollState>();
  constructor(
    private readonly apps: AppMeta[],
    private readonly deps: {
      ledger?: Ledger;
      log: Logger;
      intervalSec: number;
      probe?: Probe;
      /** False while the routes show the payment-needed page: app-hours are not recorded (payments-7). */
      billable?: () => boolean;
    },
  ) {
    for (const a of apps) this.states.set(a.id, { status: "unknown" });
  }

  status(): Record<string, AppStatus> {
    return Object.fromEntries([...this.states].map(([id, s]) => [id, s.status]));
  }

  /** One polling round. Billable seconds are the time between two consecutive healthy polls, capped at 2 intervals. */
  async pollOnce(now: number): Promise<void> {
    const probe = this.deps.probe ?? httpProbe;
    await Promise.all(
      this.apps.map(async (app) => {
        if (!app.healthcheck) return;
        const st = this.states.get(app.id) as AppPollState;
        const healthy = await probe(app.healthcheck);
        if (!healthy) {
          if (st.status !== "unhealthy") this.deps.log.warn("app unhealthy", { app: app.id });
          st.status = "unhealthy";
          st.lastHealthyAt = undefined;
          return;
        }
        if (st.status !== "healthy") this.deps.log.info("app healthy", { app: app.id });
        st.status = "healthy";
        // While not billable the poll still moves lastHealthyAt, so the next billed interval starts from it.
        const billable = this.deps.billable?.() ?? true;
        if (billable && app.metering?.source === "heartbeat" && this.deps.ledger && st.lastHealthyAt !== undefined) {
          const seconds = Math.min(now - st.lastHealthyAt, 2 * this.deps.intervalSec);
          if (seconds > 0) {
            try {
              await this.deps.ledger.record(app.id, "app_hour", BigInt(seconds), now);
            } catch (err) {
              this.deps.log.error("app-hour accounting failed", { app: app.id, ...errorFields(err) });
            }
          }
        }
        st.lastHealthyAt = now;
      }),
    );
  }
}
