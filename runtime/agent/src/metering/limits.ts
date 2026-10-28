// Bounds on callback usage. An app is its own metering source, so a buggy or compromised app can
// still over-report, but only within these limits: per event, per app and unit per clock hour, and
// (in the ledger) the number of reports one event may cut. Over the limit, the event is rejected and
// nothing is recorded.
import type { UsageUnitName } from "@sealed/core";

export interface UnitLimit {
  perEvent: bigint;
  perHour: bigint;
}

/**
 * tokens: one LLM call stays far below 10M tokens; 1B tokens an hour is 200 USD at the default price.
 * pages: one event per page or per small batch. app_hour: seconds of uptime, at most an hour per hour
 * (twice that for clock skew between reporters).
 */
export const USAGE_LIMITS: Record<UsageUnitName, UnitLimit> = {
  tokens: { perEvent: 10_000_000n, perHour: 1_000_000_000n },
  pages: { perEvent: 10_000n, perHour: 1_000_000n },
  app_hour: { perEvent: 3_600n, perHour: 7_200n },
};

export class UsageLimitError extends Error {
  constructor(
    message: string,
    readonly status: 422 | 429,
  ) {
    super(message);
  }
}

export class UsageLimiter {
  private readonly windows = new Map<string, { hour: number; used: bigint }>();
  constructor(private readonly limits: Record<UsageUnitName, UnitLimit> = USAGE_LIMITS) {}

  /** Throws when the event is over a limit; otherwise counts it. */
  admit(app: string, unit: UsageUnitName, quantity: bigint, now: number): void {
    const l = this.limits[unit];
    if (quantity > l.perEvent) throw new UsageLimitError(`quantity ${quantity} is above the per-event limit ${l.perEvent} for ${unit}`, 422);
    const key = `${app}:${unit}`;
    const hour = Math.floor(now / 3600);
    const w = this.windows.get(key);
    const used = w && w.hour === hour ? w.used : 0n;
    if (used + quantity > l.perHour) throw new UsageLimitError(`${app} is above its hourly ${unit} limit`, 429);
    this.windows.set(key, { hour, used: used + quantity });
  }

  /** Gives back an admitted quantity that was not recorded after all. */
  release(app: string, unit: UsageUnitName, quantity: bigint, now: number): void {
    const w = this.windows.get(`${app}:${unit}`);
    if (w && w.hour === Math.floor(now / 3600)) w.used = w.used > quantity ? w.used - quantity : 0n;
  }
}
