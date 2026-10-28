import { errorMessage, silentLogger, type Logger } from './log.js';

// Counts successful pages and reports them to sealed-agent (INTERFACES 11) in batches:
// one POST {"app":"scraper","unit":"pages","quantity":N} per flush instead of one per page.
// Unsent counts stay pending and are retried with backoff, so a slow or restarting agent never
// loses pages that were already crawled.

export const USAGE_EVENTS_PATH = '/v1/usage-events';

export interface UsageEvent {
  app: 'scraper';
  unit: 'pages';
  quantity: number;
}

export interface MeterOptions {
  agentUrl: string;
  flushMs: number;
  maxBatch: number;
  fetch?: typeof fetch;
  log?: Logger;
  maxBackoffMs?: number;
  requestTimeoutMs?: number;
  now?: () => number;
}

export interface Meter {
  add(pages?: number): void;
  flush(): Promise<void>;
  start(): void;
  stop(): Promise<void>;
}

export const noopMeter: Meter = {
  add() {},
  async flush() {},
  start() {},
  async stop() {},
};

export class UsageMeter implements Meter {
  private pending = 0;
  private sent = 0;
  private failures = 0;
  private nextAttemptAt = 0;
  private inFlight: Promise<void> | null = null;
  private timer: NodeJS.Timeout | undefined;
  private readonly url: string;
  private readonly fetchImpl: typeof fetch;
  private readonly log: Logger;
  private readonly maxBackoffMs: number;
  private readonly requestTimeoutMs: number;
  private readonly now: () => number;

  constructor(private readonly options: MeterOptions) {
    this.url = new URL(USAGE_EVENTS_PATH, options.agentUrl).toString();
    this.fetchImpl = options.fetch ?? fetch;
    this.log = options.log ?? silentLogger;
    this.maxBackoffMs = options.maxBackoffMs ?? 60_000;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 5_000;
    this.now = options.now ?? Date.now;
  }

  get pendingPages(): number {
    return this.pending;
  }

  get sentPages(): number {
    return this.sent;
  }

  add(pages = 1): void {
    if (!Number.isInteger(pages) || pages <= 0) return;
    this.pending += pages;
    if (this.pending >= this.options.maxBatch) void this.flush();
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), this.options.flushMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    if (this.inFlight) await this.inFlight;
    this.nextAttemptAt = 0;
    await this.flush();
    if (this.pending > 0) this.log.warn('usage not delivered before shutdown', { pages: this.pending });
  }

  flush(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    if (this.pending === 0 || this.now() < this.nextAttemptAt) return Promise.resolve();
    const quantity = this.pending;
    this.pending = 0;
    this.inFlight = this.post(quantity)
      .then(() => {
        this.sent += quantity;
        this.failures = 0;
        this.nextAttemptAt = 0;
      })
      .catch((err: unknown) => {
        this.pending += quantity;
        this.failures += 1;
        const backoff = Math.min(this.maxBackoffMs, this.options.flushMs * 2 ** (this.failures - 1));
        this.nextAttemptAt = this.now() + backoff;
        this.log.warn('usage report failed, will retry', { pages: this.pending, retryInMs: backoff, error: errorMessage(err) });
      })
      .finally(() => {
        this.inFlight = null;
      });
    return this.inFlight;
  }

  private async post(quantity: number): Promise<void> {
    const event: UsageEvent = { app: 'scraper', unit: 'pages', quantity };
    const res = await this.fetchImpl(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(this.requestTimeoutMs),
    });
    if (!res.ok) throw new Error(`agent answered ${res.status}`);
  }
}
