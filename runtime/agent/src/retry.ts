import { type Clock, systemClock } from "./clock.js";
import { errorFields, type Logger, silentLogger } from "./log.js";

export interface RetryOptions {
  /** Attempts including the first; Infinity retries until success or abort. */
  attempts?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  /** Return false to stop retrying on a given error. */
  retryIf?: (err: unknown) => boolean;
  signal?: AbortSignal;
  clock?: Clock;
  log?: Logger;
  what?: string;
}

/** Runs fn with exponential backoff (factor 2, full jitter up to the current delay). */
export async function withRetry<T>(fn: (attempt: number) => Promise<T>, opts: RetryOptions = {}): Promise<T> {
  const attempts = opts.attempts ?? 5;
  const clock = opts.clock ?? systemClock;
  const log = opts.log ?? silentLogger;
  let delay = opts.initialDelayMs ?? 1000;
  const max = opts.maxDelayMs ?? 300_000;
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      if (opts.signal?.aborted) throw err;
      if (attempt >= attempts || (opts.retryIf && !opts.retryIf(err))) throw err;
      const wait = Math.round(delay / 2 + Math.random() * (delay / 2));
      log.warn(`${opts.what ?? "operation"} failed, retrying`, { attempt, waitMs: wait, ...errorFields(err) });
      await clock.sleep(wait, opts.signal);
      delay = Math.min(delay * 2, max);
    }
  }
}
