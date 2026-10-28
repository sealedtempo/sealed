import type { Clock } from "./clock.js";
import { errorFields, type Logger } from "./log.js";

/** Runs fn every intervalMs (after the previous run finished) until the signal aborts. */
export function every(
  name: string,
  intervalMs: number,
  fn: () => Promise<unknown>,
  opts: { clock: Clock; log: Logger; signal: AbortSignal; runFirst?: boolean },
): Promise<void> {
  return (async () => {
    let first = opts.runFirst ?? false;
    while (!opts.signal.aborted) {
      if (!first) {
        try {
          await opts.clock.sleep(intervalMs, opts.signal);
        } catch {
          return;
        }
      }
      first = false;
      try {
        await fn();
      } catch (err) {
        opts.log.error(`${name} failed`, errorFields(err));
      }
    }
  })();
}
