import type { CrawlFn, CrawlSink } from '../crawl/types.js';
import type { RunStore, Run, RunStatus } from '../db/store.js';
import type { JobSpec } from '../job.js';
import { errorMessage, silentLogger, type Logger } from '../log.js';
import type { Meter } from '../meter.js';

export interface RunManagerOptions {
  store: RunStore;
  crawl: CrawlFn;
  meter: Meter;
  maxRuns: number;
  log?: Logger;
  // Events (failed and skipped URLs) kept per run; counters keep counting past this.
  maxEventsPerRun?: number;
}

export type CancelResult = 'cancelled' | 'stopping' | 'not-found' | 'finished';

export const INTERRUPTED = 'interrupted: the scraper restarted while this run was in progress';
export const SHUTDOWN = 'stopped: the scraper shut down while this run was in progress';

// Owns run execution: a FIFO of queued runs, at most maxRuns crawls at once, cancellation,
// and recovery of runs left behind by a previous process.
export class RunManager {
  private readonly queue: string[] = [];
  private readonly active = new Map<string, { abort: AbortController; done: Promise<void> }>();
  private readonly log: Logger;
  private readonly maxEvents: number;
  private accepting = true;

  constructor(private readonly options: RunManagerOptions) {
    this.log = options.log ?? silentLogger;
    this.maxEvents = options.maxEventsPerRun ?? 500;
  }

  get activeCount(): number {
    return this.active.size;
  }

  async start(): Promise<void> {
    const interrupted = await this.options.store.failInterrupted(INTERRUPTED);
    if (interrupted > 0) this.log.warn('marked interrupted runs as failed', { runs: interrupted });
    for (const id of await this.options.store.listRunIds('queued')) this.enqueue(id);
  }

  async submit(spec: JobSpec): Promise<Run> {
    if (!this.accepting) throw new Error('the scraper is shutting down');
    const run = await this.options.store.createRun(spec);
    this.log.info('run queued', { run: run.id, crawler: spec.crawler, maxPages: spec.max_pages });
    this.enqueue(run.id);
    return run;
  }

  async cancel(id: string): Promise<CancelResult> {
    const running = this.active.get(id);
    if (running) {
      running.abort.abort();
      return 'stopping';
    }
    if (await this.options.store.cancelQueued(id)) {
      const i = this.queue.indexOf(id);
      if (i >= 0) this.queue.splice(i, 1);
      return 'cancelled';
    }
    return (await this.options.store.getRun(id)) ? 'finished' : 'not-found';
  }

  // Waits for every active run to finish; with abort, active runs stop gracefully first.
  async shutdown({ abort = true } = {}): Promise<void> {
    this.accepting = false;
    this.queue.length = 0;
    const running = [...this.active.values()];
    if (abort) running.forEach((r) => r.abort.abort());
    await Promise.allSettled(running.map((r) => r.done));
  }

  async idle(): Promise<void> {
    while (this.active.size > 0 || this.queue.length > 0) {
      await Promise.allSettled([...this.active.values()].map((r) => r.done));
      await new Promise((resolve) => setImmediate(resolve));
    }
  }

  private enqueue(id: string): void {
    if (!this.queue.includes(id) && !this.active.has(id)) this.queue.push(id);
    this.pump();
  }

  private pump(): void {
    while (this.accepting && this.active.size < this.options.maxRuns && this.queue.length > 0) {
      const id = this.queue.shift()!;
      const abort = new AbortController();
      const done = this.execute(id, abort.signal).finally(() => {
        this.active.delete(id);
        this.pump();
      });
      this.active.set(id, { abort, done });
    }
  }

  private async execute(id: string, signal: AbortSignal): Promise<void> {
    const { store, crawl, meter } = this.options;
    try {
      const run = await store.getRun(id);
      if (!run || !(await store.markRunning(id))) return;
      this.log.info('run started', { run: id });
      const sink = this.sinkFor(id);
      let status: RunStatus = 'succeeded';
      let error: string | null = null;
      try {
        const summary = await crawl(run.spec, sink, signal);
        if (signal.aborted) [status, error] = this.accepting ? ['cancelled', null] : ['failed', SHUTDOWN];
        this.log.info('run finished', { run: id, status, finished: summary.requestsFinished, failed: summary.requestsFailed });
      } catch (err) {
        status = signal.aborted && this.accepting ? 'cancelled' : 'failed';
        error = signal.aborted && !this.accepting ? SHUTDOWN : errorMessage(err);
        this.log.error('run failed', { run: id, error });
      }
      await store.finishRun(id, status, error);
      await meter.flush();
    } catch (err) {
      this.log.error('run bookkeeping failed', { run: id, error: errorMessage(err) });
    }
  }

  private sinkFor(runId: string): CrawlSink {
    const { store, meter } = this.options;
    let events = 0;
    const logEvent = () => events++ < this.maxEvents;
    return {
      item: async (item) => {
        await store.addItem(runId, item);
        meter.add(1);
      },
      failed: async (url, error) => {
        await store.addFailure(runId, url, error, logEvent());
      },
      skipped: async (url, reason) => {
        await store.addSkip(runId, url, reason, logEvent());
      },
    };
  }
}
