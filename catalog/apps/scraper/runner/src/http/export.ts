import { csvRow, type CsvOptions } from '../csv.js';
import type { Item, Run, RunStore } from '../db/store.js';

// Exports stream items from Postgres page by page, so a large run never sits in memory.
// Both formats have the same flat records: url first, then the job's fields in the job's order.

const PAGE = 500;

export function exportColumns(run: Run): string[] {
  return ['url', ...Object.keys(run.spec.extract)];
}

export async function* iterateItems(store: RunStore, runId: string): AsyncGenerator<Item> {
  let after = 0;
  for (;;) {
    const page = await store.listItems(runId, { after, limit: PAGE });
    for (const item of page) yield item;
    if (page.length < PAGE) return;
    after = page[page.length - 1]!.id;
  }
}

function record(item: Item, fields: string[]): Record<string, string | null> {
  const out: Record<string, string | null> = { url: item.url };
  for (const f of fields) out[f] = item.data[f] ?? null;
  return out;
}

export async function* jsonExport(store: RunStore, run: Run): AsyncGenerator<string> {
  const fields = Object.keys(run.spec.extract);
  let first = true;
  yield '[';
  for await (const item of iterateItems(store, run.id)) {
    yield (first ? '\n' : ',\n') + JSON.stringify(record(item, fields));
    first = false;
  }
  yield first ? ']\n' : '\n]\n';
}

export async function* csvExport(store: RunStore, run: Run, options: CsvOptions): AsyncGenerator<string> {
  const columns = exportColumns(run);
  const fields = columns.slice(1);
  yield csvRow(columns, options);
  for await (const item of iterateItems(store, run.id)) {
    const rec = record(item, fields);
    yield csvRow(columns.map((c) => rec[c] ?? null), options);
  }
}

export function toStream(chunks: AsyncGenerator<string>): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await chunks.next();
        if (done) controller.close();
        else controller.enqueue(encoder.encode(value));
      } catch (err) {
        controller.error(err);
      }
    },
    async cancel() {
      await chunks.return(undefined);
    },
  });
}
