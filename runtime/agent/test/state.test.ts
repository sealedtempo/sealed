import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { emptyState, StateStore } from "../src/state.js";

describe("agent state store", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sealed-state-"));
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  it("writes snapshots atomically with mode 0600 and reads them back", async () => {
    const path = join(dir, "s", "state.json");
    const store = await StateStore.open(path, 100);
    store.state.payments.failingSince = 7;
    await store.save();
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await StateStore.open(path, 0)).state.payments.failingSince).toBe(7);
  });

  // Review finding: one failed write left the promise chain rejected, so nothing was saved again.
  it("a failed write does not poison later saves", async () => {
    const path = join(dir, "state.json");
    const store = await StateStore.open(path, 100);
    await mkdir(`${path}.tmp`); // the temp file path is a directory: the write fails with EISDIR
    store.state.payments.lastOutcome = "first";
    await expect(store.save()).rejects.toThrow();
    await rm(`${path}.tmp`, { recursive: true });
    store.state.payments.lastOutcome = "second";
    await store.save();
    store.state.payments.lastOutcome = "third";
    await store.save();
    expect(JSON.parse(await readFile(path, "utf8")).payments.lastOutcome).toBe("third");
  });

  it("serializes concurrent saves in call order", async () => {
    const path = join(dir, "state.json");
    const store = await StateStore.open(path, 100);
    const saves: Promise<void>[] = [];
    for (let i = 0; i < 5; i++) {
      store.state.payments.lastAttemptAt = i;
      saves.push(store.save());
    }
    await Promise.all(saves);
    expect(JSON.parse(await readFile(path, "utf8")).payments.lastAttemptAt).toBe(4);
  });

  it("drops the Caddy config older agents saved", async () => {
    const path = join(dir, "state.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, JSON.stringify({ ...emptyState(1), caddyOriginal: { apps: {} } }));
    expect("caddyOriginal" in (await StateStore.open(path, 0)).state).toBe(false);
  });
});
