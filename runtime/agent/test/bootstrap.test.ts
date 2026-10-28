// Bootstrap tracking for the gate (brief items 9 and 10): the done file on the data disk, or a report
// from the bootstrap service itself when its done file lives elsewhere.
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BootstrapTracker } from "../src/gate/bootstrap.js";
import { silentLogger } from "../src/log.js";
import { parseStackInfo, type StackInfo } from "../src/stack.js";
import { makeConfig, makeStackInfo } from "./helpers/fixtures.js";

function stack(bootstrap: Record<string, unknown>, services = [{ name: "crm-bootstrap", ip: "172.30.0.19", primary: false }]): StackInfo {
  const s = makeStackInfo(makeConfig()) as ReturnType<typeof makeStackInfo>;
  const crm = s.apps[0] as Record<string, unknown> & { services: unknown[] };
  crm.services = [...crm.services, ...services];
  crm.bootstrap = bootstrap;
  return parseStackInfo(JSON.stringify(s));
}

describe("bootstrap tracking", () => {
  let data: string;
  const t = { now: 0 };
  beforeEach(async () => {
    data = await mkdtemp(join(tmpdir(), "sealed-bootstrap-"));
    t.now = 1_000_000;
  });
  afterEach(() => rm(data, { recursive: true, force: true }));

  it("waits for the done file to appear as a regular file on the data disk", async () => {
    const tr = new BootstrapTracker(stack({ service: "crm-bootstrap", doneFile: "crm-bootstrap/done.json", donePath: "/mnt/sealed-data/crm/crm-bootstrap/done.json" }), data, {
      log: silentLogger,
      now: () => t.now,
    });
    expect(tr.apps()).toEqual(["crm"]);
    expect(await tr.done("llm-gateway")).toBe(true); // no bootstrap job
    expect(await tr.done("crm")).toBe(false);
    await mkdir(join(data, "crm", "crm-bootstrap"), { recursive: true });
    // A directory or a symlink in its place does not count.
    await mkdir(join(data, "crm", "crm-bootstrap", "done.json"));
    t.now += 2000;
    expect(await tr.done("crm")).toBe(false);
    await rm(join(data, "crm", "crm-bootstrap", "done.json"), { recursive: true });
    await symlink("/etc/hosts", join(data, "crm", "crm-bootstrap", "done.json"));
    t.now += 2000;
    expect(await tr.done("crm")).toBe(false);
    await rm(join(data, "crm", "crm-bootstrap", "done.json"));
    await writeFile(join(data, "crm", "crm-bootstrap", "done.json"), "{}");
    // Looked for again at most once a second.
    t.now += 500;
    expect(await tr.done("crm")).toBe(false);
    t.now += 600;
    expect(await tr.done("crm")).toBe(true);
    // Done is final for this boot.
    await rm(join(data, "crm", "crm-bootstrap", "done.json"));
    expect(await tr.done("crm")).toBe(true);
  });

  it("refuses a done file outside the app's own data directory", () => {
    expect(
      () =>
        new BootstrapTracker(stack({ service: "crm-bootstrap", doneFile: "x", donePath: "/mnt/sealed-data/llm-gateway/x/done" }), data, { log: silentLogger }),
    ).toThrow("is not under /mnt/sealed-data/crm");
  });

  it("takes a report only from the bootstrap service's own IP when the done file is not on the data disk", () => {
    const reported: string[] = [];
    const tr = new BootstrapTracker(stack({ service: "crm-bootstrap", doneFile: "/run/bootstrap/done", donePath: "" }), data, {
      log: silentLogger,
      onReported: (a) => reported.push(a),
    });
    expect(() => tr.report("crm", "172.30.0.16")).toThrow("only crm's bootstrap service");
    expect(() => tr.report("llm-gateway", "172.30.0.19")).toThrow("has no bootstrap job");
    tr.report("crm", "172.30.0.19");
    tr.report("crm", "172.30.0.19");
    expect(reported).toEqual(["crm"]);
    // After a restart the persisted report still counts.
    const again = new BootstrapTracker(stack({ service: "crm-bootstrap", doneFile: "/run/bootstrap/done", donePath: "" }), data, { log: silentLogger, reported });
    return expect(again.done("crm")).resolves.toBe(true);
  });

  it("does not take reports for apps whose done file is on the data disk", () => {
    const tr = new BootstrapTracker(stack({ service: "crm-bootstrap", doneFile: "b/done", donePath: "/mnt/sealed-data/crm/b/done" }), data, { log: silentLogger });
    expect(() => tr.report("crm", "172.30.0.19")).toThrow("done file on the data disk");
  });
});
