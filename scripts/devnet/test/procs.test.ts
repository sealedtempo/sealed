import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { freePorts } from "../src/net.ts";
import { Supervisor, waitFor } from "../src/procs.ts";

const dir = mkdtempSync(join(tmpdir(), "devnet-procs-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("process supervisor", () => {
  it("logs each process to its own file and runs commands to completion", async () => {
    const sup = new Supervisor(join(dir, "logs-a"));
    const out = await sup.runOk("echo", process.execPath, ["-e", "console.log('hello'); console.error('err')"]);
    expect(out).toContain("hello");
    expect(out).toContain("err");
    await expect(sup.runOk("fails", process.execPath, ["-e", "console.log('boom'); process.exit(3)"])).rejects.toThrow(/fails failed \(exit 3\)[\s\S]*boom/);
    const clean = await sup.run("env", process.execPath, ["-e", "console.log(JSON.stringify(Object.keys(process.env).sort()))"], { cleanEnv: true, env: { ONLY: "1" } });
    // macOS adds __CF_USER_TEXT_ENCODING to every process.
    expect((JSON.parse(clean.output.trim()) as string[]).filter((k) => !k.startsWith("__CF_"))).toEqual(["ONLY"]);
  });

  it("stops every running child, and waitFor fails fast when the watched process exits", async () => {
    const sup = new Supervisor(join(dir, "logs-b"));
    const sleeper = sup.spawn("sleeper", process.execPath, ["-e", "console.log('up'); setInterval(() => {}, 1000)"]);
    await waitFor("sleeper output", () => readFileSync(sleeper.logFile, "utf8").includes("up"), { timeoutMs: 5000 });
    expect(sup.running()).toHaveLength(1);
    await sup.stopAll();
    expect(sleeper.running).toBe(false);
    expect(sup.running()).toHaveLength(0);

    const dying = sup.spawn("dying", process.execPath, ["-e", "console.log('last words'); process.exit(2)"]);
    await expect(waitFor("never", () => false, { proc: dying, timeoutMs: 5000 })).rejects.toThrow(/dying exited \(code 2\)[\s\S]*last words/);
    await expect(waitFor("never", () => false, { timeoutMs: 300, intervalMs: 50 })).rejects.toThrow("timed out waiting for never");
  });

  it("hands out distinct free ports", async () => {
    const ports = await freePorts(8);
    expect(new Set(ports).size).toBe(8);
    for (const p of ports) expect(p).toBeGreaterThan(0);
  });
});
