import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { Supervisor } from "../src/procs.ts";
import { composerVersion } from "../src/services.ts";

const dir = mkdtempSync(join(tmpdir(), "devnet-composer-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function fakeCompose(name: string, script: string): string {
  const p = join(dir, name);
  writeFileSync(p, `#!/bin/sh\n${script}\n`);
  chmodSync(p, 0o755);
  return p;
}

describe("the devnet's configs name the composer it runs", () => {
  const sup = new Supervisor(join(dir, "logs"));

  it("reads the version from sealed-compose version", async () => {
    const bin = fakeCompose("ok", `[ "$1" = version ] && echo 9.8.7 && exit 0; exit 2`);
    expect(await composerVersion(sup, bin)).toBe("9.8.7");
  });

  it("refuses anything that is not a version, and a failing binary", async () => {
    await expect(composerVersion(sup, fakeCompose("noise", "echo composer"))).rejects.toThrow(/not a composer version/);
    await expect(composerVersion(sup, fakeCompose("fails", "exit 3"))).rejects.toThrow(/compose-version failed/);
  });

  // ws/harden-composer moved the composer to 1.3.0 while the devnet still pinned 1.2.0, which the composer refuses.
  it("pins no composerVersion of its own", () => {
    const flow = readFileSync(new URL("../src/flow.ts", import.meta.url), "utf8");
    expect(flow).not.toMatch(/composerVersion:\s*"/);
    expect(flow).not.toMatch(/(keyBroker|platformApi|tempoRpc):\s*`http:/);
  });
});
