import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { bootstrap, loadConfig } from "../bootstrap/bootstrap.mjs";
import { gateHeaders, runA6, UsageError } from "../scripts/a6-internal-tools.mjs";
import { createFakeToolJet } from "./lib/fake-tooljet.mjs";

const ORIGIN = "https://tools.34-1-2-3.sslip.io";
const ADMIN = { ADMIN_EMAIL: "admin@example.com", ADMIN_PASSWORD: "correct-horse-battery" };
const GATE = "sealed:gate-password";
const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

// A fake ToolJet behind a basic-auth gate that has been through the real bootstrap.
async function bootstrapped({ gate = GATE } = {}) {
  const fake = createFakeToolJet({ gate });
  const base = await fake.start();
  const dir = await mkdtemp(join(tmpdir(), "tools-a6-"));
  cleanups.push(() => fake.stop(), () => rm(dir, { recursive: true, force: true }));
  const cfg = loadConfig({ TOOLS_BASE_URL: base, SEALED_PUBLIC_URL_TOOLS: ORIGIN, STATE_DIR: dir, POLL_INTERVAL_MS: "10", ...ADMIN });
  if (gate) cfg.headers = gateHeaders({ GATE_BASIC: gate });
  await bootstrap(cfg);
  return { fake, base };
}

describe("a6-internal-tools", () => {
  test("loads the UI and creates an app through the gate", async () => {
    const { fake, base } = await bootstrapped();
    const now = Date.parse("2026-10-28T09:30:00Z");
    const result = await runA6({ TOOLS_URL: `${base}/`, GATE_BASIC: GATE, ...ADMIN }, { now });
    assert.equal(result.ok, true);
    assert.equal(result.name, "Sealed A6 2026-10-28T09:30:00");
    const app = fake.state.apps.get(result.appId);
    assert.equal(app.type, "front-end");
    assert.equal(app.organization_id, result.organizationId);
  });

  test("A6_CLEANUP deletes the app", async () => {
    const { fake, base } = await bootstrapped();
    const result = await runA6({ TOOLS_URL: base, GATE_BASIC: GATE, A6_CLEANUP: "1", ...ADMIN });
    assert.equal(result.cleanedUp, true);
    assert.equal(fake.state.apps.size, 0);
  });

  test("fails clearly without the gate credentials", async () => {
    const { base } = await bootstrapped();
    await assert.rejects(runA6({ TOOLS_URL: base, ...ADMIN }), /GET \/: HTTP 401/);
  });

  test("fails clearly with a wrong admin password", async () => {
    const { base } = await bootstrapped({ gate: null });
    await assert.rejects(runA6({ TOOLS_URL: base, ADMIN_EMAIL: ADMIN.ADMIN_EMAIL, ADMIN_PASSWORD: "wrong-password" }), /authenticate: HTTP 401 Invalid credentials/);
  });

  test("usage errors", async () => {
    await assert.rejects(runA6({ ...ADMIN }), UsageError);
    await assert.rejects(runA6({ TOOLS_URL: "http://x" }), UsageError);
    assert.throws(() => gateHeaders({ GATE_BASIC: "no-colon" }), UsageError);
    assert.deepEqual(gateHeaders({}), {});
    assert.deepEqual(gateHeaders({ GATE_BASIC: "a:b" }), { authorization: "Basic YTpi" });
  });

  test("the shell wrapper runs the helper and prints one JSON line", async () => {
    const { base } = await bootstrapped();
    const child = spawn("bash", [join(appDir, "scripts/a6-internal-tools.sh")], {
      env: { PATH: process.env.PATH, TOOLS_URL: base, GATE_BASIC: GATE, ...ADMIN },
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const code = await new Promise((resolve) => child.on("close", resolve));
    assert.equal(code, 0);
    assert.equal(JSON.parse(out.trim()).ok, true);
  });

  test("the shell wrapper exits 2 on bad usage", async () => {
    const child = spawn("bash", [join(appDir, "scripts/a6-internal-tools.sh")], { env: { PATH: process.env.PATH } });
    assert.equal(await new Promise((resolve) => child.on("close", resolve)), 2);
  });
});
