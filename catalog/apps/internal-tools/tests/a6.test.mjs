import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { bootstrap, loadConfig } from "../bootstrap/bootstrap.mjs";
import { gateHeaders, gateLogin, runA6, UsageError } from "../scripts/a6-internal-tools.mjs";
import { createFakeGate } from "./lib/fake-gate.mjs";
import { createFakeToolJet } from "./lib/fake-tooljet.mjs";

const ORIGIN = "https://tools.34-1-2-3.sslip.io";
const ADMIN = { ADMIN_EMAIL: "admin@example.com", ADMIN_PASSWORD: "correct-horse-battery" };
const GATE_PASSWORD = "gate-password";
const GATE = `sealed:${GATE_PASSWORD}`;
const FAST = { A6_GATE_POLL_MS: "10" };
const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

// A fake ToolJet that has been through the real bootstrap (which runs inside the VM, without the
// gate), with the Sealed gate in front of it unless gate is null.
async function bootstrapped({ gate = {} } = {}) {
  const fake = createFakeToolJet();
  const direct = await fake.start();
  const dir = await mkdtemp(join(tmpdir(), "tools-a6-"));
  cleanups.push(() => fake.stop(), () => rm(dir, { recursive: true, force: true }));
  const cfg = loadConfig({ TOOLS_BASE_URL: direct, SEALED_PUBLIC_URL_TOOLS: ORIGIN, STATE_DIR: dir, POLL_INTERVAL_MS: "10", ...ADMIN });
  await bootstrap(cfg);
  if (gate === null) return { fake, base: direct };
  const g = createFakeGate(direct, GATE_PASSWORD, gate);
  const base = await g.start();
  cleanups.push(() => g.stop());
  return { fake, base, gate: g };
}

function gateNeverReachedToolJet(fake) {
  for (const { path, authorization } of fake.state.headers) {
    assert.ok(!authorization || !Buffer.from(authorization.split(" ")[1] ?? "", "base64").toString().includes(GATE_PASSWORD), path);
  }
}

describe("a6-internal-tools", () => {
  test("loads the UI and creates an app through the gate with the sealed_gate cookie", async () => {
    const { fake, base, gate } = await bootstrapped();
    const now = Date.parse("2026-10-28T09:30:00Z");
    const lines = [];
    const result = await runA6({ TOOLS_URL: `${base}/`, GATE_BASIC: GATE, ...ADMIN }, { now, log: (l) => lines.push(l) });
    assert.equal(result.ok, true);
    assert.equal(result.name, "Sealed A6 2026-10-28T09:30:00");
    const app = fake.state.apps.get(result.appId);
    assert.equal(app.type, "front-end");
    assert.equal(app.organization_id, result.organizationId);
    assert.equal(gate.stats.basicChecks, 1, "the gate password crossed the wire once");
    assert.ok(gate.stats.cookiePasses >= 5);
    assert.ok(lines.some((l) => l.includes("using the sealed_gate cookie")));
    // ToolJet's own session cookie travels next to the gate cookie.
    const created = gate.stats.upstreamHeaders.find((h) => h.path === "/api/apps");
    assert.match(created.headers.cookie, /sealed_gate=.*tj_auth_token=|tj_auth_token=.*sealed_gate=/);
    gateNeverReachedToolJet(fake);
  });

  test("follows a gate that sets the cookie on a redirect", async () => {
    const { fake, base, gate } = await bootstrapped({ gate: { mode: "redirect" } });
    const result = await runA6({ TOOLS_URL: base, GATE_BASIC: GATE, ...ADMIN });
    assert.equal(result.ok, true);
    assert.equal(gate.stats.basicChecks, 1);
    gateNeverReachedToolJet(fake);
  });

  test("sends Basic auth on every request to a gate that sets no cookie", async () => {
    const { fake, base, gate } = await bootstrapped({ gate: { mode: "basic" } });
    const lines = [];
    const result = await runA6({ TOOLS_URL: base, GATE_BASIC: GATE, ...ADMIN }, { log: (l) => lines.push(l) });
    assert.equal(result.ok, true);
    assert.ok(lines.some((l) => l.includes("set no sealed_gate cookie")));
    assert.equal(gate.stats.basicChecks, gate.stats.upstreamHeaders.length);
    gateNeverReachedToolJet(fake);
  });

  test("waits while the gate answers 503 starting", async () => {
    const { base, gate } = await bootstrapped({ gate: { starting: 3 } });
    const result = await runA6({ TOOLS_URL: base, GATE_BASIC: GATE, ...FAST, ...ADMIN });
    assert.equal(result.ok, true);
    assert.equal(gate.stats.starting, 0);
  });

  test("gives up when the app never starts", async () => {
    const { base } = await bootstrapped({ gate: { starting: 1_000_000 } });
    await assert.rejects(runA6({ TOOLS_URL: base, GATE_BASIC: GATE, A6_GATE_WAIT_S: "0.05", ...FAST, ...ADMIN }), /did not start/);
  });

  test("A6_CLEANUP deletes the app", async () => {
    const { fake, base } = await bootstrapped();
    const result = await runA6({ TOOLS_URL: base, GATE_BASIC: GATE, A6_CLEANUP: "1", ...ADMIN });
    assert.equal(result.cleanedUp, true);
    assert.equal(fake.state.apps.size, 0);
  });

  test("fails clearly without the gate credentials or with wrong ones", async () => {
    const { base, gate } = await bootstrapped();
    await assert.rejects(runA6({ TOOLS_URL: base, ...ADMIN }), (err) => err instanceof UsageError && /behind the Sealed gate/.test(err.message));
    await assert.rejects(runA6({ TOOLS_URL: base, GATE_BASIC: "sealed:wrong", ...ADMIN }), /the gate refused GATE_BASIC/);
    assert.equal(gate.stats.upstreamHeaders.length, 0);
  });

  test("never sends the gate password to a route without a gate", async () => {
    const { fake, base } = await bootstrapped({ gate: null });
    const result = await runA6({ TOOLS_URL: base, GATE_BASIC: GATE, ...ADMIN });
    assert.equal(result.ok, true);
    assert.ok(fake.state.headers.every((h) => !h.authorization));
    assert.deepEqual(await gateLogin(base, { GATE_BASIC: GATE }), {});
  });

  test("fails clearly with a wrong admin password", async () => {
    const { base } = await bootstrapped({ gate: null });
    await assert.rejects(runA6({ TOOLS_URL: base, ADMIN_EMAIL: ADMIN.ADMIN_EMAIL, ADMIN_PASSWORD: "wrong-password" }), /authenticate: HTTP 401 Invalid credentials/);
  });

  test("usage errors", async () => {
    await assert.rejects(runA6({ ...ADMIN }), UsageError);
    await assert.rejects(runA6({ TOOLS_URL: "http://x" }), UsageError);
    await assert.rejects(runA6({ TOOLS_URL: "http://127.0.0.1:9", GATE_BASIC: "no-colon", ...ADMIN }), UsageError);
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
