import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { bootstrap, loadConfig } from "../bootstrap/bootstrap.mjs";
import { gateHeaders, runA6, UsageError } from "../scripts/a6-crm.mjs";
import { createFakeTwenty } from "./lib/fake-twenty.mjs";

const ORIGIN = "https://crm.34-1-2-3.sslip.io";
const ADMIN = { ADMIN_EMAIL: "admin@example.com", ADMIN_PASSWORD: "correct-horse-battery" };
const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

// A fake Twenty that has been through the real bootstrap, plus the api-key.json it wrote.
async function bootstrapped() {
  const fake = createFakeTwenty({ origin: ORIGIN });
  const base = await fake.start();
  const dir = await mkdtemp(join(tmpdir(), "crm-a6-"));
  cleanups.push(() => fake.stop(), () => rm(dir, { recursive: true, force: true }));
  await bootstrap(
    loadConfig({ CRM_BASE_URL: base, SEALED_PUBLIC_URL_CRM: ORIGIN, STATE_DIR: dir, POLL_INTERVAL_MS: "10", ...ADMIN }),
  );
  return { fake, base, keyFile: join(dir, "api-key.json") };
}

describe("a6-crm", () => {
  test("creates a linked company, person and opportunity with the bootstrap API key", async () => {
    const { fake, base, keyFile } = await bootstrapped();
    const result = await runA6({ CRM_URL: `${base}/`, API_KEY_FILE: keyFile });
    assert.equal(result.ok, true);
    const opp = fake.state.records.opportunities.get(result.opportunityId);
    assert.equal(opp.companyId, result.companyId);
    assert.equal(opp.pointOfContactId, result.personId);
    assert.deepEqual(opp.amount, { amountMicros: 1_000_000_000, currencyCode: "USD" });
    assert.equal(fake.state.records.people.get(result.personId).companyId, result.companyId);
  });

  test("A6_CLEANUP deletes the records", async () => {
    const { fake, base, keyFile } = await bootstrapped();
    const result = await runA6({ CRM_URL: base, API_KEY_FILE: keyFile, A6_CLEANUP: "1" });
    assert.equal(result.cleanedUp, true);
    for (const table of Object.values(fake.state.records)) assert.equal(table.size, 0);
  });

  test("mints a one-day key from the admin login and revokes it afterwards", async () => {
    const { fake, base } = await bootstrapped();
    const before = fake.state.apiKeys.size;
    const now = Date.parse("2026-10-28T00:00:00Z");
    await runA6({ CRM_URL: base, CRM_ORIGIN: ORIGIN, ...ADMIN }, { now });
    const keys = [...fake.state.apiKeys.values()];
    assert.equal(keys.length, before + 1);
    const minted = keys.find((k) => k.name === "sealed-a6");
    assert.equal(minted.revoked, true);
    assert.ok(Date.parse(minted.expiresAt) - Date.now() <= 86_400_000 + 1000);
  });

  test("revokes the minted key even when a step fails", async () => {
    const { fake, base } = await bootstrapped();
    const realCreate = fake.state.records.people;
    fake.state.records.people = undefined;
    await assert.rejects(runA6({ CRM_URL: base, CRM_ORIGIN: ORIGIN, ...ADMIN }), /POST \/rest\/people: HTTP 404/);
    fake.state.records.people = realCreate;
    assert.equal([...fake.state.apiKeys.values()].find((k) => k.name === "sealed-a6").revoked, true);
  });

  test("reports an invalid API key with the server's message", async () => {
    const { base } = await bootstrapped();
    await assert.rejects(runA6({ CRM_URL: base, API_KEY: "nope" }), /POST \/rest\/companies: HTTP 401 Token invalid\./);
  });

  test("usage errors", async () => {
    await assert.rejects(runA6({}), UsageError);
    const { base } = await bootstrapped();
    await assert.rejects(runA6({ CRM_URL: base }), UsageError);
    assert.throws(() => gateHeaders({ GATE_HEADER: "Authorization: Basic eDp5" }), UsageError);
    assert.throws(() => gateHeaders({ GATE_HEADER: "no-colon" }), UsageError);
    assert.deepEqual(gateHeaders({ GATE_COOKIE: "sealed_gate=abc", GATE_HEADER: "X-Sealed-Gate:  t0k " }), {
      cookie: "sealed_gate=abc",
      "x-sealed-gate": "t0k",
    });
  });

  test("the shell wrapper runs the helper and prints one JSON line", async () => {
    const { base, keyFile } = await bootstrapped();
    const child = spawn("bash", [join(appDir, "scripts/a6-crm.sh")], {
      env: { PATH: process.env.PATH, CRM_URL: base, API_KEY_FILE: keyFile },
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const code = await new Promise((resolve) => child.on("close", resolve));
    assert.equal(code, 0);
    const lines = out.trim().split("\n");
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0]).ok, true);
  });

  test("the shell wrapper exits 2 on bad usage", async () => {
    const child = spawn("bash", [join(appDir, "scripts/a6-crm.sh")], { env: { PATH: process.env.PATH } });
    const code = await new Promise((resolve) => child.on("close", resolve));
    assert.equal(code, 2);
  });
});
