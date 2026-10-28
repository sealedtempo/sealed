// The real A6 helper (scripts/a6-crm.mjs) against fake-espocrm.mjs, through a stand-in of the
// composer's gated Caddy site in both shapes (fake-gate.mjs), with the API key that a real
// bootstrap run wrote.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { API_KEY_FILE, run as bootstrap } from "../bootstrap/bootstrap.mjs";
import { UsageError, credentials, gateHeaders, runA6 } from "../scripts/a6-crm.mjs";
import { createFakeEspoCrm, initialState, readState, writeState } from "./lib/fake-espocrm.mjs";
import { createFakeGate } from "./lib/fake-gate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const appDir = join(here, "..");
const PUBLIC_URL = "https://crm.34-1-2-3.sslip.io";
const GATE_PASSWORD = "gate-password-1234";
const ADMIN_PASSWORD = "Correct-Horse-Battery-9";
const SWITCH_ENV = Object.fromEntries(
  Object.entries((await import("yaml")).parse(await readFile(join(appDir, "manifest.yaml"), "utf8")).telemetry_off_env),
);

const cleanups = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()();
});

// A bootstrapped instance: the real bootstrap ran against the fake, so the API user, role and
// key file are what the VM would have.
async function instance({ stripAuthorization = true, gateMode = "forward_auth", ready } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "crm-a6-"));
  const espoDir = join(dir, "espo");
  await mkdir(join(espoDir, "data"), { recursive: true });
  const write = spawnSync("/bin/sh", [join(appDir, "images/espocrm/sealed-espocrm.sh"), "write-config", join(espoDir, "data")], {
    env: { PATH: process.env.PATH, SEALED_PUBLIC_URL_CRM: PUBLIC_URL, PG_DATABASE_PASSWORD: "ab12".repeat(16), ...SWITCH_ENV },
    encoding: "utf8",
  });
  assert.equal(write.status, 0, write.stderr);
  const stateFile = join(dir, "state.json");
  writeState(stateFile, initialState(espoDir));
  const command = join(dir, "espo-command");
  await writeFile(command, `#!/bin/sh\nFAKE_ESPO_STATE='${stateFile}' exec '${process.execPath}' '${join(here, "lib/fake-espo-command.mjs")}' "$@"\n`);
  await chmod(command, 0o755);
  const app = createFakeEspoCrm({ stateFile, stripAuthorization });
  const appUrl = await app.start();
  const logs = [];
  const code = await bootstrap(
    {
      CRM_BASE_URL: appUrl, STATE_DIR: join(dir, "state"), ESPO_DIR: espoDir, ESPO_COMMAND: command,
      ADMIN_USERNAME: "admin", ADMIN_PASSWORD, API_USER_NAME: "sealed-customer", SEALED_PUBLIC_URL_CRM: PUBLIC_URL,
      HEALTH_TIMEOUT_S: "3", POLL_MS: "20",
    },
    { log: (m) => logs.push(m) },
  );
  assert.equal(code, 0, logs.join("\n"));
  const gate = createFakeGate({ upstream: appUrl, mode: gateMode, password: GATE_PASSWORD, ready });
  const url = await gate.start();
  cleanups.push(async () => {
    await gate.stop();
    await app.stop();
    await rm(dir, { recursive: true, force: true });
  });
  return { dir, url, app, gate, stateFile, keyFile: join(dir, "state", API_KEY_FILE) };
}

const env = (t, extra = {}) => ({ CRM_URL: t.url, API_KEY_FILE: t.keyFile, GATE_BASIC: `sealed:${GATE_PASSWORD}`, ...extra });
const fixedNow = () => new Date("2026-10-28T12:00:00Z");

describe("A6 through the forward_auth gate (D-044)", () => {
  test("creates a company, a contact and a deal with the bootstrap's API key and checks the links", async () => {
    const t = await instance();
    const before = t.app.seen.length;
    const result = await runA6(env(t), { now: fixedNow });
    assert.equal(result.ok, true);
    const s = readState(t.stateFile);
    const account = s.records.Account.find((a) => a.id === result.accountId);
    const contact = s.records.Contact.find((c) => c.id === result.contactId);
    const deal = s.records.Opportunity.find((o) => o.id === result.opportunityId);
    assert.equal(account.name, "A6 Company 20261028120000");
    assert.equal(contact.accountId, account.id);
    assert.equal(deal.accountId, account.id);
    assert.deepEqual(deal.contactsIds, [contact.id]);
    assert.equal(deal.closeDate, "2026-11-27");
    const apiUser = s.users.find((u) => u.type === "api");
    assert.ok([account, contact, deal].every((r) => r.createdById === apiUser.id), "records are created by the API user");
    // The first call passes on Basic and gets the cookie; the rest pass on the cookie.
    assert.equal(t.gate.seen[0].outcome, "basic");
    assert.ok(t.gate.seen.slice(1).every((r) => r.outcome === "cookie"), JSON.stringify(t.gate.seen));
    // The gate's Basic header reaches the app (forward_auth leaves Authorization alone) and
    // does not get in the way, because the image drops it before EspoCRM.
    const viaGate = t.app.seen.slice(before);
    assert.ok(viaGate.length >= 8 && viaGate.every((r) => r.authorization?.startsWith("Basic ")));
  });

  // A browser that passed the gate keeps sending its Basic credentials. EspoCRM's web app adds
  // Espo-Authorization to its API calls, which wins, but entry points (attachments, images,
  // downloads) carry only the auth-token cookie, and EspoCRM reads a Basic header before the
  // cookie (Espo\Core\Api\Auth). The image drops the header; without that, those fail.
  for (const [strip, expected] of [[true, 200], [false, 401]]) {
    test(`a cookie-only request with the gate's Basic header gets ${expected} when the image ${strip ? "drops" : "keeps"} Authorization`, async () => {
      const t = await instance({ stripAuthorization: strip });
      const s = readState(t.stateFile);
      const admin = s.users.find((u) => u.type === "admin");
      s.tokens["browser-token"] = admin.id;
      writeState(t.stateFile, s);
      const res = await fetch(`${t.url}/api/v1/Account?maxSize=1`, {
        headers: {
          authorization: `Basic ${Buffer.from(`sealed:${GATE_PASSWORD}`).toString("base64")}`,
          cookie: "auth-token=browser-token",
        },
      });
      assert.equal(res.status, expected);
    });
  }

  test("A11: --check reads the same ids back, and fails once a record is gone", async () => {
    const t = await instance();
    const result = await runA6(env(t), { now: fixedNow });
    const ids = join(t.dir, "ids.json");
    await writeFile(ids, JSON.stringify(result));
    const checked = await runA6(env(t), { argv: ["--check", ids] });
    assert.equal(checked.checked.opportunityId, result.opportunityId);
    const s = readState(t.stateFile);
    s.records.Contact = [];
    writeState(t.stateFile, s);
    await assert.rejects(runA6(env(t), { argv: ["--check", ids] }), /GET \/Contact\/\S+: HTTP 404/);
  });

  test("A6_CLEANUP=1 deletes the three records", async () => {
    const t = await instance();
    const result = await runA6(env(t, { A6_CLEANUP: "1" }), { now: fixedNow });
    assert.equal(result.cleanedUp, true);
    const s = readState(t.stateFile);
    assert.deepEqual([s.records.Account.length, s.records.Contact.length, s.records.Opportunity.length], [0, 0, 0]);
  });

  test("works as the administrator too", async () => {
    const t = await instance();
    const result = await runA6(env(t, { API_KEY_FILE: undefined, ADMIN_PASSWORD }), { now: fixedNow });
    assert.equal(result.ok, true);
  });

  test("says when the gate password is missing or the route is still starting", async () => {
    const t = await instance();
    await assert.rejects(runA6(env(t, { GATE_BASIC: undefined })), /HTTP 401 from the Sealed gate \(set GATE_BASIC/);
    const starting = await instance({ ready: () => false });
    await assert.rejects(runA6(env(starting)), /HTTP 503 \(the crm route opens when crm-bootstrap is done\)/);
  });

  test("an API user without the role is refused by EspoCRM's ACL", async () => {
    const t = await instance();
    const s = readState(t.stateFile);
    s.users.find((u) => u.type === "api").rolesIds = [];
    writeState(t.stateFile, s);
    await assert.rejects(runA6(env(t)), /POST \/Account: HTTP 403/);
  });
});

describe("A6 through the basic_auth gate (composer before brief item 9)", () => {
  test("passes the same way; Caddy strips Authorization before EspoCRM", async () => {
    const t = await instance({ gateMode: "basic_auth" });
    const result = await runA6(env(t), { now: fixedNow });
    assert.equal(result.ok, true);
    assert.ok(t.app.seen.every((r) => r.authorization === undefined));
  });
});

describe("usage", () => {
  test("needs CRM_URL and credentials, and a well-formed GATE_BASIC", async () => {
    await assert.rejects(runA6({}), UsageError);
    await assert.rejects(runA6({ CRM_URL: "http://x" }), /set API_KEY, API_KEY_FILE or ADMIN_PASSWORD/);
    assert.throws(() => gateHeaders({ GATE_BASIC: "nocolon" }), /user:password/);
    assert.deepEqual(await credentials({ API_KEY: "k" }), { "x-api-key": "k" });
    await assert.rejects(credentials({ API_KEY_FILE: "/nonexistent/api-key.json" }), /cannot read API_KEY_FILE: ENOENT/);
  });

  test("the shell wrapper exits 2 on bad usage", () => {
    const res = spawnSync("bash", [join(appDir, "scripts/a6-crm.sh")], { env: { PATH: process.env.PATH }, encoding: "utf8" });
    assert.equal(res.status, 2, res.stderr);
    assert.match(res.stderr, /a6-crm: set CRM_URL/);
  });
});
