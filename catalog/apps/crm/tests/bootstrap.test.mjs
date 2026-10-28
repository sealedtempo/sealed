import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, test } from "node:test";

import { ADMIN_ROLE_UID, bootstrap, BootstrapError, loadConfig, run } from "../bootstrap/bootstrap.mjs";
import { createFakeTwenty } from "./lib/fake-twenty.mjs";

const ORIGIN = "https://crm.34-1-2-3.sslip.io";
const EMAIL = "Admin@Example.com";
const PASSWORD = "correct-horse-battery";

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

async function setup(fakeOptions = {}, envOverrides = {}) {
  const fake = createFakeTwenty({ origin: ORIGIN, ...fakeOptions });
  const base = await fake.start();
  const dir = await mkdtemp(join(tmpdir(), "crm-bootstrap-"));
  cleanups.push(() => fake.stop(), () => rm(dir, { recursive: true, force: true }));
  const env = {
    CRM_BASE_URL: base,
    SEALED_PUBLIC_URL_CRM: ORIGIN,
    STATE_DIR: dir,
    ADMIN_EMAIL: EMAIL,
    ADMIN_PASSWORD: PASSWORD,
    POLL_INTERVAL_MS: "10",
    ...envOverrides,
  };
  return { fake, dir, env };
}

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

describe("loadConfig", () => {
  const good = {
    CRM_BASE_URL: "http://crm-server:3000/",
    SEALED_PUBLIC_URL_CRM: `${ORIGIN}/`,
    STATE_DIR: "/sealed-bootstrap",
    ADMIN_EMAIL: " Admin@Example.com ",
    ADMIN_PASSWORD: PASSWORD,
  };

  test("normalizes URLs and email and applies defaults", () => {
    const cfg = loadConfig(good);
    assert.equal(cfg.baseUrl, "http://crm-server:3000");
    assert.equal(cfg.origin, ORIGIN);
    assert.equal(cfg.email, "admin@example.com");
    assert.equal(cfg.workspaceName, "CRM");
    assert.equal(cfg.apiKeyTtlDays, 365);
    assert.equal(cfg.healthTimeoutMs, 900_000);
  });

  for (const [name, patch, message] of [
    ["missing admin email", { ADMIN_EMAIL: "" }, /missing env ADMIN_EMAIL/],
    ["bad email", { ADMIN_EMAIL: "admin" }, /not an email/],
    ["short password", { ADMIN_PASSWORD: "1234567" }, /8 to 50/],
    ["long password", { ADMIN_PASSWORD: "x".repeat(51) }, /8 to 50/],
    ["origin with a path", { SEALED_PUBLIC_URL_CRM: `${ORIGIN}/app` }, /no path/],
    ["ttl out of range", { API_KEY_TTL_DAYS: "0" }, /API_KEY_TTL_DAYS/],
    ["ttl not an integer", { API_KEY_TTL_DAYS: "1.5" }, /API_KEY_TTL_DAYS/],
  ]) {
    test(`rejects ${name}`, () => {
      assert.throws(() => loadConfig({ ...good, ...patch }), (err) => err instanceof BootstrapError && message.test(err.message));
    });
  }

  test("error messages never contain the password", () => {
    const secret = "s3cret-but-too-long-".repeat(3);
    assert.throws(() => loadConfig({ ...good, ADMIN_PASSWORD: secret }), (err) => !err.message.includes(secret));
  });
});

describe("bootstrap", () => {
  test("fresh instance: admin, active workspace, invite link off, admin API key, done file", async () => {
    const { fake, dir, env } = await setup({ unhealthyPolls: 2 });
    const now = Date.parse("2026-10-28T12:00:00Z");
    const result = await bootstrap(loadConfig(env), { now: () => now });
    assert.equal(result.status, "bootstrapped");

    const ws = fake.state.workspace;
    assert.equal(ws.status, "ACTIVE");
    assert.equal(ws.invite, false);
    assert.equal(ws.displayName, "CRM");
    assert.deepEqual([...ws.members], ["admin@example.com"]);
    assert.ok(fake.state.healthPolls >= 3, "waited for /healthz");

    const done = await readJson(join(dir, "done.json"));
    assert.equal(done.complete, true);
    assert.equal(done.app, "crm");
    assert.equal(done.workspaceId, ws.id);
    assert.equal(done.apiKeyFile, "api-key.json");
    assert.equal(done.completedAt, "2026-10-28T12:00:00.000Z");

    const key = await readJson(join(dir, "api-key.json"));
    assert.equal(key.schema, "sealed-crm-api-key/v1");
    assert.equal(key.url, ORIGIN);
    assert.equal(key.expiresAt, "2027-10-28T12:00:00.000Z");
    const stored = fake.state.apiKeys.get(key.id);
    assert.equal(stored.token, key.token);
    assert.equal(stored.roleId, "role-admin");
    assert.equal(stored.name, "sealed-customer");
    assert.equal((await stat(join(dir, "api-key.json"))).mode & 0o777, 0o600);
    assert.equal((await stat(join(dir, "done.json"))).mode & 0o777, 0o644);
  });

  test("second run after completion makes no API calls", async () => {
    const { fake, env } = await setup();
    await bootstrap(loadConfig(env));
    const calls = fake.state.calls.length;
    const result = await bootstrap(loadConfig(env));
    assert.equal(result.status, "already-done");
    assert.equal(fake.state.calls.length, calls);
  });

  test("resumes after a crash past workspace creation without creating anything twice", async () => {
    const { fake, dir, env } = await setup();
    fake.state.failNext.set("UpdateWorkspace", { errors: [{ message: "connection reset" }] });
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => l.includes("failed: closePublicInviteLink: connection reset")));
    await assert.rejects(readFile(join(dir, "done.json")), { code: "ENOENT" });

    assert.equal(await run(env, () => {}), 0);
    const signUps = fake.state.calls.filter((c) => c === "SignUp" || c === "SignUpInNewWorkspace");
    assert.deepEqual(signUps, ["SignUp", "SignUpInNewWorkspace"]);
    assert.equal(fake.state.apiKeys.size, 1);
    assert.equal(fake.state.workspace.invite, false);
  });

  test("resumes a workspace left pending when password login refuses it", async () => {
    const { fake, env } = await setup({ refusePendingLogin: true });
    fake.state.failNext.set("ActivateWorkspace", { errors: [{ message: "timeout" }] });
    assert.equal(await run(env, () => {}), 1);
    assert.equal(fake.state.workspace.status, "PENDING_CREATION");

    assert.equal(await run(env, () => {}), 0);
    assert.equal(fake.state.workspace.status, "ACTIVE");
    assert.ok(fake.state.calls.includes("SignIn"), "fell back to signIn for the pending workspace");
  });

  test("waits for an activation that is still running", async () => {
    const { fake, env } = await setup({ activationPolls: 3 });
    await bootstrap(loadConfig(env));
    assert.equal(fake.state.workspace.status, "ACTIVE");
    assert.ok(fake.state.calls.filter((c) => c === "CurrentWorkspace").length >= 3);
  });

  test("keeps an API key that was already written", async () => {
    const { fake, dir, env } = await setup({ clientConfig: { billing: { isBillingEnabled: true } } });
    assert.equal(await run(env, () => {}), 1);
    const first = await readJson(join(dir, "api-key.json"));
    fake.state.clientConfig = {};
    assert.equal(await run(env, () => {}), 0);
    const second = await readJson(join(dir, "api-key.json"));
    assert.equal(second.token, first.token);
    assert.equal(fake.state.apiKeys.size, 1);
    assert.equal(fake.state.calls.filter((c) => c === "CreateApiKey").length, 1);
  });

  test("refuses to proceed when another user already owns the instance", async () => {
    const { fake, dir, env } = await setup();
    fake.state.users.set("intruder@example.com", { password: "intruder-pass" });
    fake.state.workspace = { id: "w-intruder", status: "ACTIVE", invite: true, members: new Set(["intruder@example.com"]) };
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => /New workspace setup is disabled/.test(l)), lines.join("\n"));
    await assert.rejects(readFile(join(dir, "done.json")), { code: "ENOENT" });
  });

  test("fails when no Admin role can be assigned to API keys", async () => {
    const { env } = await setup({ roles: [{ id: "r1", label: "Member", universalIdentifier: "m", canBeAssignedToApiKeys: true }] });
    await assert.rejects(bootstrap(loadConfig(env)), /no Admin role/);
  });

  test("picks the admin role by universal identifier even when relabelled", async () => {
    const { fake, env } = await setup({ roles: [{ id: "r-admin", label: "Owners", universalIdentifier: ADMIN_ROLE_UID, canBeAssignedToApiKeys: true }] });
    await bootstrap(loadConfig(env));
    assert.equal([...fake.state.apiKeys.values()][0].roleId, "r-admin");
  });

  test("fails when the client config shows a switch that must be off", async () => {
    const { dir, env } = await setup({ clientConfig: { isMultiWorkspaceEnabled: true, analyticsEnabled: true } });
    await assert.rejects(bootstrap(loadConfig(env)), /isMultiWorkspaceEnabled, analyticsEnabled/);
    await assert.rejects(readFile(join(dir, "done.json")), { code: "ENOENT" });
  });

  test("gives up when the server never becomes healthy", async () => {
    const { env } = await setup({ unhealthyPolls: 1_000_000 }, { HEALTH_TIMEOUT_S: "1", POLL_INTERVAL_MS: "50" });
    await assert.rejects(bootstrap(loadConfig(env)), /not healthy after 1s/);
  });

  test("logs contain no password and no token", async () => {
    const { dir, env } = await setup();
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 0);
    const key = await readJson(join(dir, "api-key.json"));
    const text = lines.join("\n");
    assert.ok(!text.includes(PASSWORD));
    assert.ok(!text.includes(key.token));
    assert.ok(text.includes("bootstrap complete"));
  });
});
