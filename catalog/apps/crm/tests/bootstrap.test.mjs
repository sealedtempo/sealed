import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, test } from "node:test";

import {
  ADMIN_ROLE_UID,
  bootstrap,
  BootstrapError,
  CLIENT_CONFIG_EXPECTED,
  loadConfig,
  run,
  UnsafeInstanceError,
} from "../bootstrap/bootstrap.mjs";
import { createFakeTwenty } from "./lib/fake-twenty.mjs";

const ORIGIN = "https://crm.34-1-2-3.sslip.io";
const EMAIL = "Admin@Example.com";
const ADMIN = "admin@example.com";
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
  return { fake, dir, env, base };
}

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
const exists = (path) => access(path).then(() => true, () => false);

async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function runLogged(env) {
  const lines = [];
  const code = await run(env, (l) => lines.push(l));
  return { code, text: lines.join("\n") };
}

async function assertNotBootstrapped(dir) {
  assert.equal(await exists(join(dir, "done.json")), false, "done.json must not exist");
  assert.equal(await exists(join(dir, "api-key.json")), false, "no API key for an unsafe instance");
}

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
    assert.equal(cfg.setupUrl, "http://crm-server:3000", "no setup port: the route port is used for both phases");
    assert.equal(cfg.origin, ORIGIN);
    assert.equal(cfg.email, "admin@example.com");
    assert.equal(cfg.workspaceName, "CRM");
    assert.equal(cfg.apiKeyTtlDays, 365);
    assert.equal(cfg.healthTimeoutMs, 900_000);
  });

  test("reads the setup port URL", () => {
    assert.equal(loadConfig({ ...good, CRM_SETUP_URL: "http://crm-server:3001/" }).setupUrl, "http://crm-server:3001");
  });

  for (const [name, patch, message] of [
    ["missing admin email", { ADMIN_EMAIL: "" }, /missing env ADMIN_EMAIL/],
    ["bad email", { ADMIN_EMAIL: "admin" }, /not an email/],
    ["short password", { ADMIN_PASSWORD: "1234567" }, /8 to 50/],
    ["long password", { ADMIN_PASSWORD: "x".repeat(51) }, /8 to 50/],
    ["origin with a path", { SEALED_PUBLIC_URL_CRM: `${ORIGIN}/app` }, /SEALED_PUBLIC_URL_CRM must be a scheme and host/],
    ["setup URL with a path", { CRM_SETUP_URL: "http://crm-server:3001/x" }, /CRM_SETUP_URL must be/],
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
  test("fresh instance: server admin, active workspace, invite link off, admin API key, done file", async () => {
    const { fake, dir, env } = await setup({ unhealthyPolls: 2 });
    const now = Date.parse("2026-10-28T12:00:00Z");
    const result = await bootstrap(loadConfig(env), { now: () => now });
    assert.equal(result.status, "bootstrapped");

    const ws = fake.state.workspace;
    assert.equal(fake.state.workspaces.length, 1);
    assert.equal(ws.status, "ACTIVE");
    assert.equal(ws.invite, false);
    assert.equal(ws.displayName, "CRM");
    assert.deepEqual([...ws.members], [ADMIN]);
    const admin = fake.state.users.get(ADMIN);
    assert.equal(admin.canAccessFullAdminPanel, true);
    assert.equal(admin.canImpersonate, true);
    assert.ok(fake.state.healthPolls >= 3, "waited for /healthz");
    for (const op of ["CurrentUser", "WorkspaceMembers", "GetServerAdmins", "AdminPanelTopWorkspaces", "AdminPanelRecentUsers"]) {
      assert.ok(fake.state.calls.includes(op), `checked ${op}`);
    }

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

  test("second run after completion makes no GraphQL calls but re-checks the client config", async () => {
    const { fake, env } = await setup();
    await bootstrap(loadConfig(env));
    const calls = fake.state.calls.length;
    const reads = fake.state.clientConfigReads;
    const result = await bootstrap(loadConfig(env));
    assert.equal(result.status, "already-done");
    assert.equal(fake.state.calls.length, calls);
    assert.equal(fake.state.clientConfigReads, reads + 1);
  });

  test("a later start fails when a new release turns a switch on", async () => {
    const { fake, env } = await setup();
    await bootstrap(loadConfig(env));
    fake.state.clientConfig.analyticsEnabled = true;
    delete fake.state.clientConfig.isImapSmtpCaldavEnabled;
    const { code, text } = await runLogged(env);
    assert.equal(code, 1);
    assert.match(text, /client-config check failed: missing isImapSmtpCaldavEnabled; unexpected analyticsEnabled=true/);
  });

  test("resumes after a crash past workspace creation without creating anything twice", async () => {
    const { fake, dir, env } = await setup();
    fake.state.failNext.set("UpdateWorkspace", { errors: [{ message: "connection reset" }] });
    const first = await runLogged(env);
    assert.equal(first.code, 1);
    assert.match(first.text, /failed: closePublicInviteLink: connection reset/);
    await assertNotBootstrapped(dir);

    assert.equal(await run(env, () => {}), 0);
    const signUps = fake.state.calls.filter((c) => c === "SignUp" || c === "SignUpInNewWorkspace");
    assert.deepEqual(signUps, ["SignUp", "SignUpInNewWorkspace"]);
    assert.equal(fake.state.apiKeys.size, 1);
    assert.equal(fake.state.workspace.invite, false);
    assert.equal(fake.state.calls.filter((c) => c === "CurrentUser").length, 2, "identity checked on both runs");
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
    const { fake, dir, env } = await setup();
    fake.state.clientConfig.billing.isBillingEnabled = true;
    assert.equal(await run(env, () => {}), 1);
    const first = await readJson(join(dir, "api-key.json"));
    fake.state.clientConfig.billing.isBillingEnabled = false;
    assert.equal(await run(env, () => {}), 0);
    const second = await readJson(join(dir, "api-key.json"));
    assert.equal(second.token, first.token);
    assert.equal(fake.state.apiKeys.size, 1);
    assert.equal(fake.state.calls.filter((c) => c === "CreateApiKey").length, 1);
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

  test("gives up when the server never becomes healthy", async () => {
    const { env } = await setup({ unhealthyPolls: 1_000_000 }, { HEALTH_TIMEOUT_S: "1", POLL_INTERVAL_MS: "50" });
    await assert.rejects(bootstrap(loadConfig(env)), /not healthy at .* after 1s/);
  });

  test("logs contain no password and no token", async () => {
    const { dir, env } = await setup();
    const { code, text } = await runLogged(env);
    assert.equal(code, 0);
    const key = await readJson(join(dir, "api-key.json"));
    assert.ok(!text.includes(PASSWORD));
    assert.ok(!text.includes(key.token));
    assert.ok(text.includes("bootstrap complete"));
  });
});

describe("setup port and route port", () => {
  test("works only on the setup port until done.json, then confirms Twenty on the route port", async () => {
    const { fake, dir, env } = await setup();
    const routePort = await freePort();
    const routeEnv = { ...env, CRM_SETUP_URL: env.CRM_BASE_URL, CRM_BASE_URL: `http://127.0.0.1:${routePort}` };
    const pending = run(routeEnv, () => {});
    // Nothing listens on the route port yet, as in crm-server before done.json exists.
    while (!(await exists(join(dir, "done.json")))) await new Promise((r) => setTimeout(r, 5));
    const readsBefore = fake.state.clientConfigReads;
    await fake.listen(routePort);
    assert.equal(await pending, 0);
    assert.equal(fake.state.clientConfigReads, readsBefore + 1, "client config re-checked on the route port");
  });

  test("a later start uses only the route port", async () => {
    const { fake, env } = await setup();
    await bootstrap(loadConfig(env));
    const deadPort = await freePort();
    const result = await bootstrap(loadConfig({ ...env, CRM_SETUP_URL: `http://127.0.0.1:${deadPort}` }));
    assert.equal(result.status, "already-done");
    assert.ok(fake.state.clientConfigReads >= 2);
  });

  test("fails when crm-server never moves to the route port", async () => {
    const { dir, env } = await setup({}, { HEALTH_TIMEOUT_S: "1", POLL_INTERVAL_MS: "50" });
    const deadPort = await freePort();
    const { code, text } = await runLogged({ ...env, CRM_SETUP_URL: env.CRM_BASE_URL, CRM_BASE_URL: `http://127.0.0.1:${deadPort}` });
    assert.equal(code, 1);
    assert.match(text, new RegExp(`not healthy at http://127\\.0\\.0\\.1:${deadPort} after 1s`));
    assert.equal(await exists(join(dir, "done.json")), true, "the restart then takes the already-done path");
  });
});

describe("first-admin race", () => {
  const INTRUDER = "intruder@example.com";

  test("an outsider who signed up first holds server admin: fails closed, no key, no done file", async () => {
    const { fake, dir, env, base } = await setup();
    await fake.signUpAs(base, INTRUDER, "intruder-pass");
    assert.equal(fake.state.users.get(INTRUDER).canAccessFullAdminPanel, true, "Twenty made the outsider server admin");

    const { code, text } = await runLogged(env);
    assert.equal(code, 1);
    assert.match(text, /the bootstrap admin is not Twenty's server admin \(canAccessFullAdminPanel=false, canImpersonate=false\)/);
    assert.match(text, /delete the crm data and deploy again/);
    await assertNotBootstrapped(dir);
    assert.ok(!fake.state.calls.includes("ActivateWorkspace"), "stops before building the workspace");

    const again = await runLogged(env);
    assert.equal(again.code, 1, "a restart stays failed");
    assert.match(again.text, /not Twenty's server admin/);
    await assertNotBootstrapped(dir);
  });

  test("an outsider who created a workspace first: fails closed", async () => {
    const { fake, dir, env, base } = await setup();
    await fake.signUpAs(base, INTRUDER, "intruder-pass", { workspace: true });
    const { code, text } = await runLogged(env);
    assert.equal(code, 1);
    assert.match(text, /Sign up without workspace is not allowed/);
    await assertNotBootstrapped(dir);
  });

  test("an outsider who slipped a workspace in between signUp and signUpInNewWorkspace: fails closed", async () => {
    const { fake, dir, env, base } = await setup();
    fake.state.beforeOp.set("SignUpInNewWorkspace", () => fake.signUpAs(base, INTRUDER, "intruder-pass", { workspace: true }));
    const { code, text } = await runLogged(env);
    assert.equal(code, 1);
    assert.match(text, /New workspace setup is disabled/);
    assert.equal(fake.state.users.get(INTRUDER).canAccessFullAdminPanel, false);
    await assertNotBootstrapped(dir);
  });

  const raceCases = [
    [
      "a second server admin from a concurrent signUp",
      "SignUpInNewWorkspace",
      (fake) => fake.state.users.set(INTRUDER, { id: "u-x", email: INTRUDER, password: "x", canAccessFullAdminPanel: true, canImpersonate: true, createdAt: 99 }),
      /Twenty has 2 server admins, expected only the bootstrap admin/,
    ],
    [
      "a second workspace created concurrently",
      "ActivateWorkspace",
      (fake) => {
        fake.state.users.set(INTRUDER, { id: "u-x", email: INTRUDER, password: "x", canAccessFullAdminPanel: false, canImpersonate: false, createdAt: 99 });
        fake.state.workspaces.push({ id: "w-x", status: "ACTIVE", invite: true, members: new Set([INTRUDER]) });
      },
      /Twenty has 2 workspaces, expected only the bootstrap workspace/,
    ],
    [
      "a member who joined through the public invite link before it closed",
      "UpdateWorkspace",
      (fake) => {
        fake.state.users.set(INTRUDER, { id: "u-x", email: INTRUDER, password: "x", canAccessFullAdminPanel: false, canImpersonate: false, createdAt: 99 });
        fake.state.workspace.members.add(INTRUDER);
      },
      /the workspace has 2 members, expected only the bootstrap admin/,
    ],
    [
      "a stray account without a workspace",
      "SignUpInNewWorkspace",
      (fake) => fake.state.users.set(INTRUDER, { id: "u-x", email: INTRUDER, password: "x", canAccessFullAdminPanel: false, canImpersonate: false, createdAt: 99 }),
      /Twenty has user accounts other than the bootstrap admin/,
    ],
  ];
  for (const [name, op, act, message] of raceCases) {
    test(`${name}: fails closed before the API key`, async () => {
      const { fake, dir, env } = await setup();
      fake.state.beforeOp.set(op, async () => act(fake));
      await assert.rejects(bootstrap(loadConfig(env)), (err) => err instanceof UnsafeInstanceError && message.test(err.message));
      await assertNotBootstrapped(dir);
      assert.equal(fake.state.apiKeys.size, 0);
    });
  }
});

describe("client-config check", () => {
  test("the fake reports every checked field, as Twenty v2.52 does", async () => {
    const { fake } = await setup();
    const conf = fake.state.clientConfig;
    for (const path of Object.keys(CLIENT_CONFIG_EXPECTED)) {
      const value = path.split(".").reduce((v, k) => v?.[k], conf);
      assert.notEqual(value, undefined, path);
    }
  });

  for (const [name, mutate, message] of [
    ["switches that are on", (c) => { c.isMultiWorkspaceEnabled = true; c.analyticsEnabled = true; }, /unexpected isMultiWorkspaceEnabled=true, analyticsEnabled=true/],
    ["a renamed or dropped switch", (c) => { delete c.isGoogleCalendarEnabled; delete c.billing; }, /missing billing\.isBillingEnabled, isGoogleCalendarEnabled/],
    ["a switch of another type", (c) => { c.allowRequestsToTwentyIcons = "false"; }, /unexpected allowRequestsToTwentyIcons="false"/],
    ["an SSO provider", (c) => { c.authProviders.sso = [{ id: "okta" }]; }, /authProviders\.sso is not empty/],
    ["a Google sign-in provider", (c) => { c.authProviders.google = true; }, /authProviders\.google=true/],
    ["another public URL", (c) => { c.serverUrl = "https://evil.example"; }, /serverUrl is not SEALED_PUBLIC_URL_CRM/],
    ["a support chat", (c) => { c.support.supportDriver = "FRONT"; }, /support\.supportDriver="FRONT"/],
    ["an empty config", (c) => { for (const k of Object.keys(c)) delete c[k]; }, /missing isMultiWorkspaceEnabled/],
  ]) {
    test(`fails on ${name}`, async () => {
      const { fake, dir, env } = await setup();
      mutate(fake.state.clientConfig);
      await assert.rejects(bootstrap(loadConfig(env)), message);
      assert.equal(await exists(join(dir, "done.json")), false);
    });
  }

  test("accepts a public URL reported with a trailing slash", async () => {
    const { fake, env } = await setup();
    fake.state.clientConfig.serverUrl = `${ORIGIN}/`;
    assert.equal((await bootstrap(loadConfig(env))).status, "bootstrapped");
  });
});
