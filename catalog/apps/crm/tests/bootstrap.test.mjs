// The real bootstrap (bootstrap/bootstrap.mjs) against fake-espocrm.mjs and the bin/command
// stand-in, with data/config-override.php written by the real sealed-espocrm script.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  API_KEY_FILE,
  DONE_FILE,
  ROLE_NAME,
  checkSettings,
  loadConfig,
  run,
} from "../bootstrap/bootstrap.mjs";
import { createFakeEspoCrm, initialState, readState, writeState } from "./lib/fake-espocrm.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const appDir = join(here, "..");
const entrypoint = join(appDir, "images/espocrm/sealed-espocrm.sh");
const fakeCommand = join(here, "lib/fake-espo-command.mjs");
const PUBLIC_URL = "https://crm.34-1-2-3.sslip.io";
const ADMIN_PASSWORD = "Correct-Horse-Battery-9";
const PG_PASSWORD = "0123abcd".repeat(8);

export const SWITCH_ENV = {
  ESPOCRM_CONFIG_USE_WEB_SOCKET: "false",
  ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS: "false",
  ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_VERSION: "false",
  ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS_NEW_EXTENSION_VERSION: "false",
  ESPOCRM_CONFIG_ADMIN_PANEL_IFRAME_DISABLED: "true",
  ESPOCRM_CONFIG_ADMIN_EXTENSION_UPLOAD: "false",
  ESPOCRM_CONFIG_ADMIN_UPGRADE_DISABLED: "true",
};

function writeOverrides(dataDir, url = PUBLIC_URL) {
  const res = spawnSync("/bin/sh", [entrypoint, "write-config", dataDir], {
    env: { PATH: process.env.PATH, SEALED_PUBLIC_URL_CRM: url, PG_DATABASE_PASSWORD: PG_PASSWORD, ...SWITCH_ENV },
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stderr);
}

const cleanups = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()();
});

async function setup({ stripAuthorization = true, override = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "crm-bootstrap-"));
  const espoDir = join(dir, "espo");
  const stateDir = join(dir, "sealed-bootstrap");
  await mkdir(join(espoDir, "data/cache"), { recursive: true });
  const stateFile = join(dir, "fake-state.json");
  writeState(stateFile, initialState(espoDir));
  if (override) writeOverrides(join(espoDir, "data"));
  const command = join(dir, "espo-command");
  await writeFile(command, `#!/bin/sh\nFAKE_ESPO_STATE='${stateFile}' exec '${process.execPath}' '${fakeCommand}' "$@"\n`);
  await chmod(command, 0o755);
  const fake = createFakeEspoCrm({ stateFile, stripAuthorization });
  const base = await fake.start();
  cleanups.push(async () => {
    await fake.stop();
    await rm(dir, { recursive: true, force: true });
  });
  const env = {
    CRM_BASE_URL: base,
    STATE_DIR: stateDir,
    ESPO_DIR: espoDir,
    ESPO_COMMAND: command,
    ADMIN_USERNAME: "admin",
    ADMIN_PASSWORD,
    API_USER_NAME: "sealed-customer",
    SEALED_PUBLIC_URL_CRM: PUBLIC_URL,
    HEALTH_TIMEOUT_S: "3",
    POLL_MS: "20",
  };
  const logs = [];
  const go = (extra = {}) => run({ ...env, ...extra }, { log: (m) => logs.push(m) });
  return { dir, espoDir, stateDir, stateFile, fake, env, logs, go, state: () => readState(stateFile) };
}

const exists = (p) => stat(p).then(() => true, () => false);

describe("first run", () => {
  test("installs with the CLI, then sets up the API user, writes the key and done.json", async () => {
    const t = await setup();
    assert.equal(await t.go(), 0, t.logs.join("\n"));
    const s = t.state();
    assert.deepEqual(
      s.calls.map((c) => c[0]).filter((c) => !["config:get", "db:check"].includes(c)),
      ["config:populate", "config:set", "config:set", "rebuild", "create-admin-user", "set-password",
        "populate-scheduled-jobs", "config:set", "app-check", "config:set"],
    );
    assert.deepEqual(s.calls.find((c) => c[0] === "create-admin-user"), ["create-admin-user", "admin"]);
    assert.ok(!JSON.stringify(s.calls).includes(ADMIN_PASSWORD), "the password never goes into argv");
    assert.equal(s.users.find((u) => u.userName === "admin").password, ADMIN_PASSWORD);
    assert.equal(s.config.isInstalled, true);
    assert.equal(await exists(join(t.espoDir, "data/cache")), false, "the install starts with an empty cache");

    const role = s.roles.find((r) => r.name === ROLE_NAME);
    assert.deepEqual(role.data.Opportunity, { create: "yes", read: "all", edit: "all", delete: "all", stream: "all" });
    const apiUser = s.users.find((u) => u.userName === "sealed-customer");
    assert.equal(apiUser.type, "api");
    assert.equal(apiUser.authMethod, "ApiKey");
    assert.deepEqual(apiUser.rolesIds, [role.id]);

    const keyPath = join(t.stateDir, API_KEY_FILE);
    const saved = JSON.parse(await readFile(keyPath, "utf8"));
    assert.equal(saved.apiKey, apiUser.apiKey);
    assert.equal(saved.header, "X-Api-Key");
    assert.equal(saved.url, `${PUBLIC_URL}/api/v1/`);
    assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
    const done = JSON.parse(await readFile(join(t.stateDir, DONE_FILE), "utf8"));
    assert.equal(done.version, "10.0.11");

    // The key was used once to prove it works.
    assert.ok(t.fake.seen.some((r) => r.path.startsWith("/Account") && r.apiKey));
    const logText = t.logs.join("\n");
    assert.ok(!logText.includes(ADMIN_PASSWORD) && !logText.includes(apiUser.apiKey), "no secret in the logs");
  });

  test("a later start only re-checks the settings, without the admin password", async () => {
    const t = await setup();
    assert.equal(await t.go(), 0, t.logs.join("\n"));
    const before = t.state();
    const seenBefore = t.fake.seen.length;
    t.logs.length = 0;
    assert.equal(await t.go({ ADMIN_PASSWORD: "a-changed-password" }), 0, t.logs.join("\n"));
    const after = t.state();
    const newCalls = after.calls.slice(before.calls.length).map((c) => c[0]);
    assert.ok(newCalls.every((c) => c === "config:get"), newCalls.join(","));
    const requests = t.fake.seen.slice(seenBefore);
    assert.deepEqual([...new Set(requests.map((r) => r.path))], ["/Settings"]);
    assert.ok(requests.every((r) => !r.apiKey));
    assert.deepEqual(after.users, before.users);
  });

  test("a crash part way through the install resumes on the next run", async () => {
    const t = await setup();
    const s = t.state();
    s.failOnce = "populate-scheduled-jobs";
    writeState(t.stateFile, s);
    assert.equal(await t.go(), 1);
    assert.match(t.logs.at(-1), /failed: bin\/command populate-scheduled-jobs exited 1/);
    assert.equal(await exists(join(t.stateDir, DONE_FILE)), false);
    assert.equal(await t.go(), 0, t.logs.join("\n"));
    assert.equal(t.state().users.filter((u) => u.type === "admin").length, 1, "create-admin-user was not repeated into a second admin");
  });

  test("an API user whose key file was lost is reused, not duplicated", async () => {
    const t = await setup();
    assert.equal(await t.go(), 0);
    await rm(join(t.stateDir, DONE_FILE));
    await rm(join(t.stateDir, API_KEY_FILE));
    assert.equal(await t.go(), 0, t.logs.join("\n"));
    const users = t.state().users.filter((u) => u.userName === "sealed-customer");
    assert.equal(users.length, 1);
    const saved = JSON.parse(await readFile(join(t.stateDir, API_KEY_FILE), "utf8"));
    assert.equal(saved.apiKey, users[0].apiKey);
    assert.equal(t.state().roles.length, 1, "the role is reused too");
  });

  test("waits for the database, then gives up with a clear error", async () => {
    const t = await setup();
    const s = t.state();
    s.dbUp = false;
    writeState(t.stateFile, s);
    assert.equal(await t.go(), 1);
    assert.match(t.logs.at(-1), /the database did not answer in time/);
    assert.ok(t.logs.includes("waiting for crm-db"));
  });
});

describe("fails closed", () => {
  test("an account the bootstrap did not create stops it before the key and done.json", async () => {
    const t = await setup();
    const s = t.state();
    // A data disk that already holds an install with a stray account.
    s.users.push({ id: "u-stray", userName: "mallory", type: "regular", isActive: true, password: "x" });
    writeState(t.stateFile, s);
    assert.equal(await t.go(), 1);
    assert.match(t.logs.at(-1), /accounts other than the bootstrap admin.*delete the crm data and deploy again/);
    assert.equal(await exists(join(t.stateDir, API_KEY_FILE)), false);
    assert.equal(await exists(join(t.stateDir, DONE_FILE)), false);
  });

  test("a second admin is refused too", async () => {
    const t = await setup();
    assert.equal(await t.go(), 0);
    await rm(join(t.stateDir, DONE_FILE));
    const s = t.state();
    s.users.push({ id: "u-2", userName: "root2", type: "admin", isActive: true, password: "x" });
    writeState(t.stateFile, s);
    assert.equal(await t.go(), 1);
    assert.equal(await exists(join(t.stateDir, DONE_FILE)), false);
  });

  test("without the override files the settings check fails", async () => {
    const t = await setup({ override: false });
    assert.equal(await t.go(), 1);
    assert.match(t.logs.at(-1), /failed: config adminExtensionUpload is not set|failed: .*app-check/);
    assert.equal(await exists(join(t.stateDir, DONE_FILE)), false);
  });

  test("an override for another public URL fails the check", async () => {
    const t = await setup();
    writeOverrides(join(t.espoDir, "data"), "https://crm.example.org");
    assert.equal(await t.go(), 1);
    assert.match(t.logs.at(-1), /siteUrl is not SEALED_PUBLIC_URL_CRM/);
  });

  test("done.json without an installed EspoCRM is an error", async () => {
    const t = await setup();
    await mkdir(t.stateDir, { recursive: true });
    await writeFile(join(t.stateDir, DONE_FILE), "{}\n");
    assert.equal(await t.go(), 1);
    assert.match(t.logs.at(-1), /done\.json exists but EspoCRM is not installed/);
  });

  test("a refused admin login is reported without the password", async () => {
    const t = await setup();
    assert.equal(await t.go(), 0);
    await rm(join(t.stateDir, DONE_FILE));
    assert.equal(await t.go({ ADMIN_PASSWORD: "wrong-password-1" }), 1);
    assert.match(t.logs.at(-1), /the admin login was refused/);
    assert.ok(!t.logs.join("\n").includes("wrong-password-1"));
  });
});

describe("settings check", () => {
  const cfg = { origin: PUBLIC_URL };
  const good = {
    siteUrl: PUBLIC_URL,
    useWebSocket: false,
    adminNotifications: false,
    adminNotificationsNewVersion: false,
    adminNotificationsNewExtensionVersion: false,
    adminPanelIframeDisabled: true,
  };
  test("accepts the fixed values and a trailing slash on siteUrl", () => {
    checkSettings(cfg, good);
    checkSettings(cfg, { ...good, siteUrl: `${PUBLIC_URL}/` });
  });
  test("names a missing switch, a wrong value and the wrong URL", () => {
    const { adminPanelIframeDisabled, ...missing } = good;
    assert.throws(() => checkSettings(cfg, missing), /missing adminPanelIframeDisabled/);
    assert.throws(() => checkSettings(cfg, { ...good, adminNotifications: true }), /unexpected adminNotifications=true/);
    assert.throws(() => checkSettings(cfg, { ...good, siteUrl: "http://crm-server:8080" }), /siteUrl is not/);
  });
});

describe("configuration", () => {
  const base = {
    CRM_BASE_URL: "http://crm-server:8080/",
    STATE_DIR: "/sealed-bootstrap",
    ADMIN_USERNAME: "admin",
    ADMIN_PASSWORD,
    API_USER_NAME: "sealed-customer",
    SEALED_PUBLIC_URL_CRM: `${PUBLIC_URL}/`,
  };
  test("reads the fragment's env and defaults the CLI to php bin/command", () => {
    const cfg = loadConfig(base);
    assert.equal(cfg.baseUrl, "http://crm-server:8080");
    assert.equal(cfg.origin, PUBLIC_URL);
    assert.deepEqual(cfg.command, ["php", "bin/command"]);
  });
  for (const [name, change, message] of [
    ["a missing public URL", { SEALED_PUBLIC_URL_CRM: "" }, /missing env SEALED_PUBLIC_URL_CRM/],
    ["an http public URL", { SEALED_PUBLIC_URL_CRM: "http://crm.example" }, /must be https/],
    ["a short password", { ADMIN_PASSWORD: "short" }, /8 to 128 characters/],
    ["a two-line password", { ADMIN_PASSWORD: "longenough\nsecond" }, /on one line/],
    ["the same name twice", { API_USER_NAME: "admin" }, /must differ/],
    ["a bad user name", { ADMIN_USERNAME: "Admin User" }, /not a valid EspoCRM user name/],
  ]) {
    test(`refuses ${name}`, () => {
      assert.throws(() => loadConfig({ ...base, ...change }), message);
    });
  }
});
