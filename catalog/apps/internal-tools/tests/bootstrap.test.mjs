import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, test } from "node:test";

import { bootstrap, BootstrapError, loadConfig, run, sessionFrom } from "../bootstrap/bootstrap.mjs";
import { createFakeToolJet } from "./lib/fake-tooljet.mjs";

const ORIGIN = "https://tools.34-1-2-3.sslip.io";
const PASSWORD = "correct-horse-battery";

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

async function setup(fakeOptions = {}, envOverrides = {}) {
  const fake = createFakeToolJet(fakeOptions);
  const base = await fake.start();
  const dir = await mkdtemp(join(tmpdir(), "tools-bootstrap-"));
  cleanups.push(() => fake.stop(), () => rm(dir, { recursive: true, force: true }));
  const env = {
    TOOLS_BASE_URL: base,
    SEALED_PUBLIC_URL_TOOLS: ORIGIN,
    STATE_DIR: dir,
    ADMIN_EMAIL: "Admin@Example.com",
    ADMIN_PASSWORD: PASSWORD,
    POLL_INTERVAL_MS: "10",
    ...envOverrides,
  };
  return { fake, dir, env };
}

describe("loadConfig", () => {
  const good = {
    TOOLS_BASE_URL: "http://internal-tools-server:3000/",
    SEALED_PUBLIC_URL_TOOLS: `${ORIGIN}/`,
    STATE_DIR: "/sealed-bootstrap",
    ADMIN_EMAIL: "Admin@Example.com",
    ADMIN_PASSWORD: PASSWORD,
  };

  test("normalizes and applies defaults", () => {
    const cfg = loadConfig(good);
    assert.equal(cfg.baseUrl, "http://internal-tools-server:3000");
    assert.equal(cfg.setupUrl, cfg.baseUrl, "no setup port: the route port is used for both phases");
    assert.equal(loadConfig({ ...good, TOOLS_SETUP_URL: "http://internal-tools-server:3001/" }).setupUrl, "http://internal-tools-server:3001");
    assert.equal(cfg.origin, ORIGIN);
    assert.equal(cfg.email, "admin@example.com");
    assert.equal(cfg.adminName, "Sealed Admin");
    assert.equal(cfg.workspaceName, "Internal tools");
  });

  for (const [name, patch, message] of [
    ["missing password", { ADMIN_PASSWORD: "" }, /missing env ADMIN_PASSWORD/],
    ["short password", { ADMIN_PASSWORD: "short" }, /8 to 100/],
    ["long password", { ADMIN_PASSWORD: "x".repeat(101) }, /8 to 100/],
    ["bad email", { ADMIN_EMAIL: "nope" }, /not an email/],
    ["origin with a path", { SEALED_PUBLIC_URL_TOOLS: `${ORIGIN}/x` }, /SEALED_PUBLIC_URL_TOOLS must be a scheme and host/],
    ["setup URL with a path", { TOOLS_SETUP_URL: "http://internal-tools-server:3001/x" }, /TOOLS_SETUP_URL must be/],
    ["bad timeout", { HEALTH_TIMEOUT_S: "-1" }, /HEALTH_TIMEOUT_S/],
  ]) {
    test(`rejects ${name}`, () => {
      assert.throws(() => loadConfig({ ...good, ...patch }), (err) => err instanceof BootstrapError && message.test(err.message));
    });
  }
});

describe("sessionFrom", () => {
  test("extracts the tj_auth_token pair", () => {
    assert.equal(sessionFrom(["a=b; Path=/", "tj_auth_token=abc.def; Path=/; HttpOnly"]), "tj_auth_token=abc.def");
    assert.equal(sessionFrom(["tj_auth_token=; Max-Age=0"]), undefined);
    assert.equal(sessionFrom([]), undefined);
  });
});

describe("bootstrap", () => {
  test("fresh instance: creates the admin and workspace and checks sign-up is closed", async () => {
    const { fake, dir, env } = await setup({ unhealthyPolls: 2 });
    const now = Date.parse("2026-10-28T12:00:00Z");
    const result = await bootstrap(loadConfig(env), { now: () => now });
    assert.equal(result.status, "bootstrapped");
    const admin = fake.state.users.get("admin@example.com");
    assert.ok(admin, "admin created with a lowercase email");
    assert.equal(admin.name, "Sealed Admin");
    assert.equal(fake.state.organizations.get(admin.organizationId).name, "Internal tools");
    assert.ok(fake.state.calls.includes("POST /api/onboarding/signup"), "probed sign-up");
    assert.equal(fake.state.users.size, 1, "the probe created no user");

    const done = JSON.parse(await readFile(join(dir, "done.json"), "utf8"));
    assert.deepEqual(done, {
      schema: "sealed-bootstrap-done/v1",
      app: "internal-tools",
      complete: true,
      completedAt: "2026-10-28T12:00:00.000Z",
      organizationId: admin.organizationId,
      url: ORIGIN,
    });
    assert.equal((await stat(join(dir, "done.json"))).mode & 0o777, 0o644);
  });

  test("second run after completion only re-checks that sign-up is refused", async () => {
    const { fake, env } = await setup();
    await bootstrap(loadConfig(env));
    const calls = fake.state.calls.length;
    assert.equal((await bootstrap(loadConfig(env))).status, "already-done");
    assert.deepEqual(fake.state.calls.slice(calls), ["GET /api/health", "POST /api/onboarding/signup"]);
    assert.equal(fake.state.users.size, 1);
  });

  test("a later start fails when sign-up has been opened", async () => {
    const { fake, env } = await setup();
    await bootstrap(loadConfig(env));
    fake.state.signupsDisabled = false;
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => /self sign-up is not closed/.test(l)), lines.join("\n"));
  });

  test("re-run before done.json logs in instead of creating a second admin", async () => {
    const { fake, dir, env } = await setup();
    fake.state.signupsDisabled = false;
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => /self sign-up is not closed \(probe got HTTP 400\)/.test(l)), lines.join("\n"));
    await assert.rejects(readFile(join(dir, "done.json")), { code: "ENOENT" });

    fake.state.signupsDisabled = true;
    assert.equal(await run(env, () => {}), 0);
    assert.equal(fake.state.users.size, 1);
    assert.equal(fake.state.calls.filter((c) => c === "POST /api/authenticate").length, 1);
  });

  test("refuses an instance that someone else already set up", async () => {
    const { fake, dir, env } = await setup();
    const res = await fetch(`${env.TOOLS_BASE_URL}/api/onboarding/setup-super-admin`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "intruder@example.com", password: "intruder", name: "x", workspaceName: "y" }),
    });
    assert.equal(res.status, 201);
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 1);
    assert.ok(lines.some((l) => /already has users and the admin cannot log in \(authenticate: HTTP 401/.test(l)), lines.join("\n"));
    await assert.rejects(readFile(join(dir, "done.json")), { code: "ENOENT" });
    assert.ok(fake.state.users.has("intruder@example.com"));
  });

  test("gives up when the server never becomes healthy", async () => {
    const { env } = await setup({ unhealthyPolls: 1_000_000 }, { HEALTH_TIMEOUT_S: "1", POLL_INTERVAL_MS: "50" });
    await assert.rejects(bootstrap(loadConfig(env)), /not healthy at .* after 1s/);
  });

  test("logs contain no password and no session cookie", async () => {
    const { fake, env } = await setup();
    const lines = [];
    assert.equal(await run(env, (l) => lines.push(l)), 0);
    const text = lines.join("\n");
    assert.ok(!text.includes(PASSWORD));
    for (const token of fake.state.sessions.keys()) assert.ok(!text.includes(token));
    assert.ok(text.includes("bootstrap complete"));
  });
});

describe("setup port and route port", () => {
  async function freePort() {
    const server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    await new Promise((resolve) => server.close(resolve));
    return port;
  }
  const exists = (path) => access(path).then(() => true, () => false);

  test("works only on the setup port until done.json, then re-checks sign-up on the route port", async () => {
    const { fake, dir, env } = await setup();
    const routePort = await freePort();
    const pending = run({ ...env, TOOLS_SETUP_URL: env.TOOLS_BASE_URL, TOOLS_BASE_URL: `http://127.0.0.1:${routePort}` }, () => {});
    while (!(await exists(join(dir, "done.json")))) await new Promise((r) => setTimeout(r, 5));
    const probes = fake.state.calls.filter((c) => c === "POST /api/onboarding/signup").length;
    await fake.listen(routePort);
    assert.equal(await pending, 0);
    assert.equal(fake.state.calls.filter((c) => c === "POST /api/onboarding/signup").length, probes + 1);
  });

  test("a later start uses only the route port", async () => {
    const { env } = await setup();
    await bootstrap(loadConfig(env));
    const deadPort = await freePort();
    assert.equal((await bootstrap(loadConfig({ ...env, TOOLS_SETUP_URL: `http://127.0.0.1:${deadPort}` }))).status, "already-done");
  });

  test("an instance someone else set up never gets done.json, so the route stays closed", async () => {
    const { dir, env } = await setup();
    await fetch(`${env.TOOLS_BASE_URL}/api/onboarding/setup-super-admin`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "neighbour@example.com", password: "neighbour", name: "n", workspaceName: "n" }),
    });
    const deadPort = await freePort();
    assert.equal(await run({ ...env, TOOLS_SETUP_URL: env.TOOLS_BASE_URL, TOOLS_BASE_URL: `http://127.0.0.1:${deadPort}` }, () => {}), 1);
    assert.equal(await exists(join(dir, "done.json")), false);
  });
});
