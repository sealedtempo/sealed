// Contract test against the real EspoCRM: builds images/espocrm, boots the fragment with it and
// the pinned PostgreSQL image, waits for crm-bootstrap, then runs A6 with the API key it wrote
// and restarts the bootstrap to take the read-only path. Opt-in, because it needs a Docker
// daemon and network access for the build: SEALED_CONTRACT=1 pnpm test (CI and the dev CVM).
// Outside that, only the generated compose document is checked with `docker compose config`.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { runA6 } from "../scripts/a6-crm.mjs";
import {
  composeConfig,
  contractCompose,
  docker,
  dockerComposeAvailable,
  dockerDaemonAvailable,
  loadApp,
  waitForExit,
} from "./lib/catalog-lint.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = loadApp(appDir);
const HOST_PORT = 39_300;
// siteUrl only shapes links; the test talks to the published port directly.
const PUBLIC_URL = "https://crm.contract.test";
const BUILT = { espocrm: "sealed-crm-espocrm:contract" };

function contractSecrets() {
  return {
    PG_DATABASE_PASSWORD: randomBytes(32).toString("hex"),
    ADMIN_PASSWORD: randomBytes(18).toString("base64url"),
  };
}

async function writeStack(dir, secrets) {
  const secretsDir = join(dir, "secrets");
  await mkdir(secretsDir, { mode: 0o755 });
  for (const [name, value] of Object.entries(secrets)) await writeFile(join(secretsDir, name), value, { mode: 0o644 });
  const doc = contractCompose(app, { secrets, secretsDir, publicUrl: PUBLIC_URL, hostPort: HOST_PORT, builtImages: BUILT });
  const file = join(dir, "compose.json");
  await writeFile(file, JSON.stringify(doc, null, 2));
  return { file, doc };
}

describe("contract compose document", () => {
  test("is valid compose and wires secrets, the public URL and the switches", { skip: !dockerComposeAvailable() && "docker compose not installed" }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "crm-contract-doc-"));
    try {
      const { file } = await writeStack(dir, contractSecrets());
      const result = composeConfig(file, "sealed-crm-contract-doc");
      assert.ok(result.ok, result.stderr);
      const services = result.config.services;
      for (const name of ["crm-server", "crm-daemon", "crm-bootstrap"]) {
        assert.equal(services[name].environment.SEALED_PUBLIC_URL_CRM, PUBLIC_URL, name);
        assert.equal(services[name].environment.ESPOCRM_CONFIG_ADMIN_NOTIFICATIONS, "false", name);
        assert.ok(services[name].environment.PG_DATABASE_PASSWORD, name);
        assert.equal(services[name].image, BUILT.espocrm, name);
      }
      assert.ok(services["crm-bootstrap"].environment.ADMIN_PASSWORD);
      assert.equal(services["crm-server"].environment.ADMIN_PASSWORD, undefined);
      assert.equal(services["crm-server"].ports[0].published, String(HOST_PORT));
      assert.equal(services["crm-server"].ports[0].target, 8080);
      assert.match(services["crm-db"].image, /^docker\.io\/library\/postgres@sha256:1beaa308/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

const enabled = process.env.SEALED_CONTRACT === "1";
const skip = !enabled ? "set SEALED_CONTRACT=1 to build and boot the real image" : !dockerDaemonAvailable() && "no Docker daemon";
describe("contract: real EspoCRM 10.0.11", { skip }, () => {
  test("the image builds, the bootstrap completes, and A6 passes with the bootstrap API key", { timeout: 2_400_000 }, async (t) => {
    docker(["build", "--platform", "linux/amd64", "-t", BUILT.espocrm, join(appDir, "images/espocrm")]);
    const dir = await mkdtemp(join(tmpdir(), "crm-contract-"));
    const project = `sealed-crm-contract-${process.pid}`;
    const { file } = await writeStack(dir, contractSecrets());
    const compose = (...args) => docker(["compose", "-p", project, "-f", file, ...args]);
    t.after(async () => {
      try {
        compose("down", "-v", "--remove-orphans");
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    compose("up", "-d");
    const code = await waitForExit(project, file, "crm-bootstrap", 1_800_000);
    assert.equal(code, 0, compose("logs", "crm-bootstrap"));
    compose("cp", "crm-bootstrap:/sealed-bootstrap/api-key.json", join(dir, "api-key.json"));
    const key = JSON.parse(await readFile(join(dir, "api-key.json"), "utf8"));
    assert.equal(key.url, `${PUBLIC_URL}/api/v1/`);

    const base = `http://127.0.0.1:${HOST_PORT}`;
    const result = await runA6({ CRM_URL: base, API_KEY_FILE: join(dir, "api-key.json"), A6_CLEANUP: "1" });
    assert.equal(result.ok, true);

    // The gate's Basic header must not turn into an EspoCRM login (the image drops it).
    const withBasic = await fetch(`${base}/api/v1/Account?maxSize=1`, {
      headers: { "x-api-key": key.apiKey, authorization: `Basic ${Buffer.from("sealed:x").toString("base64")}` },
    });
    assert.equal(withBasic.status, 200);
    // The web installer is not in the image.
    assert.equal((await fetch(`${base}/install/`)).status, 404);

    // A restart takes the read-only path and passes the settings check again.
    compose("start", "crm-bootstrap");
    assert.equal(await waitForExit(project, file, "crm-bootstrap", 600_000), 0, compose("logs", "crm-bootstrap"));
  });
});
