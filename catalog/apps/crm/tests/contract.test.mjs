// Contract test against the real Twenty: boots the fragment with the pinned upstream images,
// waits for crm-bootstrap, then runs A6 with the API key it wrote. Opt-in, because it needs a
// Docker daemon and pulls about 1.5 GB: SEALED_CONTRACT=1 pnpm test (CI and the dev CVM).
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
const PUBLIC_URL = `http://localhost:${HOST_PORT}`;

function contractSecrets() {
  return {
    ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    PG_DATABASE_PASSWORD: randomBytes(32).toString("hex"),
    VALKEY_PASSWORD: randomBytes(32).toString("hex"),
    ADMIN_EMAIL: "admin@contract.example",
    ADMIN_PASSWORD: randomBytes(18).toString("base64url"),
  };
}

async function writeStack(dir, secrets) {
  const secretsDir = join(dir, "secrets");
  await mkdir(secretsDir, { mode: 0o755 });
  for (const [name, value] of Object.entries(secrets)) await writeFile(join(secretsDir, name), value, { mode: 0o644 });
  const doc = contractCompose(app, { secrets, secretsDir, publicUrl: PUBLIC_URL, hostPort: HOST_PORT });
  const file = join(dir, "compose.json");
  await writeFile(file, JSON.stringify(doc, null, 2));
  return { file, doc };
}

describe("contract compose document", () => {
  test("is valid compose and wires secrets, the public URL and the volume owners", { skip: !dockerComposeAvailable() && "docker compose not installed" }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "crm-contract-doc-"));
    try {
      const { file, doc } = await writeStack(dir, contractSecrets());
      const result = composeConfig(file, "sealed-crm-contract-doc");
      assert.ok(result.ok, result.stderr);
      const services = result.config.services;
      assert.equal(services["crm-server"].environment.SEALED_PUBLIC_URL_CRM, PUBLIC_URL);
      assert.equal(services["crm-server"].environment.TELEMETRY_ENABLED, "false");
      assert.ok(services["crm-bootstrap"].environment.ADMIN_PASSWORD);
      assert.equal(services["crm-server"].ports[0].published, String(HOST_PORT));
      assert.equal(services["crm-server"].ports[0].target, 3000, "the route port, not the setup port");
      assert.match(services["crm-server"].image, /^docker\.io\/twentycrm\/twenty@sha256:20b1010a/);
      assert.match(doc.services["crm-contract-init"].entrypoint[2], /chown 1000:1000 \/sealed-init\/crm-bootstrap/);
      assert.equal(services["crm-bootstrap"].depends_on["crm-contract-init"].condition, "service_completed_successfully");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

const enabled = process.env.SEALED_CONTRACT === "1";
const skip = !enabled ? "set SEALED_CONTRACT=1 to boot the real images" : !dockerDaemonAvailable() && "no Docker daemon";
describe("contract: real Twenty v2.52.0", { skip }, () => {
  test("bootstrap completes, the route port opens, and A6 passes with the bootstrap API key", { timeout: 2_400_000 }, async (t) => {
    const dir = await mkdtemp(join(tmpdir(), "crm-contract-"));
    const project = `sealed-crm-contract-${process.pid}`;
    const secrets = contractSecrets();
    const { file } = await writeStack(dir, secrets);
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
    assert.equal(key.url, PUBLIC_URL);

    const result = await runA6({ CRM_URL: `http://127.0.0.1:${HOST_PORT}`, API_KEY_FILE: join(dir, "api-key.json"), A6_CLEANUP: "1" });
    assert.equal(result.ok, true);

    // A restart takes the read-only path and passes the client-config check again.
    compose("start", "crm-bootstrap");
    assert.equal(await waitForExit(project, file, "crm-bootstrap", 600_000), 0, compose("logs", "crm-bootstrap"));
  });
});
