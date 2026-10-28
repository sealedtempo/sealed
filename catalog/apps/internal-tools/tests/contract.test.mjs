// Contract test against the real ToolJet: builds the derived image from images/tooljet-ce,
// boots the fragment with it and the pinned upstream images, waits for the bootstrap, then runs
// A6 as the admin. Opt-in, because it needs a Docker daemon and pulls about 2 GB:
// SEALED_CONTRACT=1 pnpm test (CI and the dev CVM). Outside that, only the generated compose
// document is checked with `docker compose config`.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { runA6 } from "../scripts/a6-internal-tools.mjs";
import {
  composeConfig,
  contractCompose,
  docker,
  dockerComposeAvailable,
  dockerDaemonAvailable,
  loadApp,
  waitForExit,
} from "./lib/app.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = loadApp(appDir);
const HOST_PORT = 39_301;
const PUBLIC_URL = `http://localhost:${HOST_PORT}`;
const BUILT = { tooljet: "sealed-contract/tooljet:local" };

function contractSecrets() {
  const hex = () => randomBytes(32).toString("hex");
  return {
    LOCKBOX_MASTER_KEY: hex(),
    SECRET_KEY_BASE: hex(),
    PGRST_JWT_SECRET: hex(),
    PGPASSWORD: hex(),
    SAMPLE_DB_PASSWORD: hex(),
    REDIS_PASSWORD: hex(),
    ADMIN_EMAIL: "admin@contract.example",
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
  test("is valid compose and wires secrets, the public URL and the volume owners", { skip: !dockerComposeAvailable() && "docker compose not installed" }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "tools-contract-doc-"));
    try {
      const { file, doc } = await writeStack(dir, contractSecrets());
      const result = composeConfig(file, "sealed-tools-contract-doc");
      assert.ok(result.ok, result.stderr);
      const services = result.config.services;
      assert.equal(services["internal-tools-server"].image, BUILT.tooljet);
      assert.equal(services["internal-tools-server"].environment.SEALED_PUBLIC_URL_TOOLS, PUBLIC_URL);
      assert.equal(services["internal-tools-server"].environment.DISABLE_TOOLJET_TELEMETRY, "true");
      assert.equal(services["internal-tools-server"].ports[0].target, 3000, "the route port, not the setup port");
      assert.match(services["internal-tools-postgrest"].image, /^docker\.io\/postgrest\/postgrest@sha256:5f4ce744/);
      assert.match(doc.services["internal-tools-contract-init"].entrypoint[2], /chown 1000:1000 \/sealed-init\/internal-tools-bootstrap/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

const enabled = process.env.SEALED_CONTRACT === "1";
const skip = !enabled ? "set SEALED_CONTRACT=1 to build and boot the real images" : !dockerDaemonAvailable() && "no Docker daemon";
describe("contract: real ToolJet CE v3.20.251-lts", { skip }, () => {
  test("the derived image builds, the bootstrap completes, and A6 passes as the admin", { timeout: 3_600_000 }, async (t) => {
    const dir = await mkdtemp(join(tmpdir(), "tools-contract-"));
    const project = `sealed-tools-contract-${process.pid}`;
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

    docker(["build", "--platform", "linux/amd64", "-t", BUILT.tooljet, join(appDir, "images/tooljet-ce")]);
    const listing = docker(["run", "--rm", "--entrypoint", "/bin/sh", BUILT.tooljet, "-c", "find / -xdev -print"], { maxBuffer: 1 << 30 });
    const { findExcluded } = await import("../tools/check-image-paths.mjs");
    assert.deepEqual(findExcluded(listing.split("\n"), app.manifest.license_exclusions), []);

    compose("up", "-d");
    const code = await waitForExit(project, file, "internal-tools-bootstrap", 2_400_000);
    assert.equal(code, 0, compose("logs", "internal-tools-bootstrap"));

    const result = await runA6({ TOOLS_URL: `http://127.0.0.1:${HOST_PORT}`, ADMIN_EMAIL: secrets.ADMIN_EMAIL, ADMIN_PASSWORD: secrets.ADMIN_PASSWORD, A6_CLEANUP: "1" });
    assert.equal(result.ok, true);

    compose("start", "internal-tools-bootstrap");
    assert.equal(await waitForExit(project, file, "internal-tools-bootstrap", 600_000), 0, compose("logs", "internal-tools-bootstrap"));
  });
});
