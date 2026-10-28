// Runs internal-tools-server's entrypoint script from the fragment with a stand-in for the
// derived image's /app/server/sealed-entrypoint.sh: ToolJet must listen only on the setup port
// until done.json exists, then only on the route port. Runs under every POSIX shell found.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { unescapeFromCompose } from "../tools/embed-bootstrap.mjs";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const fragment = parse(readFileSync(join(appDir, "compose.fragment.yaml"), "utf8"));
const server = fragment.services["internal-tools-server"];
const script = unescapeFromCompose(server.entrypoint[2]);
const shells = ["/bin/sh", "/bin/dash", "/bin/busybox"].filter((s) => existsSync(s));

const FAKE_TOOLJET = `
const http = require("node:http");
const fs = require("node:fs");
if (process.env.FAKE_EXIT) process.exit(Number(process.env.FAKE_EXIT));
fs.appendFileSync(process.env.FAKE_LOG, "listen " + process.env.PORT + "\\n");
const s = http.createServer((q, r) => r.end("ok")).listen(Number(process.env.PORT), "127.0.0.1");
process.on("SIGTERM", () => s.close(() => process.exit(0)));
`;

const cleanups = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()();
});

async function freePort() {
  const s = createServer();
  await new Promise((resolve) => s.listen(0, "127.0.0.1", resolve));
  const { port } = s.address();
  await new Promise((resolve) => s.close(resolve));
  return port;
}

async function responds(port) {
  try {
    return (await fetch(`http://127.0.0.1:${port}/api/health`)).status === 200;
  } catch {
    return false;
  }
}

async function until(check, what, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

async function start(shell, { done = false, env = {} } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "tools-entry-"));
  const doneFile = join(dir, "done.json");
  const log = join(dir, "log");
  const fakeEntrypoint = join(dir, "entrypoint.sh");
  await writeFile(join(dir, "tooljet.cjs"), FAKE_TOOLJET);
  await writeFile(fakeEntrypoint, `#!/bin/sh\nexec "${process.execPath}" "${join(dir, "tooljet.cjs")}"\n`);
  await chmod(fakeEntrypoint, 0o755);
  await writeFile(log, "");
  if (done) await writeFile(doneFile, "{}");
  const routePort = await freePort();
  const setupPort = await freePort();
  const body = script.replaceAll("/sealed-bootstrap/done.json", doneFile).replaceAll("/app/server/sealed-entrypoint.sh", fakeEntrypoint);
  assert.notEqual(body, script);
  const child = spawn(shell, ["-c", body, "internal-tools-server", ...server.command], {
    env: {
      PATH: process.env.PATH,
      SEALED_PUBLIC_URL_TOOLS: "https://tools.34-1-2-3.sslip.io",
      PGPASSWORD: "pg",
      SAMPLE_DB_PASSWORD: "sample",
      PORT: String(routePort),
      TOOLS_SETUP_PORT: String(setupPort),
      FAKE_LOG: log,
      ...env,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
  cleanups.push(async () => {
    child.kill("SIGKILL");
    await exited;
    await rm(dir, { recursive: true, force: true });
  });
  return { child, exited, doneFile, log, routePort, setupPort, stderr: () => stderr };
}

describe("internal-tools-server entrypoint", () => {
  test("the fragment wires the setup port, the done file and the route port", () => {
    assert.equal(server.environment.PORT, "3000");
    assert.equal(server.environment.TOOLS_SETUP_PORT, "3001");
    assert.ok(server.volumes.includes("internal-tools-bootstrap:/sealed-bootstrap:ro"));
    const bootstrap = fragment.services["internal-tools-bootstrap"].environment;
    assert.equal(bootstrap.TOOLS_SETUP_URL, "http://internal-tools-server:3001");
    assert.equal(bootstrap.TOOLS_BASE_URL, "http://internal-tools-server:3000");
    assert.match(server.healthcheck.test[1], /localhost:3000\/api\/health \|\| .*localhost:3001\/api\/health/);
  });

  for (const shell of shells) {
    describe(shell, () => {
      test("serves only on the setup port until done.json, then only on the route port", async () => {
        const run = await start(shell);
        await until(() => responds(run.setupPort), "the setup port");
        assert.equal(await responds(run.routePort), false, "the route port stays closed during setup");
        await writeFile(run.doneFile, "{}");
        await until(() => responds(run.routePort), "the route port");
        assert.equal(await responds(run.setupPort), false, "the setup listener is gone");
        assert.deepEqual((await readFile(run.log, "utf8")).trim().split("\n"), [`listen ${run.setupPort}`, `listen ${run.routePort}`]);
        assert.match(run.stderr(), /internal-tools-bootstrap is done, serving on port/);
        run.child.kill("SIGTERM");
        assert.equal((await run.exited).code, 0, "ToolJet owns the process after the switch and stops cleanly");
      });

      test("starts straight on the route port once done.json exists", async () => {
        const run = await start(shell, { done: true });
        await until(() => responds(run.routePort), "the route port");
        assert.equal(await responds(run.setupPort), false);
        assert.deepEqual((await readFile(run.log, "utf8")).trim().split("\n"), [`listen ${run.routePort}`]);
      });

      test("exits non-zero when ToolJet stops before the bootstrap finished", async () => {
        const run = await start(shell, { env: { FAKE_EXIT: "3" } });
        const { code } = await run.exited;
        assert.equal(code, 1);
        assert.match(run.stderr(), /ToolJet exited \(3\) before internal-tools-bootstrap finished/);
      });

      test("stops ToolJet and exits on SIGTERM during setup", async () => {
        const run = await start(shell);
        await until(() => responds(run.setupPort), "the setup port");
        run.child.kill("SIGTERM");
        const { code } = await run.exited;
        assert.equal(code, 143);
        await until(async () => !(await responds(run.setupPort)), "the setup listener to stop");
      });
    });
  }
});
