#!/usr/bin/env node
// A6 acceptance helper for internal-tools (ToolJet CE): load the UI, log in as the admin,
// create an app through the API, and find it in the app list and the editor endpoint.
//
// Env:
//   TOOLS_URL      https://tools.<ip-with-dashes>.sslip.io, or http://internal-tools-server:3000 in the VM
//   ADMIN_EMAIL, ADMIN_PASSWORD   the admin created by internal-tools-bootstrap
//   GATE_BASIC     "user:password" for the Sealed gate (HTTP basic auth; ToolJet itself uses a cookie)
//   GATE_COOKIE    "name=value" cookie that passes the Sealed gate
//   GATE_HEADER    "Name: value" header that passes the Sealed gate
//   A6_CLEANUP=1   delete the app at the end
// Prints one JSON line with the app id. Exit code 0 on success, 1 on failure, 2 on bad usage.

import { fileURLToPath } from "node:url";

import { login, request } from "../bootstrap/bootstrap.mjs";

export class UsageError extends Error {}

export function gateHeaders(env) {
  const headers = {};
  if (env.GATE_BASIC) {
    if (!env.GATE_BASIC.includes(":")) throw new UsageError('GATE_BASIC must look like "user:password"');
    headers.authorization = `Basic ${Buffer.from(env.GATE_BASIC).toString("base64")}`;
  }
  if (env.GATE_COOKIE) headers.cookie = env.GATE_COOKIE;
  if (env.GATE_HEADER) {
    const i = env.GATE_HEADER.indexOf(":");
    if (i < 1) throw new UsageError('GATE_HEADER must look like "Name: value"');
    headers[env.GATE_HEADER.slice(0, i).trim().toLowerCase()] = env.GATE_HEADER.slice(i + 1).trim();
  }
  return headers;
}

function expectStatus(res, allowed, what) {
  if (!allowed.includes(res.status)) {
    const msg = Array.isArray(res.json?.message) ? res.json.message.join("; ") : (res.json?.message ?? "");
    throw new Error(`${what}: HTTP ${res.status} ${msg}`.trim());
  }
}

export async function runA6(env, { now = Date.now(), log = () => {} } = {}) {
  if (!env.TOOLS_URL) throw new UsageError("set TOOLS_URL");
  if (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) throw new UsageError("set ADMIN_EMAIL and ADMIN_PASSWORD");
  const cfg = {
    baseUrl: env.TOOLS_URL.replace(/\/+$/, ""),
    email: env.ADMIN_EMAIL.trim().toLowerCase(),
    password: env.ADMIN_PASSWORD,
    headers: gateHeaders(env),
  };

  log("loading the UI");
  const page = await request(cfg, "GET", "/");
  expectStatus(page, [200], "GET /");
  if (!page.contentType.includes("text/html") || !/<html/i.test(page.text)) {
    throw new Error("GET / did not return the ToolJet web app");
  }
  expectStatus(await request(cfg, "GET", "/api/health"), [200], "GET /api/health");

  log("logging in");
  const { session, organizationId } = await login(cfg);
  const auth = { session, workspaceId: organizationId };

  log("creating an app");
  const name = `Sealed A6 ${new Date(now).toISOString().slice(0, 19)}`;
  const created = await request(cfg, "POST", "/api/apps", { ...auth, body: { name, type: "front-end" } });
  expectStatus(created, [200, 201], "POST /api/apps");
  const appId = created.json?.id;
  if (!appId) throw new Error("POST /api/apps: response has no id");

  const list = await request(cfg, "GET", "/api/apps?type=front-end", auth);
  expectStatus(list, [200], "GET /api/apps");
  if (!(list.json?.apps ?? []).some((a) => a.id === appId)) throw new Error("the new app is not in the app list");

  const app = await request(cfg, "GET", `/api/apps/${appId}`, auth);
  expectStatus(app, [200], "GET /api/apps/:id");
  if (app.json?.id !== appId || app.json?.name !== name) throw new Error("GET /api/apps/:id returned another app");

  if (env.A6_CLEANUP === "1") {
    log("deleting the app");
    expectStatus(await request(cfg, "DELETE", `/api/apps/${appId}`, auth), [200, 204], "DELETE /api/apps/:id");
  }
  return { ok: true, appId, name, organizationId, cleanedUp: env.A6_CLEANUP === "1" };
}

async function main() {
  try {
    const result = await runA6(process.env, { log: (line) => console.error(`[a6-internal-tools] ${line}`) });
    console.log(JSON.stringify(result));
  } catch (err) {
    console.error(`[a6-internal-tools] FAIL: ${err.message}`);
    process.exitCode = err instanceof UsageError ? 2 : 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
