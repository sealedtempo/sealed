#!/usr/bin/env node
// A6 acceptance helper for internal-tools (ToolJet CE): load the UI, log in as the admin,
// create an app through the API, and find it in the app list and the editor endpoint.
//
// Env:
//   TOOLS_URL      https://tools.<ip-with-dashes>.sslip.io, or http://internal-tools-server:3000 in the VM
//   ADMIN_EMAIL, ADMIN_PASSWORD   the admin created by internal-tools-bootstrap
//   GATE_BASIC     "sealed:<gate password>" for the Sealed gate (Caddy forward_auth to sealed-agent).
//                  The helper first probes the route without it; only if the gate asks (401 with a
//                  Basic challenge) does it send Basic auth, once, and then it uses only the
//                  sealed_gate cookie the gate sets. ToolJet's own tj_auth_token cookie travels next
//                  to it. A gate that sets no cookie gets Basic auth on every request.
//   A6_GATE_WAIT_S seconds to wait while the gate answers 503 starting (bootstrap not done), 300
//   A6_CLEANUP=1   delete the app at the end
// Prints one JSON line with the app id. Exit code 0 on success, 1 on failure, 2 on bad usage.

import { fileURLToPath } from "node:url";

import { login, request } from "../bootstrap/bootstrap.mjs";

export class UsageError extends Error {}

export const GATE_COOKIE = "sealed_gate";
const PROBE = "/api/health";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export function gateHeaders(env) {
  const headers = {};
  if (env.GATE_BASIC) {
    if (!env.GATE_BASIC.includes(":")) throw new UsageError('GATE_BASIC must look like "user:password"');
    headers.authorization = `Basic ${Buffer.from(env.GATE_BASIC).toString("base64")}`;
  }
  return headers;
}

function gateCookie(res) {
  for (const value of res.headers.getSetCookie()) {
    const [pair] = value.split(";");
    const at = pair.indexOf("=");
    if (at > 0 && pair.slice(0, at).trim() === GATE_COOKIE && pair.slice(at + 1).trim()) return pair.slice(at + 1).trim();
  }
  return undefined;
}

// Logs in to the Sealed gate in front of baseUrl and returns the headers every later request
// carries: {cookie: "sealed_gate=..."} normally, {authorization} for a gate that sets no cookie,
// or {} when the route has no gate (the gate password is then never sent).
export async function gateLogin(baseUrl, env, { log = () => {}, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const waitMs = Number(env.A6_GATE_WAIT_S ?? "300") * 1000;
  const pollMs = Number(env.A6_GATE_POLL_MS ?? "5000");
  if (!Number.isFinite(waitMs) || waitMs < 0 || !Number.isFinite(pollMs) || pollMs < 0) {
    throw new UsageError("A6_GATE_WAIT_S and A6_GATE_POLL_MS must be non-negative numbers");
  }
  const deadline = Date.now() + waitMs;
  const get = async (url, headers) => {
    try {
      return await fetch(url, { headers, redirect: "manual" });
    } catch (err) {
      throw new Error(`GET ${PROBE}: request failed (${err.cause?.code ?? err.message})`);
    }
  };
  const untilStarted = async (attempt) => {
    for (;;) {
      const res = await attempt();
      if (res.status !== 503 || Date.now() >= deadline) return res;
      log(`waiting for the app to start (503 on ${PROBE})`);
      await sleep(pollMs);
    }
  };

  let res = await untilStarted(() => get(baseUrl + PROBE, {}));
  if (res.status === 503) throw new Error(`the app did not start within ${waitMs / 1000}s (HTTP 503)`);
  if (res.status !== 401 || !/^basic/i.test(res.headers.get("www-authenticate") ?? "")) {
    log("the route did not ask for the gate password, so it is not sent");
    return {};
  }
  const basic = gateHeaders(env);
  if (!basic.authorization) throw new UsageError("the route is behind the Sealed gate: set GATE_BASIC=sealed:<gate password>");
  let cookie;
  res = await untilStarted(async () => {
    let r = await get(baseUrl + PROBE, basic);
    cookie = gateCookie(r) ?? cookie;
    if (REDIRECTS.has(r.status) && cookie) {
      const next = new URL(r.headers.get("location") ?? PROBE, baseUrl + PROBE);
      if (next.origin !== new URL(baseUrl).origin) throw new Error(`the gate redirected to another origin: ${next.host}`);
      r = await get(next.href, { cookie: `${GATE_COOKIE}=${cookie}` });
      cookie = gateCookie(r) ?? cookie;
    }
    return r;
  });
  if (res.status === 401) throw new Error("the gate refused GATE_BASIC (HTTP 401)");
  if (res.status === 503) throw new Error(`the app did not start within ${waitMs / 1000}s (gate answered 503)`);
  if (cookie) {
    log("logged in to the gate once, using the sealed_gate cookie from now on");
    return { cookie: `${GATE_COOKIE}=${cookie}` };
  }
  log("the gate set no sealed_gate cookie; sending Basic auth on every request");
  return basic;
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
  if (env.GATE_BASIC) gateHeaders(env); // usage check before any request
  const baseUrl = env.TOOLS_URL.replace(/\/+$/, "");
  const cfg = {
    baseUrl,
    email: env.ADMIN_EMAIL.trim().toLowerCase(),
    password: env.ADMIN_PASSWORD,
    headers: await gateLogin(baseUrl, env, { log }),
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
