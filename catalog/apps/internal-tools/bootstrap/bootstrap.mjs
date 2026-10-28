// Sealed internal-tools bootstrap for ToolJet CE v3.20.
//
// Runs inside the VM. Until done.json exists, internal-tools-server listens only on its setup
// port (TOOLS_SETUP_URL, http://internal-tools-server:3001), which no Caddy route points at;
// this job creates the first admin and the default workspace there with the one-time
// /api/onboarding/setup-super-admin endpoint (it only works while the instance has no users),
// confirms the admin can log in, confirms that self sign-up is refused, and writes done.json.
// The server then moves to the route port (TOOLS_BASE_URL, http://internal-tools-server:3000).
// On every later start the job only re-checks, read-only, that sign-up is refused there.
// If someone else ran setup-super-admin first, the admin cannot log in and the job fails, so
// done.json is never written and the route never opens onto their instance. Safe to re-run.
// This file is embedded verbatim into compose.fragment.yaml (tools/embed-bootstrap.mjs), so it
// may only import node: builtins.
//
// Secrets (ADMIN_EMAIL, ADMIN_PASSWORD) arrive as env vars from envexec. They and the session
// cookie are kept out of logs and error messages.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const DONE_FILE = "done.json";
export const SESSION_COOKIE = "tj_auth_token";

export class BootstrapError extends Error {}

function trimSlash(url) {
  return url.replace(/\/+$/, "");
}

function positiveInt(env, name, fallback, max) {
  const value = Number(env[name] ?? String(fallback));
  if (!Number.isInteger(value) || value < 1 || value > max) {
    throw new BootstrapError(`${name} must be an integer between 1 and ${max}`);
  }
  return value;
}

function httpUrl(name, value) {
  const url = trimSlash(value);
  if (!/^https?:\/\/[^/]+$/.test(url)) throw new BootstrapError(`${name} must be a scheme and host with no path`);
  return url;
}

export function loadConfig(env) {
  const required = (name) => {
    const value = env[name];
    if (!value) throw new BootstrapError(`missing env ${name}`);
    return value;
  };
  const email = required("ADMIN_EMAIL").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new BootstrapError("ADMIN_EMAIL is not an email address");
  const password = required("ADMIN_PASSWORD");
  // ToolJet accepts 5 to 100 characters; Sealed asks for at least 8.
  if (password.length < 8 || password.length > 100) {
    throw new BootstrapError("ADMIN_PASSWORD must be 8 to 100 characters");
  }
  const origin = httpUrl("SEALED_PUBLIC_URL_TOOLS", required("SEALED_PUBLIC_URL_TOOLS"));
  const baseUrl = httpUrl("TOOLS_BASE_URL", required("TOOLS_BASE_URL"));
  return {
    baseUrl,
    setupUrl: env.TOOLS_SETUP_URL ? httpUrl("TOOLS_SETUP_URL", env.TOOLS_SETUP_URL) : baseUrl,
    origin,
    stateDir: required("STATE_DIR"),
    email,
    password,
    adminName: env.ADMIN_NAME || "Sealed Admin",
    workspaceName: env.WORKSPACE_NAME || "Internal tools",
    healthTimeoutMs: positiveInt(env, "HEALTH_TIMEOUT_S", 900, 86400) * 1000,
    pollMs: positiveInt(env, "POLL_INTERVAL_MS", 5000, 600000),
    headers: {},
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function describe(json) {
  const m = json?.message;
  return Array.isArray(m) ? m.join("; ") : typeof m === "string" ? m : "";
}

export async function request(cfg, method, path, { body, session, workspaceId } = {}) {
  const headers = { ...cfg.headers };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (session) headers.cookie = [cfg.headers.cookie, session].filter(Boolean).join("; ");
  if (workspaceId) headers["tj-workspace-id"] = workspaceId;
  let res;
  try {
    res = await fetch(`${cfg.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
    });
  } catch (err) {
    throw new BootstrapError(`${method} ${path}: request failed (${err.cause?.code ?? err.message})`);
  }
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return {
    status: res.status,
    json,
    text,
    contentType: res.headers.get("content-type") ?? "",
    setCookies: res.headers.getSetCookie(),
  };
}

export function sessionFrom(setCookies) {
  const cookie = setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  const pair = cookie?.split(";")[0];
  return pair && pair.length > SESSION_COOKIE.length + 1 ? pair : undefined;
}

function sessionResult(operation, res) {
  const session = sessionFrom(res.setCookies);
  const organizationId = res.json?.current_organization_id;
  if (!session || !organizationId) throw new BootstrapError(`${operation}: response has no session or workspace`);
  return { session, organizationId };
}

export async function waitHealthy(cfg, log) {
  const deadline = Date.now() + cfg.healthTimeoutMs;
  for (;;) {
    try {
      const res = await fetch(`${cfg.baseUrl}/api/health`, { headers: cfg.headers });
      if (res.status === 200) return;
    } catch {
      // server not listening yet
    }
    if (Date.now() >= deadline) {
      throw new BootstrapError(`server not healthy at ${cfg.baseUrl} after ${cfg.healthTimeoutMs / 1000}s`);
    }
    log(`waiting for ${cfg.baseUrl}/api/health`);
    await sleep(cfg.pollMs);
  }
}

// Creates the first admin and workspace. Returns undefined when the instance already has users
// (ToolJet's FirstUserSignupGuard answers 403).
export async function setupSuperAdmin(cfg) {
  const res = await request(cfg, "POST", "/api/onboarding/setup-super-admin", {
    body: { email: cfg.email, password: cfg.password, name: cfg.adminName, workspaceName: cfg.workspaceName },
  });
  if (res.status === 403) return undefined;
  if (res.status !== 200 && res.status !== 201) {
    throw new BootstrapError(`setup-super-admin: HTTP ${res.status} ${describe(res.json)}`.trim());
  }
  return sessionResult("setup-super-admin", res);
}

export async function login(cfg) {
  const res = await request(cfg, "POST", "/api/authenticate", { body: { email: cfg.email, password: cfg.password } });
  if (res.status !== 200 && res.status !== 201) {
    throw new BootstrapError(`authenticate: HTTP ${res.status} ${describe(res.json)}`.trim());
  }
  return sessionResult("authenticate", res);
}

// Guards run before validation in ToolJet (NestJS), so an empty body gets 403 when
// DISABLE_SIGNUPS=true and 400 when sign-up is open. Either way no user is created.
export async function verifySignupClosed(cfg) {
  const res = await request(cfg, "POST", "/api/onboarding/signup", { body: {} });
  if (res.status !== 403) throw new BootstrapError(`self sign-up is not closed (probe got HTTP ${res.status})`);
}

async function verifySession(cfg, { session, organizationId }) {
  const res = await request(cfg, "GET", "/api/apps?type=front-end", { session, workspaceId: organizationId });
  if (res.status !== 200) throw new BootstrapError(`GET /api/apps with the admin session: HTTP ${res.status}`);
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return undefined;
    throw new BootstrapError(`cannot read ${file}: ${err.message}`);
  }
}

export async function bootstrap(cfg, { log = () => {}, now = () => Date.now() } = {}) {
  const doneFile = join(cfg.stateDir, DONE_FILE);
  const setup = { ...cfg, baseUrl: cfg.setupUrl };
  const done = await readJson(doneFile);
  if (done?.complete === true) {
    log("already bootstrapped, re-checking that self sign-up is refused");
    await waitHealthy(cfg, log);
    await verifySignupClosed(cfg);
    return { status: "already-done", organizationId: done.organizationId };
  }
  await mkdir(cfg.stateDir, { recursive: true });
  await waitHealthy(setup, log);

  log("creating the first admin and workspace");
  let session = await setupSuperAdmin(setup);
  if (!session) {
    log("instance already has users, logging in as the admin");
    try {
      session = await login(setup);
    } catch (err) {
      throw new BootstrapError(`the instance already has users and the admin cannot log in (${err.message})`);
    }
  }
  await verifySession(setup, session);
  log("checking that self sign-up is refused");
  await verifySignupClosed(setup);

  const tmp = `${doneFile}.tmp`;
  const record = {
    schema: "sealed-bootstrap-done/v1",
    app: "internal-tools",
    complete: true,
    completedAt: new Date(now()).toISOString(),
    organizationId: session.organizationId,
    url: cfg.origin,
  };
  await writeFile(tmp, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o644 });
  await rename(tmp, doneFile);
  if (cfg.setupUrl !== cfg.baseUrl) {
    log("done.json written, waiting for internal-tools-server on the route port");
    await waitHealthy(cfg, log);
    await verifySignupClosed(cfg);
  }
  log("bootstrap complete");
  return { status: "bootstrapped", organizationId: session.organizationId };
}

export async function run(env, log = (line) => console.log(`[internal-tools-bootstrap] ${line}`)) {
  try {
    await bootstrap(loadConfig(env), { log });
    return 0;
  } catch (err) {
    log(`failed: ${err instanceof BootstrapError ? err.message : "unexpected error"}`);
    if (!(err instanceof BootstrapError)) console.error(err?.stack ?? String(err));
    return 1;
  }
}

if (process.env.SEALED_BOOTSTRAP === "run") {
  process.exitCode = await run(process.env);
}
