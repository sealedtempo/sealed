// Sealed crm bootstrap for Twenty v2.52.
//
// Runs once inside the VM, against http://crm-server:3000, before the crm route opens:
// first admin, the single workspace, activation, public invite link off, and an API key
// for the customer written to the bootstrap volume. Safe to re-run: every step checks
// what already exists. This file is embedded verbatim into compose.fragment.yaml
// (tools/embed-bootstrap.mjs), so it may only import node: builtins.
//
// Secrets (ADMIN_EMAIL, ADMIN_PASSWORD) arrive as env vars from envexec. They and every
// token are kept out of logs and error messages.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const ADMIN_ROLE_UID = "20202020-02c2-43f2-b94d-cab1f2b532eb";
export const DONE_FILE = "done.json";
export const STATE_FILE = "state.json";
export const API_KEY_FILE = "api-key.json";
const DAY_MS = 86_400_000;

export class BootstrapError extends Error {}

export class GraphQLRequestError extends BootstrapError {
  constructor(operation, errors) {
    const messages = errors.map((e) => e?.message ?? "unknown error").join("; ");
    super(`${operation}: ${messages}`);
    this.operation = operation;
    this.codes = errors.map((e) => e?.extensions?.subCode ?? e?.extensions?.code).filter(Boolean);
  }
}

export const QUERIES = {
  checkUserExists:
    "query CheckUserExists($email: String!) { checkUserExists(email: $email) { exists availableWorkspacesCount } }",
  signUp:
    "mutation SignUp($email: String!, $password: String!) { signUp(email: $email, password: $password) { tokens { accessOrWorkspaceAgnosticToken { token } } } }",
  signIn:
    "mutation SignIn($email: String!, $password: String!) { signIn(email: $email, password: $password) { availableWorkspaces { availableWorkspacesForSignIn { id loginToken } } tokens { accessOrWorkspaceAgnosticToken { token } } } }",
  signUpInNewWorkspace:
    "mutation SignUpInNewWorkspace($input: SignUpInNewWorkspaceInput) { signUpInNewWorkspace(input: $input) { loginToken { token } workspace { id workspaceUrls { subdomainUrl customUrl } } } }",
  getLoginTokenFromCredentials:
    "mutation GetLoginTokenFromCredentials($email: String!, $password: String!, $origin: String!) { getLoginTokenFromCredentials(email: $email, password: $password, origin: $origin) { loginToken { token } } }",
  getAuthTokensFromLoginToken:
    "mutation GetAuthTokensFromLoginToken($loginToken: String!, $origin: String!) { getAuthTokensFromLoginToken(loginToken: $loginToken, origin: $origin) { tokens { accessOrWorkspaceAgnosticToken { token } } } }",
  currentWorkspace:
    "query CurrentWorkspace { currentWorkspace { id activationStatus isPublicInviteLinkEnabled } }",
  activateWorkspace:
    "mutation ActivateWorkspace($input: ActivateWorkspaceInput!) { activateWorkspace(data: $input) { id activationStatus } }",
  closePublicInviteLink:
    "mutation UpdateWorkspace($input: UpdateWorkspaceInput!) { updateWorkspace(data: $input) { id isPublicInviteLinkEnabled } }",
  getApiKeyRoles:
    "query GetApiKeyRoles { getApiKeyRoles { id label universalIdentifier canBeAssignedToApiKeys } }",
  createApiKey:
    "mutation CreateApiKey($input: CreateApiKeyInput!) { createApiKey(input: $input) { id name expiresAt } }",
  generateApiKeyToken:
    "mutation GenerateApiKeyToken($apiKeyId: UUID!, $expiresAt: String!) { generateApiKeyToken(apiKeyId: $apiKeyId, expiresAt: $expiresAt) { token } }",
  revokeApiKey: "mutation RevokeApiKey($input: RevokeApiKeyInput!) { revokeApiKey(input: $input) { id } }",
};

function trimSlash(url) {
  return url.replace(/\/+$/, "");
}

function positiveInt(env, name, fallback, max) {
  const raw = env[name] ?? String(fallback);
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > max) {
    throw new BootstrapError(`${name} must be an integer between 1 and ${max}`);
  }
  return value;
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
  // Twenty's PASSWORD_REGEX is /^.{8,50}$/.
  if (password.length < 8 || password.length > 50) {
    throw new BootstrapError("ADMIN_PASSWORD must be 8 to 50 characters");
  }
  const origin = trimSlash(required("SEALED_PUBLIC_URL_CRM"));
  if (!/^https?:\/\/[^/]+$/.test(origin)) throw new BootstrapError("SEALED_PUBLIC_URL_CRM must be a scheme and host with no path");
  return {
    baseUrl: trimSlash(required("CRM_BASE_URL")),
    origin,
    stateDir: required("STATE_DIR"),
    email,
    password,
    workspaceName: env.WORKSPACE_NAME || "CRM",
    apiKeyName: env.API_KEY_NAME || "sealed-customer",
    apiKeyTtlDays: positiveInt(env, "API_KEY_TTL_DAYS", 365, 36500),
    healthTimeoutMs: positiveInt(env, "HEALTH_TIMEOUT_S", 900, 86400) * 1000,
    pollMs: positiveInt(env, "POLL_INTERVAL_MS", 5000, 600000),
    headers: {},
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function gql(cfg, path, operation, variables = {}, token = undefined) {
  const headers = { "content-type": "application/json", ...cfg.headers };
  if (token) headers.authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`${cfg.baseUrl}/${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ query: QUERIES[operation], variables }),
    });
  } catch (err) {
    throw new BootstrapError(`${operation}: request failed (${err.cause?.code ?? err.message})`);
  }
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new BootstrapError(`${operation}: HTTP ${res.status} with a non-JSON body`);
  }
  if (Array.isArray(body.errors) && body.errors.length > 0) throw new GraphQLRequestError(operation, body.errors);
  if (!res.ok || !body.data) throw new BootstrapError(`${operation}: HTTP ${res.status}`);
  return body.data;
}

export async function waitHealthy(cfg, log) {
  const deadline = Date.now() + cfg.healthTimeoutMs;
  for (;;) {
    try {
      const res = await fetch(`${cfg.baseUrl}/healthz`, { headers: cfg.headers });
      if (res.status === 200) return;
    } catch {
      // server not listening yet
    }
    if (Date.now() >= deadline) throw new BootstrapError(`server not healthy after ${cfg.healthTimeoutMs / 1000}s`);
    log("waiting for crm-server /healthz");
    await sleep(cfg.pollMs);
  }
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return undefined;
    throw new BootstrapError(`cannot read ${file}: ${err.message}`);
  }
}

async function writeJsonAtomic(file, value, mode = 0o600) {
  const tmp = `${file}.tmp`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await rename(tmp, file);
}

function accessToken(data, field) {
  const token = data?.[field]?.tokens?.accessOrWorkspaceAgnosticToken?.token;
  if (!token) throw new BootstrapError(`${field}: response has no token`);
  return token;
}

async function exchangeLoginToken(cfg, loginToken) {
  const data = await gql(cfg, "metadata", "getAuthTokensFromLoginToken", { loginToken, origin: cfg.origin });
  return accessToken(data, "getAuthTokensFromLoginToken");
}

// Logs in to the existing workspace with the admin password.
export async function login(cfg) {
  const data = await gql(cfg, "metadata", "getLoginTokenFromCredentials", {
    email: cfg.email,
    password: cfg.password,
    origin: cfg.origin,
  });
  const loginToken = data?.getLoginTokenFromCredentials?.loginToken?.token;
  if (!loginToken) throw new BootstrapError("getLoginTokenFromCredentials: response has no login token");
  return exchangeLoginToken(cfg, loginToken);
}

// Gets a session for a workspace the bootstrap created earlier, even one that is not active
// yet (password login may refuse it, while signIn still lists it with a login token).
async function resume(cfg, workspaceId) {
  try {
    return await login(cfg);
  } catch (err) {
    if (!workspaceId) throw err;
  }
  const data = await gql(cfg, "metadata", "signIn", { email: cfg.email, password: cfg.password });
  const listed = data?.signIn?.availableWorkspaces?.availableWorkspacesForSignIn ?? [];
  const ws = listed.find((w) => w.id === workspaceId);
  if (!ws?.loginToken) throw new BootstrapError("signIn: the bootstrap workspace is not available to the admin");
  return exchangeLoginToken(cfg, ws.loginToken);
}

// Creates the admin (or signs in an admin left without a workspace) and the single workspace.
async function createAdminAndWorkspace(cfg, userExists) {
  const credentials = { email: cfg.email, password: cfg.password };
  const agnostic = userExists
    ? accessToken(await gql(cfg, "metadata", "signIn", credentials), "signIn")
    : accessToken(await gql(cfg, "metadata", "signUp", credentials), "signUp");
  const data = await gql(
    cfg,
    "metadata",
    "signUpInNewWorkspace",
    { input: { displayName: cfg.workspaceName } },
    agnostic,
  );
  const result = data?.signUpInNewWorkspace;
  if (!result?.loginToken?.token || !result?.workspace?.id) {
    throw new BootstrapError("signUpInNewWorkspace: response has no login token or workspace");
  }
  return { workspaceId: result.workspace.id, token: await exchangeLoginToken(cfg, result.loginToken.token) };
}

async function ensureActive(cfg, token, status, log) {
  const deadline = Date.now() + cfg.healthTimeoutMs;
  let current = status;
  for (;;) {
    if (current === "ACTIVE") return;
    if (current === "PENDING_CREATION") {
      log("activating workspace (builds the workspace schema)");
      const data = await gql(cfg, "metadata", "activateWorkspace", { input: {} }, token);
      current = data?.activateWorkspace?.activationStatus ?? "ONGOING_CREATION";
      continue;
    }
    if (current !== "ONGOING_CREATION") throw new BootstrapError(`workspace is ${current}, expected ACTIVE`);
    if (Date.now() >= deadline) throw new BootstrapError("workspace activation did not finish in time");
    await sleep(cfg.pollMs);
    current = (await gql(cfg, "metadata", "currentWorkspace", {}, token)).currentWorkspace?.activationStatus;
  }
}

async function closePublicInviteLink(cfg, token) {
  const data = await gql(cfg, "metadata", "closePublicInviteLink", { input: { isPublicInviteLinkEnabled: false } }, token);
  if (data?.updateWorkspace?.isPublicInviteLinkEnabled !== false) {
    throw new BootstrapError("updateWorkspace did not disable the public invite link");
  }
}

export async function pickAdminRole(cfg, token) {
  const roles = (await gql(cfg, "metadata", "getApiKeyRoles", {}, token)).getApiKeyRoles ?? [];
  const role =
    roles.find((r) => r.universalIdentifier === ADMIN_ROLE_UID) ??
    roles.find((r) => r.label === "Admin" && r.canBeAssignedToApiKeys !== false);
  if (!role) throw new BootstrapError("no Admin role can be assigned to API keys");
  return role.id;
}

export async function createApiKey(cfg, token, { name, ttlDays, now = Date.now() }) {
  const roleId = await pickAdminRole(cfg, token);
  const expiresAt = new Date(now + ttlDays * DAY_MS).toISOString();
  const created = (await gql(cfg, "metadata", "createApiKey", { input: { name, expiresAt, roleId } }, token)).createApiKey;
  if (!created?.id) throw new BootstrapError("createApiKey: response has no id");
  const minted = await gql(cfg, "metadata", "generateApiKeyToken", { apiKeyId: created.id, expiresAt }, token);
  const apiKey = minted?.generateApiKeyToken?.token;
  if (!apiKey) throw new BootstrapError("generateApiKeyToken: response has no token");
  return { id: created.id, name, expiresAt, token: apiKey };
}

export async function revokeApiKey(cfg, token, id) {
  await gql(cfg, "metadata", "revokeApiKey", { input: { id } }, token);
}

// Fails if the public client config shows any switch the manifest turns off.
export async function verifyClientConfig(cfg) {
  const res = await fetch(`${cfg.baseUrl}/client-config`, { headers: cfg.headers });
  if (!res.ok) throw new BootstrapError(`/client-config: HTTP ${res.status}`);
  const conf = await res.json();
  const mustBeFalse = {
    isMultiWorkspaceEnabled: conf.isMultiWorkspaceEnabled,
    "billing.isBillingEnabled": conf.billing?.isBillingEnabled,
    analyticsEnabled: conf.analyticsEnabled,
    allowRequestsToTwentyIcons: conf.allowRequestsToTwentyIcons,
    isConfigVariablesInDbEnabled: conf.isConfigVariablesInDbEnabled,
    isImapSmtpCaldavEnabled: conf.isImapSmtpCaldavEnabled,
    isGoogleMessagingEnabled: conf.isGoogleMessagingEnabled,
    isGoogleCalendarEnabled: conf.isGoogleCalendarEnabled,
    isMicrosoftMessagingEnabled: conf.isMicrosoftMessagingEnabled,
    isMicrosoftCalendarEnabled: conf.isMicrosoftCalendarEnabled,
  };
  const on = Object.entries(mustBeFalse).filter(([, v]) => v === true).map(([k]) => k);
  if (on.length > 0) throw new BootstrapError(`client-config has switches on that must be off: ${on.join(", ")}`);
}

export async function bootstrap(cfg, { log = () => {}, now = () => Date.now() } = {}) {
  const doneFile = join(cfg.stateDir, DONE_FILE);
  const stateFile = join(cfg.stateDir, STATE_FILE);
  const apiKeyFile = join(cfg.stateDir, API_KEY_FILE);
  const done = await readJson(doneFile);
  if (done?.complete === true) {
    log("already bootstrapped");
    return { status: "already-done", workspaceId: done.workspaceId };
  }
  await mkdir(cfg.stateDir, { recursive: true });
  await waitHealthy(cfg, log);

  const state = (await readJson(stateFile)) ?? {};
  const exists = (await gql(cfg, "metadata", "checkUserExists", { email: cfg.email })).checkUserExists;
  let token;
  let workspaceId = state.workspaceId;
  let status;
  if (state.workspaceId || (exists?.exists && exists.availableWorkspacesCount > 0)) {
    log("admin and workspace exist, logging in");
    token = await resume(cfg, state.workspaceId);
    const ws = (await gql(cfg, "metadata", "currentWorkspace", {}, token)).currentWorkspace;
    if (state.workspaceId && ws?.id !== state.workspaceId) {
      throw new BootstrapError("the admin's workspace is not the one this bootstrap created");
    }
    workspaceId = ws?.id;
    status = ws?.activationStatus;
  } else {
    log(exists?.exists ? "admin exists without a workspace, creating it" : "creating admin and workspace");
    ({ workspaceId, token } = await createAdminAndWorkspace(cfg, Boolean(exists?.exists)));
    await writeJsonAtomic(stateFile, { workspaceId, workspaceCreatedAt: new Date(now()).toISOString() });
    status = "PENDING_CREATION";
  }
  if (!workspaceId) throw new BootstrapError("could not determine the workspace id");

  await ensureActive(cfg, token, status, log);
  log("closing the public invite link");
  await closePublicInviteLink(cfg, token);

  const existingKey = await readJson(apiKeyFile);
  if (!existingKey?.token) {
    log("creating the customer API key");
    const key = await createApiKey(cfg, token, { name: cfg.apiKeyName, ttlDays: cfg.apiKeyTtlDays, now: now() });
    await writeJsonAtomic(apiKeyFile, {
      schema: "sealed-crm-api-key/v1",
      id: key.id,
      name: key.name,
      expiresAt: key.expiresAt,
      createdAt: new Date(now()).toISOString(),
      url: cfg.origin,
      token: key.token,
    });
  }

  await verifyClientConfig(cfg);
  await writeJsonAtomic(
    doneFile,
    {
      schema: "sealed-bootstrap-done/v1",
      app: "crm",
      complete: true,
      completedAt: new Date(now()).toISOString(),
      workspaceId,
      apiKeyFile: API_KEY_FILE,
    },
    0o644,
  );
  log("bootstrap complete");
  return { status: "bootstrapped", workspaceId };
}

export async function run(env, log = (line) => console.log(`[crm-bootstrap] ${line}`)) {
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
