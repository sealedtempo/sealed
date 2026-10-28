// In-memory stand-in for the Twenty v2.52 endpoints the bootstrap and the A6 helper use:
// GET /healthz, GET /client-config, POST /metadata and POST /admin-panel (GraphQL, matched by
// operation name) and the REST endpoints for companies, people and opportunities.
//
// It applies the rules of sign-in-up.service.ts and the admin panel guards at commit 62c9c99:
// - signUp without a workspace only while the instance has no workspace;
// - signUpInNewWorkspace while there is no workspace (IS_MULTIWORKSPACE_ENABLED=false refuses
//   it with SIGNUP_DISABLED afterwards);
// - every new user gets canAccessFullAdminPanel and canImpersonate when no server admin exists
//   yet (shouldGrantServerAdmin = !hasServerAdmin()), so whoever signs up first is server admin;
// - getServerAdmins needs canAccessFullAdminPanel, adminPanelTopWorkspaces needs canImpersonate,
//   adminPanelRecentUsers needs either; both lists are capped at 10;
// - origin checks on login tokens, bearer tokens, API key revocation.
// Attackers in the tests use the same HTTP API, so the bootstrap sees what Twenty would show.

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

export const ADMIN_ROLE = { id: "role-admin", label: "Admin", universalIdentifier: "20202020-02c2-43f2-b94d-cab1f2b532eb", canBeAssignedToApiKeys: true };
const MEMBER_ROLE = { id: "role-member", label: "Member", universalIdentifier: "member", canBeAssignedToApiKeys: true };
const LIST_LIMIT = 10;

// GET /client-config as Twenty v2.52 builds it (client-config.service.ts) for the env the crm
// fragment and the manifest's telemetry_off_env set.
export function defaultClientConfig(origin) {
  return {
    appVersion: "v2.52.0",
    billing: {
      isBillingEnabled: false,
      billingUrl: "",
      trialPeriods: [
        { duration: 30, isCreditCardRequired: true },
        { duration: 30, isCreditCardRequired: false },
      ],
    },
    aiModels: [],
    aiEvaluationModels: [],
    aiModelTiers: [],
    authProviders: { google: false, magicLink: false, password: true, microsoft: false, sso: [] },
    signInPrefilled: false,
    isMultiWorkspaceEnabled: false,
    isEmailVerificationRequired: false,
    defaultSubdomain: "app",
    frontDomain: new URL(origin).hostname,
    serverUrl: origin,
    publicFunctionDomain: null,
    support: { supportDriver: "NONE" },
    sentry: { release: "v2.52.0", tracesSampleRate: 1 },
    captcha: {},
    api: { mutationMaximumAffectedRecords: 100 },
    onboarding: null,
    isAttachmentPreviewEnabled: true,
    analyticsEnabled: false,
    canManageFeatureFlags: false,
    publicFeatureFlags: [],
    isCookieSessionEnabled: true,
    isMicrosoftMessagingEnabled: false,
    isMicrosoftCalendarEnabled: false,
    isGoogleMessagingEnabled: false,
    isGoogleCalendarEnabled: false,
    isConfigVariablesInDbEnabled: false,
    isImapSmtpCaldavEnabled: false,
    isEmailingDomainInDemoMode: false,
    allowRequestsToTwentyIcons: false,
    isBookCallOnboardingStepEnabled: false,
    isCompanyEnrichmentEnabled: false,
    isCloudflareIntegrationEnabled: false,
    isClickHouseConfigured: false,
    isWorkspaceSchemaDDLLocked: false,
    isOnboardingAiChatEnabled: false,
    enterpriseInstanceType: "PRODUCTION",
  };
}

function gqlError(message, subCode, code = "FORBIDDEN") {
  return { errors: [{ message, extensions: { code, subCode } }] };
}

export function createFakeTwenty({
  origin,
  unhealthyPolls = 0,
  roles = [ADMIN_ROLE, MEMBER_ROLE],
  clientConfig,
  activationPolls = 0,
  refusePendingLogin = false,
} = {}) {
  const state = {
    users: new Map(),
    workspaces: [],
    tokens: new Map(),
    apiKeys: new Map(),
    records: { companies: new Map(), people: new Map(), opportunities: new Map() },
    calls: [],
    healthPolls: 0,
    clientConfigReads: 0,
    activationPollsLeft: activationPolls,
    failNext: new Map(),
    // Async actions run just before the named operation is handled (an attacker's timing).
    beforeOp: new Map(),
    clientConfig: clientConfig ?? defaultClientConfig(origin),
    // The single workspace in the normal case; single-workspace mode resolves the origin to the
    // oldest workspace.
    get workspace() {
      return this.workspaces[0];
    },
  };

  const hasServerAdmin = () => [...state.users.values()].some((u) => u.canAccessFullAdminPanel);
  const createUser = (email, password) => {
    const grant = !hasServerAdmin();
    const user = { id: randomUUID(), email, password, canAccessFullAdminPanel: grant, canImpersonate: grant, createdAt: state.users.size };
    state.users.set(email, user);
    return user;
  };
  const findWorkspace = (id) => state.workspaces.find((w) => w.id === id);

  const issue = (kind, payload) => {
    const token = `${kind}-${randomUUID()}`;
    state.tokens.set(token, { ...payload, kind });
    return token;
  };
  const bearer = (req, kind) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    const t = m && state.tokens.get(m[1]);
    return t && t.kind === kind ? t : undefined;
  };
  // A workspace access token and its user and workspace, or undefined.
  const session = (req) => {
    const at = bearer(req, "at");
    const ws = at && findWorkspace(at.workspaceId);
    return ws ? { user: state.users.get(at.email), ws } : undefined;
  };
  const unauthenticated = () => gqlError("Unauthenticated", "UNAUTHENTICATED", "UNAUTHENTICATED");

  const metadataOps = {
    CheckUserExists: ({ email }) => {
      const user = state.users.get(email);
      const count = state.workspaces.filter((w) => w.members.has(email) && w.status === "ACTIVE").length;
      return { checkUserExists: { exists: Boolean(user), availableWorkspacesCount: user ? count : 0 } };
    },
    SignUp: ({ email, password }) => {
      if (state.users.has(email)) return gqlError("User already exists", "USER_ALREADY_EXISTS");
      if (state.workspaces.length > 0) return gqlError("Sign up without workspace is not allowed", "SIGNUP_DISABLED");
      createUser(email, password);
      return { signUp: { tokens: { accessOrWorkspaceAgnosticToken: { token: issue("wa", { email }) } } } };
    },
    SignIn: ({ email, password }) => {
      const user = state.users.get(email);
      if (!user || user.password !== password) return gqlError("Wrong password", "FORBIDDEN_EXCEPTION");
      const listed = state.workspaces
        .filter((w) => w.members.has(email))
        .map((w) => ({ id: w.id, loginToken: issue("lt", { email, workspaceId: w.id }) }));
      return {
        signIn: {
          availableWorkspaces: { availableWorkspacesForSignIn: listed },
          tokens: { accessOrWorkspaceAgnosticToken: { token: issue("wa", { email }) } },
        },
      };
    },
    SignUpInNewWorkspace: ({ input }, req) => {
      const wa = bearer(req, "wa");
      if (!wa) return unauthenticated();
      if (state.workspaces.length > 0) return gqlError("New workspace setup is disabled", "SIGNUP_DISABLED");
      const ws = { id: randomUUID(), displayName: input?.displayName, status: "PENDING_CREATION", invite: true, members: new Set([wa.email]) };
      state.workspaces.push(ws);
      return {
        signUpInNewWorkspace: {
          loginToken: { token: issue("lt", { email: wa.email, workspaceId: ws.id }) },
          workspace: { id: ws.id, workspaceUrls: { subdomainUrl: origin, customUrl: null } },
        },
      };
    },
    GetLoginTokenFromCredentials: ({ email, password, origin: o }) => {
      const ws = state.workspace;
      if (o !== origin || !ws) return gqlError("Workspace not found", "WORKSPACE_NOT_FOUND");
      const user = state.users.get(email);
      if (!user || user.password !== password || !ws.members.has(email)) return gqlError("Wrong password", "FORBIDDEN_EXCEPTION");
      if (refusePendingLogin && ws.status !== "ACTIVE") return gqlError("Workspace is not ready", "WORKSPACE_NOT_READY");
      return { getLoginTokenFromCredentials: { loginToken: { token: issue("lt", { email, workspaceId: ws.id }) } } };
    },
    GetAuthTokensFromLoginToken: ({ loginToken, origin: o }) => {
      const lt = state.tokens.get(loginToken);
      if (!lt || lt.kind !== "lt" || o !== origin) return gqlError("Invalid login token", "INVALID_INPUT");
      state.tokens.delete(loginToken);
      return { getAuthTokensFromLoginToken: { tokens: { accessOrWorkspaceAgnosticToken: { token: issue("at", lt) } } } };
    },
    CurrentUser: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      const { id, email, canAccessFullAdminPanel, canImpersonate } = s.user;
      return { currentUser: { id, email, canAccessFullAdminPanel, canImpersonate } };
    },
    WorkspaceMembers: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      // Members live in the workspace schema, which activation builds.
      if (s.ws.status !== "ACTIVE") return gqlError("Workspace schema not found", "WORKSPACE_SCHEMA_NOT_FOUND", "INTERNAL_SERVER_ERROR");
      const members = [...s.ws.members].map((email) => ({ id: state.users.get(email).id, userEmail: email }));
      return { currentUser: { email: s.user.email, workspaceMembers: members, currentWorkspace: { id: s.ws.id } } };
    },
    CurrentWorkspace: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      if (s.ws.status === "ONGOING_CREATION" && state.activationPollsLeft-- <= 0) s.ws.status = "ACTIVE";
      return { currentWorkspace: { id: s.ws.id, activationStatus: s.ws.status, isPublicInviteLinkEnabled: s.ws.invite } };
    },
    ActivateWorkspace: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      if (s.ws.status !== "PENDING_CREATION") return gqlError("Workspace is not pending creation", "WORKSPACE_ALREADY_ACTIVATED");
      s.ws.status = state.activationPollsLeft > 0 ? "ONGOING_CREATION" : "ACTIVE";
      return { activateWorkspace: { id: s.ws.id, activationStatus: s.ws.status } };
    },
    UpdateWorkspace: ({ input }, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      if ("isPublicInviteLinkEnabled" in input) s.ws.invite = input.isPublicInviteLinkEnabled;
      return { updateWorkspace: { id: s.ws.id, isPublicInviteLinkEnabled: s.ws.invite } };
    },
    GetApiKeyRoles: (_, req) => {
      if (!session(req)) return unauthenticated();
      return { getApiKeyRoles: roles };
    },
    CreateApiKey: ({ input }, req) => {
      if (!session(req)) return unauthenticated();
      if (!input?.name || !input?.expiresAt || !roles.some((r) => r.id === input.roleId)) {
        return gqlError("Invalid API key input", "INVALID_INPUT");
      }
      const id = randomUUID();
      state.apiKeys.set(id, { ...input, revoked: false });
      return { createApiKey: { id, name: input.name, expiresAt: input.expiresAt } };
    },
    GenerateApiKeyToken: ({ apiKeyId, expiresAt }, req) => {
      if (!session(req)) return unauthenticated();
      const key = state.apiKeys.get(apiKeyId);
      if (!key || key.expiresAt !== expiresAt) return gqlError("API key not found", "API_KEY_NOT_FOUND");
      const token = issue("key", { apiKeyId });
      key.token = token;
      return { generateApiKeyToken: { token } };
    },
    RevokeApiKey: ({ input }, req) => {
      if (!session(req)) return unauthenticated();
      const key = state.apiKeys.get(input.id);
      if (!key) return gqlError("API key not found", "API_KEY_NOT_FOUND");
      key.revoked = true;
      return { revokeApiKey: { id: input.id } };
    },
  };

  const forbidden = () => gqlError("You do not have access to the admin panel", "FORBIDDEN_EXCEPTION");
  const adminPanelOps = {
    GetServerAdmins: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      if (!s.user.canAccessFullAdminPanel) return forbidden();
      const admins = [...state.users.values()].filter((u) => u.canAccessFullAdminPanel || u.canImpersonate);
      return {
        getServerAdmins: admins.map(({ id, email, canAccessFullAdminPanel, canImpersonate }) => ({ id, email, canAccessFullAdminPanel, canImpersonate })),
      };
    },
    AdminPanelTopWorkspaces: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      if (!s.user.canImpersonate) return forbidden();
      const top = [...state.workspaces].sort((a, b) => b.members.size - a.members.size).slice(0, LIST_LIMIT);
      return { adminPanelTopWorkspaces: top.map((w) => ({ id: w.id, totalUsers: w.members.size })) };
    },
    AdminPanelRecentUsers: (_, req) => {
      const s = session(req);
      if (!s) return unauthenticated();
      if (!s.user.canAccessFullAdminPanel && !s.user.canImpersonate) return forbidden();
      const recent = [...state.users.values()].sort((a, b) => b.createdAt - a.createdAt).slice(0, LIST_LIMIT);
      return { adminPanelRecentUsers: recent.map(({ id, email }) => ({ id, email })) };
    },
  };

  const restAuth = (req) => {
    const t = bearer(req, "key");
    const key = t && state.apiKeys.get(t.apiKeyId);
    return key && !key.revoked;
  };

  const singular = { companies: "Company", people: "Person", opportunities: "Opportunity" };

  async function handleRest(req, res, body, url) {
    if (!restAuth(req)) return send(res, 401, { statusCode: 401, error: "Unauthorized", messages: ["Token invalid."] });
    const [, , object, id] = url.pathname.split("/");
    const table = state.records[object];
    if (!table) return send(res, 404, { statusCode: 404, messages: [`object ${object} not found`] });
    if (req.method === "POST" && !id) {
      const record = { id: randomUUID(), ...body };
      table.set(record.id, record);
      return send(res, 201, { data: { [`create${singular[object]}`]: record } });
    }
    const record = table.get(id);
    if (!record) return send(res, 404, { statusCode: 404, messages: ["record not found"] });
    if (req.method === "GET") {
      const out = { ...record };
      if (object === "opportunities" && url.searchParams.get("depth") === "1") {
        out.company = state.records.companies.get(record.companyId) ?? null;
        out.pointOfContact = state.records.people.get(record.pointOfContactId) ?? null;
      }
      const key = singular[object].charAt(0).toLowerCase() + singular[object].slice(1);
      return send(res, 200, { data: { [key]: out } });
    }
    if (req.method === "DELETE") {
      table.delete(id);
      return send(res, 200, { data: { [`delete${singular[object]}`]: { id } } });
    }
    return send(res, 405, { messages: ["method not allowed"] });
  }

  function send(res, status, json) {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(json));
  }

  async function graphql(res, ops, body, req) {
    const name = /^(?:query|mutation)\s+(\w+)/.exec(body?.query ?? "")?.[1];
    state.calls.push(name);
    const hook = state.beforeOp.get(name);
    if (hook) {
      state.beforeOp.delete(name);
      await hook();
    }
    const forced = state.failNext.get(name);
    if (forced) {
      state.failNext.delete(name);
      return send(res, 200, forced);
    }
    const op = ops[name];
    if (!op) return send(res, 400, { errors: [{ message: `unknown operation ${name}` }] });
    const out = op(body.variables ?? {}, req);
    return send(res, 200, out.errors ? out : { data: out });
  }

  const handler = async (req, res) => {
    const url = new URL(req.url, "http://fake");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : undefined;
    if (req.method === "GET" && url.pathname === "/healthz") {
      state.healthPolls++;
      if (state.healthPolls <= unhealthyPolls) return send(res, 503, { status: "error" });
      return send(res, 200, { status: "ok", info: {}, error: {}, details: {} });
    }
    if (req.method === "GET" && url.pathname === "/client-config") {
      state.clientConfigReads++;
      return send(res, 200, state.clientConfig);
    }
    if (req.method === "POST" && url.pathname === "/metadata") return graphql(res, metadataOps, body, req);
    if (req.method === "POST" && url.pathname === "/admin-panel") return graphql(res, adminPanelOps, body, req);
    if (url.pathname.startsWith("/rest/")) return handleRest(req, res, body, url);
    return send(res, 404, { messages: ["not found"] });
  };

  const servers = [];
  // Each listener is another port onto the same instance (the setup port and the route port).
  async function listen(port = 0) {
    const server = createServer(handler);
    servers.push(server);
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    return `http://127.0.0.1:${server.address().port}`;
  }

  // Signs an account up through the public API the way an outsider would.
  async function signUpAs(base, email, password, { workspace = false } = {}) {
    const call = async (query, variables, token) => {
      const headers = { "content-type": "application/json" };
      if (token) headers.authorization = `Bearer ${token}`;
      const res = await fetch(`${base}/metadata`, { method: "POST", headers, body: JSON.stringify({ query, variables }) });
      return res.json();
    };
    const up = await call("mutation SignUp($email: String!, $password: String!) { signUp }", { email, password });
    const wa = up.data?.signUp?.tokens?.accessOrWorkspaceAgnosticToken?.token;
    if (!wa) throw new Error(`signUp failed: ${JSON.stringify(up.errors)}`);
    if (!workspace) return;
    const ws = await call("mutation SignUpInNewWorkspace($input: SignUpInNewWorkspaceInput) { x }", { input: { displayName: "mine" } }, wa);
    if (!ws.data) throw new Error(`signUpInNewWorkspace failed: ${JSON.stringify(ws.errors)}`);
  }

  return {
    state,
    listen,
    signUpAs,
    start: listen,
    async stop() {
      await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
    },
  };
}
