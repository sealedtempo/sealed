// In-memory stand-in for the Twenty v2.52 endpoints the bootstrap and the A6 helper use:
// GET /healthz, GET /client-config, POST /metadata (auth, workspace and API key operations,
// matched by operation name) and the REST endpoints for companies, people and opportunities.
// It enforces the rules the real server applies (single workspace, origin checks, bearer
// tokens, key revocation) so the tests exercise the same failure modes.

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

export const ADMIN_ROLE = { id: "role-admin", label: "Admin", universalIdentifier: "20202020-02c2-43f2-b94d-cab1f2b532eb", canBeAssignedToApiKeys: true };
const MEMBER_ROLE = { id: "role-member", label: "Member", universalIdentifier: "member", canBeAssignedToApiKeys: true };

function gqlError(message, subCode) {
  return { errors: [{ message, extensions: { code: "FORBIDDEN", subCode } }] };
}

export function createFakeTwenty({ origin, unhealthyPolls = 0, roles = [ADMIN_ROLE, MEMBER_ROLE], clientConfig = {}, activationPolls = 0, refusePendingLogin = false } = {}) {
  const state = {
    users: new Map(),
    workspace: undefined,
    tokens: new Map(),
    apiKeys: new Map(),
    records: { companies: new Map(), people: new Map(), opportunities: new Map() },
    calls: [],
    healthPolls: 0,
    activationPollsLeft: activationPolls,
    failNext: new Map(),
    clientConfig,
  };

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

  const ops = {
    CheckUserExists: ({ email }) => {
      const user = state.users.get(email);
      const member = user && state.workspace?.members.has(email) && state.workspace.status === "ACTIVE";
      return { checkUserExists: { exists: Boolean(user), availableWorkspacesCount: member ? 1 : 0 } };
    },
    SignUp: ({ email, password }) => {
      if (state.users.has(email)) return gqlError("User already exists", "USER_ALREADY_EXISTS");
      if (state.workspace) return gqlError("New workspace setup is disabled", "SIGNUP_DISABLED");
      state.users.set(email, { password });
      return { signUp: { tokens: { accessOrWorkspaceAgnosticToken: { token: issue("wa", { email }) } } } };
    },
    SignIn: ({ email, password }) => {
      const user = state.users.get(email);
      if (!user || user.password !== password) return gqlError("Wrong password", "FORBIDDEN_EXCEPTION");
      const listed = state.workspace?.members.has(email)
        ? [{ id: state.workspace.id, loginToken: issue("lt", { email, workspaceId: state.workspace.id }) }]
        : [];
      return {
        signIn: {
          availableWorkspaces: { availableWorkspacesForSignIn: listed },
          tokens: { accessOrWorkspaceAgnosticToken: { token: issue("wa", { email }) } },
        },
      };
    },
    SignUpInNewWorkspace: ({ input }, req) => {
      const wa = bearer(req, "wa");
      if (!wa) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      if (state.workspace) return gqlError("New workspace setup is disabled", "SIGNUP_DISABLED");
      state.workspace = {
        id: randomUUID(),
        displayName: input?.displayName,
        status: "PENDING_CREATION",
        invite: true,
        members: new Set([wa.email]),
      };
      return {
        signUpInNewWorkspace: {
          loginToken: { token: issue("lt", { email: wa.email, workspaceId: state.workspace.id }) },
          workspace: { id: state.workspace.id, workspaceUrls: { subdomainUrl: origin, customUrl: null } },
        },
      };
    },
    GetLoginTokenFromCredentials: ({ email, password, origin: o }) => {
      if (o !== origin) return gqlError("Workspace not found", "WORKSPACE_NOT_FOUND");
      const user = state.users.get(email);
      if (!state.workspace) return gqlError("Workspace not found", "WORKSPACE_NOT_FOUND");
      if (!user || user.password !== password) return gqlError("Wrong password", "FORBIDDEN_EXCEPTION");
      if (refusePendingLogin && state.workspace.status !== "ACTIVE") return gqlError("Workspace is not ready", "WORKSPACE_NOT_READY");
      return { getLoginTokenFromCredentials: { loginToken: { token: issue("lt", { email, workspaceId: state.workspace.id }) } } };
    },
    GetAuthTokensFromLoginToken: ({ loginToken, origin: o }) => {
      const lt = state.tokens.get(loginToken);
      if (!lt || lt.kind !== "lt" || o !== origin) return gqlError("Invalid login token", "INVALID_INPUT");
      state.tokens.delete(loginToken);
      return { getAuthTokensFromLoginToken: { tokens: { accessOrWorkspaceAgnosticToken: { token: issue("at", lt) } } } };
    },
    CurrentWorkspace: (_, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      if (state.workspace.status === "ONGOING_CREATION" && state.activationPollsLeft-- <= 0) state.workspace.status = "ACTIVE";
      const w = state.workspace;
      return { currentWorkspace: { id: w.id, activationStatus: w.status, isPublicInviteLinkEnabled: w.invite } };
    },
    ActivateWorkspace: (_, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      if (state.workspace.status !== "PENDING_CREATION") return gqlError("Workspace is not pending creation", "WORKSPACE_ALREADY_ACTIVATED");
      state.workspace.status = state.activationPollsLeft > 0 ? "ONGOING_CREATION" : "ACTIVE";
      return { activateWorkspace: { id: state.workspace.id, activationStatus: state.workspace.status } };
    },
    UpdateWorkspace: ({ input }, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      if ("isPublicInviteLinkEnabled" in input) state.workspace.invite = input.isPublicInviteLinkEnabled;
      return { updateWorkspace: { id: state.workspace.id, isPublicInviteLinkEnabled: state.workspace.invite } };
    },
    GetApiKeyRoles: (_, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      return { getApiKeyRoles: roles };
    },
    CreateApiKey: ({ input }, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      if (!input?.name || !input?.expiresAt || !roles.some((r) => r.id === input.roleId)) {
        return gqlError("Invalid API key input", "INVALID_INPUT");
      }
      const id = randomUUID();
      state.apiKeys.set(id, { ...input, revoked: false });
      return { createApiKey: { id, name: input.name, expiresAt: input.expiresAt } };
    },
    GenerateApiKeyToken: ({ apiKeyId, expiresAt }, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      const key = state.apiKeys.get(apiKeyId);
      if (!key || key.expiresAt !== expiresAt) return gqlError("API key not found", "API_KEY_NOT_FOUND");
      const token = issue("key", { apiKeyId });
      key.token = token;
      return { generateApiKeyToken: { token } };
    },
    RevokeApiKey: ({ input }, req) => {
      if (!bearer(req, "at")) return gqlError("Unauthenticated", "UNAUTHENTICATED");
      const key = state.apiKeys.get(input.id);
      if (!key) return gqlError("API key not found", "API_KEY_NOT_FOUND");
      key.revoked = true;
      return { revokeApiKey: { id: input.id } };
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

  const server = createServer(async (req, res) => {
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
      return send(res, 200, {
        isMultiWorkspaceEnabled: false,
        billing: { isBillingEnabled: false },
        analyticsEnabled: false,
        allowRequestsToTwentyIcons: false,
        isConfigVariablesInDbEnabled: false,
        isImapSmtpCaldavEnabled: false,
        ...state.clientConfig,
      });
    }
    if (req.method === "POST" && url.pathname === "/metadata") {
      const name = /^(?:query|mutation)\s+(\w+)/.exec(body?.query ?? "")?.[1];
      state.calls.push(name);
      const forced = state.failNext.get(name);
      if (forced) {
        state.failNext.delete(name);
        return send(res, 200, forced);
      }
      const op = ops[name];
      if (!op) return send(res, 400, { errors: [{ message: `unknown operation ${name}` }] });
      return send(res, 200, (() => {
        const out = op(body.variables ?? {}, req);
        return out.errors ? out : { data: out };
      })());
    }
    if (url.pathname.startsWith("/rest/")) return handleRest(req, res, body, url);
    return send(res, 404, { messages: ["not found"] });
  });

  return {
    state,
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      return `http://127.0.0.1:${server.address().port}`;
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
