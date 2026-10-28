// In-memory stand-in for the ToolJet CE v3.20 endpoints the bootstrap and the A6 helper use.
// It applies ToolJet's rules: setup-super-admin only while there are no users (403 after),
// guards before body validation on sign-up (403 when DISABLE_SIGNUPS, else 400 for an empty
// body), the tj_auth_token cookie plus tj-workspace-id header on app endpoints, and app name
// and type validation. The Sealed gate in front of it is tests/lib/fake-gate.mjs.

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

export function createFakeToolJet({ unhealthyPolls = 0, signupsDisabled = true } = {}) {
  const state = {
    users: new Map(),
    organizations: new Map(),
    sessions: new Map(),
    apps: new Map(),
    calls: [],
    healthPolls: 0,
    signupsDisabled,
  };

  const send = (res, status, json, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(json));
  };
  const issueSession = (email, organizationId) => {
    const token = `jwt-${randomUUID()}`;
    state.sessions.set(token, { email, organizationId });
    return { "set-cookie": `tj_auth_token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax` };
  };
  const session = (req) => {
    const m = /(?:^|;\s*)tj_auth_token=([^;]+)/.exec(req.headers.cookie ?? "");
    const s = m && state.sessions.get(m[1]);
    return s && req.headers["tj-workspace-id"] === s.organizationId ? s : undefined;
  };
  const loginPayload = (user) => ({
    id: user.id,
    email: user.email,
    first_name: user.name,
    current_organization_id: user.organizationId,
    current_organization_slug: state.organizations.get(user.organizationId).slug,
  });

  const routes = {
    "POST /api/onboarding/setup-super-admin": (req, res, body) => {
      if (state.users.size > 0) return send(res, 403, { statusCode: 403, message: "Forbidden resource" });
      const { email, password, name, workspaceName } = body ?? {};
      if (!email || !name || !workspaceName || typeof password !== "string" || password.length < 5) {
        return send(res, 400, { statusCode: 400, message: ["invalid admin setup"] });
      }
      const organizationId = randomUUID();
      state.organizations.set(organizationId, { id: organizationId, name: workspaceName, slug: workspaceName.toLowerCase().replace(/\W+/g, "-") });
      const user = { id: randomUUID(), email, password, name, organizationId };
      state.users.set(email, user);
      return send(res, 201, loginPayload(user), issueSession(email, organizationId));
    },
    "POST /api/authenticate": (req, res, body) => {
      const user = state.users.get(body?.email);
      if (!user || user.password !== body?.password) return send(res, 401, { statusCode: 401, message: "Invalid credentials" });
      return send(res, 201, loginPayload(user), issueSession(user.email, user.organizationId));
    },
    "POST /api/onboarding/signup": (req, res, body) => {
      if (state.signupsDisabled) return send(res, 403, { statusCode: 403, message: "Forbidden resource" });
      if (!body?.email || !body?.password) return send(res, 400, { statusCode: 400, message: ["email must be an email"] });
      return send(res, 201, { ok: true });
    },
    "GET /api/apps": (req, res) => {
      const s = session(req);
      if (!s) return send(res, 401, { statusCode: 401, message: "Unauthorized" });
      const apps = [...state.apps.values()].filter((a) => a.organization_id === s.organizationId);
      return send(res, 200, { apps, meta: { total_count: apps.length } });
    },
    "POST /api/apps": (req, res, body) => {
      const s = session(req);
      if (!s) return send(res, 401, { statusCode: 401, message: "Unauthorized" });
      if (!body?.name || body.name.length > 50) return send(res, 400, { statusCode: 400, message: ["Maximum length has been reached."] });
      if (!["front-end", "workflow", "module"].includes(body.type)) return send(res, 400, { statusCode: 400, message: ["Invalid app type."] });
      const app = { id: randomUUID(), name: body.name, slug: randomUUID(), type: body.type, organization_id: s.organizationId };
      state.apps.set(app.id, app);
      return send(res, 201, app);
    },
  };

  const handler = async (req, res) => {
    const url = new URL(req.url, "http://fake");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : undefined;
    state.calls.push(`${req.method} ${url.pathname}`);
    state.headers = [...(state.headers ?? []), { path: url.pathname, authorization: req.headers.authorization, cookie: req.headers.cookie }];

    if (req.method === "GET" && url.pathname === "/api/health") {
      state.healthPolls++;
      if (state.healthPolls <= unhealthyPolls) return send(res, 502, { message: "bad gateway" });
      return send(res, 200, { message: "Instance seems healthy but this is probably not the right URL to access." });
    }
    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end("<!DOCTYPE html><html><head><title>ToolJet</title></head><body><div id=\"app\"></div></body></html>");
    }
    const appMatch = /^\/api\/apps\/([0-9a-f-]+)$/.exec(url.pathname);
    if (appMatch) {
      const s = session(req);
      if (!s) return send(res, 401, { statusCode: 401, message: "Unauthorized" });
      const app = state.apps.get(appMatch[1]);
      if (!app || app.organization_id !== s.organizationId) return send(res, 404, { statusCode: 404, message: "App not found" });
      if (req.method === "GET") return send(res, 200, app);
      if (req.method === "DELETE") {
        state.apps.delete(app.id);
        return send(res, 200, {});
      }
    }
    const route = routes[`${req.method} ${url.pathname}`];
    if (route) return route(req, res, body);
    return send(res, 404, { statusCode: 404, message: "Not Found" });
  };

  const servers = [];
  // Each listener is another port onto the same instance (the setup port and the route port).
  async function listen(port = 0) {
    const server = createServer(handler);
    servers.push(server);
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    return `http://127.0.0.1:${server.address().port}`;
  }

  return {
    state,
    listen,
    start: listen,
    async stop() {
      await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
    },
  };
}
