// In-memory stand-in for EspoCRM 10.0 behind the crm image's Apache, for the bootstrap and A6
// tests. It follows the upstream source at tag 10.0.11 where the bootstrap and A6 depend on it:
//   - auth (Espo\Core\Api\Auth): Espo-Authorization (base64 user:password, or user:token with
//     Espo-Authorization-By-Token: true), X-Api-Key for API users, and, when the image does not
//     drop it, a standard Authorization: Basic header read as an EspoCRM login (PHP_AUTH_USER);
//   - GET /api/v1/Settings without auth returns the global items, admins also get the admin
//     items (Tools\App\SettingsService), merged from config and data/config-override.php;
//   - API users get their key generated on create, visible to admins only
//     (Classes\RecordHooks\User\BeforeCreate, Classes\Record\User\OutputFilter);
//   - API users reach a scope only through a role that grants it;
//   - Opportunity requires name, amount and closeDate; Contact requires lastName.
// The CLI stand-in (fake-espo-command.mjs) changes the same state file, so an install through
// bin/command is what the HTTP side sees.

import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";

export const GLOBAL_ITEMS = ["siteUrl", "useWebSocket", "useCache", "language", "version"];
export const ADMIN_ITEMS = [
  "adminNotifications", "adminNotificationsNewVersion", "adminNotificationsNewExtensionVersion",
  "adminNotificationsCronIsNotConfigured", "adminPanelIframeDisabled", "adminPanelIframeUrl", "jobRunInParallel",
];
export const SYSTEM_ITEMS = ["adminExtensionUpload", "adminUpgrade", "adminUpgradeDisabled", "phpExecutablePath", "restrictedMode"];

export function initialState(espoDir) {
  return {
    espoDir,
    dbUp: true,
    config: {},
    populated: false,
    rebuilt: false,
    users: [{ id: "system", userName: "system", type: "system", isActive: true }],
    roles: [],
    records: { Account: [], Contact: [], Opportunity: [] },
    tokens: {},
    calls: [],
  };
}

export function readState(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

export function writeState(file, state) {
  writeFileSync(file, JSON.stringify(state, null, 1));
}

// Parses the flat PHP arrays sealed-espocrm writes ("'key' => value," lines; nested arrays are
// read one level deep).
export function parsePhpConfig(text) {
  const out = {};
  let nested;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    let m = /^'([A-Za-z0-9_]+)' => \[$/.exec(line);
    if (m) {
      nested = m[1];
      out[nested] = {};
      continue;
    }
    if (line === "],") {
      nested = undefined;
      continue;
    }
    m = /^'([A-Za-z0-9_]+)' => (.*),$/.exec(line);
    if (!m) continue;
    let value = m[2];
    if (value === "true") value = true;
    else if (value === "false") value = false;
    else if (/^\d+$/.test(value)) value = Number(value);
    else if (/^'.*'$/.test(value)) value = value.slice(1, -1);
    else throw new Error(`unparsed PHP value ${value}`);
    if (nested) out[nested][m[1]] = value;
    else out[m[1]] = value;
  }
  return out;
}

function readOverride(espoDir, name) {
  try {
    return parsePhpConfig(readFileSync(join(espoDir, "data", name), "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return {};
    throw err;
  }
}

// EspoCRM's merge order: config, internal config, override, internal override.
export function mergedConfig(state) {
  return {
    ...state.config,
    ...readOverride(state.espoDir, "config-override.php"),
    ...readOverride(state.espoDir, "config-internal-override.php"),
  };
}

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(body === undefined ? "" : JSON.stringify(body));
};

function decode(value) {
  const text = Buffer.from(value, "base64").toString("utf8");
  const i = text.indexOf(":");
  return i < 0 ? [text, ""] : [text.slice(0, i), text.slice(i + 1)];
}

function publicUser(user, viewer) {
  const out = { ...user };
  delete out.password;
  if (user.type === "api" && viewer?.type !== "admin") delete out.apiKey;
  return out;
}

export function createFakeEspoCrm({ stateFile, stripAuthorization = true }) {
  const seen = [];
  const load = () => readState(stateFile);
  const save = (s) => writeState(stateFile, s);

  function authenticate(state, req) {
    const espo = req.headers["espo-authorization"];
    if (espo) {
      const [userName, secret] = decode(espo);
      const user = state.users.find((u) => u.userName === userName && u.isActive !== false);
      if (!user) return { fail: true };
      if (req.headers["espo-authorization-by-token"] === "true") {
        return state.tokens[secret] === user.id ? { user } : { fail: true };
      }
      if (user.password !== secret || user.type === "api") return { fail: true };
      const token = randomBytes(16).toString("hex");
      state.tokens[token] = user.id;
      return { user, token };
    }
    const apiKey = req.headers["x-api-key"];
    if (apiKey) {
      const user = state.users.find((u) => u.type === "api" && u.apiKey === apiKey && u.isActive !== false);
      return user ? { user } : { fail: true };
    }
    const authorization = req.headers.authorization;
    if (authorization && !stripAuthorization && authorization.startsWith("Basic ")) {
      // What EspoCRM does with PHP_AUTH_USER when nothing removes the header.
      const [userName, password] = decode(authorization.slice(6));
      const user = state.users.find((u) => u.userName === userName && u.password === password);
      return user ? { user } : { fail: true };
    }
    // Only when no other auth data was sent, as in EspoCRM.
    const cookie = (req.headers.cookie ?? "").split(";").map((c) => c.trim()).find((c) => c.startsWith("auth-token="));
    if (cookie) {
      const user = state.users.find((u) => u.id === state.tokens[cookie.slice("auth-token=".length)]);
      return user ? { user } : { fail: true };
    }
    return {};
  }

  function canAccess(state, user, scope, action) {
    if (user.type === "admin") return true;
    if (user.type !== "api") return false;
    return (user.rolesIds ?? []).some((id) => {
      const role = state.roles.find((r) => r.id === id);
      const level = role?.data?.[scope]?.[action];
      return level === "yes" || level === "all";
    });
  }

  function settingsView(state, user) {
    const config = mergedConfig(state);
    const keys = user?.type === "admin" ? [...GLOBAL_ITEMS, ...ADMIN_ITEMS] : GLOBAL_ITEMS;
    return Object.fromEntries(keys.filter((k) => k in config).map((k) => [k, config[k]]));
  }

  function list(items, url, viewer) {
    let out = items;
    for (let i = 0; url.searchParams.has(`where[${i}][type]`); i++) {
      const attr = url.searchParams.get(`where[${i}][attribute]`);
      const value = url.searchParams.get(`where[${i}][value]`);
      out = out.filter((x) => x[attr] === value);
    }
    const max = Number(url.searchParams.get("maxSize") ?? 20);
    return { total: out.length, list: out.slice(0, max).map((x) => publicUser(x, viewer)) };
  }

  const REQUIRED = { Account: ["name"], Contact: ["lastName"], Opportunity: ["name", "amount", "closeDate"] };

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks).toString("utf8");
    const url = new URL(req.url, "http://fake");
    const path = url.pathname.replace(/^\/api\/v1/, "");
    seen.push({ method: req.method, path, authorization: req.headers.authorization, apiKey: Boolean(req.headers["x-api-key"]) });
    const state = load();
    if (!mergedConfig(state).isInstalled) return json(res, 500, { message: "not installed" });
    const auth = authenticate(state, req);
    if (auth.fail) {
      save(state);
      return json(res, 401, undefined, { "x-status-reason": "Unauthorized" });
    }
    const user = auth.user;
    let body;
    try {
      body = raw ? JSON.parse(raw) : undefined;
    } catch {
      return json(res, 400, { message: "bad json" });
    }
    const done = (status, payload) => {
      save(state);
      json(res, status, payload);
    };

    if (req.method === "GET" && path === "/Settings") return done(200, settingsView(state, user));
    if (!user) return json(res, 401, undefined, { "x-status-reason": "Unauthorized" });

    if (req.method === "GET" && path === "/App/user") {
      return done(200, { user: publicUser(user, user), token: auth.token ?? Object.keys(state.tokens).find((t) => state.tokens[t] === user.id) });
    }

    let m;
    if ((m = /^\/(User|Role)$/.exec(path))) {
      if (user.type !== "admin") return json(res, 403, { message: "forbidden" });
      const collection = m[1] === "User" ? state.users : state.roles;
      if (req.method === "GET") return done(200, list(collection, url, user));
      if (req.method === "POST") {
        const item = { id: randomUUID().replace(/-/g, "").slice(0, 17), ...body };
        if (m[1] === "User") {
          if (!item.userName) return json(res, 400, { message: "userName required" });
          if (state.users.some((u) => u.userName === item.userName)) return json(res, 409, { message: "duplicate" });
          if (item.type === "api") item.apiKey = randomBytes(16).toString("hex");
        }
        collection.push(item);
        return done(200, publicUser(item, user));
      }
    }
    if ((m = /^\/User\/([^/]+)$/.exec(path))) {
      if (user.type !== "admin") return json(res, 403, { message: "forbidden" });
      const target = state.users.find((u) => u.id === m[1]);
      if (!target) return json(res, 404, { message: "not found" });
      if (req.method === "GET") return done(200, publicUser(target, user));
      if (req.method === "PUT") {
        Object.assign(target, body);
        return done(200, publicUser(target, user));
      }
    }
    if ((m = /^\/(Account|Contact|Opportunity)$/.exec(path))) {
      const scope = m[1];
      if (req.method === "GET") {
        if (!canAccess(state, user, scope, "read")) return json(res, 403, { message: "forbidden" });
        return done(200, list(state.records[scope], url, user));
      }
      if (req.method === "POST") {
        if (!canAccess(state, user, scope, "create")) return json(res, 403, { message: "forbidden" });
        for (const field of REQUIRED[scope]) {
          if (body?.[field] === undefined || body[field] === "") return json(res, 400, { message: `${field} is required` });
        }
        const record = { id: randomUUID().replace(/-/g, "").slice(0, 17), ...body, createdById: user.id };
        state.records[scope].push(record);
        return done(200, record);
      }
    }
    if ((m = /^\/(Account|Contact|Opportunity)\/([^/]+)$/.exec(path))) {
      const scope = m[1];
      const records = state.records[scope];
      const index = records.findIndex((r) => r.id === m[2]);
      if (index < 0) return json(res, 404, { message: "not found" });
      if (req.method === "GET") {
        if (!canAccess(state, user, scope, "read")) return json(res, 403, { message: "forbidden" });
        return done(200, records[index]);
      }
      if (req.method === "DELETE") {
        if (!canAccess(state, user, scope, "delete")) return json(res, 403, { message: "forbidden" });
        records.splice(index, 1);
        return done(200, true);
      }
    }
    if ((m = /^\/Account\/([^/]+)\/opportunities$/.exec(path)) && req.method === "GET") {
      if (!canAccess(state, user, "Opportunity", "read")) return json(res, 403, { message: "forbidden" });
      const items = state.records.Opportunity.filter((o) => o.accountId === m[1]);
      return done(200, { total: items.length, list: items });
    }
    return json(res, 404, { message: "no route" });
  });

  return {
    seen,
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      return `http://127.0.0.1:${server.address().port}`;
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
