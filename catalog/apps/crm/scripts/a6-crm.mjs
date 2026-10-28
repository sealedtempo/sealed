#!/usr/bin/env node
// A6 acceptance helper for crm (EspoCRM): create an account (company), a contact linked to it
// and an opportunity (deal) linked to both through the REST API, then read them back and check
// the links. A11 uses --check with the ids from an earlier run to show the data survived.
//
// Env:
//   CRM_URL        https://crm.<ip-with-dashes>.sslip.io, or http://crm-server:8080 inside the VM
//   API_KEY        an EspoCRM API key (API user, sent as X-Api-Key), or
//   API_KEY_FILE   api-key.json written by crm-bootstrap, or
//   ADMIN_PASSWORD (and ADMIN_USERNAME, default "admin") to work as the administrator instead
//   GATE_BASIC     "sealed:<gate password>" for the Sealed gate. Sent as "Authorization: Basic"
//                  on every call; the gate (forward_auth, D-044) answers with its sealed_gate
//                  cookie, which is sent back from then on. EspoCRM never reads that header
//                  (the crm image drops it), so it does not clash with EspoCRM's own auth.
//   A6_CLEANUP=1   delete the three records at the end
// Usage: a6-crm.mjs [--check ids.json]
// Prints one JSON line with the record ids. Exit code 0 on success, 1 on failure, 2 on bad usage.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export class UsageError extends Error {}
export class A6Error extends Error {}

export function gateHeaders(env) {
  if (!env.GATE_BASIC) return {};
  if (!/^[^:]+:.+$/.test(env.GATE_BASIC)) throw new UsageError('GATE_BASIC must look like "user:password"');
  return { authorization: `Basic ${Buffer.from(env.GATE_BASIC).toString("base64")}` };
}

export async function credentials(env) {
  if (env.API_KEY) return { "x-api-key": env.API_KEY };
  if (env.API_KEY_FILE) {
    let saved;
    try {
      saved = JSON.parse(await readFile(env.API_KEY_FILE, "utf8"));
    } catch (err) {
      throw new UsageError(`cannot read API_KEY_FILE: ${err.code ?? err.message}`);
    }
    if (typeof saved.apiKey !== "string" || saved.apiKey.length === 0) throw new UsageError("API_KEY_FILE has no apiKey");
    return { [String(saved.header ?? "X-Api-Key").toLowerCase()]: saved.apiKey };
  }
  if (env.ADMIN_PASSWORD) {
    const user = env.ADMIN_USERNAME || "admin";
    return {
      "espo-authorization": Buffer.from(`${user}:${env.ADMIN_PASSWORD}`).toString("base64"),
      "espo-authorization-by-token": "false",
    };
  }
  throw new UsageError("set API_KEY, API_KEY_FILE or ADMIN_PASSWORD");
}

function describe(res, json) {
  const reason = res.headers.get("x-status-reason");
  if (reason) return reason;
  if (typeof json?.message === "string") return json.message;
  return "";
}

// Keeps the gate's cookie between calls (one cookie, sealed_gate, is all the gate sets).
function storeCookies(ctx, res) {
  const list = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
  for (const line of list) {
    const [pair] = line.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) ctx.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}

async function call(ctx, method, path, body) {
  const headers = { accept: "application/json", ...ctx.gate, ...ctx.auth };
  if (ctx.cookies.size > 0) headers.cookie = [...ctx.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  if (body !== undefined) headers["content-type"] = "application/json";
  let res;
  try {
    res = await fetch(`${ctx.base}/api/v1${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(60_000),
    });
  } catch (err) {
    throw new A6Error(`${method} ${path}: ${err.cause?.code ?? err.name}`);
  }
  storeCookies(ctx, res);
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  if (!res.ok) {
    if (res.status === 401 && res.headers.get("www-authenticate")?.includes('realm="sealed"')) {
      throw new A6Error(`${method} ${path}: HTTP 401 from the Sealed gate (set GATE_BASIC=sealed:<gate password>)`);
    }
    if (res.status === 503) throw new A6Error(`${method} ${path}: HTTP 503 (the crm route opens when crm-bootstrap is done)`);
    const why = describe(res, json);
    throw new A6Error(`${method} ${path}: HTTP ${res.status}${why ? ` (${why})` : ""}`);
  }
  if (json === undefined && method !== "DELETE") throw new A6Error(`${method} ${path}: the response is not JSON`);
  return json;
}

function expect(cond, message) {
  if (!cond) throw new A6Error(message);
}

export async function verify(ctx, ids) {
  const account = await call(ctx, "GET", `/Account/${ids.accountId}`);
  const contact = await call(ctx, "GET", `/Contact/${ids.contactId}`);
  const opportunity = await call(ctx, "GET", `/Opportunity/${ids.opportunityId}`);
  expect(account?.id === ids.accountId, "account: wrong id");
  expect(contact?.accountId === ids.accountId, "contact is not linked to the account");
  expect(opportunity?.accountId === ids.accountId, "opportunity is not linked to the account");
  expect((opportunity?.contactsIds ?? []).includes(ids.contactId), "opportunity is not linked to the contact");
  const related = await call(ctx, "GET", `/Account/${ids.accountId}/opportunities?select=id&maxSize=50`);
  expect((related?.list ?? []).some((o) => o.id === ids.opportunityId), "the account does not list the opportunity");
  return { account, contact, opportunity };
}

export async function runA6(env, { argv = [], now = () => new Date() } = {}) {
  if (!env.CRM_URL) throw new UsageError("set CRM_URL");
  const ctx = {
    base: env.CRM_URL.replace(/\/+$/, ""),
    gate: gateHeaders(env),
    auth: await credentials(env),
    cookies: new Map(),
  };
  const checkIndex = argv.indexOf("--check");
  if (checkIndex >= 0) {
    const file = argv[checkIndex + 1];
    if (!file) throw new UsageError("--check needs the ids file of an earlier run");
    const ids = JSON.parse(await readFile(file, "utf8"));
    await verify(ctx, ids);
    return { ok: true, checked: ids };
  }

  // Unauthenticated settings read first: shows the gate and the route are open.
  await call(ctx, "GET", "/Settings");
  const stamp = now().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const account = await call(ctx, "POST", "/Account", { name: `A6 Company ${stamp}`, website: "https://example.com", type: "Customer" });
  expect(typeof account?.id === "string", "POST /Account: no id");
  const contact = await call(ctx, "POST", "/Contact", {
    firstName: "Ada",
    lastName: `A6 ${stamp}`,
    emailAddress: `a6-${stamp}@example.com`,
    accountId: account.id,
  });
  expect(typeof contact?.id === "string", "POST /Contact: no id");
  const closeDate = new Date(now().getTime() + 30 * 86_400_000).toISOString().slice(0, 10);
  const opportunity = await call(ctx, "POST", "/Opportunity", {
    name: `A6 Deal ${stamp}`,
    accountId: account.id,
    contactsIds: [contact.id],
    amount: 12000,
    amountCurrency: "USD",
    stage: "Prospecting",
    closeDate,
  });
  expect(typeof opportunity?.id === "string", "POST /Opportunity: no id");
  const ids = { accountId: account.id, contactId: contact.id, opportunityId: opportunity.id };
  await verify(ctx, ids);
  if (env.A6_CLEANUP === "1") {
    await call(ctx, "DELETE", `/Opportunity/${ids.opportunityId}`);
    await call(ctx, "DELETE", `/Contact/${ids.contactId}`);
    await call(ctx, "DELETE", `/Account/${ids.accountId}`);
  }
  return { ok: true, ...ids, cleanedUp: env.A6_CLEANUP === "1" };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await runA6(process.env, { argv: process.argv.slice(2) });
    console.log(JSON.stringify(result));
  } catch (err) {
    console.error(`a6-crm: ${err.message}`);
    process.exitCode = err instanceof UsageError ? 2 : 1;
  }
}
