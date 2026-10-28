#!/usr/bin/env node
// A6 acceptance helper for crm: with a Twenty API key, create a company, a person and an
// opportunity through the REST API, then read the opportunity back with its relations.
//
// Env:
//   CRM_URL        https://crm.<ip-with-dashes>.sslip.io, or http://crm-server:3000 inside the VM
//   API_KEY        a Twenty API key, or
//   API_KEY_FILE   api-key.json written by crm-bootstrap, or
//   ADMIN_EMAIL and ADMIN_PASSWORD   mint a one-day key for this run and revoke it afterwards
//   CRM_ORIGIN     origin for the admin login (default: CRM_URL)
//   GATE_BASIC     "sealed:<gate password>" for the Sealed gate, sent on calls that carry no
//                  Twenty token (GET /healthz, the admin login). Calls with a Twenty token send
//                  it as "Authorization: Bearer", which only a bearer-passthrough route lets
//                  through (interface change 6); the basic-auth gate refuses them.
//   A6_CLEANUP=1   delete the three records at the end
// Prints one JSON line with the record ids. Exit code 0 on success, 1 on failure, 2 on bad usage.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { createApiKey, login, revokeApiKey } from "../bootstrap/bootstrap.mjs";

export class UsageError extends Error {}

// Headers for requests without a Twenty token. Requests with one replace Authorization with
// their bearer token.
export function gateHeaders(env) {
  if (!env.GATE_BASIC) return {};
  if (!/^[^:]+:.+$/.test(env.GATE_BASIC)) throw new UsageError('GATE_BASIC must look like "user:password"');
  return { authorization: `Basic ${Buffer.from(env.GATE_BASIC).toString("base64")}` };
}

function describe(json) {
  if (Array.isArray(json?.messages)) return json.messages.join("; ");
  return json?.error ?? json?.message ?? "";
}

async function rest(ctx, method, path, body) {
  const headers = { ...ctx.headers, authorization: `Bearer ${ctx.apiKey}` };
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(`${ctx.base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = {};
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      throw new Error(`${method} ${path}: HTTP ${res.status} with a non-JSON body`);
    }
  }
  if (res.status === 401 && /^basic/i.test(res.headers.get("www-authenticate") ?? "")) {
    throw new Error(
      `${method} ${path}: HTTP 401 from the Sealed gate, which refuses Twenty's bearer token ` +
        "(the crm route needs bearer passthrough or a cookie gate, interface change 6)",
    );
  }
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status} ${describe(json)}`.trim());
  return json;
}

async function resolveApiKey(env, base, headers) {
  if (env.API_KEY) return { apiKey: env.API_KEY };
  if (env.API_KEY_FILE) {
    const file = JSON.parse(await readFile(env.API_KEY_FILE, "utf8"));
    if (!file.token) throw new UsageError(`${env.API_KEY_FILE} has no token`);
    return { apiKey: file.token };
  }
  if (env.ADMIN_EMAIL && env.ADMIN_PASSWORD) {
    const cfg = {
      baseUrl: base,
      origin: (env.CRM_ORIGIN ?? base).replace(/\/+$/, ""),
      email: env.ADMIN_EMAIL.trim().toLowerCase(),
      password: env.ADMIN_PASSWORD,
      headers,
    };
    const session = await login(cfg);
    const key = await createApiKey(cfg, session, { name: "sealed-a6", ttlDays: 1 });
    return { apiKey: key.token, revoke: () => revokeApiKey(cfg, session, key.id) };
  }
  throw new UsageError("set API_KEY, API_KEY_FILE, or ADMIN_EMAIL and ADMIN_PASSWORD");
}

export async function runA6(env, { now = Date.now(), log = () => {} } = {}) {
  if (!env.CRM_URL) throw new UsageError("set CRM_URL");
  const base = env.CRM_URL.replace(/\/+$/, "");
  const headers = gateHeaders(env);
  const health = await fetch(`${base}/healthz`, { headers });
  if (health.status === 401) throw new Error("GET /healthz: HTTP 401 from the Sealed gate (set GATE_BASIC=sealed:<gate password>)");
  if (health.status !== 200) throw new Error(`GET /healthz: HTTP ${health.status}`);

  const { apiKey, revoke } = await resolveApiKey(env, base, headers);
  const ctx = { base, headers, apiKey };
  const tag = `A6 ${new Date(now).toISOString()}`;
  try {
    log("creating company");
    const company = await rest(ctx, "POST", "/rest/companies", {
      name: `Sealed ${tag}`,
      domainName: { primaryLinkUrl: "https://a6.example" },
    });
    const companyId = company?.data?.createCompany?.id;
    if (!companyId) throw new Error("POST /rest/companies: response has no id");

    log("creating person");
    const person = await rest(ctx, "POST", "/rest/people", {
      name: { firstName: "Ada", lastName: "Sealed" },
      emails: { primaryEmail: `ada+${now}@a6.example` },
      jobTitle: "A6 contact",
      companyId,
    });
    const personId = person?.data?.createPerson?.id;
    if (!personId) throw new Error("POST /rest/people: response has no id");

    log("creating opportunity");
    const opportunity = await rest(ctx, "POST", "/rest/opportunities", {
      name: `Deal ${tag}`,
      amount: { amountMicros: 1_000_000_000, currencyCode: "USD" },
      stage: "NEW",
      companyId,
      pointOfContactId: personId,
    });
    const opportunityId = opportunity?.data?.createOpportunity?.id;
    if (!opportunityId) throw new Error("POST /rest/opportunities: response has no id");

    log("reading opportunity back");
    const read = await rest(ctx, "GET", `/rest/opportunities/${opportunityId}?depth=1`);
    const opp = read?.data?.opportunity;
    if (opp?.id !== opportunityId) throw new Error("GET /rest/opportunities/:id returned another record");
    if (opp?.company?.id !== companyId) throw new Error("opportunity is not linked to the company");
    if (opp?.pointOfContact?.id !== personId) throw new Error("opportunity is not linked to the person");

    if (env.A6_CLEANUP === "1") {
      log("deleting records");
      await rest(ctx, "DELETE", `/rest/opportunities/${opportunityId}`);
      await rest(ctx, "DELETE", `/rest/people/${personId}`);
      await rest(ctx, "DELETE", `/rest/companies/${companyId}`);
    }
    return { ok: true, companyId, personId, opportunityId, cleanedUp: env.A6_CLEANUP === "1" };
  } finally {
    if (revoke) await revoke().catch(() => log("warning: could not revoke the A6 API key"));
  }
}

async function main() {
  try {
    const result = await runA6(process.env, { log: (line) => console.error(`[a6-crm] ${line}`) });
    console.log(JSON.stringify(result));
  } catch (err) {
    console.error(`[a6-crm] FAIL: ${err.message}`);
    process.exitCode = err instanceof UsageError ? 2 : 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();

