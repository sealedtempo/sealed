import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { type ApiHandlers, type ApiServerOptions, createApiServer, UsageRejected } from "../src/server.js";
import { AttestError, ClientRateLimiter, RateLimiter } from "../src/attest.js";
import { fromPeer, testPeerOf } from "./helpers/fixtures.js";

function handlers(over: Partial<ApiHandlers> = {}): ApiHandlers {
  return {
    isReady: () => true,
    readyInfo: () => ({ deploymentId: "0x01" }),
    recordUsage: async () => "accepted",
    recordSpend: () => {},
    reserveSpend: () => ({ ok: true }),
    releaseSpend: () => ({ ok: true }),
    attest: async () => ({ ok: true }),
    gate: async () => ({ status: 401 }),
    bootstrapDone: () => {},
    ...over,
  };
}

describe("agent local API", () => {
  let close: (() => Promise<void>) | undefined;
  afterEach(async () => close?.());
  async function start(h: ApiHandlers, opts: ApiServerOptions = {}) {
    const server = createApiServer(h, silentLogger, { peerOf: testPeerOf, ...opts });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", () => ok()));
    close = () => new Promise((ok) => server.close(() => ok()));
    return parseEndpoint(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  }

  it("reports readiness on /healthz and /v1/ready; usage and spend wait for it", async () => {
    let ready = false;
    const ep = await start(handlers({ isReady: () => ready }));
    expect((await localRequest(ep, "/healthz")).status).toBe(503);
    expect((await localRequest(ep, "/v1/usage-events", { body: { app: "crm", unit: "pages", quantity: 1 } })).status).toBe(503);
    expect((await localRequest(ep, "/v1/spend", { body: {} })).status).toBe(503);
    ready = true;
    expect((await localRequest(ep, "/healthz")).status).toBe(200);
    const r = await localRequest(ep, "/v1/ready");
    expect(JSON.parse(r.body)).toEqual({ ready: true, deploymentId: "0x01" });
  });

  it("validates usage events and passes the caller address to the handler", async () => {
    const seen: [string, string][] = [];
    const ep = await start(
      handlers({
        recordUsage: async (e, peer) => {
          seen.push([e.app, peer]);
          if (e.app === "ghost") throw new UsageRejected("unknown app ghost");
          if (peer !== "172.30.0.17") throw new UsageRejected("not your app", 403);
          return "accepted";
        },
      }),
    );
    const post = (body: unknown, peer = "172.30.0.17") => localRequest(ep, "/v1/usage-events", { body, headers: fromPeer(peer) });
    expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 123, meta: { model: "m" } })).status).toBe(202);
    expect((await post({ app: "llm-gateway", unit: "tokens", quantity: 1 }, "172.30.0.16")).status).toBe(403);
    expect((await post({ app: "llm-gateway", unit: "tokens", quantity: -1 })).status).toBe(400);
    expect((await post("{nope")).status).toBe(400);
    expect((await post({ app: "ghost", unit: "tokens", quantity: 1 })).status).toBe(422);
    expect((await post("x".repeat(70_000))).status).toBe(413);
    expect(seen).toEqual([
      ["llm-gateway", "172.30.0.17"],
      ["llm-gateway", "172.30.0.16"],
      ["ghost", "172.30.0.17"],
    ]);
  });

  it("maps handler refusals of spend reports to their status", async () => {
    const ep = await start(handlers({ recordSpend: (_b, peer) => {
      if (peer !== "172.30.0.5") throw new UsageRejected("payer only", 403);
    } }));
    expect((await localRequest(ep, "/v1/spend", { body: {}, headers: fromPeer("172.30.0.16") })).status).toBe(403);
    expect((await localRequest(ep, "/v1/spend", { body: {}, headers: fromPeer("172.30.0.5") })).status).toBe(204);
  });

  it("maps attestation errors and rate limits /attest globally", async () => {
    const ep = await start(
      handlers({ attest: async (n) => (n === "bad" ? Promise.reject(new AttestError(400, "nonce must be hex")) : { nonce: n }) }),
      { attestLimiter: new RateLimiter(0.001, 2) },
    );
    expect((await localRequest(ep, "/attest?nonce=bad")).status).toBe(400);
    expect(JSON.parse((await localRequest(ep, "/attest?nonce=0x01")).body)).toEqual({ nonce: "0x01" });
    expect((await localRequest(ep, "/attest?nonce=0x01")).status).toBe(429);
    expect((await localRequest(ep, "/nope")).status).toBe(404);
  });

  // Review finding: one global bucket let any internet client starve verifiers.
  it("rate limits /attest per client; X-Forwarded-For counts only when Caddy relays the request", async () => {
    const ep = await start(handlers(), {
      attestLimiter: new RateLimiter(1000, 1000),
      attestClientLimiter: new ClientRateLimiter(0.001, 2),
      trustedProxy: () => "172.30.0.4",
    });
    const viaCaddy = (client: string) => localRequest(ep, "/attest?nonce=0x01", { headers: { ...fromPeer("172.30.0.4"), "x-forwarded-for": client } });
    expect((await viaCaddy("198.51.100.7")).status).toBe(200);
    expect((await viaCaddy("198.51.100.7")).status).toBe(200);
    expect((await viaCaddy("198.51.100.7")).status).toBe(429);
    expect((await viaCaddy("203.0.113.9")).status).toBe(200);
    // An app container cannot pick another client's bucket by sending its own header.
    const direct = () => localRequest(ep, "/attest?nonce=0x01", { headers: { ...fromPeer("172.30.0.16"), "x-forwarded-for": "203.0.113.50" } });
    expect((await direct()).status).toBe(200);
    expect((await direct()).status).toBe(200);
    expect((await direct()).status).toBe(429);
    expect((await localRequest(ep, "/attest?nonce=0x01", { headers: { ...fromPeer("172.30.0.4"), "x-forwarded-for": "203.0.113.50" } })).status).toBe(200);
  });

  it("the per-client limiter stays bounded in memory", () => {
    const l = new ClientRateLimiter(0.001, 1, 3);
    for (const c of ["a", "b", "c"]) expect(l.take(c)).toBe(true);
    expect(l.take("a")).toBe(false);
    expect(l.take("d")).toBe(true); // evicts "b", the least recently used
    expect(l.take("b")).toBe(true);
  });
});
