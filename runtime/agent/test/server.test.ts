import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { localRequest, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { type ApiHandlers, createApiServer, UsageRejected } from "../src/server.js";
import { AttestError, RateLimiter } from "../src/attest.js";

function handlers(over: Partial<ApiHandlers> = {}): ApiHandlers {
  return {
    isReady: () => true,
    readyInfo: () => ({ deploymentId: "0x01" }),
    recordUsage: async () => "accepted",
    recordSpend: () => {},
    attest: async () => ({ ok: true }),
    ...over,
  };
}

describe("agent local API", () => {
  let close: (() => Promise<void>) | undefined;
  afterEach(async () => close?.());
  async function start(h: ApiHandlers, limiter?: RateLimiter) {
    const server = createApiServer(h, silentLogger, limiter);
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", () => ok()));
    close = () => new Promise((ok) => server.close(() => ok()));
    return parseEndpoint(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  }

  it("reports readiness on /healthz and /v1/ready", async () => {
    let ready = false;
    const ep = await start(handlers({ isReady: () => ready }));
    expect((await localRequest(ep, "/healthz")).status).toBe(503);
    expect((await localRequest(ep, "/v1/usage-events", { body: { app: "crm", unit: "pages", quantity: 1 } })).status).toBe(503);
    ready = true;
    expect((await localRequest(ep, "/healthz")).status).toBe(200);
    const r = await localRequest(ep, "/v1/ready");
    expect(JSON.parse(r.body)).toEqual({ ready: true, deploymentId: "0x01" });
  });

  it("validates usage events", async () => {
    const seen: unknown[] = [];
    const ep = await start(handlers({ recordUsage: async (e) => (seen.push(e), e.app === "ghost" ? Promise.reject(new UsageRejected("unknown app ghost")) : "accepted") }));
    const ok = await localRequest(ep, "/v1/usage-events", { body: { app: "llm-gateway", unit: "tokens", quantity: 123, meta: { model: "m" } } });
    expect(ok.status).toBe(202);
    expect((await localRequest(ep, "/v1/usage-events", { body: { app: "llm-gateway", unit: "tokens", quantity: -1 } })).status).toBe(400);
    expect((await localRequest(ep, "/v1/usage-events", { body: "{nope" })).status).toBe(400);
    expect((await localRequest(ep, "/v1/usage-events", { body: { app: "ghost", unit: "tokens", quantity: 1 } })).status).toBe(422);
    expect((await localRequest(ep, "/v1/usage-events", { body: "x".repeat(70_000) })).status).toBe(413);
    expect(seen.length).toBe(2);
  });

  it("maps attestation errors and rate limits /attest", async () => {
    const ep = await start(
      handlers({ attest: async (n) => (n === "bad" ? Promise.reject(new AttestError(400, "nonce must be hex")) : { nonce: n }) }),
      new RateLimiter(0.001, 2),
    );
    expect((await localRequest(ep, "/attest?nonce=bad")).status).toBe(400);
    expect(JSON.parse((await localRequest(ep, "/attest?nonce=0x01")).body)).toEqual({ nonce: "0x01" });
    expect((await localRequest(ep, "/attest?nonce=0x01")).status).toBe(429);
    expect((await localRequest(ep, "/nope")).status).toBe(404);
  });
});
