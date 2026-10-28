import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { counts, healthBody, MAX_EGRESS_KEYS } from "../src/healthReport.js";
import { fetchJson, localRequest, parseEndpoint, ResponseTooLargeError } from "../src/http.js";

describe("response size caps", () => {
  let server: http.Server;
  let base: string;
  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const big = req.url === "/big";
      res.writeHead(200, { "content-type": "application/json", ...(req.url === "/chunked" ? {} : { "content-length": big ? 2_000_000 : 2 }) });
      if (req.url === "/chunked") {
        for (let i = 0; i < 20; i++) res.write(`"${"x".repeat(100_000)}"`);
        return res.end();
      }
      res.end(big ? "x".repeat(2_000_000) : "{}");
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", () => ok()));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((ok) => server.close(() => ok())));

  it("fetchJson rejects bodies above the cap, declared or streamed", async () => {
    expect(await fetchJson(`${base}/small`, { maxBytes: 1000 })).toEqual({});
    await expect(fetchJson(`${base}/big`, { maxBytes: 1_000_000 })).rejects.toThrow(ResponseTooLargeError);
    await expect(fetchJson(`${base}/chunked`, { maxBytes: 1_000_000 })).rejects.toThrow(ResponseTooLargeError);
  });

  it("localRequest (sockets, sidecars) rejects bodies above the cap", async () => {
    await expect(localRequest(parseEndpoint(base), "/big", { maxBytes: 1_000_000 })).rejects.toThrow(ResponseTooLargeError);
    expect((await localRequest(parseEndpoint(base), "/small")).body).toBe("{}");
  });
});

describe("egress counters in health reports", () => {
  it("keep only host:port keys, at most MAX_EGRESS_KEYS, largest first", () => {
    const many = Object.fromEntries(Array.from({ length: 80 }, (_, i) => [`h${i}.example.com:443`, i]));
    const c = counts({ ...many, "free text that is not a host": 1_000, "UPPER.example:443": 5, "a.example:443": -1 });
    expect(Object.keys(c).length).toBe(MAX_EGRESS_KEYS);
    expect(c["h79.example.com:443"]).toBe(79);
    expect(c["h0.example.com:443"]).toBeUndefined();
    expect(Object.keys(c).some((k) => k.includes(" ") || k.startsWith("UPPER") || k.startsWith("a."))).toBe(false);
    const body = healthBody({ at: 1, apps: {}, egress: { allowed: many, blocked: { "*.evil.example:443": 2 } }, payments: {} });
    expect(Object.keys(body.egress.allowed).length).toBe(MAX_EGRESS_KEYS);
    expect(body.egress.blocked).toEqual({ "*.evil.example:443": 2 });
  });
});
