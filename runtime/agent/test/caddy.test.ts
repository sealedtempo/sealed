import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isPaymentNeededConfig, PaymentGate, paymentNeededConfig, SocketCaddyAdmin } from "../src/caddy.js";
import { parseEndpoint } from "../src/http.js";
import { type FakeCaddy, sampleCaddyConfig, startFakeCaddy } from "./helpers/fakeCaddy.js";

const appHosts = ["crm.34-1-2-3.sslip.io", "gateway.34-1-2-3.sslip.io"];

describe("payment-needed switch", () => {
  it("replaces app routes only and keeps the attest route", () => {
    const original = sampleCaddyConfig("34-1-2-3");
    const switched = paymentNeededConfig(original, appHosts) as typeof original;
    const routes = switched.apps.http.servers.srv0.routes as unknown as { "@id"?: string; handle: { handler: string; status_code?: number }[]; match: unknown }[];
    expect(routes[0]?.handle[0]).toMatchObject({ handler: "static_response", status_code: 402 });
    expect(routes[1]?.handle[0]?.handler).toBe("static_response");
    expect(routes[2]?.handle[0]?.handler).toBe("subroute");
    expect(routes[0]?.match).toEqual(original.apps.http.servers.srv0.routes[0]?.match);
    expect(isPaymentNeededConfig(switched)).toBe(true);
    expect(isPaymentNeededConfig(original)).toBe(false);
    expect(JSON.stringify(switched)).not.toMatch(/\u2014/); // no em-dashes in UI copy
  });

  describe("through the admin API on a unix socket", () => {
    let dir: string;
    let caddy: FakeCaddy;
    let saved: unknown;
    let gate: PaymentGate;
    beforeEach(async () => {
      dir = await mkdtemp(join(tmpdir(), "caddy-admin-"));
      caddy = await startFakeCaddy(join(dir, "admin.sock"), sampleCaddyConfig("34-1-2-3"));
      saved = undefined;
      gate = new PaymentGate(new SocketCaddyAdmin(parseEndpoint(join(dir, "admin.sock"))), appHosts, {
        getOriginal: () => saved,
        setOriginal: async (c) => {
          saved = c;
        },
      });
    });
    afterEach(async () => {
      await caddy.close();
      await rm(dir, { recursive: true, force: true });
    });

    it("switches, is idempotent, and restores the exact original", async () => {
      const original = structuredClone(caddy.config);
      await gate.enable();
      expect(isPaymentNeededConfig(caddy.config)).toBe(true);
      await gate.enable();
      expect(caddy.loads).toBe(1);
      expect(saved).toEqual(original);
      await gate.disable();
      expect(caddy.config).toEqual(original);
      expect(saved).toBeUndefined();
      await gate.disable();
      expect(caddy.loads).toBe(2);
    });

    it("re-applies after Caddy restarted from its Caddyfile", async () => {
      await gate.enable();
      caddy.config = sampleCaddyConfig("34-1-2-3");
      await gate.enable();
      expect(isPaymentNeededConfig(caddy.config)).toBe(true);
      await gate.disable();
      expect(caddy.config).toEqual(sampleCaddyConfig("34-1-2-3"));
    });
  });
});
