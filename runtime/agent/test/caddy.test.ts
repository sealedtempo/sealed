import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DirectCaddySwitch } from "../src/caddy.js";
import { parseEndpoint } from "../src/http.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { CADDYFILE, CADDYFILE_PAYMENT_NEEDED } from "./helpers/fixtures.js";

const files = { normal: CADDYFILE, paymentNeeded: CADDYFILE_PAYMENT_NEEDED };

describe("payment-needed switch (measured Caddyfiles over the admin socket)", () => {
  let dir: string;
  let caddy: FakeCaddy;
  let socket: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "caddy-admin-"));
    socket = join(dir, "admin.sock");
    caddy = await startFakeCaddy(socket, CADDYFILE);
  });
  afterEach(async () => {
    await caddy.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("loads exactly the measured files as text/caddyfile; re-applying the running file reloads nothing", async () => {
    const sw = new DirectCaddySwitch(parseEndpoint(socket), files);
    await sw.apply("payment-needed");
    expect(caddy.current).toBe(CADDYFILE_PAYMENT_NEEDED);
    await sw.apply("payment-needed");
    expect(caddy.reloads).toBe(1);
    await sw.apply("normal");
    expect(caddy.current).toBe(CADDYFILE);
    expect(caddy.contentTypes).toEqual(["text/caddyfile", "text/caddyfile", "text/caddyfile"]);
    caddy.failNext = 1;
    await expect(sw.apply("payment-needed")).rejects.toThrow("HTTP 500");
  });
});
