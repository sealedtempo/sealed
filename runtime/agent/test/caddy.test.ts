import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adminSocketReachable, canReachAdminSocket, DirectCaddySwitch } from "../src/caddy.js";
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

  // Review ws-int-agent 9: the dropped user reaches the composer 1.2 socket itself, so no root process stays;
  // a stack whose socket it cannot reach fails the boot (agent.ts) instead of getting a root helper.
  it("the run-as user can reach the composer 1.2 socket, and nothing else counts as reachable", async () => {
    const agent = { uid: 10001, gid: 10001 };
    const v12 = { adminSocketMode: "0660", adminSocketOwner: "10001:10001" };
    const volume = { uid: 10001, gid: 10001, mode: 0o2770 };
    expect(canReachAdminSocket(agent, v12, volume)).toBe(true);
    // Group access alone is enough (Caddy owns the socket, the setgid volume gives it group 10001).
    expect(canReachAdminSocket(agent, { adminSocketMode: "0660", adminSocketOwner: "0:10001" }, { uid: 0, gid: 10001, mode: 0o2770 })).toBe(true);
    // Composer 1.1 (no socket facts), another group, a socket without group write, a directory without search.
    expect(canReachAdminSocket(agent, {}, volume)).toBe(false);
    expect(canReachAdminSocket({ uid: 10002, gid: 10002 }, v12, volume)).toBe(false);
    expect(canReachAdminSocket(agent, { adminSocketMode: "0640", adminSocketOwner: "0:10001" }, volume)).toBe(false);
    expect(canReachAdminSocket(agent, v12, { uid: 0, gid: 0, mode: 0o750 })).toBe(false);
    expect(canReachAdminSocket(agent, v12, undefined)).toBe(false);
    // With the directory read from disk: here the test user owns it.
    const me = { uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 };
    expect(await adminSocketReachable(me, socket, { adminSocketMode: "0600", adminSocketOwner: `${me.uid}:${me.gid}` })).toBe(true);
    expect(await adminSocketReachable(me, join(dir, "missing", "admin.sock"), v12)).toBe(false);
  });
});
