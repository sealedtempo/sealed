// The password gate behind Caddy's forward_auth (brief item 9, D-044): cookie, Basic, bootstrap,
// failure budgets and the success cache, on a fake clock.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BcryptWorker, GateBusyError } from "../src/gate/bcrypt.js";
import { clientKey, GATE_COOKIE_TTL_SEC, Gate, type GateDecision, type GateOptions, sameOriginPath, TokenBucket } from "../src/gate/gate.js";

const vectors = (await readFile(join(import.meta.dirname, "fixtures/bcrypt-go-vectors.jsonl"), "utf8"))
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l) as { password: string; cost: number; hash: string });
const gateVector = vectors.find((v) => v.password === Buffer.from("sealed-gate-password").toString("hex")) as (typeof vectors)[number];
const PASSWORD = "sealed-gate-password";
const HASH = gateVector.hash;
const basic = (user: string, pw: string) => `Basic ${Buffer.from(`${user}:${pw}`).toString("base64")}`;
const cookieOf = (d: GateDecision) => ((d.status === 200 || d.status === 303) && d.setCookie ? (d.setCookie.split(";")[0] as string) : "");

function makeGate(over: Partial<GateOptions> & { t?: { now: number }; done?: Set<string> } = {}) {
  const t = over.t ?? { now: 1_800_000_000_000 };
  const done = over.done ?? new Set(["crm", "tools-app"]);
  const calls: string[] = [];
  const gate = new Gate({
    routes: new Map([
      ["crm", { app: "crm" }],
      ["tools", { app: "tools-app" }],
      ["gateway", { app: "tools-app", bearer: true }],
    ]),
    username: "sealed",
    bootstrapDone: async (app) => done.has(app),
    verify: async (pw, hash) => {
      calls.push(Buffer.from(pw).toString("utf8"));
      return hash === HASH && Buffer.from(pw).toString("utf8") === PASSWORD;
    },
    now: () => t.now,
    ...over,
  });
  gate.setHash(HASH);
  return { gate, t, calls, done };
}

describe("password gate (/v1/gate)", () => {
  it("lets Basic sealed:<password> in once and hands out a cookie that admits without credentials", async () => {
    const { gate } = makeGate();
    const first = await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "1.1.1.1" });
    expect(first).toMatchObject({ status: 200, via: "basic", stripAuthorization: true });
    const setCookie = (first as { setCookie: string }).setCookie;
    expect(setCookie).toMatch(/^sealed_gate=v1\.\d+\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}; Path=\/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax$/);
    // The cookie is route independent and leaves the app's own Authorization header alone (Twenty's Bearer).
    const again = await gate.check({ route: "tools", cookie: `other=1; ${cookieOf(first)}`, authorization: "Bearer twenty-token", client: "1.1.1.1" });
    expect(again).toEqual({ status: 200, via: "cookie", stripAuthorization: false });
    // A browser that also replays the gate's Basic credentials gets them stripped before the app.
    expect(await gate.check({ route: "crm", cookie: cookieOf(first), authorization: basic("sealed", "anything"), client: "1.1.1.1" })).toEqual({
      status: 200,
      via: "cookie",
      stripAuthorization: true,
    });
  });

  it("sends a browser navigation back to the same URL with the cookie, since forward_auth passes 3xx answers through", async () => {
    const { gate } = makeGate();
    const nav = { route: "crm", authorization: basic("sealed", PASSWORD), client: "c", method: "GET", uri: "/objects/companies?view=all", fetchMode: "navigate" };
    const d = await gate.check(nav);
    expect(d).toMatchObject({ status: 303, location: "/objects/companies?view=all" });
    expect(await gate.check({ route: "crm", cookie: cookieOf(d), client: "c", method: "GET", uri: "/objects/companies?view=all", fetchMode: "navigate" })).toMatchObject({ status: 200, via: "cookie" });
    // Not for API calls, form posts or URIs that could leave the origin.
    expect((await gate.check({ ...nav, fetchMode: "cors" })).status).toBe(200);
    expect((await gate.check({ ...nav, method: "POST" })).status).toBe(200);
    for (const uri of ["//evil.example/x", "https://evil.example/", "/\\evil.example", "/a\r\nSet-Cookie: x=1", "", undefined]) {
      expect((await gate.check({ ...nav, uri })).status, String(uri)).toBe(200);
    }
    expect(sameOriginPath("/ok/path?q=1#f")).toBe("/ok/path?q=1#f");
  });

  it("answers 401 for missing, wrong or non-Basic credentials and for other users", async () => {
    const { gate, calls } = makeGate();
    expect(await gate.check({ route: "crm", client: "c" })).toEqual({ status: 401 });
    expect(await gate.check({ route: "crm", authorization: "Bearer abc", client: "c" })).toEqual({ status: 401 });
    expect(await gate.check({ route: "crm", authorization: basic("sealed", "wrong"), client: "c" })).toEqual({ status: 401 });
    expect(await gate.check({ route: "crm", authorization: basic("admin", PASSWORD), client: "c" })).toEqual({ status: 401 });
    expect(await gate.check({ route: "crm", authorization: basic("sealed", "x".repeat(73)), client: "c" })).toEqual({ status: 401 });
    expect(await gate.check({ route: "crm", authorization: "Basic !!!", client: "c" })).toEqual({ status: 401 });
    // bcrypt ran for the one plausible attempt only.
    expect(calls).toEqual(["wrong"]);
  });

  it("refuses forged, expired and other-boot cookies", async () => {
    const { gate, t } = makeGate();
    const ok = await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" });
    const value = cookieOf(ok).slice("sealed_gate=".length);
    expect(gate.validCookie(value)).toBe(true);
    const [v, exp, sid, mac] = value.split(".") as [string, string, string, string];
    expect(gate.validCookie(`${v}.${Number(exp) + 100}.${sid}.${mac}`)).toBe(false);
    expect(gate.validCookie(`${v}.${exp}.${sid.replace(/^./, sid[0] === "A" ? "B" : "A")}.${mac}`)).toBe(false);
    expect(gate.validCookie(`${v}.${exp}.${sid}.${mac.replace(/^./, mac[0] === "A" ? "B" : "A")}`)).toBe(false);
    expect(gate.validCookie("v1.1.2.3")).toBe(false);
    // A gate with another per-boot key (an agent restart) does not accept it.
    const { gate: rebooted } = makeGate({ t });
    expect(rebooted.validCookie(value)).toBe(false);
    t.now += GATE_COOKIE_TTL_SEC * 1000;
    expect(gate.validCookie(value)).toBe(false);
    expect(await gate.check({ route: "crm", cookie: `sealed_gate=${value}`, client: "c" })).toEqual({ status: 401 });
  });

  it("keeps a route at 503 starting until its app's bootstrap is done, and refuses routes it does not gate", async () => {
    const { gate, done } = makeGate({ done: new Set() });
    expect(await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).toEqual({ status: 503, reason: "starting" });
    done.add("crm");
    expect((await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).status).toBe(200);
    expect(await gate.check({ route: "tools", authorization: basic("sealed", PASSWORD), client: "c" })).toEqual({ status: 503, reason: "starting" });
    expect(await gate.check({ route: "relay", client: "c" })).toEqual({ status: 403, reason: "not a gated route" });
    expect(await gate.check({ route: "", client: "c" })).toEqual({ status: 403, reason: "not a gated route" });
  });

  it("answers 503 until the hash is released, and fails closed on a hash it cannot use", async () => {
    const problems: string[] = [];
    const g = new Gate({
      routes: new Map([["crm", { app: "crm" }]]),
      username: "sealed",
      bootstrapDone: async () => true,
      verify: async () => true,
      onProblem: (p) => problems.push(p),
    });
    expect(await g.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).toEqual({ status: 503, reason: "starting" });
    g.setHash("$2a$14$hash");
    expect(await g.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).toEqual({ status: 503, reason: "not_configured" });
    g.setHash(HASH.replace(/^\$2a\$05\$/, "$2a$25$"));
    expect(g.configured).toBe(false);
    g.setHash(undefined);
    // Once the keys are released, a missing hash is a configuration problem, not a start-up state.
    expect(await g.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).toEqual({ status: 503, reason: "not_configured" });
    expect(problems).toEqual([
      "the released gate password is not a bcrypt hash",
      "the gate password hash has cost 25, above 20",
      "the gate password hash was not released",
    ]);
    g.setHash(HASH);
    expect((await g.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).status).toBe(200);
  });

  it("remembers successful checks briefly instead of paying bcrypt on every request", async () => {
    const { gate, calls, t } = makeGate();
    const auth = basic("sealed", PASSWORD);
    for (let i = 0; i < 5; i++) expect((await gate.check({ route: "crm", authorization: auth, client: "c" })).status).toBe(200);
    expect(calls).toEqual([PASSWORD]);
    t.now += 5 * 60_000;
    expect((await gate.check({ route: "crm", authorization: auth, client: "c" })).status).toBe(200);
    expect(calls).toEqual([PASSWORD, PASSWORD]);
    // Wrong passwords are never cached.
    await gate.check({ route: "crm", authorization: basic("sealed", "nope"), client: "c" });
    await gate.check({ route: "crm", authorization: basic("sealed", "nope"), client: "c" });
    expect(calls.filter((c) => c === "nope")).toHaveLength(2);
  });

  it("rate limits failed attempts per client and, for clients that failed recently, overall; a success gives its token back", async () => {
    const t = { now: 1_800_000_000_000 };
    const { gate, calls } = makeGate({ t, limits: { clientBurst: 3, clientPerSec: 1 / 6, globalBurst: 3, globalPerSec: 1 / 3600, suspectMs: 600_000 } });
    const wrong = { route: "crm", authorization: basic("sealed", "guess"), client: "9.9.9.9" };
    // The first failure costs only the client's budget; later ones, while the client is suspect, also a global token.
    for (let i = 0; i < 3; i++) expect(await gate.check(wrong)).toEqual({ status: 401 });
    expect(await gate.check(wrong)).toEqual({ status: 429, retryAfterSec: 6 });
    expect(calls).toHaveLength(3);
    // Even the right password waits once the client's budget is spent: no bcrypt oracle under attack.
    expect((await gate.check({ ...wrong, authorization: basic("sealed", PASSWORD) })).status).toBe(429);
    t.now += 6_000;
    expect((await gate.check({ ...wrong, authorization: basic("sealed", PASSWORD) })).status).toBe(200);
    // That success refunded both tokens: the client can fail once more right away, which takes the last global token.
    expect(await gate.check(wrong)).toEqual({ status: 401 });
    // Another client's first failure is on its own budget; its second waits for the global budget.
    expect(await gate.check({ ...wrong, client: "8.8.8.8" })).toEqual({ status: 401 });
    expect(await gate.check({ ...wrong, client: "8.8.8.8" })).toEqual({ status: 429, retryAfterSec: 3594 }); // 6 s of refill since the global budget was last full
    // A client without recent failures is never held to it.
    expect((await gate.check({ ...wrong, client: "7.7.7.7", authorization: basic("sealed", PASSWORD) })).status).toBe(200);
    expect(calls).toHaveLength(6); // 7.7.7.7's check hit the success cache
    // A valid cookie is never rate limited.
    const ok = await makeGate({ t }).gate.check({ ...wrong, authorization: basic("sealed", PASSWORD) });
    expect(ok.status).toBe(200);
  });

  // Review ws-int-agent 6: a few addresses, each inside its own budget, kept the global budget empty, and then
  // nobody could log in with Basic.
  it("other clients' failures never lock out a login from a client without recent failures", async () => {
    const t = { now: 1_800_000_000_000 };
    const { gate } = makeGate({ t });
    const attackers = Array.from({ length: 12 }, (_, i) => `198.51.100.${i + 1}`);
    // Each attacker stays inside its own budget (10 burst, one per 6 s) for ten minutes.
    for (let round = 0; round < 100; round++) {
      for (const a of attackers) await gate.check({ route: "crm", authorization: basic("sealed", `guess-${round}`), client: a });
      t.now += 6_000;
    }
    // The global budget is spent by now: suspect clients get 429 ...
    const last = await Promise.all(attackers.map((a) => gate.check({ route: "crm", authorization: basic("sealed", "guess"), client: a })));
    expect(last.filter((d) => d.status === 429).length).toBeGreaterThan(0);
    // ... but a new client with the right password gets in at once.
    expect((await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "203.0.113.50" })).status).toBe(200);
    // A client whose last failure is older than the suspect window is not held to the global budget either.
    expect((await gate.check({ route: "crm", authorization: basic("sealed", "typo"), client: "203.0.113.51" })).status).toBe(401);
    t.now += 11 * 60_000;
    expect((await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "203.0.113.51" })).status).toBe(200);
  });

  it("counts IPv6 clients per /64", async () => {
    expect(clientKey("2001:db8:1:2:aaaa::1")).toBe("2001:db8:1:2::/64");
    expect(clientKey("2001:0db8:0001:0002:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    expect(clientKey("2001:db8::7")).toBe("2001:db8:0:0::/64");
    expect(clientKey("203.0.113.9")).toBe("203.0.113.9");
    const { gate } = makeGate({ limits: { clientBurst: 2, clientPerSec: 1 / 6, globalBurst: 100, globalPerSec: 1, suspectMs: 600_000 } });
    const wrong = (client: string) => gate.check({ route: "crm", authorization: basic("sealed", "guess"), client });
    expect((await wrong("2001:db8:1:2::a")).status).toBe(401);
    expect((await wrong("2001:db8:1:2::b")).status).toBe(401);
    expect((await wrong("2001:db8:1:2::c")).status).toBe(429);
    expect((await wrong("2001:db8:1:3::a")).status).toBe(401);
  });

  // Review ws-int-agent 7 and C-3: the gate accepted forms Caddy did not strip, so the gate's credential reached the app.
  it("accepts only the Basic and cookie forms Caddy strips", async () => {
    const { gate, calls } = makeGate();
    const b64 = Buffer.from(`sealed:${PASSWORD}`).toString("base64");
    // Every accepted form starts with Caddy's prefix match (composer 1.2: spaces; 1.3: spaces or tabs).
    for (const header of [`Basic ${b64}`, `basic  ${b64}`, `BASIC ${b64}`]) {
      expect(header).toMatch(/^[Bb][Aa][Ss][Ii][Cc] +c2VhbGVkO/);
      expect(await gate.check({ route: "crm", authorization: header, client: "c" }), header).toMatchObject({ status: 200, via: "basic", stripAuthorization: true });
    }
    // A tab, a missing pad, base64url characters or trailing junk are not the gate's credential: 401, no bcrypt.
    const before = calls.length;
    for (const header of [`Basic\t${b64}`, `Basic ${Buffer.from("sealed:pwd1").toString("base64").replace(/=+$/, "")}`, `Basic ${Buffer.from("sealed:a?>").toString("base64").replace("/", "_")}`, `Basic ${b64} x`, `Basic ${b64}==`]) {
      expect(await gate.check({ route: "crm", authorization: header, client: "c" }), header).toEqual({ status: 401 });
    }
    expect(calls.length).toBe(before);
    // Cookies: only the exact name after the separator's whitespace counts, as `(^|;\s*)sealed_gate=` matches.
    const d = await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" });
    const value = cookieOf(d).slice("sealed_gate=".length);
    for (const cookie of [`sealed_gate=${value}`, `a=1;sealed_gate=${value}`, `a=1;\t sealed_gate=${value}`]) {
      expect((await gate.check({ route: "crm", cookie, client: "c" })).status, cookie).toBe(200);
    }
    for (const cookie of [`sealed_gate =${value}`, `a=1; sealed_gate\t=${value}`, `xsealed_gate=${value}`, `a=1;\u000bsealed_gate=${value}`]) {
      expect(await gate.check({ route: "crm", cookie, client: "c" }), JSON.stringify(cookie)).toEqual({ status: 401 });
    }
  });

  // Review C-6: requests with a Bearer token on a bearer-passthrough route skipped the bootstrap hold.
  it("?bearer=1 holds a bearer-passthrough route until bootstrap is done, then opens it for Bearer requests only", async () => {
    const { gate, done } = makeGate({ done: new Set() });
    const bearer = { route: "gateway", authorization: "Bearer sk-app-key", client: "c", bearer: true };
    expect(await gate.check(bearer)).toEqual({ status: 503, reason: "starting" });
    done.add("tools-app");
    expect(await gate.check(bearer)).toEqual({ status: 200, via: "bearer", stripAuthorization: false });
    expect(await gate.check({ ...bearer, authorization: basic("sealed", PASSWORD) })).toEqual({ status: 401 });
    expect(await gate.check({ ...bearer, authorization: undefined })).toEqual({ status: 401 });
    expect(await gate.check({ ...bearer, route: "crm" })).toEqual({ status: 403, reason: "not a bearer-passthrough route" });
    // Before the keys are released the route is starting, whatever the token.
    const fresh = new Gate({ routes: new Map([["gateway", { app: "a", bearer: true }]]), username: "sealed", bootstrapDone: async () => true, verify: async () => true });
    expect(await fresh.check(bearer)).toEqual({ status: 503, reason: "starting" });
  });

  it("answers 429 when too many checks are in flight", async () => {
    const { gate } = makeGate({
      verify: async () => {
        throw new GateBusyError("busy");
      },
    });
    expect(await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).toEqual({ status: 429, retryAfterSec: 1 });
  });

  describe("with the real bcrypt worker", () => {
    const worker = new BcryptWorker();
    afterAll(() => worker.close());
    it("accepts the password Go hashed and refuses others", async () => {
      const { gate } = makeGate({ verify: (pw, h) => worker.verify(pw, h) });
      expect((await gate.check({ route: "crm", authorization: basic("sealed", PASSWORD), client: "c" })).status).toBe(200);
      expect((await gate.check({ route: "crm", authorization: basic("sealed", `${PASSWORD}!`), client: "c" })).status).toBe(401);
    });
  });

  it("token buckets refill over time and never above the burst", () => {
    const t = { now: 0 };
    const b = new TokenBucket(1, 2, () => t.now);
    expect([b.take(), b.take(), b.take()]).toEqual([true, true, false]);
    expect(b.retryAfterSec()).toBe(1);
    t.now = 10_000;
    b.give();
    expect([b.take(), b.take(), b.take()]).toEqual([true, true, false]);
  });
});
