// The password gate behind Caddy's forward_auth (brief item 9, D-044): cookie, Basic, bootstrap,
// failure budgets and the success cache, on a fake clock.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BcryptWorker, GateBusyError } from "../src/gate/bcrypt.js";
import { GATE_COOKIE_TTL_SEC, Gate, type GateDecision, type GateOptions, TokenBucket } from "../src/gate/gate.js";

const vectors = (await readFile(join(import.meta.dirname, "fixtures/bcrypt-go-vectors.jsonl"), "utf8"))
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l) as { password: string; cost: number; hash: string });
const gateVector = vectors.find((v) => v.password === Buffer.from("sealed-gate-password").toString("hex")) as (typeof vectors)[number];
const PASSWORD = "sealed-gate-password";
const HASH = gateVector.hash;
const basic = (user: string, pw: string) => `Basic ${Buffer.from(`${user}:${pw}`).toString("base64")}`;
const cookieOf = (d: GateDecision) => (d.status === 200 && d.setCookie ? (d.setCookie.split(";")[0] as string) : "");

function makeGate(over: Partial<GateOptions> & { t?: { now: number }; done?: Set<string> } = {}) {
  const t = over.t ?? { now: 1_800_000_000_000 };
  const done = over.done ?? new Set(["crm", "tools-app"]);
  const calls: string[] = [];
  const gate = new Gate({
    routes: new Map([
      ["crm", { app: "crm" }],
      ["tools", { app: "tools-app" }],
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

  it("rate limits failed attempts per client and overall, and a success gives its token back", async () => {
    const t = { now: 1_800_000_000_000 };
    const { gate, calls } = makeGate({ t, limits: { clientBurst: 3, clientPerSec: 1 / 6, globalBurst: 5, globalPerSec: 1 } });
    const wrong = { route: "crm", authorization: basic("sealed", "guess"), client: "9.9.9.9" };
    for (let i = 0; i < 3; i++) expect(await gate.check(wrong)).toEqual({ status: 401 });
    expect(await gate.check(wrong)).toEqual({ status: 429, retryAfterSec: 6 });
    expect(calls).toHaveLength(3);
    // Even the right password waits once the client's budget is spent: no bcrypt oracle under attack.
    expect((await gate.check({ ...wrong, authorization: basic("sealed", PASSWORD) })).status).toBe(429);
    t.now += 6_000;
    expect((await gate.check({ ...wrong, authorization: basic("sealed", PASSWORD) })).status).toBe(200);
    // That success refunded its token: the client can fail once more right away.
    expect(await gate.check(wrong)).toEqual({ status: 401 });
    // Other clients have their own budget, until the global one (5, 4 left) runs out.
    for (const c of ["8.8.8.8", "7.7.7.7", "6.6.6.6", "5.5.5.5"]) expect(await gate.check({ ...wrong, client: c })).toEqual({ status: 401 });
    expect(await gate.check({ ...wrong, client: "4.4.4.4" })).toEqual({ status: 429, retryAfterSec: 1 });
    expect(calls).toHaveLength(9);
    // A valid cookie is never rate limited.
    const ok = await makeGate({ t }).gate.check({ ...wrong, authorization: basic("sealed", PASSWORD) });
    expect(ok.status).toBe(200);
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
