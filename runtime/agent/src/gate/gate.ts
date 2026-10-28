// The password gate behind Caddy's forward_auth (brief item 9, D-044). Caddy asks
// `GET /v1/gate?route=<route>` with the client's headers before it proxies a gated route:
//
// - 200 when the request carries a valid `sealed_gate` cookie, or Basic credentials for user `sealed`
//   that match the released bcrypt hash. A Basic success also sets `sealed_gate` (HMAC-SHA256 with a
//   key made at boot, over route-independent session data, 12 h); for a browser navigation it does so
//   with a 303 back to the same URL, which forward_auth passes to the browser as it is. The app's own Authorization header
//   is not the gate's business when the cookie is used (Twenty sends a Bearer header); when the header
//   holds the gate's own Basic credentials the answer says so, so Caddy can drop it before the app.
// - 401 with `WWW-Authenticate: Basic realm="sealed"` otherwise.
// - 503 `starting` until the route's app finished its bootstrap (sealed-stack/v1 `bootstrap`), so
//   routes stay closed while first-run setup is still open.
// - 429 when a client (or everyone together) has failed too often: a failed attempt costs a token,
//   bcrypt runs only when one is left, and a success gives it back. Successful checks are cached
//   briefly, so a client that keeps sending Basic credentials does not pay bcrypt on every request.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { BCRYPT_MAX_COST, BCRYPT_MAX_PASSWORD_BYTES, GateBusyError, parseBcrypt } from "./bcrypt.js";

export const GATE_COOKIE = "sealed_gate";
export const GATE_COOKIE_TTL_SEC = 12 * 3600;
export const GATE_REALM = 'Basic realm="sealed"';
const COOKIE_TAG = "sealed/gate-cookie/v1";
const MAX_COOKIES_CHECKED = 8;

export type GateDecision =
  | { status: 200; via: "cookie" | "basic"; setCookie?: string; stripAuthorization: boolean }
  /** A Basic success on a top-level GET navigation: set the cookie and send the browser back to the same URL. */
  | { status: 303; location: string; setCookie: string }
  | { status: 401 }
  | { status: 429; retryAfterSec: number }
  | { status: 503; reason: "starting" | "not_configured" | "busy" }
  | { status: 403; reason: string };

export interface GateRequest {
  route: string;
  cookie?: string;
  authorization?: string;
  /** The internet client (Caddy's X-Forwarded-For), for the per-client failure budget. */
  client: string;
  /** The original request's method and URI (forward_auth's X-Forwarded-Method and X-Forwarded-Uri). */
  method?: string;
  uri?: string;
  /** The browser's Sec-Fetch-Mode. */
  fetchMode?: string;
}

/**
 * Where a navigation that just passed Basic auth is sent back to: its own path and query. Only a
 * same-origin absolute path is accepted (no scheme, no `//host`, no backslashes or controls).
 */
export function sameOriginPath(uri: string | undefined): string | undefined {
  if (!uri || uri.length > 4096 || !uri.startsWith("/") || uri.startsWith("//")) return undefined;
  if (/[\\\u0000-\u001f\u007f]/.test(uri)) return undefined;
  return uri;
}

/** Token bucket with refunds, on an injectable millisecond clock. */
export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(
    private readonly perSecond: number,
    private readonly burst: number,
    private readonly now: () => number,
  ) {
    this.tokens = burst;
    this.last = now();
  }
  private refill(): void {
    const t = this.now();
    this.tokens = Math.min(this.burst, this.tokens + ((t - this.last) / 1000) * this.perSecond);
    this.last = t;
  }
  take(): boolean {
    this.refill();
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
  give(): void {
    this.refill();
    this.tokens = Math.min(this.burst, this.tokens + 1);
  }
  /** Whole seconds until one token is available. */
  retryAfterSec(): number {
    this.refill();
    return this.tokens >= 1 ? 0 : Math.max(1, Math.ceil((1 - this.tokens) / this.perSecond));
  }
}

export interface GateLimits {
  /** Failed attempts one client may make in a burst, and how fast that budget refills. */
  clientBurst: number;
  clientPerSec: number;
  /** The same for all clients together (bcrypt runs in one worker). */
  globalBurst: number;
  globalPerSec: number;
}

export const DEFAULT_GATE_LIMITS: GateLimits = { clientBurst: 10, clientPerSec: 1 / 6, globalBurst: 30, globalPerSec: 1 };

export interface GateRoute {
  app: string;
}

export interface GateOptions {
  /** Gated route names (sealed-stack/v1 routes with auth `gate` or `bearer-passthrough`) and their app. */
  routes: ReadonlyMap<string, GateRoute>;
  username: string;
  /** True once the app's bootstrap is done (apps without one are always done). */
  bootstrapDone: (app: string) => Promise<boolean>;
  verify: (password: Uint8Array, hash: string) => Promise<boolean>;
  /** Milliseconds. */
  now?: () => number;
  /** The per-boot cookie key (tests fix it). */
  key?: Uint8Array;
  limits?: GateLimits;
  /** How long a successful Basic check is remembered. */
  cacheTtlMs?: number;
  maxClients?: number;
  onProblem?: (problem: string) => void;
}

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

/** The gate's Basic credentials, or undefined when the header is not Basic auth. */
function parseBasic(header: string | undefined): { user: string; password: Buffer } | undefined {
  const m = /^Basic[ \t]+([A-Za-z0-9+/=]+)[ \t]*$/i.exec(header ?? "");
  if (!m) return undefined;
  const raw = Buffer.from(m[1] as string, "base64");
  const colon = raw.indexOf(0x3a);
  if (colon < 0) return undefined;
  return { user: raw.subarray(0, colon).toString("utf8"), password: raw.subarray(colon + 1) };
}

export class Gate {
  private readonly key: Uint8Array;
  private readonly now: () => number;
  private readonly limits: GateLimits;
  private readonly global: TokenBucket;
  private readonly clients = new Map<string, TokenBucket>();
  /** HMAC(key, Authorization header) -> expiry (ms) of a successful check. */
  private readonly cache = new Map<string, number>();
  private hash?: string;
  private hashProblem?: string;
  /** setHash ran: from then on a missing hash means "not configured", not "starting". */
  private released = false;

  constructor(private readonly o: GateOptions) {
    this.key = o.key ?? randomBytes(32);
    this.now = o.now ?? Date.now;
    this.limits = o.limits ?? DEFAULT_GATE_LIMITS;
    this.global = new TokenBucket(this.limits.globalPerSec, this.limits.globalBurst, this.now);
  }

  /** The released bcrypt hash (`_gate/GATE_PASSWORD_BCRYPT`). Until it is set the gate answers 503 `starting`. */
  setHash(hash: string | undefined): void {
    this.released = true;
    this.cache.clear();
    this.hash = hash?.trim();
    this.hashProblem = undefined;
    const parsed = this.hash ? parseBcrypt(this.hash) : undefined;
    if (!this.hash) this.hashProblem = "the gate password hash was not released";
    else if (!parsed) this.hashProblem = "the released gate password is not a bcrypt hash";
    else if (parsed.cost > BCRYPT_MAX_COST) this.hashProblem = `the gate password hash has cost ${parsed.cost}, above ${BCRYPT_MAX_COST}`;
    if (this.hashProblem) this.o.onProblem?.(this.hashProblem);
  }

  get configured(): boolean {
    return this.hash !== undefined && this.hashProblem === undefined;
  }

  private mac(data: string, tag: string): Buffer {
    return createHmac("sha256", this.key).update(`${tag}|${data}`).digest();
  }

  /** A fresh `sealed_gate` value: v1.<expiresAt>.<session id>.<HMAC>. */
  mintCookie(): string {
    const exp = Math.floor(this.now() / 1000) + GATE_COOKIE_TTL_SEC;
    const sid = b64url(randomBytes(16));
    return `v1.${exp}.${sid}.${b64url(this.mac(`${exp}.${sid}`, COOKIE_TAG))}`;
  }

  setCookieHeader(value: string): string {
    return `${GATE_COOKIE}=${value}; Path=/; Max-Age=${GATE_COOKIE_TTL_SEC}; HttpOnly; Secure; SameSite=Lax`;
  }

  validCookie(value: string): boolean {
    const m = /^v1\.(\d{1,12})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/.exec(value);
    if (!m) return false;
    const exp = Number(m[1]);
    const nowSec = Math.floor(this.now() / 1000);
    if (exp <= nowSec || exp > nowSec + GATE_COOKIE_TTL_SEC + 60) return false;
    const want = this.mac(`${m[1]}.${m[2]}`, COOKIE_TAG);
    const got = Buffer.from(m[3] as string, "base64url");
    return got.length === want.length && timingSafeEqual(got, want);
  }

  private hasValidCookie(header: string | undefined): boolean {
    if (!header) return false;
    let checked = 0;
    for (const part of header.split(";")) {
      const eq = part.indexOf("=");
      if (eq < 0 || part.slice(0, eq).trim() !== GATE_COOKIE) continue;
      if (this.validCookie(part.slice(eq + 1).trim())) return true;
      if (++checked >= MAX_COOKIES_CHECKED) break;
    }
    return false;
  }

  private bucket(client: string): TokenBucket {
    let b = this.clients.get(client);
    if (b) this.clients.delete(client);
    else {
      b = new TokenBucket(this.limits.clientPerSec, this.limits.clientBurst, this.now);
      if (this.clients.size >= (this.o.maxClients ?? 4096)) {
        const oldest = this.clients.keys().next().value;
        if (oldest !== undefined) this.clients.delete(oldest);
      }
    }
    this.clients.set(client, b);
    return b;
  }

  private cached(authorization: string): boolean {
    const k = this.mac(authorization, "basic").toString("hex");
    const exp = this.cache.get(k);
    if (exp === undefined) return false;
    if (exp <= this.now()) {
      this.cache.delete(k);
      return false;
    }
    return true;
  }

  private remember(authorization: string): void {
    const k = this.mac(authorization, "basic").toString("hex");
    this.cache.delete(k);
    this.cache.set(k, this.now() + (this.o.cacheTtlMs ?? 5 * 60_000));
    while (this.cache.size > 1024) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
  }

  async check(req: GateRequest): Promise<GateDecision> {
    const route = this.o.routes.get(req.route);
    if (!route) return { status: 403, reason: "not a gated route" };
    if (!this.released) return { status: 503, reason: "starting" };
    if (!this.configured || this.hash === undefined) return { status: 503, reason: "not_configured" };
    if (!(await this.o.bootstrapDone(route.app))) return { status: 503, reason: "starting" };

    const basic = parseBasic(req.authorization);
    const stripAuthorization = basic !== undefined && basic.user === this.o.username;
    if (this.hasValidCookie(req.cookie)) return { status: 200, via: "cookie", stripAuthorization };
    if (!basic) return { status: 401 };
    const authorization = req.authorization as string;
    if (stripAuthorization && this.cached(authorization)) return this.admitted(req, stripAuthorization);

    const client = this.bucket(req.client);
    if (!client.take()) return { status: 429, retryAfterSec: client.retryAfterSec() };
    if (!this.global.take()) {
      client.give();
      return { status: 429, retryAfterSec: this.global.retryAfterSec() };
    }
    if (!stripAuthorization || basic.password.length > BCRYPT_MAX_PASSWORD_BYTES) return { status: 401 };
    let ok: boolean;
    const password = new Uint8Array(basic.password);
    try {
      ok = await this.o.verify(password, this.hash);
    } catch (err) {
      client.give();
      this.global.give();
      if (err instanceof GateBusyError) return { status: 429, retryAfterSec: 1 };
      throw err;
    } finally {
      password.fill(0);
      basic.password.fill(0);
    }
    if (!ok) return { status: 401 };
    client.give();
    this.global.give();
    this.remember(authorization);
    return this.admitted(req, stripAuthorization);
  }

  /**
   * A Basic success. forward_auth copies nothing from a 2xx answer onto the client's response, while
   * it passes any other answer through as it is; so a browser navigation (GET, Sec-Fetch-Mode
   * navigate) gets 303 back to the same URL with the cookie, and comes back with it. Other requests
   * get 200 with Set-Cookie for Caddy to copy, and keep working with Basic (cached) if it does not.
   */
  private admitted(req: GateRequest, stripAuthorization: boolean): GateDecision {
    const setCookie = this.setCookieHeader(this.mintCookie());
    const location = sameOriginPath(req.uri);
    if (location && (req.method ?? "GET").toUpperCase() === "GET" && req.fetchMode === "navigate") return { status: 303, location, setCookie };
    return { status: 200, via: "basic", setCookie, stripAuthorization };
  }
}
