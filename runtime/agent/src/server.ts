// sealed-agent local API on :7070 (INTERFACES 11). Reachable on the apps network only; Caddy
// exposes /attest publicly. Callers are identified by their fixed apps-network IP (the composer pins
// every service's address), which the handlers check for usage events and spend counters.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type UsageEvent, usageEventSchema } from "@sealed/core";
import { AttestError, ClientRateLimiter, RateLimiter } from "./attest.js";
import { BootstrapError } from "./gate/bootstrap.js";
import { SpendBudgetError, UnknownReservationError } from "./payments/budget.js";
import { GATE_REALM, type GateDecision, type GateRequest } from "./gate/gate.js";
import { errorFields, type Logger } from "./log.js";
import { normalizePeer } from "./stack.js";

export interface ApiHandlers {
  isReady(): boolean;
  readyInfo(): Record<string, unknown>;
  recordUsage(ev: UsageEvent, peer: string): Promise<"accepted" | "duplicate">;
  recordSpend(body: unknown, peer: string): void;
  /** POST /v1/spend/reserve and /release (D-048): the payer's share of the daily budget. */
  reserveSpend(body: unknown, peer: string): unknown | Promise<unknown>;
  releaseSpend(body: unknown, peer: string): unknown | Promise<unknown>;
  attest(nonce: string): Promise<unknown>;
  /** GET /v1/gate (Caddy forward_auth). `peer` is the socket peer, `req.client` the internet client. */
  gate(req: GateRequest, peer: string): Promise<GateDecision>;
  /** POST /v1/bootstrap/done from a bootstrap service whose done file is not on the data disk. */
  bootstrapDone(body: unknown, peer: string): void;
}

/** A request the caller may not make (403) or whose content is refused (422 / 429 / 400). */
export class UsageRejected extends Error {
  constructor(
    message: string,
    readonly status: 400 | 403 | 422 | 429 | 503 = 422,
  ) {
    super(message);
  }
}

export interface ApiServerOptions {
  /** Global /attest budget: quotes are expensive. */
  attestLimiter?: RateLimiter;
  /** Per-client /attest budget, keyed by the client address. */
  attestClientLimiter?: ClientRateLimiter;
  /** Caddy's address: only its X-Forwarded-For names the internet client. */
  trustedProxy?: () => string | undefined;
  /** The caller's address (tests substitute it; production uses the socket peer). */
  peerOf?: (req: http.IncomingMessage) => string;
}

const MAX_BODY = 64 * 1024;

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw Object.assign(new Error("body too large"), { status: 413 });
    chunks.push(c as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
  } catch {
    throw Object.assign(new Error("invalid JSON"), { status: 400 });
  }
}

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
    ...headers,
  });
  res.end(text);
}

/** Header names on a 200 from /v1/gate that Caddy can copy (forward_auth `copy_headers`) or act on. */
export const GATE_VIA_HEADER = "x-sealed-gate";
export const GATE_STRIP_HEADER = "x-sealed-gate-strip-authorization";

function sendGate(res: http.ServerResponse, d: GateDecision): void {
  switch (d.status) {
    case 200:
      return send(res, 200, "", {
        [GATE_VIA_HEADER]: d.via,
        ...(d.stripAuthorization ? { [GATE_STRIP_HEADER]: "1" } : {}),
        ...(d.setCookie ? { "set-cookie": d.setCookie } : {}),
      });
    case 303:
      return send(res, 303, "", { location: d.location, "set-cookie": d.setCookie });
    case 401:
      return send(res, 401, "unauthorized", { "www-authenticate": GATE_REALM });
    case 429:
      return send(res, 429, "too many attempts", { "retry-after": String(d.retryAfterSec) });
    case 503:
      return send(res, 503, d.reason === "starting" ? "starting" : d.reason === "busy" ? "busy" : "gate not configured", { "retry-after": "5" });
    case 403:
      return send(res, 403, d.reason);
  }
}

const first = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

/** The client an /attest request is for: Caddy's X-Forwarded-For entry when Caddy relays it, else the peer. */
export function attestClient(req: http.IncomingMessage, peer: string, trustedProxy: string | undefined): string {
  const xff = req.headers["x-forwarded-for"];
  if (trustedProxy && peer === trustedProxy && typeof xff === "string" && xff.trim() !== "") {
    return normalizePeer(xff.split(",").at(-1)?.trim());
  }
  return peer;
}

export function createApiServer(h: ApiHandlers, log: Logger, opts: ApiServerOptions = {}): http.Server {
  const attestLimiter = opts.attestLimiter ?? new RateLimiter(10, 40);
  const clientLimiter = opts.attestClientLimiter ?? new ClientRateLimiter(1, 5);
  const peerOf = opts.peerOf ?? ((req: http.IncomingMessage) => normalizePeer(req.socket.remoteAddress));
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://agent");
    const route = `${req.method} ${url.pathname}`;
    try {
      switch (route) {
        case "GET /healthz":
          return h.isReady() ? send(res, 200, "ok") : send(res, 503, "starting");
        case "GET /v1/ready":
          return send(res, h.isReady() ? 200 : 503, { ready: h.isReady(), ...h.readyInfo() });
        case "POST /v1/usage-events": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          const parsed = usageEventSchema.safeParse(await readJson(req));
          if (!parsed.success) return send(res, 400, { error: parsed.error.issues[0]?.message ?? "invalid event" });
          const result = await h.recordUsage(parsed.data, peerOf(req));
          return send(res, 202, { status: result });
        }
        case "POST /v1/spend": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          h.recordSpend(await readJson(req), peerOf(req));
          return send(res, 204, "");
        }
        case "GET /v1/gate": {
          const peer = peerOf(req);
          const decision = await h.gate(
            {
              route: url.searchParams.get("route") ?? "",
              cookie: first(req.headers.cookie),
              authorization: first(req.headers.authorization),
              client: attestClient(req, peer, opts.trustedProxy?.()),
              method: first(req.headers["x-forwarded-method"]),
              uri: first(req.headers["x-forwarded-uri"]),
              fetchMode: first(req.headers["sec-fetch-mode"]),
            },
            peer,
          );
          return sendGate(res, decision);
        }
        case "POST /v1/spend/reserve": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          return send(res, 200, await h.reserveSpend(await readJson(req), peerOf(req)));
        }
        case "POST /v1/spend/release": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          return send(res, 200, await h.releaseSpend(await readJson(req), peerOf(req)));
        }
        case "POST /v1/bootstrap/done": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          h.bootstrapDone(await readJson(req), peerOf(req));
          return send(res, 204, "");
        }
        case "GET /attest": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          const client = attestClient(req, peerOf(req), opts.trustedProxy?.());
          if (!clientLimiter.take(client) || !attestLimiter.take()) return send(res, 429, { error: "rate limited" });
          return send(res, 200, await h.attest(url.searchParams.get("nonce") ?? ""));
        }
        default:
          return send(res, 404, { error: "not found" });
      }
    } catch (err) {
      if (err instanceof AttestError) return send(res, err.status, { error: err.message });
      if (err instanceof UsageRejected) return send(res, err.status, { error: err.message });
      if (err instanceof BootstrapError) return send(res, err.status, { error: err.message });
      if (err instanceof UnknownReservationError) return send(res, 404, { ok: false, error: err.message });
      if (err instanceof SpendBudgetError) return send(res, 400, { error: err.message });
      const status = (err as { status?: number }).status;
      if (status) return send(res, status, { error: (err as Error).message });
      log.error("api error", { route, ...errorFields(err) });
      return send(res, 500, { error: "internal error" });
    }
  });
}

export async function listen(server: http.Server, host: string, port: number): Promise<AddressInfo> {
  await new Promise<void>((ok, fail) => server.once("error", fail).listen(port, host, () => ok()));
  return server.address() as AddressInfo;
}
