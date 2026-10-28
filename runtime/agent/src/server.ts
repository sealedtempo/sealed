// sealed-agent local API on :7070 (INTERFACES 11). Reachable on the apps network only; Caddy
// exposes /attest publicly. Callers are identified by their fixed apps-network IP (the composer pins
// every service's address), which the handlers check for usage events and spend counters.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type UsageEvent, usageEventSchema } from "@sealed/core";
import { AttestError, ClientRateLimiter, RateLimiter } from "./attest.js";
import { errorFields, type Logger } from "./log.js";
import { normalizePeer } from "./stack.js";

export interface ApiHandlers {
  isReady(): boolean;
  readyInfo(): Record<string, unknown>;
  recordUsage(ev: UsageEvent, peer: string): Promise<"accepted" | "duplicate">;
  recordSpend(body: unknown, peer: string): void;
  attest(nonce: string): Promise<unknown>;
}

/** A request the caller may not make (403) or whose content is refused (422 / 429 / 400). */
export class UsageRejected extends Error {
  constructor(
    message: string,
    readonly status: 400 | 403 | 422 | 429 = 422,
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

function send(res: http.ServerResponse, status: number, body: unknown): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
  });
  res.end(text);
}

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
