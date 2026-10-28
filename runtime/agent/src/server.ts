// sealed-agent local API on :7070 (INTERFACES 11). Reachable on the apps network only; Caddy
// exposes /attest publicly.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type UsageEvent, usageEventSchema } from "@sealed/core";
import { AttestError, RateLimiter } from "./attest.js";
import { errorFields, type Logger } from "./log.js";

export interface ApiHandlers {
  isReady(): boolean;
  readyInfo(): Record<string, unknown>;
  recordUsage(ev: UsageEvent): Promise<"accepted" | "duplicate">;
  recordSpend(body: Record<string, unknown>): void;
  attest(nonce: string): Promise<unknown>;
}

export class UsageRejected extends Error {}

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

export function createApiServer(h: ApiHandlers, log: Logger, attestLimiter = new RateLimiter(5, 20)): http.Server {
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
          const result = await h.recordUsage(parsed.data);
          return send(res, 202, { status: result });
        }
        case "POST /v1/spend": {
          const body = await readJson(req);
          if (!body || typeof body !== "object" || Array.isArray(body)) return send(res, 400, { error: "expected an object" });
          h.recordSpend(body as Record<string, unknown>);
          return send(res, 204, "");
        }
        case "GET /attest": {
          if (!h.isReady()) return send(res, 503, { error: "not ready" });
          if (!attestLimiter.take()) return send(res, 429, { error: "rate limited" });
          return send(res, 200, await h.attest(url.searchParams.get("nonce") ?? ""));
        }
        default:
          return send(res, 404, { error: "not found" });
      }
    } catch (err) {
      if (err instanceof AttestError) return send(res, err.status, { error: err.message });
      if (err instanceof UsageRejected) return send(res, 422, { error: err.message });
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
