// A fake Caddy admin API on a unix socket: POST /load with a Caddyfile (Content-Type text/caddyfile).
// Like Caddy, a load whose content equals the running config is accepted without a reload.
import { serve, type TestServer } from "./http.js";

export interface FakeCaddy extends TestServer {
  /** The Caddyfile currently running. */
  current: string;
  /** Loads that changed the running config. */
  reloads: number;
  /** Every /load request, including no-op ones. */
  loads: number;
  contentTypes: string[];
  failNext: number;
}

export async function startFakeCaddy(socket: string, initial: string): Promise<FakeCaddy> {
  const rec = { current: initial, reloads: 0, loads: 0, contentTypes: [] as string[], failNext: 0 };
  const server = await serve(
    (req, body) => {
      if (req.method === "POST" && req.url === "/load") {
        rec.loads++;
        rec.contentTypes.push(String(req.headers["content-type"]));
        if (rec.failNext > 0) {
          rec.failNext--;
          return { status: 500, body: { error: "adapt failed" } };
        }
        if (req.headers["content-type"] !== "text/caddyfile") return { status: 400, body: { error: "unsupported content type" } };
        if (body !== rec.current) {
          rec.current = body;
          rec.reloads++;
        }
        return { status: 200 };
      }
      return { status: 404, body: { error: "not found" } };
    },
    { socket },
  );
  return Object.assign(rec, server);
}
