// A fake Caddy admin API on a unix socket: GET /config/ and POST /load.
import { serve, type TestServer } from "./http.js";

export interface FakeCaddy extends TestServer {
  config: unknown;
  loads: number;
}

export async function startFakeCaddy(socket: string, initial: unknown): Promise<FakeCaddy> {
  const rec = { config: structuredClone(initial), loads: 0 };
  const server = await serve(
    (req, body) => {
      if (req.method === "GET" && req.url === "/config/") return { status: 200, body: rec.config };
      if (req.method === "POST" && req.url === "/load") {
        rec.config = JSON.parse(body);
        rec.loads++;
        return { status: 200 };
      }
      return { status: 404, body: { error: "not found" } };
    },
    { socket },
  );
  return Object.assign(rec, server);
}

/** A Caddyfile-adapter-shaped config with app routes and the public attest route. */
export function sampleCaddyConfig(ipDashes: string) {
  const host = (r: string) => `${r}.${ipDashes}.sslip.io`;
  const proxy = (upstream: string) => ({ handler: "subroute", routes: [{ handle: [{ handler: "reverse_proxy", upstreams: [{ dial: upstream }] }] }] });
  return {
    admin: { listen: "unix//run/caddy-admin/admin.sock" },
    apps: {
      http: {
        servers: {
          srv0: {
            listen: [":443"],
            routes: [
              { match: [{ host: [host("crm")] }], handle: [proxy("crm-server:3000")], terminal: true },
              { match: [{ host: [host("gateway")] }], handle: [proxy("llm-gateway:4000")], terminal: true },
              { match: [{ host: [host("attest")] }], handle: [proxy("sealed-agent:7070")], terminal: true },
            ],
          },
        },
      },
    },
  };
}
