// Small JSON-over-HTTP helpers. External calls use fetch (which honours HTTP(S)_PROXY when
// NODE_USE_ENV_PROXY=1, so they go through sealed-egress). Calls inside the VM (dstack socket,
// Caddy admin socket, sidecars) use node:http with a private agent that never uses a proxy.
import http from "node:http";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
    url: string,
  ) {
    super(`HTTP ${status} from ${url}`);
    this.name = "HttpError";
  }
  json(): unknown {
    try {
      return JSON.parse(this.body);
    } catch {
      return undefined;
    }
  }
}

/** Retry on network errors, 429 and 5xx; not on other 4xx. */
export function isRetryable(err: unknown): boolean {
  if (err instanceof HttpError) return err.status === 429 || err.status >= 500;
  return true;
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export async function fetchJson<T = unknown>(url: string, opts: RequestOptions = {}): Promise<T> {
  const res = await fetch(url, {
    method: opts.method ?? (opts.body === undefined ? "GET" : "POST"),
    headers: { accept: "application/json", ...(opts.body !== undefined ? { "content-type": "application/json" } : {}), ...opts.headers },
    body: opts.body === undefined ? undefined : typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
    redirect: "error",
  });
  const text = await res.text();
  if (!res.ok) throw new HttpError(res.status, text.slice(0, 2000), url);
  return (text ? JSON.parse(text) : undefined) as T;
}

export type Endpoint = { socketPath: string } | { baseUrl: string };

/** Parses "unix:/path", "/path" or "http://host:port" into an Endpoint. */
export function parseEndpoint(spec: string): Endpoint {
  if (spec.startsWith("http://") || spec.startsWith("https://")) return { baseUrl: spec.replace(/\/$/, "") };
  return { socketPath: spec.startsWith("unix:") ? spec.slice(5) : spec };
}

const directAgent = new http.Agent({ keepAlive: false });

export interface LocalResponse {
  status: number;
  body: string;
}

/** HTTP/1.1 request to a unix socket or a plain-HTTP base URL, bypassing any proxy. */
export function localRequest(ep: Endpoint, path: string, opts: RequestOptions = {}): Promise<LocalResponse> {
  const payload = opts.body === undefined ? undefined : typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
  const method = opts.method ?? (payload === undefined ? "GET" : "POST");
  const headers: Record<string, string> = { host: "localhost", ...opts.headers };
  if (payload !== undefined) {
    headers["content-type"] ??= "application/json";
    headers["content-length"] = String(Buffer.byteLength(payload));
  }
  return new Promise((resolve, reject) => {
    const target =
      "socketPath" in ep
        ? { socketPath: ep.socketPath, path }
        : (() => {
            const u = new URL(path, `${ep.baseUrl}/`);
            if (u.protocol !== "http:") throw new Error("local endpoints must be plain http");
            return { hostname: u.hostname, port: u.port || 80, path: `${u.pathname}${u.search}` };
          })();
    const req = http.request({ ...target, method, headers, agent: directAgent, timeout: opts.timeoutMs ?? 30_000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error(`timeout calling ${path}`)));
    req.on("error", reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

export async function localJson<T = unknown>(ep: Endpoint, path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await localRequest(ep, path, opts);
  const where = "socketPath" in ep ? `unix:${ep.socketPath}${path}` : `${ep.baseUrl}${path}`;
  if (res.status < 200 || res.status >= 300) throw new HttpError(res.status, res.body.slice(0, 2000), where);
  return (res.body ? JSON.parse(res.body) : undefined) as T;
}
