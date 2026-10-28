// Ports and small HTTP helpers. Ports are chosen by the OS (bind to port 0) and held until every port of the run
// is chosen, so two components never get the same one.
import { createServer, type Server } from "node:net";

export async function freePorts(n: number, host = "127.0.0.1"): Promise<number[]> {
  const servers: Server[] = [];
  const ports: number[] = [];
  try {
    for (let i = 0; i < n; i++) {
      const srv = createServer();
      servers.push(srv);
      await new Promise<void>((ok, fail) => {
        srv.once("error", fail);
        srv.listen(0, host, () => ok());
      });
      const addr = srv.address();
      if (!addr || typeof addr !== "object") throw new Error("no port");
      ports.push(addr.port);
    }
  } finally {
    await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  }
  return ports;
}

export interface HttpResult<T = unknown> {
  status: number;
  body: T;
  text: string;
  headers: Headers;
}

export async function http<T = unknown>(
  url: string,
  o: { method?: string; body?: unknown; headers?: Record<string, string>; timeoutMs?: number } = {},
): Promise<HttpResult<T>> {
  const headers: Record<string, string> = { ...o.headers };
  let body: string | undefined;
  if (o.body !== undefined) {
    body = typeof o.body === "string" ? o.body : JSON.stringify(o.body);
    headers["content-type"] ??= "application/json";
  }
  const res = await fetch(url, { method: o.method ?? (body === undefined ? "GET" : "POST"), headers, body, signal: AbortSignal.timeout(o.timeoutMs ?? 30_000) });
  const text = await res.text();
  let parsed: unknown = text;
  try {
    parsed = text === "" ? undefined : JSON.parse(text);
  } catch {
    // not JSON
  }
  return { status: res.status, body: parsed as T, text, headers: res.headers };
}

/** True once a GET answers (any status). */
export async function answers(url: string): Promise<boolean> {
  try {
    await fetch(url, { signal: AbortSignal.timeout(2000) });
    return true;
  } catch {
    return false;
  }
}
