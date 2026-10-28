import http from "node:http";
import type { AddressInfo } from "node:net";

export type Handler = (req: http.IncomingMessage, body: string) => Promise<{ status: number; body?: unknown }> | { status: number; body?: unknown };

export interface TestServer {
  url: string;
  close(): Promise<void>;
}

/** Minimal JSON HTTP server on 127.0.0.1 (or a unix socket) for fakes. */
export async function serve(handler: Handler, opts: { socket?: string } = {}): Promise<TestServer> {
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    try {
      const out = await handler(req, Buffer.concat(chunks).toString("utf8"));
      const text = out.body === undefined ? "" : JSON.stringify(out.body);
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(text);
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: (err as Error).message }));
    }
  });
  if (opts.socket) await new Promise<void>((ok) => server.listen(opts.socket, () => ok()));
  else await new Promise<void>((ok) => server.listen(0, "127.0.0.1", () => ok()));
  const url = opts.socket ? opts.socket : `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url,
    close: () =>
      new Promise<void>((ok) => {
        server.close(() => ok());
        server.closeAllConnections();
      }),
  };
}
