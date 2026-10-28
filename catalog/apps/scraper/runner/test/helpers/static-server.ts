import { readFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { extname, join, normalize, resolve } from 'node:path';

export type Override = (req: IncomingMessage, res: ServerResponse) => void;

export interface StaticServer {
  port: number;
  hits: string[];
  close(): Promise<void>;
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

// Serves a directory the way the platform VM serves the fixture site: "/" and "dir/" map to
// index.html, anything else is a file or 404. `overrides` replace single paths (for robots tests).
export async function startStaticServer(root: string, overrides: Record<string, Override> = {}): Promise<StaticServer> {
  const base = resolve(root);
  const hits: string[] = [];
  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    hits.push(path);
    const override = overrides[path];
    if (override) return override(req, res);
    let rel = normalize(decodeURIComponent(path));
    if (rel.endsWith('/')) rel += 'index.html';
    const file = join(base, rel);
    if (!file.startsWith(base)) {
      res.writeHead(400).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(body);
    } catch {
      res.writeHead(404, { 'content-type': 'text/html' }).end('<h1>Not found</h1>');
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: (server.address() as AddressInfo).port,
    hits,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
