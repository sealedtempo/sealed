import { createServer, request, type IncomingHttpHeaders } from 'node:http';
import { connect, type AddressInfo, type Socket } from 'node:net';

// A tiny stand-in for sealed-egress: absolute-URI HTTP proxying and CONNECT, with its own name
// resolution. Only host:port pairs in `routes` are reachable (mapped to local ports); everything
// else is refused with 403 and `X-Sealed-Egress: blocked`, as the real egress proxy refuses
// non-allowlisted destinations. Pairs in `limitOnce` first get one 429 `X-Sealed-Egress: limited`.
// Because test host names (fixture.test) resolve nowhere else, a request that reaches a fixture
// server proves it went through this proxy.

export interface ProxyLogEntry {
  method: string;
  target: string;
  allowed: boolean;
  headers: IncomingHttpHeaders;
}

export interface TestProxy {
  url: string;
  log: ProxyLogEntry[];
  close(): Promise<void>;
}

export interface TestProxyOptions {
  limitOnce?: string[];
}

export async function startTestProxy(routes: Record<string, number>, options: TestProxyOptions = {}): Promise<TestProxy> {
  const log: ProxyLogEntry[] = [];
  const sockets = new Set<Socket>();
  const lookup = (hostname: string, port: number) => routes[`${hostname}:${port}`];
  const toLimit = new Set(options.limitOnce ?? []);
  const limited = (hostname: string, port: number) => toLimit.delete(`${hostname}:${port}`);

  const server = createServer((req, res) => {
    let target: URL;
    try {
      target = new URL(req.url ?? '');
    } catch {
      res.writeHead(400).end('absolute URI required');
      return;
    }
    const port = Number(target.port || 80);
    const local = lookup(target.hostname, port);
    log.push({ method: req.method ?? 'GET', target: target.toString(), allowed: local !== undefined, headers: req.headers });
    if (local === undefined) {
      res.writeHead(403, { 'content-type': 'text/plain', 'x-sealed-egress': 'blocked' }).end('blocked by test egress');
      return;
    }
    if (limited(target.hostname, port)) {
      res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '1', 'x-sealed-egress': 'limited' }).end('slow down');
      return;
    }
    const upstream = request(
      { host: '127.0.0.1', port: local, method: req.method, path: target.pathname + target.search, headers: req.headers },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers);
        up.pipe(res);
      },
    );
    upstream.on('error', () => res.writeHead(502).end());
    req.pipe(upstream);
  });

  server.on('connect', (req, client: Socket, head: Buffer) => {
    const [hostname = '', portText = '443'] = (req.url ?? '').split(':');
    const local = lookup(hostname, Number(portText));
    log.push({ method: 'CONNECT', target: req.url ?? '', allowed: local !== undefined, headers: req.headers });
    if (local === undefined) {
      client.end('HTTP/1.1 403 Forbidden\r\nX-Sealed-Egress: blocked\r\n\r\n');
      return;
    }
    if (limited(hostname, Number(portText))) {
      client.end('HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nX-Sealed-Egress: limited\r\n\r\n');
      return;
    }
    const upstream = connect(local, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
  });

  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    log,
    close: () =>
      new Promise<void>((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}
