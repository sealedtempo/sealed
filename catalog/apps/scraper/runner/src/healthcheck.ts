// Container healthcheck: exits 0 when /healthz answers 200. `agent: false` keeps the probe off the
// env proxy that NODE_USE_ENV_PROXY installs on the global agent.
import { request } from 'node:http';

const port = Number(process.env.PORT ?? 8080);
const req = request({ host: '127.0.0.1', port, path: '/healthz', method: 'GET', agent: false, timeout: 4_000 }, (res) => {
  res.resume();
  process.exit(res.statusCode === 200 ? 0 : 1);
});
req.on('timeout', () => req.destroy(new Error('timeout')));
req.on('error', () => process.exit(1));
req.end();
