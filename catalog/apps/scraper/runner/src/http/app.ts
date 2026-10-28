import { Hono } from 'hono';
import { errorMessage, silentLogger } from '../log.js';
import { apiRoutes } from './api.js';
import { DEFAULT_ALLOWED_CLIENTS, parseAllowedClients } from '../client-policy.js';
import { clientGuard } from './clients.js';
import type { AppDeps } from './deps.js';
import { pageSecurity, sameOriginGuard } from './security.js';
import { notFoundPage, uiRoutes } from './ui.js';

export function createApp(deps: AppDeps): Hono {
  const log = deps.log ?? silentLogger;
  const app = new Hono();

  app.use('*', pageSecurity);
  app.use('*', clientGuard(deps.clients ?? parseAllowedClients(DEFAULT_ALLOWED_CLIENTS), deps.remoteAddress));
  app.use('*', sameOriginGuard(deps.publicOrigin));

  app.get('/healthz', async (c) => {
    try {
      await deps.store.ping();
      return c.json({ status: 'ok', crawlers: deps.crawlers });
    } catch {
      return c.json({ status: 'unavailable' }, 503);
    }
  });

  app.route('/api/v1', apiRoutes(deps));
  app.route('/', uiRoutes(deps));

  app.notFound((c) =>
    c.req.path.startsWith('/api/')
      ? c.json({ error: { code: 'not_found', message: 'no such endpoint' } }, 404)
      : c.html(notFoundPage(), 404),
  );

  app.onError((err, c) => {
    log.error('request failed', { method: c.req.method, path: c.req.routePath, error: errorMessage(err) });
    return c.req.path.startsWith('/api/')
      ? c.json({ error: { code: 'internal', message: 'internal error' } }, 500)
      : c.text('Internal error', 500);
  });

  return app;
}
