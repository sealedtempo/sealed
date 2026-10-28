import { getConnInfo } from '@hono/node-server/conninfo';
import type { Context, MiddlewareHandler } from 'hono';
import type { ClientPolicy } from '../client-policy.js';

export function nodeRemoteAddress(c: Context): string | undefined {
  try {
    return getConnInfo(c).remote.address;
  } catch {
    return undefined;
  }
}

// /healthz stays open: it reveals only whether Postgres answers.
const OPEN_PATHS = new Set(['/healthz']);

// Fails closed: an unknown peer address is refused.
export function clientGuard(policy: ClientPolicy, remoteAddress: (c: Context) => string | undefined = nodeRemoteAddress): MiddlewareHandler {
  return async (c, next) => {
    if (OPEN_PATHS.has(c.req.path) || policy.allows(remoteAddress(c))) return next();
    return c.req.path.startsWith('/api/')
      ? c.json({ error: { code: 'forbidden_client', message: 'this client may not use the scraper' } }, 403)
      : c.text('Forbidden', 403);
  };
}
