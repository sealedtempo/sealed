import type { MiddlewareHandler } from 'hono';
import { secureHeaders } from 'hono/secure-headers';

// The UI renders scraped text, so it is served with a strict CSP: no scripts at all, styles only
// from our own stylesheet, forms only back to this origin, never framed.
export const pageSecurity = secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'none'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    baseUri: ["'none'"],
  },
  referrerPolicy: 'no-referrer',
  crossOriginResourcePolicy: 'same-origin',
  strictTransportSecurity: false,
});

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// The UI sits behind Sealed's gate (Caddy forward_auth to sealed-agent). A browser that logged in
// to the gate keeps sending its cached Basic credentials, also on requests another site starts, so
// the gate alone does not stop cross-site form posts. Refuse state-changing requests that a browser
// marks as cross-site or whose Origin is not this app's: exactly publicOrigin when it is known
// (SEALED_PUBLIC_URL_SCRAPER), otherwise the request's host. Clients that send neither header
// (curl, scripts) are unaffected.
export function sameOriginGuard(publicOrigin?: string): MiddlewareHandler {
  return async (c, next) => {
    if (SAFE_METHODS.has(c.req.method)) return next();
    const site = c.req.header('sec-fetch-site');
    if (site && site !== 'same-origin' && site !== 'none') {
      return c.json({ error: { code: 'cross_site', message: 'cross-site request refused' } }, 403);
    }
    const origin = c.req.header('origin');
    if (origin && publicOrigin) {
      if (origin !== publicOrigin) return c.json({ error: { code: 'cross_site', message: 'cross-site request refused' } }, 403);
    } else if (origin) {
      const host = c.req.header('x-forwarded-host') ?? c.req.header('host');
      let originHost: string | null = null;
      try {
        originHost = origin === 'null' ? null : new URL(origin).host;
      } catch {
        originHost = null;
      }
      if (!host || originHost !== host) {
        return c.json({ error: { code: 'cross_site', message: 'cross-site request refused' } }, 403);
      }
    }
    return next();
  };
}
