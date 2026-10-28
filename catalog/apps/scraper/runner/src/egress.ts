// How sealed-egress refusals reach the crawler, and how they are reported. sealed-egress answers a
// destination that is not allowlisted with 403 and a caller over its rate with 429, both marked
// with an X-Sealed-Egress header (blocked, limited, auth-required). For https targets the answer
// arrives as a failed CONNECT, for http targets as an ordinary response.

export type EgressVerdict = 'blocked' | 'limited';

export const EGRESS_HEADER = 'x-sealed-egress';

export function egressVerdictFromHeader(value: string | string[] | undefined | null): EgressVerdict | null {
  const v = (Array.isArray(value) ? value[0] : value)?.trim().toLowerCase();
  if (!v) return null;
  return v === 'limited' ? 'limited' : 'blocked';
}

// got-scraping reports a refused CONNECT as "Proxy responded with 403 Forbidden"; Firefox reports
// NS_ERROR_PROXY_* navigation errors.
const PROXY_STATUS = /Proxy responded with (\d{3})/;
const FIREFOX_BLOCKED = /NS_ERROR_PROXY_(FORBIDDEN|AUTHENTICATION_FAILED)/;
const FIREFOX_LIMITED = /NS_ERROR_PROXY_TOO_MANY_REQUESTS/;

export function egressVerdictFromError(error: Error): EgressVerdict | null {
  const message = error.message ?? '';
  const status = PROXY_STATUS.exec(message)?.[1];
  if (status === '403' || status === '407') return 'blocked';
  if (status === '429') return 'limited';
  if (FIREFOX_BLOCKED.test(message)) return 'blocked';
  if (FIREFOX_LIMITED.test(message)) return 'limited';
  return null;
}

export function hostPort(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname}:${u.port || (u.protocol === 'https:' ? '443' : '80')}`;
  } catch {
    return url;
  }
}

export function egressMessage(verdict: EgressVerdict, url: string): string {
  return verdict === 'limited'
    ? 'rate limited by sealed-egress'
    : `blocked by sealed-egress: ${hostPort(url)} is not in egressAdditions.scraper`;
}
