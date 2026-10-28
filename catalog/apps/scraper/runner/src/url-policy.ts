import { BlockList, isIP } from 'node:net';

// First line of defence against crawling the VM's own network. sealed-egress enforces the real
// allowlist and IP range rules; this check gives early, readable errors and stops Firefox from
// trying loopback or link-local addresses at all. With SCRAPER_ALLOW_NO_PROXY=1 (local
// development only) it is the only check.

const blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv4');
}
// IPv6 ranges that are local themselves or carry an IPv4 address a gateway may unwrap.
for (const [net, prefix] of [
  ['::', 96], // unspecified, loopback and IPv4-compatible (::a.b.c.d)
  ['::ffff:0:0:0', 96], // IPv4-translated (SIIT)
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001::', 32], // Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['fec0::', 10], // site-local (deprecated)
  ['ff00::', 8], // multicast
] as const) {
  blocked.addSubnet(net, prefix, 'ipv6');
}

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];

export function checkTargetUrl(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'is not a valid URL';
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'must use http or https';
  if (url.username || url.password) return 'must not contain credentials';

  // "localhost." and "sealed-agent." name the same hosts as without the dot.
  const host = url.hostname.toLowerCase().replace(/\.+$/, '');
  if (!host) return 'is not a valid URL';
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  const family = isIP(bare);
  if (family === 4 || family === 6) {
    // BlockList treats every IPv4 address as inside ::ffff:0:0/96, so mapped addresses are refused here.
    if (family === 6 && bare.startsWith('::ffff:')) return 'must not target a private, loopback or link-local address';
    return blocked.check(bare, family === 4 ? 'ipv4' : 'ipv6') ? 'must not target a private, loopback or link-local address' : null;
  }
  if (host === 'localhost' || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return 'must not target a local or internal name';
  if (!host.includes('.')) return 'must use a fully qualified host name';
  return null;
}
