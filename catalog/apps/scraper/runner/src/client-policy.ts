import { BlockList, isIP } from 'node:net';

// Who may call the runner, by socket peer address. In the VM the only client is Caddy, at the fixed
// apps-network address 172.30.0.4 (INTERFACES 6), which enforces the password gate. Any other
// container on the apps network is refused, so none can skip the gate, read results or use the
// scraper to reach sites its own egress rules do not allow. Loopback is for local development.

export const DEFAULT_ALLOWED_CLIENTS = '172.30.0.4,127.0.0.1,::1';

export class ClientListError extends Error {}

export interface ClientPolicy {
  allows(address: string | undefined): boolean;
  readonly entries: readonly string[];
}

// "::ffff:172.30.0.4" (a dual-stack listener) and "fe80::1%eth0" compare as the plain address.
export function normalizeAddress(address: string): string {
  const bare = address.replace(/%.*$/, '');
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(bare);
  return mapped ? mapped[1]! : bare.toLowerCase();
}

export function parseAllowedClients(list: string): ClientPolicy {
  const blockList = new BlockList();
  const entries = list
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
  if (entries.length === 0) throw new ClientListError('must list at least one address');
  for (const entry of entries) {
    const [address = '', prefixText, extra] = entry.split('/');
    const family = isIP(address);
    if (family === 0 || extra !== undefined) throw new ClientListError(`${entry} is not an IP address or CIDR range`);
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (prefixText === undefined) {
      blockList.addAddress(address, type);
      continue;
    }
    const prefix = Number(prefixText);
    if (!/^\d+$/.test(prefixText) || prefix > (family === 4 ? 32 : 128)) throw new ClientListError(`${entry} has an invalid prefix length`);
    blockList.addSubnet(address, prefix, type);
  }
  return {
    entries,
    allows(address) {
      if (!address) return false;
      const normalized = normalizeAddress(address);
      const family = isIP(normalized);
      if (family === 0) return false;
      return blockList.check(normalized, family === 4 ? 'ipv4' : 'ipv6');
    },
  };
}
