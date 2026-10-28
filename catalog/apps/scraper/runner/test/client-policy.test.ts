import { describe, expect, it } from 'vitest';
import { ClientListError, DEFAULT_ALLOWED_CLIENTS, normalizeAddress, parseAllowedClients } from '../src/client-policy.js';

describe('parseAllowedClients', () => {
  it('allows only Caddy and loopback by default', () => {
    const policy = parseAllowedClients(DEFAULT_ALLOWED_CLIENTS);
    expect(policy.allows('172.30.0.4')).toBe(true);
    expect(policy.allows('::ffff:172.30.0.4')).toBe(true);
    expect(policy.allows('127.0.0.1')).toBe(true);
    expect(policy.allows('::1')).toBe(true);
    // Other apps on the apps network, the egress proxy and the agent.
    for (const peer of ['172.30.0.2', '172.30.0.3', '172.30.0.5', '172.30.0.16', '172.30.0.40', '10.0.0.4']) {
      expect(policy.allows(peer), peer).toBe(false);
    }
  });

  it('fails closed on unknown or malformed peers', () => {
    const policy = parseAllowedClients(DEFAULT_ALLOWED_CLIENTS);
    expect(policy.allows(undefined)).toBe(false);
    expect(policy.allows('')).toBe(false);
    expect(policy.allows('caddy')).toBe(false);
  });

  it('takes addresses and CIDR ranges of both families', () => {
    const policy = parseAllowedClients(' 172.30.0.4 , 10.1.0.0/16, fd00::/8 ');
    expect(policy.entries).toEqual(['172.30.0.4', '10.1.0.0/16', 'fd00::/8']);
    expect(policy.allows('10.1.200.3')).toBe(true);
    expect(policy.allows('10.2.0.1')).toBe(false);
    expect(policy.allows('fd12::1')).toBe(true);
    expect(policy.allows('127.0.0.1')).toBe(false);
  });

  it('rejects entries that are not addresses or ranges', () => {
    for (const bad of ['', ' , ', 'caddy', '172.30.0.4/33', '172.30.0.4/x', '::1/129', '10.0.0.0/8/1']) {
      expect(() => parseAllowedClients(bad), bad).toThrow(ClientListError);
    }
  });
});

describe('normalizeAddress', () => {
  it('unwraps IPv4-mapped addresses and drops zone ids', () => {
    expect(normalizeAddress('::FFFF:172.30.0.4')).toBe('172.30.0.4');
    expect(normalizeAddress('fe80::1%eth0')).toBe('fe80::1');
    expect(normalizeAddress('FD00::1')).toBe('fd00::1');
  });
});
