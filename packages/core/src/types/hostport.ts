// Ports of the Go composer's address rules (runtime/composer/egress.go and config.go), so that @sealed/core refuses
// exactly the configs the composer refuses. Each function says which Go code it follows; TestConfigParity in
// runtime/composer and test/configParity.test.ts here run both over one table (runtime/composer/testdata/
// config-parity.json). Change both sides together.

/** An egress allow entry as ParseHostPort returns it. */
export interface HostPort {
  host: string;
  port: number;
  wildcard: boolean;
  ip: boolean;
}

/** An IPv4 prefix: its first address as a 32-bit number and its length. */
export interface Prefix4 {
  addr: number;
  bits: number;
}

const DNS_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_INT64 = 9223372036854775807n;

/**
 * netip.ParseAddr for strings that hold no ':' (the only kind these rules accept): four decimal fields 0 to 255
 * without leading zeros. Returns the address as an unsigned 32-bit number, undefined otherwise.
 */
export function parseIPv4(s: string): number | undefined {
  if (!/^[0-9.]+$/.test(s)) return undefined;
  const parts = s.split(".");
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const p of parts) {
    if (p === "" || p.length > 3 || (p.length > 1 && p[0] === "0")) return undefined;
    const v = Number(p);
    if (v > 255) return undefined;
    n = n * 256 + v;
  }
  return n;
}

const prefix = (a: number, b: number, c: number, d: number, bits: number): Prefix4 => ({ addr: ((a << 24) | (b << 16) | (c << 8) | d) >>> 0, bits });

/** egress.go specialIPv4: this network, loopback, link-local, CGNAT, IETF, 6to4 relay, benchmarking, multicast, reserved. */
const SPECIAL_IPV4: readonly Prefix4[] = [
  prefix(0, 0, 0, 0, 8),
  prefix(127, 0, 0, 0, 8),
  prefix(169, 254, 0, 0, 16),
  prefix(100, 64, 0, 0, 10),
  prefix(192, 0, 0, 0, 24),
  prefix(192, 88, 99, 0, 24),
  prefix(198, 18, 0, 0, 15),
  prefix(224, 0, 0, 0, 4),
  prefix(240, 0, 0, 0, 4),
];

/** The composer's VMRanges (defaults.go): every address of the VM's Docker networks. */
export const VM_RANGES = ["172.30.0.0/16", "172.31.0.0/24"] as const;
const VM_PREFIXES: readonly Prefix4[] = [prefix(172, 30, 0, 0, 16), prefix(172, 31, 0, 0, 24)];

const mask = (bits: number) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
const lastAddr = (p: Prefix4) => (p.addr | (~mask(p.bits) >>> 0)) >>> 0;

/** Prefix.Contains for IPv4. */
export function prefixContains(p: Prefix4, a: number): boolean {
  return (a & mask(p.bits)) >>> 0 === p.addr;
}

/** Prefix.Overlaps for two masked IPv4 prefixes. */
export function prefixesOverlap(a: Prefix4, b: Prefix4): boolean {
  const bits = Math.min(a.bits, b.bits);
  return (a.addr & mask(bits)) >>> 0 === (b.addr & mask(bits)) >>> 0;
}

/** netip.Addr.IsPrivate for IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918). */
export function isPrivateIPv4(a: number): boolean {
  const o0 = a >>> 24;
  const o1 = (a >>> 16) & 0xff;
  return o0 === 10 || (o0 === 172 && (o1 & 0xf0) === 16) || (o0 === 192 && o1 === 168);
}

/**
 * netip.ParsePrefix for IPv4, then the composer's allowedVpcRanges rule (config.go Validate): a canonical (masked)
 * IPv4 CIDR whose first and last addresses are private. Returns the prefix, or an error message.
 */
export function parseVpcRange(s: string): Prefix4 | string {
  const i = s.lastIndexOf("/");
  const bad = `${JSON.stringify(s)} must be a canonical private IPv4 CIDR`;
  if (i < 0) return bad;
  const addr = parseIPv4(s.slice(0, i));
  const bitsStr = s.slice(i + 1);
  if (addr === undefined || !/^(0|[1-9][0-9]*)$/.test(bitsStr)) return bad;
  const bits = Number(bitsStr);
  if (bits > 32) return bad;
  const p = { addr, bits };
  if ((addr & mask(bits)) >>> 0 !== addr || !isPrivateIPv4(addr)) return bad;
  if (!isPrivateIPv4(lastAddr(p))) return `${JSON.stringify(s)} extends beyond private address space`;
  for (const [k, vm] of VM_PREFIXES.entries()) {
    if (prefixesOverlap(p, vm)) return `${JSON.stringify(s)} overlaps the VM's internal networks ${VM_RANGES[k]}`;
  }
  return p;
}

/**
 * egress.go ParseHostPortIn: an exact lowercase DNS name of at least two labels, a one-label wildcard (*.example.com)
 * or a public unicast IPv4 literal (a private one only inside `privateRanges`), then a port 1 to 65535 without
 * leading zeros. Returns the parsed entry, or an error message.
 */
export function parseHostPortIn(s: string, privateRanges: readonly Prefix4[] = []): HostPort | string {
  const q = JSON.stringify(s);
  const i = s.lastIndexOf(":");
  if (i <= 0 || i === s.length - 1) return `${q} must be host:port`;
  const host = s.slice(0, i);
  const portStr = s.slice(i + 1);
  // strconv.Atoi accepts a sign; Itoa(port) == portStr then refuses it and leading zeros.
  const port = /^[+-]?[0-9]+$/.test(portStr) ? Number(portStr) : Number.NaN;
  if (!Number.isInteger(port) || port < 1 || port > 65535 || String(port) !== portStr) return `${q} has an invalid port`;
  if (/[[\]:]/.test(host)) return `${q}: IPv6 destinations are not supported`;
  const addr = parseIPv4(host);
  if (addr !== undefined) {
    for (const p of SPECIAL_IPV4) if (prefixContains(p, addr)) return `${q}: ${host} is a special-use address`;
    if (isPrivateIPv4(addr) && !privateRanges.some((p) => prefixContains(p, addr))) return `${q}: private address ${host} is allowed only inside allowedVpcRanges`;
    return { host, port, wildcard: false, ip: true };
  }
  const wildcard = host.startsWith("*.");
  const name = wildcard ? host.slice(2) : host;
  // Go measures bytes; a non-ASCII name fails the label rule below either way.
  if (name.length > 253) return `${q}: host name too long`;
  const labels = name.split(".");
  if (labels.length < 2) return `${q}: host must be a fully qualified name with at least two labels`;
  for (const l of labels) if (!DNS_LABEL.test(l)) return `${q}: invalid host label ${JSON.stringify(l)} (lowercase letters, digits and hyphens only)`;
  // strconv.Atoi succeeds only within int64, so a longer all-digit label is not "numeric" to Go.
  const tld = labels[labels.length - 1] as string;
  if (/^[0-9]+$/.test(tld) && BigInt(tld) <= MAX_INT64) return `${q}: numeric top-level label`;
  return { host, port, wildcard, ip: false };
}

/** ParseHostPort: ParseHostPortIn without private ranges. */
export function parseHostPort(s: string): HostPort | string {
  return parseHostPortIn(s, []);
}

/** The parts of a Go url.URL these rules read. */
export interface GoURL {
  /** Lowercased, as url.Parse stores it. */
  scheme: string;
  opaque: string;
  hasUser: boolean;
  /** host[:port] as written (the rules refuse every host that url.Parse would unescape). */
  host: string;
  /** The unescaped path, as UTF-8 bytes read one per character (only compared with ASCII strings). */
  path: string;
  rawQuery: string;
  forceQuery: boolean;
  /** The unescaped fragment. */
  fragment: string;
}

const isHex = (c: string | undefined) => c !== undefined && /^[0-9A-Fa-f]$/.test(c);

/** url.unescape in path and fragment mode: every % starts a two-digit hex escape. Undefined on a bad escape. */
function unescapePath(s: string): string | undefined {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (c !== "%") {
      out += c;
      continue;
    }
    if (!isHex(s[i + 1]) || !isHex(s[i + 2])) return undefined;
    out += String.fromCharCode(Number.parseInt(s.slice(i + 1, i + 3), 16));
    i += 2;
  }
  return out;
}

/**
 * net/url.Parse as Go 1.27 does it, for what the endpoint rules read. Returns undefined where url.Parse returns an
 * error, and for any host that url.Parse would accept only to have ParseHostPort refuse it (brackets, '%'), which
 * the endpoint rules refuse either way.
 */
export function goParseURL(raw: string): GoURL | undefined {
  const hash = raw.indexOf("#");
  const beforeFrag = hash < 0 ? raw : raw.slice(0, hash);
  const rawFrag = hash < 0 ? "" : raw.slice(hash + 1);
  // stringContainsCTLByte runs on the part before '#' only.
  for (let i = 0; i < beforeFrag.length; i++) {
    const c = beforeFrag.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return undefined;
  }
  // getScheme
  let scheme = "";
  let rest = beforeFrag;
  for (let i = 0; i < beforeFrag.length; i++) {
    const c = beforeFrag[i] as string;
    if (/[A-Za-z]/.test(c)) continue;
    if (/[0-9+.-]/.test(c)) {
      if (i === 0) break;
      continue;
    }
    if (c === ":") {
      if (i === 0) return undefined; // missing protocol scheme
      scheme = beforeFrag.slice(0, i).toLowerCase();
      rest = beforeFrag.slice(i + 1);
    }
    break;
  }
  let rawQuery = "";
  let forceQuery = false;
  if (rest.endsWith("?") && rest.split("?").length === 2) {
    forceQuery = true;
    rest = rest.slice(0, -1);
  } else {
    const q = rest.indexOf("?");
    if (q >= 0) {
      rawQuery = rest.slice(q + 1);
      rest = rest.slice(0, q);
    }
  }
  const url: GoURL = { scheme, opaque: "", hasUser: false, host: "", path: "", rawQuery, forceQuery, fragment: "" };
  if (!rest.startsWith("/")) {
    if (scheme !== "") {
      url.opaque = rest;
      return withFragment(url, rawFrag);
    }
    // A relative reference whose first segment holds a colon is an error in Go.
    if ((rest.split("/")[0] as string).includes(":")) return undefined;
  }
  if (rest.startsWith("//") && (scheme !== "" || !rest.startsWith("///"))) {
    let authority = rest.slice(2);
    rest = "";
    const slash = authority.indexOf("/");
    if (slash >= 0) {
      rest = authority.slice(slash);
      authority = authority.slice(0, slash);
    }
    let hostPart = authority;
    const at = authority.lastIndexOf("@");
    if (at >= 0) {
      url.hasUser = true;
      hostPart = authority.slice(at + 1);
    }
    // parseHost: a '[' starts an IPv6 literal (refused by ParseHostPort) or is an error; '%' can only escape bytes
    // that no DNS label holds. Either way no endpoint rule accepts the host.
    if (hostPart.includes("[") || hostPart.includes("%")) return undefined;
    const colon = hostPart.indexOf(":");
    if (colon >= 0 && !/^:[0-9]*$/.test(hostPart.slice(colon))) return undefined;
    url.host = hostPart;
  }
  const path = unescapePath(rest);
  if (path === undefined) return undefined;
  url.path = path;
  return withFragment(url, rawFrag);
}

function withFragment(url: GoURL, rawFrag: string): GoURL | undefined {
  if (rawFrag === "") return url;
  const f = unescapePath(rawFrag);
  if (f === undefined) return undefined;
  url.fragment = f;
  return url;
}

/** url.URL.Hostname and Port: split host[:port] at a last ':' followed by digits only. */
export function splitHostPort(hostPort: string): [host: string, port: string] {
  const colon = hostPort.lastIndexOf(":");
  if (colon >= 0 && /^:[0-9]*$/.test(hostPort.slice(colon))) return [hostPort.slice(0, colon), hostPort.slice(colon + 1)];
  return [hostPort, ""];
}

/**
 * egress.go endpointHostPort: an https URL without credentials whose host is one exact name or public IPv4 address
 * (port 443 by default). Returns the egress allow entry, or an error message.
 */
export function endpointHostPort(raw: string): string | { error: string } {
  const q = JSON.stringify(raw);
  const u = goParseURL(raw);
  if (u === undefined) return { error: `${q} is not a valid URL` };
  if (u.scheme !== "https" || u.opaque !== "" || u.host === "") return { error: `${q} must be an https URL` };
  if (u.hasUser) return { error: "credentials in URLs are not allowed" };
  const [host, port] = splitHostPort(u.host);
  const entry = `${host}:${port === "" ? "443" : port}`;
  const hp = parseHostPort(entry);
  if (typeof hp === "string") return { error: hp };
  if (hp.wildcard) return { error: `${q} must name one host, not a wildcard` };
  return entry;
}

/**
 * The dev-sim form of an endpoint (SEALED_DEV_SIM=1 only, never a production stack): http or https, any host name
 * or address including loopback, an optional numeric port, no credentials. Local tests run their fake key broker,
 * platform and RPC on http://127.0.0.1.
 */
export function devEndpoint(raw: string): string | { error: string } {
  const q = JSON.stringify(raw);
  const u = goParseURL(raw);
  if (u === undefined || (u.scheme !== "https" && u.scheme !== "http") || u.opaque !== "" || u.host === "") return { error: `${q} must be an http or https URL` };
  if (u.hasUser) return { error: "credentials in URLs are not allowed" };
  const [host, port] = splitHostPort(u.host);
  if (!/^[A-Za-z0-9.-]+$/.test(host) || (port !== "" && !(Number(port) >= 1 && Number(port) <= 65535))) return { error: `${q} has an invalid host or port` };
  return `${host}:${port === "" ? (u.scheme === "https" ? "443" : "80") : port}`;
}
