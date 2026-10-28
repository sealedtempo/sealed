package policy

import (
	"fmt"
	"net/netip"
)

// IPClass says what kind of destination an address is.
type IPClass int

const (
	ClassPublic IPClass = iota
	// ClassPrivate covers RFC 1918, CGNAT (100.64/10) and IPv6 ULA (fc00::/7).
	// These are denied unless allowedPrivateCidrs lists them.
	ClassPrivate
	// The remaining classes are denied always.
	ClassMetadata
	ClassLoopback
	ClassLinkLocal
	ClassUnspecified
	ClassMulticast
	ClassIPv4Embedded // NAT64, 6to4, Teredo: they can carry any IPv4, metadata included
	ClassReserved
)

func (c IPClass) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassPrivate:
		return "private"
	case ClassMetadata:
		return "metadata"
	case ClassLoopback:
		return "loopback"
	case ClassLinkLocal:
		return "link-local"
	case ClassUnspecified:
		return "unspecified"
	case ClassMulticast:
		return "multicast"
	case ClassIPv4Embedded:
		return "ipv4-embedding"
	case ClassReserved:
		return "reserved"
	}
	return fmt.Sprintf("class(%d)", int(c))
}

// Metadata server addresses: GCE/AWS IPv4, GCE IPv6, AWS IPv6.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd20:ce::254"),
	netip.MustParseAddr("fd00:ec2::254"),
}

type classRange struct {
	prefix netip.Prefix
	class  IPClass
}

func mustPrefixes(class IPClass, cidrs ...string) []classRange {
	out := make([]classRange, len(cidrs))
	for i, c := range cidrs {
		out[i] = classRange{netip.MustParsePrefix(c), class}
	}
	return out
}

// Checked in order; first match wins. Addresses that match nothing are public.
var classRanges = concat(
	mustPrefixes(ClassUnspecified, "0.0.0.0/8", "::/128"),
	mustPrefixes(ClassLoopback, "127.0.0.0/8", "::1/128"),
	mustPrefixes(ClassLinkLocal, "169.254.0.0/16", "fe80::/10"),
	mustPrefixes(ClassMulticast, "224.0.0.0/4", "ff00::/8"),
	mustPrefixes(ClassReserved, "240.0.0.0/4"),
	mustPrefixes(ClassPrivate, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"),
	mustPrefixes(ClassIPv4Embedded, "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"),
	// IPv6 outside 2000::/3 global unicast that is not listed above
	// (IPv4-compatible ::/96, discard 100::/64, site-local fec0::/10, unallocated space).
	mustPrefixes(ClassReserved, "::/3", "4000::/2", "8000::/2", "c000::/3", "e000::/4", "f000::/5", "f800::/6", "fe00::/9", "fec0::/10"),
)

func concat(lists ...[]classRange) []classRange {
	var out []classRange
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// Classify returns the class of ip. IPv4-mapped IPv6 addresses are classified
// as the IPv4 address they carry.
func Classify(ip netip.Addr) IPClass {
	if !ip.IsValid() {
		return ClassReserved
	}
	ip = ip.Unmap().WithZone("")
	for _, m := range metadataAddrs {
		if ip == m {
			return ClassMetadata
		}
	}
	for _, r := range classRanges {
		if r.prefix.Contains(ip) {
			return r.class
		}
	}
	return ClassPublic
}

// allowablePrivateRanges are the only ranges allowedPrivateCidrs may open.
var allowablePrivateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// IPPolicy decides whether a resolved destination address may be dialed.
type IPPolicy struct {
	allowedPrivate []netip.Prefix
}

// NewIPPolicy builds a policy from already validated private CIDRs.
func NewIPPolicy(allowedPrivate []netip.Prefix) IPPolicy {
	return IPPolicy{allowedPrivate: append([]netip.Prefix(nil), allowedPrivate...)}
}

// Check returns nil if ip may be dialed, or an error naming why not.
func (p IPPolicy) Check(ip netip.Addr) error {
	ip = ip.Unmap().WithZone("")
	switch class := Classify(ip); class {
	case ClassPublic:
		return nil
	case ClassPrivate:
		for _, pfx := range p.allowedPrivate {
			if pfx.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("destination %s is a private address not in allowedPrivateCidrs", ip)
	default:
		return fmt.Errorf("destination %s is a %s address", ip, class)
	}
}

// AllowedPrivate returns the private prefixes this policy opens.
func (p IPPolicy) AllowedPrivate() []netip.Prefix {
	return append([]netip.Prefix(nil), p.allowedPrivate...)
}

// AlwaysDeniedPrefixes lists ranges that are never dialable whatever the
// config says. The proxy hands them to smokescreen as explicit deny rules.
func AlwaysDeniedPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, m := range metadataAddrs {
		out = append(out, netip.PrefixFrom(m, m.BitLen()))
	}
	for _, r := range classRanges {
		if r.class != ClassPrivate {
			out = append(out, r.prefix)
		}
	}
	return out
}

func validateAllowedPrivateCIDR(s string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
	}
	if pfx.Masked() != pfx || pfx.String() != s {
		return netip.Prefix{}, fmt.Errorf("CIDR %q is not in canonical form (want %q)", s, pfx.Masked().String())
	}
	if pfx.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("CIDR %q must be written as plain IPv4", s)
	}
	for _, allowed := range allowablePrivateRanges {
		if allowed.Bits() <= pfx.Bits() && allowed.Contains(pfx.Addr()) {
			return pfx, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("CIDR %q is not inside a private range (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)", s)
}
