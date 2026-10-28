package policy

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]IPClass{
		"8.8.8.8":                ClassPublic,
		"203.0.113.10":           ClassPublic,
		"2606:4700::1111":        ClassPublic,
		"169.254.169.254":        ClassMetadata,
		"::ffff:169.254.169.254": ClassMetadata,
		"fd20:ce::254":           ClassMetadata,
		"fd00:ec2::254":          ClassMetadata,
		"169.254.1.1":            ClassLinkLocal,
		"fe80::1":                ClassLinkLocal,
		"127.0.0.1":              ClassLoopback,
		"127.255.255.254":        ClassLoopback,
		"::1":                    ClassLoopback,
		"::ffff:127.0.0.1":       ClassLoopback,
		"0.0.0.0":                ClassUnspecified,
		"0.1.2.3":                ClassUnspecified,
		"::":                     ClassUnspecified,
		"10.0.0.5":               ClassPrivate,
		"172.16.0.1":             ClassPrivate,
		"172.31.255.255":         ClassPrivate,
		"172.32.0.1":             ClassPublic,
		"192.168.1.1":            ClassPrivate,
		"100.64.0.1":             ClassPrivate, // CGNAT
		"100.127.255.255":        ClassPrivate,
		"100.128.0.1":            ClassPublic,
		"fd12:3456::1":           ClassPrivate, // ULA
		"fc00::1":                ClassPrivate,
		"224.0.0.1":              ClassMulticast,
		"ff02::1":                ClassMulticast,
		"240.0.0.1":              ClassReserved,
		"255.255.255.255":        ClassReserved,
		"64:ff9b::a9fe:a9fe":     ClassIPv4Embedded, // NAT64 of 169.254.169.254
		"64:ff9b:1::1":           ClassIPv4Embedded,
		"2002:a9fe:a9fe::1":      ClassIPv4Embedded, // 6to4
		"2001::1":                ClassIPv4Embedded, // Teredo
		"::a9fe:a9fe":            ClassReserved,     // IPv4-compatible
		"100::1":                 ClassReserved,     // discard-only
		"fec0::1":                ClassReserved,     // site-local
		"4000::1":                ClassReserved,     // outside 2000::/3
		"192.0.0.8":              ClassReserved,     // IETF protocol assignments
		"198.18.0.1":             ClassReserved,     // benchmarking
		"198.19.255.255":         ClassReserved,
		"192.88.99.1":            ClassReserved, // retired 6to4 relay anycast
		"2001:2::1":              ClassReserved, // IPv6 benchmarking
		"2001:10::1":             ClassReserved, // ORCHID
		"2001:20::1":             ClassReserved, // ORCHIDv2
		"198.51.100.7":           ClassPublic,   // TEST-NET-2 stays public (unrouted fixture)
		"172.30.0.1":             ClassVMInternal,
		"172.30.0.3":             ClassVMInternal,
		"172.31.0.2":             ClassVMInternal,
		"172.30.1.1":             ClassPrivate,
	}
	for s, want := range cases {
		if got := Classify(netip.MustParseAddr(s)); got != want {
			t.Errorf("Classify(%s) = %s, want %s", s, got, want)
		}
	}
	if Classify(netip.Addr{}) != ClassReserved {
		t.Error("invalid address must not be public")
	}
}

func TestIPPolicyCheck(t *testing.T) {
	p := NewIPPolicy([]netip.Prefix{netip.MustParsePrefix("10.10.0.0/16"), netip.MustParsePrefix("fd00:1::/64")})
	allowed := []string{"8.8.8.8", "10.10.3.4", "fd00:1::5", "::ffff:10.10.0.1"}
	denied := []string{"10.11.0.1", "192.168.0.1", "100.64.0.1", "fd00:2::1", "127.0.0.1", "169.254.169.254", "169.254.0.1", "0.0.0.0", "64:ff9b::a0a:1", "fd20:ce::254"}
	for _, s := range allowed {
		if err := p.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("Check(%s) = %v, want allowed", s, err)
		}
	}
	for _, s := range denied {
		if err := p.Check(netip.MustParseAddr(s)); err == nil {
			t.Errorf("Check(%s) allowed, want denied", s)
		}
	}
	// Even a policy that opens all of fc00::/7 keeps the IPv6 metadata server closed.
	wide := NewIPPolicy([]netip.Prefix{netip.MustParsePrefix("fc00::/7")})
	if wide.Check(netip.MustParseAddr("fd20:ce::254")) == nil {
		t.Error("IPv6 metadata server reachable through an allowed ULA range")
	}
}

func TestValidateAllowedPrivateCIDR(t *testing.T) {
	good := []string{"10.0.0.0/8", "10.128.0.0/9", "172.16.0.0/12", "192.168.10.0/24", "100.64.0.0/10", "fc00::/7", "fd00:1::/64", "10.1.2.3/32"}
	bad := []string{"0.0.0.0/0", "8.8.8.0/24", "169.254.0.0/16", "169.254.169.254/32", "127.0.0.0/8", "10.0.0.1/8", "10.0.0.0/7", "::/0", "fe80::/10", "64:ff9b::/96", "::ffff:10.0.0.0/104", "10.0.0.0", "garbage", "172.30.0.0/24", "172.30.0.128/25", "172.31.0.5/32"}
	for _, s := range good {
		if _, err := validateAllowedPrivateCIDR(s); err != nil {
			t.Errorf("validateAllowedPrivateCIDR(%q) = %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := validateAllowedPrivateCIDR(s); err == nil {
			t.Errorf("validateAllowedPrivateCIDR(%q) accepted", s)
		}
	}
}

func TestAlwaysDeniedPrefixes(t *testing.T) {
	denied := AlwaysDeniedPrefixes()
	contains := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, p := range denied {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, s := range []string{"169.254.169.254", "127.0.0.1", "0.0.0.0", "224.0.0.1", "fe80::1", "::1", "64:ff9b::1", "fd20:ce::254", "172.30.0.1", "172.31.0.1", "198.18.0.1"} {
		if !contains(s) {
			t.Errorf("%s missing from always-denied prefixes", s)
		}
	}
	// Private ranges are opened by allowedPrivateCidrs, so they must not be
	// in the always-deny list (smokescreen's most-specific rule would tie).
	for _, s := range []string{"10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "fd12::1", "8.8.8.8"} {
		if contains(s) {
			t.Errorf("%s must not be always-denied", s)
		}
	}
}
