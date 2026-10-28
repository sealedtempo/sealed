package verify

import "net/netip"

// Test hooks for package verify_test.
var HostAllowed = hostAllowed

func IsPublicAddr(s string) bool { return isPublicAddr(netip.MustParseAddr(s)) }
