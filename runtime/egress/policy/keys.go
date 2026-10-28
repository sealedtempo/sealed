package policy

import (
	"net/netip"
	"strconv"
	"strings"
)

// Stats keys leave the VM: sealed-agent forwards GET /v1/stats to the
// platform inside /v1/health. P5 requires that to be content-free, so every
// key is either an allowlist entry (the platform already knows the measured
// config) or a word from the fixed vocabulary below. Nothing a container
// chooses (hostnames, labels, IP addresses, port numbers) appears in a key
// unless the caller's allowlist already contains it.
//
//	allowed   <entry>                 the entry that matched
//	blocked   <entry>                 matched, but resolved to a denied address
//	          <pattern>:<port>        name on the allowlist, port not allowed for it
//	          <pattern>:53            DNS: ANY, non-IN class or stripped answers
//	          unlisted:<port>         hostname not on the allowlist (DNS uses :53)
//	          ip-<class>:<port>       raw IP not on the allowlist (ip-public, ip-metadata, ...)
//	          invalid:<port>          destination is not a valid host
//	          unauthenticated:0       missing or wrong proxy credential
//	          rate-limited:0          proxy request over the caller's rate (DNS: rate-limited:53)
//	          other:0                 overflow, see stats.DefaultMaxKeys
//
// <port> is the requested port when it is 80, 443 or a port the caller's
// allowlist lists, and "other" otherwise.
const (
	KeyUnlisted        = "unlisted"
	KeyInvalid         = "invalid"
	KeyUnauthenticated = "unauthenticated:0"
	KeyRateLimited     = "rate-limited:0"
	KeyRateLimitedDNS  = "rate-limited:53"
	PortOther          = "other"
	dnsPort            = 53
)

// PortToken renders port for a stats key: the number when it is 80, 443 or
// listed somewhere in this allowlist, else PortOther. A nil allowlist lists
// nothing.
func (a *Allowlist) PortToken(port uint16) string {
	if port == 80 || port == 443 || (a != nil && a.ports[port]) {
		return strconv.Itoa(int(port))
	}
	return PortOther
}

// BlockedKey returns the stats key for a denied attempt to reach host:port.
// host is taken as seen on the wire (any case, optional trailing dot or
// IPv6 brackets). listed reports whether the key is one of the caller's
// allowlist entries, which bounds it by the config. A nil allowlist (an
// unknown source) allows nothing.
func (a *Allowlist) BlockedKey(host string, port uint16) (key string, listed bool) {
	if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); err == nil {
		ip = ip.Unmap().WithZone("")
		if a != nil {
			if e, ok := a.Match(ip.String(), port); ok {
				return e.String(), true
			}
		}
		return "ip-" + Classify(ip).String() + ":" + a.PortToken(port), false
	}
	name, err := NormalizeHostname(host)
	if err != nil {
		return KeyInvalid + ":" + a.PortToken(port), false
	}
	if a != nil {
		if e, ok := a.Match(name, port); ok {
			return e.String(), true
		}
		if e, ok := a.MatchName(name); ok {
			return e.HostPattern() + ":" + a.PortToken(port), false
		}
	}
	return KeyUnlisted + ":" + a.PortToken(port), false
}

// BlockedDNSKey returns the stats key for a refused lookup of name. listed
// reports whether name matched an allowlist entry (the key is then that
// entry's pattern with port 53, one per entry).
func (a *Allowlist) BlockedDNSKey(name string) (key string, listed bool) {
	n, err := NormalizeHostname(name)
	if err != nil {
		return KeyInvalid + ":53", false
	}
	if a != nil {
		if e, ok := a.MatchName(n); ok {
			return DNSKey(e), true
		}
	}
	return KeyUnlisted + ":53", false
}

// DNSKey is the stats key for a lookup that matched e: its host pattern with
// port 53.
func DNSKey(e Entry) string {
	return e.HostPattern() + ":" + strconv.Itoa(dnsPort)
}
