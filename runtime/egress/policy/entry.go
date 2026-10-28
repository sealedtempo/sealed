package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Entry is one allowlist item: "host:port", "*.domain:port" (exactly one
// extra label) or "a.b.c.d:port" (a raw IPv4 destination).
type Entry struct {
	Host     string // hostname, wildcard base domain, or IP literal
	Port     uint16
	Wildcard bool
	IP       netip.Addr // set when the entry is a raw IP
}

func (e Entry) String() string {
	host := e.Host
	if e.Wildcard {
		host = "*." + host
	}
	return host + ":" + strconv.Itoa(int(e.Port))
}

// IsIP reports whether the entry names a raw IP destination.
func (e Entry) IsIP() bool { return e.IP.IsValid() }

// ParseEntry parses an allowlist entry in its canonical form. Hosts must
// already be lowercase ASCII (punycode for IDNs) without a trailing dot.
func ParseEntry(s string) (Entry, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Entry{}, fmt.Errorf("entry %q is not host:port", s)
	}
	port, err := ParsePort(portStr)
	if err != nil || port == 0 {
		return Entry{}, fmt.Errorf("entry %q has an invalid port", s)
	}
	if strings.ContainsRune(host, ':') {
		return Entry{}, fmt.Errorf("entry %q: IPv6 literal destinations are not supported", s)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.String() != host {
			return Entry{}, fmt.Errorf("entry %q: IP is not in canonical form", s)
		}
		return Entry{Host: host, Port: port, IP: ip}, nil
	}
	if base, ok := strings.CutPrefix(host, "*."); ok {
		if err := ValidateHostname(base); err != nil {
			return Entry{}, fmt.Errorf("entry %q: %w", s, err)
		}
		if suffix, icann := publicsuffix.PublicSuffix(base); icann && suffix == base {
			return Entry{}, fmt.Errorf("entry %q: wildcard over the public suffix %q is not allowed", s, base)
		}
		return Entry{Host: base, Port: port, Wildcard: true}, nil
	}
	if err := ValidateHostname(host); err != nil {
		return Entry{}, fmt.Errorf("entry %q: %w", s, err)
	}
	return Entry{Host: host, Port: port}, nil
}

// ParsePort parses a decimal port with no sign or leading zeros.
func ParsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(n), nil
}

// ValidateHostname accepts lowercase LDH names (underscores allowed inside
// labels) with at least two labels and a non-numeric last label.
func ValidateHostname(h string) error {
	if h == "" || len(h) > 253 {
		return errors.New("hostname must be 1 to 253 characters")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("hostname %q must have at least two labels", h)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("hostname %q has an empty or over-long label", h)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("hostname %q has a label starting or ending with '-'", h)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("hostname %q has a character outside [a-z0-9-_]", h)
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return fmt.Errorf("hostname %q has a numeric last label", h)
	}
	return nil
}

// NormalizeHostname lowercases ASCII and strips one trailing dot, then
// validates. It is used for names seen on the wire (requests, DNS queries).
func NormalizeHostname(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if err := ValidateHostname(h); err != nil {
		return "", err
	}
	return h, nil
}

// UnmatchedKey returns the stats key for a destination that matched no
// allowlist entry. Hostnames are reduced to their registrable domain
// ("*.evil.com:443"), so a blocked name cannot smuggle data into the counts
// that leave the VM, and random subdomains collapse into one key.
func UnmatchedKey(host string, port uint16) string {
	p := strconv.Itoa(int(port))
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is6() && !ip.Is4In6() {
			return "[" + ip.String() + "]:" + p
		}
		return ip.Unmap().String() + ":" + p
	}
	h, err := NormalizeHostname(host)
	if err != nil {
		return "invalid:" + p
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		labels := strings.Split(h, ".")
		if len(labels) <= 2 {
			return h + ":" + p
		}
		base = strings.Join(labels[len(labels)-2:], ".")
	}
	if base == h {
		return h + ":" + p
	}
	return "*." + base + ":" + p
}
