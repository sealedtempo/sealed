package policy

import (
	"net/netip"
	"strconv"
	"strings"
)

// Allowlist answers "may this caller reach host:port" and "may this caller
// resolve this name". Lookups are map hits, never globbing.
type Allowlist struct {
	entries   []Entry
	exact     map[string]Entry // "host:port" or "ip:port"
	wildcard  map[string]Entry // "base:port" for "*.base:port"
	names     map[string]Entry // exact hostnames, any port (DNS)
	wildNames map[string]Entry // wildcard bases, any port (DNS)
}

// NewAllowlist indexes entries. The first entry for a name wins as the
// representative used in DNS stats.
func NewAllowlist(entries []Entry) *Allowlist {
	a := &Allowlist{
		entries:   append([]Entry(nil), entries...),
		exact:     map[string]Entry{},
		wildcard:  map[string]Entry{},
		names:     map[string]Entry{},
		wildNames: map[string]Entry{},
	}
	for _, e := range entries {
		key := e.Host + ":" + strconv.Itoa(int(e.Port))
		switch {
		case e.Wildcard:
			a.wildcard[key] = e
			if _, ok := a.wildNames[e.Host]; !ok {
				a.wildNames[e.Host] = e
			}
		case e.IsIP():
			a.exact[key] = e
		default:
			a.exact[key] = e
			if _, ok := a.names[e.Host]; !ok {
				a.names[e.Host] = e
			}
		}
	}
	return a
}

// Entries returns the entries in config order.
func (a *Allowlist) Entries() []Entry { return append([]Entry(nil), a.entries...) }

// Match finds the entry that allows host:port. host must be normalized: a
// lowercase hostname without trailing dot, or an IP literal.
func (a *Allowlist) Match(host string, port uint16) (Entry, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		e, ok := a.exact[ip.Unmap().String()+":"+strconv.Itoa(int(port))]
		return e, ok
	}
	if ValidateHostname(host) != nil {
		return Entry{}, false
	}
	p := ":" + strconv.Itoa(int(port))
	if e, ok := a.exact[host+p]; ok {
		return e, true
	}
	if _, parent, ok := strings.Cut(host, "."); ok {
		if e, ok := a.wildcard[parent+p]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

// MatchName finds an entry whose host allows resolving name on any port.
// Raw IP entries never match a name.
func (a *Allowlist) MatchName(name string) (Entry, bool) {
	if ValidateHostname(name) != nil {
		return Entry{}, false
	}
	if e, ok := a.names[name]; ok {
		return e, true
	}
	if _, parent, ok := strings.Cut(name, "."); ok {
		if e, ok := a.wildNames[parent]; ok {
			return e, true
		}
	}
	return Entry{}, false
}
