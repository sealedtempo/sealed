package policy

import (
	"net/netip"
	"sort"
)

// CallerPolicy is the compiled allowlist of one caller.
type CallerPolicy struct {
	Name      string
	IP        netip.Addr
	Allow     *Allowlist
	ProxyAuth bool
}

// Policy is the compiled, read-only form of a validated Config.
type Policy struct {
	callersByIP   map[netip.Addr]*CallerPolicy
	callersByName map[string]*CallerPolicy
	statsReaders  map[netip.Addr]bool
	ip            IPPolicy
	upstreams     []netip.AddrPort
}

// Compile validates cfg and builds lookup tables. localDeny adds ranges that
// are denied whatever the config says (the egress container's own networks).
func Compile(cfg *Config, localDeny ...netip.Prefix) (*Policy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Policy{
		callersByIP:   map[netip.Addr]*CallerPolicy{},
		callersByName: map[string]*CallerPolicy{},
		statsReaders:  map[netip.Addr]bool{},
	}
	var prefixes []netip.Prefix
	for _, s := range cfg.AllowedPrivateCIDRs {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	p.ip = NewIPPolicy(prefixes, localDeny...)
	for _, c := range cfg.Callers {
		entries := make([]Entry, 0, len(c.Allow))
		for _, s := range c.Allow {
			e, _ := ParseEntry(s) // validated above
			entries = append(entries, e)
		}
		cp := &CallerPolicy{Name: c.Name, IP: netip.MustParseAddr(c.IP), Allow: NewAllowlist(entries), ProxyAuth: c.ProxyAuth}
		p.callersByIP[cp.IP] = cp
		p.callersByName[cp.Name] = cp
	}
	for _, r := range cfg.StatsReaders {
		p.statsReaders[netip.MustParseAddr(r)] = true
	}
	for _, u := range cfg.UpstreamDNS {
		p.upstreams = append(p.upstreams, netip.MustParseAddrPort(u))
	}
	return p, nil
}

// CallerByIP returns the caller whose fixed IP is ip.
func (p *Policy) CallerByIP(ip netip.Addr) (*CallerPolicy, bool) {
	c, ok := p.callersByIP[ip.Unmap()]
	return c, ok
}

// CallerByName returns the caller with the given name.
func (p *Policy) CallerByName(name string) (*CallerPolicy, bool) {
	c, ok := p.callersByName[name]
	return c, ok
}

// IsStatsReader reports whether ip may read GET /v1/stats.
func (p *Policy) IsStatsReader(ip netip.Addr) bool { return p.statsReaders[ip.Unmap()] }

// IP returns the destination address policy.
func (p *Policy) IP() IPPolicy { return p.ip }

// Upstreams returns the upstream DNS servers in config order.
func (p *Policy) Upstreams() []netip.AddrPort { return append([]netip.AddrPort(nil), p.upstreams...) }

// ProxyAuthCallers returns the names of callers that must authenticate,
// sorted.
func (p *Policy) ProxyAuthCallers() []string {
	var names []string
	for n, c := range p.callersByName {
		if c.ProxyAuth {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// CallerNames returns the caller names, sorted.
func (p *Policy) CallerNames() []string {
	names := make([]string, 0, len(p.callersByName))
	for n := range p.callersByName {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
