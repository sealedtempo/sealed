package policy

import (
	"fmt"
	"net/netip"
	"sort"
)

// CallerPolicy is the compiled allowlist of one caller.
type CallerPolicy struct {
	Name      string
	IP        netip.Addr
	Allow     *Allowlist
	ProxyAuth bool
	// private holds the caller's raw IP entries that are private addresses
	// inside allowedPrivateCidrs, in config order. They are the only
	// private destinations this caller reaches: allowedPrivateCidrs is
	// stack-wide, but what it opens is per caller and per entry (runtime-1).
	private []Entry
}

// PrivateEntries returns the caller's raw IP entries that open a private
// address, in config order.
func (c *CallerPolicy) PrivateEntries() []Entry { return append([]Entry(nil), c.private...) }

func (c *CallerPolicy) allowsPrivate(ap netip.AddrPort) bool {
	for _, e := range c.private {
		if e.IP == ap.Addr() && e.Port == ap.Port() {
			return true
		}
	}
	return false
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
		for _, e := range entries {
			if e.IsIP() && Classify(e.IP) == ClassPrivate && p.ip.Check(e.IP) == nil {
				cp.private = append(cp.private, e)
			}
		}
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

// CheckDial is the last check before the proxy connects to addr for caller
// c, whose request named host (normalized: a hostname or an IP literal).
// Every address must pass IP().Check. A hostname may only reach a public
// address (IPPolicy.CheckResolved), whatever its DNS answers. A private
// address is reached only when the request named that very address and c
// lists it, on that port, as a raw IP entry. So one caller's VPC entries
// open nothing for another caller, another port or any hostname
// (runtime-1).
func (p *Policy) CheckDial(c *CallerPolicy, host string, addr netip.AddrPort) error {
	ip := addr.Addr().Unmap().WithZone("")
	target, err := netip.ParseAddr(host)
	if err != nil {
		return p.ip.CheckResolved(ip)
	}
	if target.Unmap() != ip {
		return fmt.Errorf("destination %s is not the requested address %s", ip, target)
	}
	if err := p.ip.Check(ip); err != nil {
		return err
	}
	ap := netip.AddrPortFrom(ip, addr.Port())
	if Classify(ip) == ClassPrivate && (c == nil || !c.allowsPrivate(ap)) {
		return fmt.Errorf("destination %s is a private address that is not a raw IP entry of this caller", ap)
	}
	return nil
}

// PrivateEntries returns the private raw IP entries of every caller, each
// ip:port once, sorted. They are the only private destinations the proxy's
// rules admit; CheckDial still requires the caller's own entry.
func (p *Policy) PrivateEntries() []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	for _, c := range p.callersByName {
		for _, e := range c.private {
			ap := netip.AddrPortFrom(e.IP, e.Port)
			if !seen[ap] {
				seen[ap] = true
				out = append(out, ap)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

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
