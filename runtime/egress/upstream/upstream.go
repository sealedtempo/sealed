// Package upstream talks to the configured upstream DNS servers. It is used
// by the filtering DNS server (to forward allowed queries) and by the proxy
// (to resolve destinations before the IP check). It never reads
// /etc/hosts or resolv.conf search domains.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/sealed-dev/sealed/runtime/egress/policy"
)

// EDNSSize is the UDP payload size advertised upstream (DNS flag day 2020).
const EDNSSize = 1232

// Client sends queries to a list of upstream servers with failover, and
// retries over TCP when a UDP answer is truncated.
type Client struct {
	servers []string
	udp     *dns.Client
	tcp     *dns.Client
	next    atomic.Uint32
	cache   *addrCache
}

// Proxy lookups are cached for at most cacheTTL (less if the records say
// so), so the proxy keeps working for recently used names when a DNS flood
// gets the VM rate-limited upstream. The DNS server path is never cached.
const (
	cacheTTL     = 30 * time.Second
	cacheEntries = 1024
)

// New returns a Client for servers. timeout bounds each single exchange.
func New(servers []netip.AddrPort, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	c := &Client{
		udp:   &dns.Client{Net: "udp", UDPSize: EDNSSize, Timeout: timeout},
		tcp:   &dns.Client{Net: "tcp", Timeout: timeout},
		cache: newAddrCache(cacheEntries, cacheTTL),
	}
	for _, s := range servers {
		c.servers = append(c.servers, s.String())
	}
	return c
}

// Exchange sends q to the upstreams, starting with a different server each
// call. A transport error, SERVFAIL or REFUSED moves on to the next server.
func (c *Client) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if len(c.servers) == 0 {
		return nil, errors.New("no upstream DNS servers")
	}
	if len(q.Question) != 1 {
		return nil, errors.New("query must have exactly one question")
	}
	start := int((c.next.Add(1) - 1) % uint32(len(c.servers)))
	var lastResp *dns.Msg
	var lastErr error
	for i := range c.servers {
		server := c.servers[(start+i)%len(c.servers)]
		resp, err := c.exchangeOne(ctx, q, server)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			lastResp = resp
			continue
		}
		return resp, nil
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

func (c *Client) exchangeOne(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	resp, _, err := c.udp.ExchangeContext(ctx, q, server)
	if err == nil && resp.Truncated {
		resp, _, err = c.tcp.ExchangeContext(ctx, q, server)
	}
	if err != nil {
		return nil, err
	}
	if err := sameQuestion(q, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func sameQuestion(q, resp *dns.Msg) error {
	if len(resp.Question) != 1 {
		return errors.New("upstream answer has no single question")
	}
	a, b := q.Question[0], resp.Question[0]
	if !strings.EqualFold(a.Name, b.Name) || a.Qtype != b.Qtype || a.Qclass != b.Qclass {
		return errors.New("upstream answer is for a different question")
	}
	return nil
}

// LookupPort implements smokescreen.Resolver. Ports are always numeric.
func (c *Client) LookupPort(_ context.Context, _, service string) (int, error) {
	p, err := policy.ParsePort(service)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", service)
	}
	return int(p), nil
}

// LookupIP implements smokescreen.Resolver. network is "ip", "ip4" or "ip6".
// IPv4 addresses come first.
func (c *Client) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []net.IP{net.IP(ip.Unmap().AsSlice())}, nil
	}
	name, err := policy.NormalizeHostname(host)
	if err != nil {
		return nil, &net.DNSError{Err: "invalid hostname", Name: host, IsNotFound: true}
	}
	var types []uint16
	switch network {
	case "ip4":
		types = []uint16{dns.TypeA}
	case "ip6":
		types = []uint16{dns.TypeAAAA}
	case "ip", "":
		types = []uint16{dns.TypeA, dns.TypeAAAA}
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	results := make([][]netip.Addr, len(types))
	errs := make([]error, len(types))
	var wg sync.WaitGroup
	for i, t := range types {
		wg.Go(func() {
			results[i], errs[i] = c.lookup(ctx, name, t)
		})
	}
	wg.Wait()
	var out []net.IP
	for _, addrs := range results {
		for _, a := range addrs {
			out = append(out, net.IP(a.AsSlice()))
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	for _, e := range errs {
		if e != nil {
			return nil, &net.DNSError{Err: e.Error(), Name: host, IsTemporary: true}
		}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (c *Client) lookup(ctx context.Context, name string, qtype uint16) ([]netip.Addr, error) {
	if addrs, ok := c.cache.get(name, qtype); ok {
		return addrs, nil
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	q.SetEdns0(EDNSSize, false)
	resp, err := c.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("upstream rcode %s", rcodeName(resp.Rcode))
	}
	addrs := AddressesFor(resp, name, qtype)
	if len(addrs) > 0 {
		c.cache.put(name, qtype, addrs, minTTL(resp.Answer))
	}
	return addrs, nil
}

func minTTL(rrs []dns.RR) time.Duration {
	ttl := uint32(1<<32 - 1)
	for _, rr := range rrs {
		ttl = min(ttl, rr.Header().Ttl)
	}
	return time.Duration(ttl) * time.Second
}

type cacheKey struct {
	name  string
	qtype uint16
}

type cacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// addrCache is a small positive cache. When full it drops expired entries,
// then an arbitrary one; it never holds an answer past its TTL.
type addrCache struct {
	mu     sync.Mutex
	max    int
	maxTTL time.Duration
	now    func() time.Time
	m      map[cacheKey]cacheEntry
}

func newAddrCache(max int, maxTTL time.Duration) *addrCache {
	return &addrCache{max: max, maxTTL: maxTTL, now: time.Now, m: map[cacheKey]cacheEntry{}}
}

func (c *addrCache) get(name string, qtype uint16) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := cacheKey{name, qtype}
	e, ok := c.m[k]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expires) {
		delete(c.m, k)
		return nil, false
	}
	return append([]netip.Addr(nil), e.addrs...), true
}

func (c *addrCache) put(name string, qtype uint16, addrs []netip.Addr, ttl time.Duration) {
	ttl = min(ttl, c.maxTTL)
	if ttl < time.Second {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max {
		for k, e := range c.m {
			if !now.Before(e.expires) {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < c.max {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[cacheKey{name, qtype}] = cacheEntry{addrs: append([]netip.Addr(nil), addrs...), expires: now.Add(ttl)}
}

// AddressesFor returns the A or AAAA addresses that answer qname, following
// a CNAME chain inside the answer section (at most 16 hops). Records whose
// owner is not on the chain are ignored.
func AddressesFor(resp *dns.Msg, qname string, qtype uint16) []netip.Addr {
	target := dns.CanonicalName(qname)
	for hop := 0; hop < 16; hop++ {
		var out []netip.Addr
		next := ""
		for _, rr := range resp.Answer {
			if dns.CanonicalName(rr.Header().Name) != target {
				continue
			}
			switch v := rr.(type) {
			case *dns.A:
				if qtype == dns.TypeA {
					if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
						out = append(out, a)
					}
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					if a, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
						out = append(out, a)
					}
				}
			case *dns.CNAME:
				next = dns.CanonicalName(v.Target)
			}
		}
		if len(out) > 0 || next == "" {
			return out
		}
		target = next
	}
	return nil
}

func rcodeName(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return strconv.Itoa(rc)
}
