// Package dnsfilter is the DNS server every container uses. It answers A and
// AAAA queries only for names on the calling container's allowlist,
// forwards those upstream, and answers everything else with NXDOMAIN (or
// REFUSED for unknown sources and query kinds used for tunneling).
package dnsfilter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/sealed-dev/sealed/runtime/egress/policy"
	"github.com/sealed-dev/sealed/runtime/egress/stats"
	"github.com/sealed-dev/sealed/runtime/egress/upstream"
)

// DNSPort is the port used in stats keys for DNS lookups ("name:53").
const DNSPort = 53

const (
	queryTimeout = 4 * time.Second
	maxUDPSize   = 4096
)

// Server is a dns.Handler plus the UDP and TCP listeners serving it.
type Server struct {
	policy   *policy.Policy
	upstream *upstream.Client
	stats    *stats.Counter
	sourceIP func(netip.AddrPort) netip.Addr

	mu      sync.Mutex
	servers []*dns.Server
}

// New returns a Server. sourceIP maps a client address to the caller IP
// used for policy; production passes the remote IP unchanged.
func New(p *policy.Policy, up *upstream.Client, st *stats.Counter, sourceIP func(netip.AddrPort) netip.Addr) *Server {
	return &Server{policy: p, upstream: up, stats: st, sourceIP: sourceIP}
}

// Serve starts answering on pc (UDP) and ln (TCP). It returns once both
// servers are accepting; serve errors are sent to errs.
func (s *Server) Serve(pc net.PacketConn, ln net.Listener, errs chan<- error) {
	udp := &dns.Server{PacketConn: pc, Handler: s, UDPSize: maxUDPSize}
	tcp := &dns.Server{Listener: ln, Handler: s}
	s.mu.Lock()
	s.servers = []*dns.Server{udp, tcp}
	s.mu.Unlock()
	var started sync.WaitGroup
	for _, srv := range []*dns.Server{udp, tcp} {
		started.Add(1)
		srv.NotifyStartedFunc = started.Done
		go func() {
			if err := srv.ActivateAndServe(); err != nil && errs != nil {
				select {
				case errs <- err:
				default:
				}
			}
		}()
	}
	started.Wait()
}

// Shutdown stops both listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	servers := s.servers
	s.mu.Unlock()
	var errs []error
	for _, srv := range servers {
		if err := srv.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	reply := s.answer(w.RemoteAddr(), req)
	if isUDP(w.LocalAddr()) {
		reply.Truncate(udpSize(req))
	}
	_ = w.WriteMsg(reply)
}

func (s *Server) answer(remote net.Addr, req *dns.Msg) *dns.Msg {
	if req.Opcode != dns.OpcodeQuery {
		return rcode(req, dns.RcodeNotImplemented)
	}
	if len(req.Question) != 1 {
		return rcode(req, dns.RcodeFormatError)
	}
	q := req.Question[0]

	callerName := policy.UnknownCaller
	caller, known := s.callerFor(remote)
	if known {
		callerName = caller.Name
	}
	name, nameErr := policy.NormalizeHostname(q.Name)
	if !known {
		s.stats.Block(callerName, policy.UnmatchedKey(strings.TrimSuffix(q.Name, "."), DNSPort))
		return rcode(req, dns.RcodeRefused)
	}
	var entry policy.Entry
	allowed := false
	if nameErr == nil {
		entry, allowed = caller.Allow.MatchName(name)
	}
	if !allowed {
		s.stats.Block(callerName, policy.UnmatchedKey(strings.TrimSuffix(q.Name, "."), DNSPort))
		return rcode(req, dns.RcodeNameError)
	}
	key := nameKey(entry)
	if q.Qclass != dns.ClassINET || q.Qtype == dns.TypeANY {
		s.stats.Block(callerName, key)
		return rcode(req, dns.RcodeRefused)
	}
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		// Allowed name, but only addresses are served: empty NOERROR.
		return rcode(req, dns.RcodeSuccess)
	}

	out := new(dns.Msg)
	out.SetQuestion(dns.Fqdn(name), q.Qtype)
	out.RecursionDesired = true
	out.SetEdns0(upstream.EDNSSize, false)
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	resp, err := s.upstream.Exchange(ctx, out)
	if err != nil {
		return rcode(req, dns.RcodeServerFailure)
	}

	reply := rcode(req, resp.Rcode)
	reply.RecursionAvailable = resp.RecursionAvailable
	filtered := false
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.CNAME:
			reply.Answer = append(reply.Answer, v)
		case *dns.A:
			if s.addressAllowed(v.A) {
				reply.Answer = append(reply.Answer, v)
			} else {
				filtered = true
			}
		case *dns.AAAA:
			if s.addressAllowed(v.AAAA) {
				reply.Answer = append(reply.Answer, v)
			} else {
				filtered = true
			}
		}
	}
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			reply.Ns = append(reply.Ns, soa)
		}
	}
	if filtered {
		// An allowed name pointing at metadata, loopback or a private range
		// (DNS rebinding): drop those addresses and count the attempt.
		s.stats.Block(callerName, key)
	}
	return reply
}

func (s *Server) callerFor(remote net.Addr) (*policy.CallerPolicy, bool) {
	ap, ok := addrPort(remote)
	if !ok {
		return nil, false
	}
	return s.policy.CallerByIP(s.sourceIP(ap))
}

func (s *Server) addressAllowed(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	return ok && s.policy.IP().Check(a) == nil
}

// nameKey is the stats key for a lookup that matched entry: the entry's
// host pattern with the DNS port.
func nameKey(e policy.Entry) string {
	e.Port = DNSPort
	return e.String()
}

func rcode(req *dns.Msg, rc int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rc)
	m.RecursionAvailable = true
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(maxUDPSize, false)
	}
	return m
}

func udpSize(req *dns.Msg) int {
	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
		size = int(opt.UDPSize())
	}
	return min(size, maxUDPSize)
}

func isUDP(a net.Addr) bool {
	_, ok := a.(*net.UDPAddr)
	return ok
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), true
	case *net.TCPAddr:
		return v.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}
