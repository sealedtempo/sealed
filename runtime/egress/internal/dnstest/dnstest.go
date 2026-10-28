// Package dnstest is a fake recursive DNS server for tests. It serves UDP
// and TCP on one 127.0.0.1 port, truncates UDP answers the way a real
// server does, and records every query it receives.
package dnstest

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Query is one query the server received.
type Query struct {
	Net  string // "udp" or "tcp"
	Name string
	Type uint16
}

// Server is a fake upstream resolver.
type Server struct {
	Addr string // host:port, same port for UDP and TCP

	mu        sync.Mutex
	records   map[string][]dns.RR // canonical name -> records (A, AAAA, CNAME, TXT)
	wildcards map[string][]string // suffix -> IPv4 addresses for any name under it
	servfail  bool
	queries   []Query
}

// Start runs a server until the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{records: map[string][]dns.RR{}, wildcards: map[string][]string{}}
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; i < 10; i++ {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("dnstest: listen udp: %v", err)
		}
		l, err := net.Listen("tcp", p.LocalAddr().String())
		if err == nil {
			pc, ln = p, l
			break
		}
		p.Close()
	}
	if pc == nil {
		t.Fatal("dnstest: could not bind udp and tcp on one port")
	}
	s.Addr = pc.LocalAddr().String()
	udp := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve("udp")), UDPSize: 4096}
	tcp := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(s.serve("tcp"))}
	var started sync.WaitGroup
	for _, srv := range []*dns.Server{udp, tcp} {
		started.Add(1)
		srv.NotifyStartedFunc = started.Done
		go func() { _ = srv.ActivateAndServe() }()
	}
	started.Wait()
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	})
	return s
}

// AddA adds A records for name.
func (s *Server) AddA(name string, ips ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := dns.CanonicalName(name)
	for _, ip := range ips {
		s.records[n] = append(s.records[n], &dns.A{
			Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip).To4(),
		})
	}
}

// AddAAAA adds AAAA records for name.
func (s *Server) AddAAAA(name string, ips ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := dns.CanonicalName(name)
	for _, ip := range ips {
		s.records[n] = append(s.records[n], &dns.AAAA{
			Hdr:  dns.RR_Header{Name: n, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(ip).To16(),
		})
	}
}

// AddCNAME makes name an alias of target.
func (s *Server) AddCNAME(name, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := dns.CanonicalName(name)
	s.records[n] = append(s.records[n], &dns.CNAME{
		Hdr:    dns.RR_Header{Name: n, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: dns.CanonicalName(target),
	})
}

// AddTXT adds a TXT record for name.
func (s *Server) AddTXT(name, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := dns.CanonicalName(name)
	s.records[n] = append(s.records[n], &dns.TXT{
		Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{text},
	})
}

// AddWildcardA answers A queries for any name strictly under suffix.
func (s *Server) AddWildcardA(suffix string, ips ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wildcards[dns.CanonicalName(suffix)] = append(s.wildcards[dns.CanonicalName(suffix)], ips...)
}

// SetServfail makes every answer SERVFAIL.
func (s *Server) SetServfail(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servfail = on
}

// Queries returns the queries received so far.
func (s *Server) Queries() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Query(nil), s.queries...)
}

// QueriedName reports whether any query for name (any type) arrived.
func (s *Server) QueriedName(name string) bool {
	n := dns.CanonicalName(name)
	for _, q := range s.Queries() {
		if q.Name == n {
			return true
		}
	}
	return false
}

func (s *Server) serve(network string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		if len(req.Question) != 1 {
			m.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		name := dns.CanonicalName(q.Name)

		s.mu.Lock()
		s.queries = append(s.queries, Query{Net: network, Name: name, Type: q.Qtype})
		servfail := s.servfail
		answer, found := s.resolve(name, q.Qtype)
		s.mu.Unlock()

		switch {
		case servfail:
			m.Rcode = dns.RcodeServerFailure
		case !found:
			m.Rcode = dns.RcodeNameError
		default:
			m.Answer = answer
		}
		if opt := req.IsEdns0(); opt != nil {
			m.SetEdns0(opt.UDPSize(), false)
		}
		if network == "udp" {
			size := dns.MinMsgSize
			if opt := req.IsEdns0(); opt != nil {
				size = int(opt.UDPSize())
			}
			m.Truncate(size)
		}
		_ = w.WriteMsg(m)
	}
}

// resolve answers like a recursive resolver: it follows CNAMEs and returns
// the whole chain. found is false when the name does not exist at all.
// Callers hold s.mu.
func (s *Server) resolve(name string, qtype uint16) ([]dns.RR, bool) {
	var out []dns.RR
	found := false
	for hop := 0; hop < 8; hop++ {
		rrs, ok := s.records[name]
		if !ok {
			rrs, ok = s.wildcard(name)
		}
		if !ok {
			return out, found
		}
		found = true
		next := ""
		for _, rr := range rrs {
			if c, isCNAME := rr.(*dns.CNAME); isCNAME {
				out = append(out, dns.Copy(rr))
				next = c.Target
			} else if rr.Header().Rrtype == qtype {
				out = append(out, dns.Copy(rr))
			}
		}
		if next == "" {
			return out, true
		}
		name = next
	}
	return out, found
}

func (s *Server) wildcard(name string) ([]dns.RR, bool) {
	for suffix, ips := range s.wildcards {
		if name != suffix && strings.HasSuffix(name, "."+suffix) {
			var rrs []dns.RR
			for _, ip := range ips {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(ip).To4(),
				})
			}
			return rrs, true
		}
	}
	return nil, false
}
