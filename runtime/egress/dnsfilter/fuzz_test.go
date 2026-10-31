package dnsfilter

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/sealedtempo/sealed/runtime/egress/internal/dnstest"
	"github.com/sealedtempo/sealed/runtime/egress/limits"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	"github.com/sealedtempo/sealed/runtime/egress/stats"
	"github.com/sealedtempo/sealed/runtime/egress/upstream"
)

var fuzzAllow = []string{
	"api.alpha.test:443", "*.wild.alpha.test:443", "rebind.alpha.test:443", "mixed.alpha.test:443",
	"alias.alpha.test:443", "198.51.100.7:443", "_srv.alpha.test:8443",
}

// refNameAllowed is the DNS rule written out directly: the normalized name is
// an exact host entry, or one label below a wildcard base.
func refNameAllowed(name string) bool {
	if policy.ValidateHostname(name) != nil {
		return false
	}
	for _, s := range fuzzAllow {
		h, _, _ := net.SplitHostPort(s)
		if base, ok := strings.CutPrefix(h, "*."); ok {
			if label, ok := strings.CutSuffix(name, "."+base); ok && label != "" && !strings.Contains(label, ".") {
				return true
			}
		} else if name == h {
			return true
		}
	}
	return false
}

func fuzzPolicy(t testing.TB, upstreamAddr string) *policy.Policy {
	cfg := &policy.Config{
		Listen:      &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS: []string{upstreamAddr},
		Callers: []policy.Caller{
			{Name: "alpha", IP: alphaIP.String(), Allow: fuzzAllow},
			{Name: "beta", IP: betaIP.String(), Allow: []string{"beta.test:443"}},
		},
		AllowedPrivateCIDRs: []string{"10.8.0.0/16"},
		StatsReaders:        []string{},
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

var fuzzLimits = limits.Config{DNSRate: 1e9, DNSBurst: 1 << 30, DNSInflight: 1 << 20}

// checkReply holds for every answer the filter sends: only CNAME, A and AAAA
// in the answer section, every address allowed by the IP policy, only SOA in
// the authority section, only OPT in the additional section.
func checkReply(t *testing.T, pol *policy.Policy, reply *dns.Msg) {
	t.Helper()
	for _, rr := range reply.Answer {
		switch v := rr.(type) {
		case *dns.CNAME:
		case *dns.A:
			a, ok := netip.AddrFromSlice(v.A)
			if !ok || pol.IP().Check(a.Unmap()) != nil {
				t.Fatalf("reply carries denied A %v", v.A)
			}
		case *dns.AAAA:
			a, ok := netip.AddrFromSlice(v.AAAA)
			if !ok || pol.IP().Check(a) != nil {
				t.Fatalf("reply carries denied AAAA %v", v.AAAA)
			}
		default:
			t.Fatalf("reply carries a %s record", dns.TypeToString[rr.Header().Rrtype])
		}
	}
	for _, rr := range reply.Ns {
		if _, ok := rr.(*dns.SOA); !ok {
			t.Fatalf("authority section carries a %s record", dns.TypeToString[rr.Header().Rrtype])
		}
	}
	for _, rr := range reply.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			t.Fatalf("additional section carries a %s record", dns.TypeToString[rr.Header().Rrtype])
		}
	}
	if _, err := reply.Pack(); err != nil {
		t.Fatalf("reply does not pack: %v", err)
	}
}

type recordingWriter struct {
	local, remote net.Addr
	msg           *dns.Msg
}

func (w *recordingWriter) LocalAddr() net.Addr         { return w.local }
func (w *recordingWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *recordingWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *recordingWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *recordingWriter) Close() error                { return nil }
func (w *recordingWriter) TsigStatus() error           { return nil }
func (w *recordingWriter) TsigTimersOnly(bool)         {}
func (w *recordingWriter) Hijack()                     {}

func querySeeds() [][]byte {
	var out [][]byte
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{"api.alpha.test.", dns.TypeA}, {"API.Alpha.TEST.", dns.TypeAAAA}, {"x.wild.alpha.test.", dns.TypeA},
		{"x.y.wild.alpha.test.", dns.TypeA}, {"wild.alpha.test.", dns.TypeA}, {"rebind.alpha.test.", dns.TypeA},
		{"mixed.alpha.test.", dns.TypeA}, {"alias.alpha.test.", dns.TypeA}, {"api.alpha.test.", dns.TypeTXT},
		{"api.alpha.test.", dns.TypeANY}, {"beta.test.", dns.TypeA}, {"evil.test.", dns.TypeA},
		{"api\\.alpha.test.", dns.TypeA}, {"_srv.alpha.test.", dns.TypeSRV}, {"7.100.51.198.in-addr.arpa.", dns.TypePTR},
	} {
		m := new(dns.Msg)
		m.SetQuestion(q.name, q.qtype)
		m.SetEdns0(4096, false)
		if b, err := m.Pack(); err == nil {
			out = append(out, b)
		}
	}
	return out
}

// FuzzQuery feeds arbitrary DNS messages to the filter as caller alpha (or an
// unknown source). Properties: the upstream only ever sees A or AAAA queries
// of class IN for names the allowlist allows (checked against refNameAllowed,
// on the name the upstream actually received), refused names never reach it,
// and every reply passes checkReply and fits the client's UDP size.
func FuzzQuery(f *testing.F) {
	for _, s := range querySeeds() {
		f.Add(s, false)
	}
	f.Add([]byte{0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0}, true)
	up := dnstest.Start(f)
	up.AddA("api.alpha.test", "203.0.113.10")
	up.AddAAAA("api.alpha.test", "2001:db8::10")
	up.AddWildcardA("wild.alpha.test", "203.0.113.11")
	up.AddA("rebind.alpha.test", "169.254.169.254")
	up.AddA("mixed.alpha.test", "10.0.0.5", "10.8.1.1", "203.0.113.12")
	up.AddCNAME("alias.alpha.test", "edge.cdn.test")
	up.AddA("edge.cdn.test", "203.0.113.13")
	pol := fuzzPolicy(f, up.Addr)
	srv := New(pol, upstream.New(pol.Upstreams(), time.Second), stats.New(time.Now(), 0), func(ap netip.AddrPort) netip.Addr { return ap.Addr() }, fuzzLimits)
	seen := 0
	f.Fuzz(func(t *testing.T, raw []byte, unknown bool) {
		req := new(dns.Msg)
		if err := req.Unpack(raw); err != nil {
			return
		}
		from := alphaIP
		if unknown {
			from = netip.MustParseAddr("172.30.0.99")
		}
		w := &recordingWriter{
			local:  &net.UDPAddr{IP: net.IPv4(172, 30, 0, 2), Port: 53},
			remote: &net.UDPAddr{IP: from.AsSlice(), Port: 5353},
		}
		srv.ServeDNS(w, req)
		if w.msg == nil {
			t.Fatal("no reply written")
		}
		checkReply(t, pol, w.msg)
		if packed, err := w.msg.Pack(); err != nil || len(packed) > udpSize(req) {
			t.Fatalf("UDP reply is %d bytes, the client allows %d (%v)", len(packed), udpSize(req), err)
		}

		qs := up.Queries()
		fresh := qs[min(seen, len(qs)):]
		seen = len(qs)
		for _, q := range fresh {
			if q.Type != dns.TypeA && q.Type != dns.TypeAAAA {
				t.Fatalf("upstream received a %s query for %q", dns.TypeToString[q.Type], q.Name)
			}
			if !refNameAllowed(strings.TrimSuffix(q.Name, ".")) {
				t.Fatalf("upstream received a query for %q, which the allowlist does not allow", q.Name)
			}
		}
		if len(req.Question) == 1 && len(fresh) > 0 {
			q := req.Question[0]
			norm, err := policy.NormalizeHostname(q.Name)
			if unknown || err != nil || !refNameAllowed(norm) || q.Qclass != dns.ClassINET {
				t.Fatalf("query %q (class %d, unknown source %v) reached the upstream", q.Name, q.Qclass, unknown)
			}
		}
	})
}

// fuzzUpstream answers every query with the records of the current fuzz
// input: a hostile or broken upstream resolver.
type fuzzUpstream struct {
	mu   sync.Mutex
	resp *dns.Msg
}

func (u *fuzzUpstream) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	u.mu.Lock()
	tmpl := u.resp
	u.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(req)
	if tmpl != nil {
		m.Rcode = tmpl.Rcode
		m.Truncated = false
		m.Answer, m.Ns, m.Extra = tmpl.Answer, tmpl.Ns, tmpl.Extra
		m.Authoritative = tmpl.Authoritative
		m.RecursionAvailable = tmpl.RecursionAvailable
	}
	_ = w.WriteMsg(m)
}

// FuzzUpstreamAnswer lets the upstream answer allowed queries with arbitrary
// records. Properties: the filtered reply passes checkReply (no metadata,
// loopback, private or VM-internal address and no other record type gets
// through), and upstream.AddressesFor only returns addresses of records on
// the CNAME chain of the question.
func FuzzUpstreamAnswer(f *testing.F) {
	seed := func(rrs ...string) []byte {
		m := new(dns.Msg)
		m.SetQuestion("api.alpha.test.", dns.TypeA)
		for _, s := range rrs {
			rr, err := dns.NewRR(s)
			if err != nil {
				f.Fatal(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		b, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	f.Add(seed("api.alpha.test. 60 IN A 203.0.113.10"), "api.alpha.test", false)
	f.Add(seed("api.alpha.test. 60 IN A 169.254.169.254", "api.alpha.test. 60 IN A 203.0.113.10"), "api.alpha.test", false)
	f.Add(seed("api.alpha.test. 60 IN CNAME evil.test.", "evil.test. 60 IN A 127.0.0.1", "evil.test. 60 IN AAAA ::ffff:127.0.0.1"), "api.alpha.test", true)
	f.Add(seed("api.alpha.test. 60 IN AAAA 64:ff9b::a9fe:a9fe", "api.alpha.test. 60 IN TXT \"x\"", "api.alpha.test. 60 IN A 172.30.0.3"), "api.alpha.test", true)
	f.Add(seed("x.wild.alpha.test. 60 IN A 10.8.1.1", "x.wild.alpha.test. 60 IN A 10.9.1.1"), "x.wild.alpha.test", false)

	u := &fuzzUpstream{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		f.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		f.Fatal(err)
	}
	var started sync.WaitGroup
	servers := []*dns.Server{{PacketConn: pc, Handler: u, UDPSize: 65535}, {Listener: ln, Handler: u}}
	for _, s := range servers {
		started.Add(1)
		s.NotifyStartedFunc = started.Done
		go func() { _ = s.ActivateAndServe() }()
	}
	started.Wait()
	f.Cleanup(func() {
		for _, s := range servers {
			_ = s.Shutdown()
		}
	})
	pol := fuzzPolicy(f, pc.LocalAddr().String())
	srv := New(pol, upstream.New(pol.Upstreams(), time.Second), stats.New(time.Now(), 0), func(ap netip.AddrPort) netip.Addr { return ap.Addr() }, fuzzLimits)
	f.Fuzz(func(t *testing.T, raw []byte, name string, aaaa bool) {
		tmpl := new(dns.Msg)
		if err := tmpl.Unpack(raw); err != nil {
			return
		}
		qtype := dns.TypeA
		if aaaa {
			qtype = dns.TypeAAAA
		}
		// AddressesFor is what the proxy's resolver uses on the same answers.
		fqdn := dns.Fqdn(name)
		if _, ok := dns.IsDomainName(fqdn); ok {
			got := upstream.AddressesFor(tmpl, fqdn, qtype)
			want := refAddresses(tmpl, fqdn, qtype)
			if len(got) != len(want) {
				t.Fatalf("AddressesFor(%q) = %v, reference %v", fqdn, got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("AddressesFor(%q) = %v, reference %v", fqdn, got, want)
				}
			}
		}
		u.mu.Lock()
		u.resp = tmpl
		u.mu.Unlock()
		// Only questions that survive the wire reach the filter.
		q0 := new(dns.Msg)
		q0.SetQuestion(fqdn, qtype)
		wire, err := q0.Pack()
		if err != nil {
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(wire); err != nil {
			return
		}
		name = q.Question[0].Name
		reply := srv.answer(&net.UDPAddr{IP: alphaIP.AsSlice(), Port: 5353}, q)
		checkReply(t, pol, reply)
		norm, err := policy.NormalizeHostname(name)
		if (err != nil || !refNameAllowed(norm)) && len(reply.Answer) > 0 {
			t.Fatalf("refused name %q got answers %v", name, reply.Answer)
		}
	})
}

// refAddresses follows the CNAME chain from qname through the answer section
// (at most 16 names) and returns the addresses owned by the last name that has
// any, in answer order.
func refAddresses(m *dns.Msg, qname string, qtype uint16) []netip.Addr {
	target := strings.ToLower(qname)
	for hop := 0; hop < 16; hop++ {
		var addrs []netip.Addr
		next := ""
		for _, rr := range m.Answer {
			if strings.ToLower(rr.Header().Name) != target {
				continue
			}
			switch v := rr.(type) {
			case *dns.A:
				if qtype == dns.TypeA {
					if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
						addrs = append(addrs, a)
					}
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					if a, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
						addrs = append(addrs, a)
					}
				}
			case *dns.CNAME:
				next = strings.ToLower(v.Target)
			}
		}
		if len(addrs) > 0 || next == "" {
			return addrs
		}
		target = next
	}
	return nil
}
