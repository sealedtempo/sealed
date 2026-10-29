package dnsfilter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/sealedtempo/sealed/runtime/egress/internal/dnstest"
	"github.com/sealedtempo/sealed/runtime/egress/limits"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	"github.com/sealedtempo/sealed/runtime/egress/stats"
	"github.com/sealedtempo/sealed/runtime/egress/upstream"
)

var (
	alphaIP = netip.MustParseAddr("172.30.0.16")
	betaIP  = netip.MustParseAddr("172.30.0.17")
)

type fixture struct {
	srv   *Server
	up    *dnstest.Server
	stats *stats.Counter
}

func newFixture(t *testing.T) *fixture { return newFixtureWith(t, nil) }

// newFixtureWith lets a test adjust the config before it is compiled.
func newFixtureWith(t *testing.T, mutate func(*policy.Config)) *fixture {
	t.Helper()
	up := dnstest.Start(t)
	up.AddA("api.alpha.test", "203.0.113.10")
	up.AddAAAA("api.alpha.test", "2001:db8::10")
	up.AddTXT("api.alpha.test", "v=spf1 -all")
	up.AddA("beta.test", "203.0.113.20")
	up.AddWildcardA("wild.alpha.test", "203.0.113.11")
	up.AddA("rebind.alpha.test", "169.254.169.254")
	up.AddA("mixed.alpha.test", "10.0.0.5", "203.0.113.12")
	up.AddCNAME("alias.alpha.test", "edge.cdn.test")
	up.AddA("edge.cdn.test", "203.0.113.13")
	up.AddWildcardA("evil.test", "203.0.113.66")
	var many []string
	for i := 1; i <= 120; i++ {
		many = append(many, fmt.Sprintf("203.0.113.%d", i))
	}
	up.AddA("big.alpha.test", many...)

	cfg := &policy.Config{
		Listen:      &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS: []string{up.Addr},
		Callers: []policy.Caller{
			{Name: "alpha", IP: alphaIP.String(), Allow: []string{
				"api.alpha.test:443", "*.wild.alpha.test:443", "rebind.alpha.test:443",
				"mixed.alpha.test:443", "alias.alpha.test:443", "big.alpha.test:443", "198.51.100.7:443",
			}},
			{Name: "beta", IP: betaIP.String(), Allow: []string{"beta.test:443"}},
		},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{},
	}
	if mutate != nil {
		mutate(cfg)
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st := stats.New(time.Now(), 0)
	up4 := upstream.New(pol.Upstreams(), time.Second)
	return &fixture{srv: New(pol, up4, st, func(ap netip.AddrPort) netip.Addr { return ap.Addr() }, limits.Config{}), up: up, stats: st}
}

func (f *fixture) ask(from netip.Addr, name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	return f.srv.answer(&net.UDPAddr{IP: from.AsSlice(), Port: 5353}, q)
}

func addrs(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		case *dns.CNAME:
			out = append(out, "cname:"+v.Target)
		}
	}
	return out
}

func TestAllowedNamesAreForwarded(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"api.alpha.test", dns.TypeA, "[203.0.113.10]"},
		{"API.Alpha.Test", dns.TypeA, "[203.0.113.10]"},
		{"api.alpha.test", dns.TypeAAAA, "[2001:db8::10]"},
		{"x1.wild.alpha.test", dns.TypeA, "[203.0.113.11]"},
		{"alias.alpha.test", dns.TypeA, "[cname:edge.cdn.test. 203.0.113.13]"},
	}
	for _, c := range cases {
		m := f.ask(alphaIP, c.name, c.qtype)
		if m.Rcode != dns.RcodeSuccess || fmt.Sprint(addrs(m)) != c.want {
			t.Errorf("%s %s: rcode %s answers %v, want %s", c.name, dns.TypeToString[c.qtype], dns.RcodeToString[m.Rcode], addrs(m), c.want)
		}
		if !m.Response || m.Question[0].Name != dns.Fqdn(c.name) {
			t.Errorf("%s: reply header/question wrong: %v", c.name, m.Question)
		}
	}
	if n := f.stats.Snapshot().Blocked.Total(); n != 0 {
		t.Errorf("allowed lookups counted as blocked: %d", n)
	}
}

func TestBlockedNamesGetNXDOMAINAndAreCounted(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"x7f3a9c1.evil.test", "q2w3e4.evil.test", "a.b.wild.alpha.test", "wild.alpha.test", "alpha.test"} {
		m := f.ask(alphaIP, name, dns.TypeA)
		if m.Rcode != dns.RcodeNameError || len(m.Answer) != 0 {
			t.Errorf("%s: rcode %s answers %v, want NXDOMAIN", name, dns.RcodeToString[m.Rcode], addrs(m))
		}
	}
	if f.up.QueriedName("x7f3a9c1.evil.test") {
		t.Error("blocked name leaked to the upstream resolver")
	}
	b := f.stats.Snapshot().Callers["alpha"].Blocked
	// Every name off the allowlist is one fixed key: the queried labels and
	// the registrable domain never leave the VM.
	if b["unlisted:53"] != 5 || len(b) != 1 {
		t.Errorf("blocked counts = %v, want only unlisted:53", b)
	}
}

func TestTunnelingTypes(t *testing.T) {
	f := newFixture(t)
	// Not allowed: NXDOMAIN whatever the type.
	for _, qt := range []uint16{dns.TypeTXT, dns.TypeANY, dns.TypeNULL, dns.TypeMX, dns.TypeCNAME} {
		if m := f.ask(alphaIP, "data123.evil.test", qt); m.Rcode != dns.RcodeNameError {
			t.Errorf("%s on blocked name: %s", dns.TypeToString[qt], dns.RcodeToString[m.Rcode])
		}
	}
	// Allowed name: ANY refused, other non-address types get an empty answer
	// and never reach the upstream.
	if m := f.ask(alphaIP, "api.alpha.test", dns.TypeANY); m.Rcode != dns.RcodeRefused {
		t.Errorf("ANY: %s", dns.RcodeToString[m.Rcode])
	}
	m := f.ask(alphaIP, "api.alpha.test", dns.TypeTXT)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Errorf("TXT on allowed name: %s %v", dns.RcodeToString[m.Rcode], m.Answer)
	}
	for _, q := range f.up.Queries() {
		if q.Type != dns.TypeA && q.Type != dns.TypeAAAA {
			t.Errorf("non-address query %s reached the upstream", dns.TypeToString[q.Type])
		}
	}
	chaos := new(dns.Msg)
	chaos.SetQuestion("api.alpha.test.", dns.TypeA)
	chaos.Question[0].Qclass = dns.ClassCHAOS
	if r := f.srv.answer(&net.UDPAddr{IP: alphaIP.AsSlice()}, chaos); r.Rcode != dns.RcodeRefused {
		t.Errorf("CHAOS class: %s", dns.RcodeToString[r.Rcode])
	}
}

func TestRebindingAnswersAreFiltered(t *testing.T) {
	f := newFixture(t)
	m := f.ask(alphaIP, "rebind.alpha.test", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Errorf("metadata answer not stripped: %v", addrs(m))
	}
	m = f.ask(alphaIP, "mixed.alpha.test", dns.TypeA)
	if fmt.Sprint(addrs(m)) != "[203.0.113.12]" {
		t.Errorf("private answer not stripped: %v", addrs(m))
	}
	b := f.stats.Snapshot().Callers["alpha"].Blocked
	if b["rebind.alpha.test:53"] != 1 || b["mixed.alpha.test:53"] != 1 {
		t.Errorf("rebinding not counted: %v", b)
	}
}

// TestPrivateAnswersAreFilteredInsideAllowedRanges: a name never resolves
// to a private address, even one inside allowedPrivateCidrs that the
// caller lists as a raw IP entry (runtime-1).
func TestPrivateAnswersAreFilteredInsideAllowedRanges(t *testing.T) {
	f := newFixtureWith(t, func(cfg *policy.Config) {
		cfg.AllowedPrivateCIDRs = []string{"10.0.0.0/8"}
		cfg.Callers[0].Allow = append(cfg.Callers[0].Allow, "10.0.0.5:443")
	})
	m := f.ask(alphaIP, "mixed.alpha.test", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || fmt.Sprint(addrs(m)) != "[203.0.113.12]" {
		t.Errorf("private answer inside allowedPrivateCidrs not stripped: %s %v", dns.RcodeToString[m.Rcode], addrs(m))
	}
	if b := f.stats.Snapshot().Callers["alpha"].Blocked; b["mixed.alpha.test:53"] != 1 {
		t.Errorf("rebinding not counted: %v", b)
	}
}

func TestPerCallerIsolationAndUnknownSources(t *testing.T) {
	f := newFixture(t)
	if m := f.ask(betaIP, "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Errorf("beta resolved alpha's name: %s", dns.RcodeToString[m.Rcode])
	}
	if m := f.ask(alphaIP, "beta.test", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Errorf("alpha resolved beta's name: %s", dns.RcodeToString[m.Rcode])
	}
	if m := f.ask(betaIP, "beta.test", dns.TypeA); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("beta cannot resolve its own name: %s", dns.RcodeToString[m.Rcode])
	}
	if m := f.ask(netip.MustParseAddr("172.30.0.99"), "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Errorf("unknown source: %s", dns.RcodeToString[m.Rcode])
	}
	s := f.stats.Snapshot()
	if s.Callers["beta"].Blocked["unlisted:53"] != 1 || s.Callers["alpha"].Blocked["unlisted:53"] != 1 {
		t.Errorf("isolation blocks not counted: %v", s.Callers)
	}
	if s.Callers[policy.UnknownCaller].Blocked["unlisted:53"] != 1 {
		t.Errorf("unknown source not counted: %v", s.Callers)
	}
}

func TestMalformedQueries(t *testing.T) {
	f := newFixture(t)
	two := new(dns.Msg)
	two.SetQuestion("api.alpha.test.", dns.TypeA)
	two.Question = append(two.Question, two.Question[0])
	if r := f.srv.answer(&net.UDPAddr{IP: alphaIP.AsSlice()}, two); r.Rcode != dns.RcodeFormatError {
		t.Errorf("two questions: %s", dns.RcodeToString[r.Rcode])
	}
	notify := new(dns.Msg)
	notify.SetNotify("alpha.test.")
	if r := f.srv.answer(&net.UDPAddr{IP: alphaIP.AsSlice()}, notify); r.Rcode != dns.RcodeNotImplemented {
		t.Errorf("NOTIFY: %s", dns.RcodeToString[r.Rcode])
	}
	if m := f.ask(alphaIP, `bad\000name.alpha.test`, dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Errorf("binary label: %s", dns.RcodeToString[m.Rcode])
	}
}

func TestQueryRateIsPerCaller(t *testing.T) {
	f := newFixture(t)
	f.srv.rate = limits.NewRate(0.001, 3)
	for i := 0; i < 3; i++ {
		if m := f.ask(alphaIP, "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeSuccess {
			t.Fatalf("query %d: %s", i, dns.RcodeToString[m.Rcode])
		}
	}
	before := len(f.up.Queries())
	for i := 0; i < 5; i++ {
		if m := f.ask(alphaIP, "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeRefused {
			t.Fatalf("over the rate: %s, want REFUSED", dns.RcodeToString[m.Rcode])
		}
	}
	if len(f.up.Queries()) != before {
		t.Error("rate-limited queries reached the upstream")
	}
	if m := f.ask(betaIP, "beta.test", dns.TypeA); m.Rcode != dns.RcodeSuccess {
		t.Errorf("beta limited by alpha's flood: %s", dns.RcodeToString[m.Rcode])
	}
	if got := f.stats.Snapshot().Callers["alpha"].Blocked[policy.KeyRateLimitedDNS]; got != 5 {
		t.Errorf("rate-limited count = %d", got)
	}
}

func TestInflightUpstreamQueriesAreCapped(t *testing.T) {
	f := newFixture(t)
	f.srv.inflight = limits.NewInflight(1)
	hold, ok := f.srv.inflight.Begin("alpha")
	if !ok {
		t.Fatal("Begin")
	}
	if m := f.ask(alphaIP, "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Errorf("over the in-flight cap: %s", dns.RcodeToString[m.Rcode])
	}
	// Answers that need no upstream still work.
	if m := f.ask(alphaIP, "evil.test", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Errorf("blocked name: %s", dns.RcodeToString[m.Rcode])
	}
	hold()
	if m := f.ask(alphaIP, "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeSuccess {
		t.Errorf("after release: %s", dns.RcodeToString[m.Rcode])
	}
}

func TestUpstreamFailureIsServfail(t *testing.T) {
	f := newFixture(t)
	f.up.SetServfail(true)
	if m := f.ask(alphaIP, "api.alpha.test", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
}

// TestTruncationOverUDPAndTCP runs the server on real sockets: a big answer
// is truncated for a plain UDP client, and the TCP retry gets all of it.
func TestTruncationOverUDPAndTCP(t *testing.T) {
	f := newFixture(t)
	f.srv.sourceIP = func(netip.AddrPort) netip.Addr { return alphaIP }
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Skipf("tcp port collision: %v", err)
	}
	f.srv.Serve(pc, ln, nil)
	t.Cleanup(func() { _ = f.srv.Shutdown(context.Background()) })
	server := pc.LocalAddr().String()

	q := new(dns.Msg)
	q.SetQuestion("big.alpha.test.", dns.TypeA)
	udp := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	r, _, err := udp.Exchange(q, server)
	if err != nil {
		t.Fatal(err)
	}
	r.Compress = true // Len reports the compressed wire size
	if !r.Truncated || len(r.Answer) >= 120 || r.Len() > dns.MinMsgSize {
		t.Fatalf("UDP answer: truncated=%v answers=%d len=%d", r.Truncated, len(r.Answer), r.Len())
	}
	tcp := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	r, _, err = tcp.Exchange(q, server)
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated || len(r.Answer) != 120 {
		t.Fatalf("TCP answer: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}

	// With EDNS0 the UDP client gets as much as its buffer allows.
	q.SetEdns0(4096, false)
	r, _, err = udp.Exchange(q, server)
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated || len(r.Answer) != 120 {
		t.Errorf("EDNS UDP answer: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
}
