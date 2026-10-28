package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/sealed-dev/sealed/runtime/egress/internal/dnstest"
)

func addr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// deadServer returns an address with nothing listening on UDP.
func deadServer(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := pc.LocalAddr().String()
	pc.Close()
	return addr(t, a)
}

func TestLookupIPOrderAndFamilies(t *testing.T) {
	up := dnstest.Start(t)
	up.AddA("api.example.test", "203.0.113.10", "203.0.113.11")
	up.AddAAAA("api.example.test", "2001:db8::10")
	c := New([]netip.AddrPort{addr(t, up.Addr)}, time.Second)
	ctx := context.Background()

	ips, err := c.LookupIP(ctx, "ip", "API.example.test.")
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(ips)
	if got != "[203.0.113.10 203.0.113.11 2001:db8::10]" {
		t.Errorf("ip = %s", got)
	}
	if ips, _ := c.LookupIP(ctx, "ip4", "api.example.test"); len(ips) != 2 {
		t.Errorf("ip4 = %v", ips)
	}
	if ips, _ := c.LookupIP(ctx, "ip6", "api.example.test"); len(ips) != 1 || ips[0].String() != "2001:db8::10" {
		t.Errorf("ip6 = %v", ips)
	}
	if ips, err := c.LookupIP(ctx, "ip", "198.51.100.7"); err != nil || ips[0].String() != "198.51.100.7" {
		t.Errorf("IP literal = %v, %v", ips, err)
	}
	if _, err := c.LookupIP(ctx, "tcp", "api.example.test"); err == nil {
		t.Error("unsupported network accepted")
	}
}

func TestLookupIPNotFound(t *testing.T) {
	up := dnstest.Start(t)
	c := New([]netip.AddrPort{addr(t, up.Addr)}, time.Second)
	_, err := c.LookupIP(context.Background(), "ip", "missing.example.test")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("err = %v, want not-found DNSError", err)
	}
	if _, err := c.LookupIP(context.Background(), "ip", "localhost"); err == nil {
		t.Error("single-label name resolved")
	}
	if up.QueriedName("localhost") {
		t.Error("invalid name was sent upstream")
	}
}

func TestLookupIPFollowsCNAMEChainOnly(t *testing.T) {
	up := dnstest.Start(t)
	up.AddCNAME("www.example.test", "edge.cdn.test")
	up.AddA("edge.cdn.test", "203.0.113.50")
	c := New([]netip.AddrPort{addr(t, up.Addr)}, time.Second)
	ips, err := c.LookupIP(context.Background(), "ip4", "www.example.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "203.0.113.50" {
		t.Fatalf("ips = %v, %v", ips, err)
	}

	// Records for owners off the chain are ignored.
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "other.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("10.0.0.1")},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "a.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "b.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "B.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("203.0.113.9")},
	}
	got := AddressesFor(m, "a.test", dns.TypeA)
	if len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Errorf("AddressesFor = %v", got)
	}
}

func TestExchangeFailsOverToNextServer(t *testing.T) {
	broken := dnstest.Start(t)
	broken.SetServfail(true)
	good := dnstest.Start(t)
	good.AddA("api.example.test", "203.0.113.10")
	c := New([]netip.AddrPort{deadServer(t), addr(t, broken.Addr), addr(t, good.Addr)}, 300*time.Millisecond)
	for i := 0; i < 3; i++ { // every starting server must end at the good one
		ips, err := c.LookupIP(context.Background(), "ip4", "api.example.test")
		if err != nil || len(ips) != 1 {
			t.Fatalf("round %d: %v, %v", i, ips, err)
		}
	}
}

func TestExchangeRetriesTruncatedAnswerOverTCP(t *testing.T) {
	up := dnstest.Start(t)
	var many []string
	for i := 1; i <= 120; i++ {
		many = append(many, fmt.Sprintf("203.0.113.%d", i))
	}
	up.AddA("big.example.test", many...)
	c := New([]netip.AddrPort{addr(t, up.Addr)}, time.Second)
	ips, err := c.LookupIP(context.Background(), "ip4", "big.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 120 {
		t.Fatalf("got %d addresses, want 120", len(ips))
	}
	sawUDP, sawTCP := false, false
	for _, q := range up.Queries() {
		if q.Name == "big.example.test." {
			sawUDP = sawUDP || q.Net == "udp"
			sawTCP = sawTCP || q.Net == "tcp"
		}
	}
	if !sawUDP || !sawTCP {
		t.Errorf("udp %v tcp %v: want a UDP try then a TCP retry", sawUDP, sawTCP)
	}
}

func TestSameQuestion(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("a.example.test.", dns.TypeA)
	r := new(dns.Msg)
	r.SetQuestion("A.EXAMPLE.test.", dns.TypeA)
	if err := sameQuestion(q, r); err != nil {
		t.Errorf("case difference rejected: %v", err)
	}
	r.SetQuestion("b.example.test.", dns.TypeA)
	if sameQuestion(q, r) == nil {
		t.Error("different name accepted")
	}
	r.SetQuestion("a.example.test.", dns.TypeAAAA)
	if sameQuestion(q, r) == nil {
		t.Error("different type accepted")
	}
}

func TestLookupPort(t *testing.T) {
	c := New(nil, 0)
	if p, err := c.LookupPort(context.Background(), "tcp", "443"); err != nil || p != 443 {
		t.Errorf("443 = %d, %v", p, err)
	}
	for _, bad := range []string{"https", "0", "0443", "65536", ""} {
		if _, err := c.LookupPort(context.Background(), "tcp", bad); err == nil {
			t.Errorf("LookupPort(%q) accepted", bad)
		}
	}
	if _, err := c.Exchange(context.Background(), new(dns.Msg)); err == nil {
		t.Error("Exchange without servers succeeded")
	}
}
