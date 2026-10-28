package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"

	"github.com/sealed-dev/sealed/runtime/egress/policy"
	"github.com/sealed-dev/sealed/runtime/egress/stats"
	"github.com/sealed-dev/sealed/runtime/egress/upstream"
)

func readRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest(%q): %v", raw, err)
	}
	return r
}

func TestDestination(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		port uint16
		ok   bool
	}{
		{"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n", "api.example.com", 443, true},
		{"CONNECT API.Example.COM.:443 HTTP/1.1\r\nHost: API.Example.COM.:443\r\n\r\n", "api.example.com", 443, true},
		{"CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n", "198.51.100.7", 443, true},
		{"GET http://api.example.com/x?y=1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "api.example.com", 80, true},
		{"GET http://api.example.com:8080/ HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n", "api.example.com", 8080, true},
		{"CONNECT api.example.com HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "", 0, false},           // no port
		{"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n", "", 0, false},                       // IPv6 literal
		{"CONNECT api.example.com:0443 HTTP/1.1\r\nHost: api.example.com:0443\r\n\r\n", "", 0, false}, // leading zero
		{"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n", "", 0, false},               // single label
		{"GET https://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "", 0, false},      // https without CONNECT
		{"GET ftp://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "", 0, false},        // other scheme
		{"GET /relative HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "", 0, false},                     // not a proxy request
	}
	for _, c := range cases {
		r := readRequest(t, c.raw)
		host, port, err := destination(r)
		if (err == nil) != c.ok || host != c.host || port != c.port {
			t.Errorf("destination(%q) = %q, %d, %v", strings.SplitN(c.raw, "\r\n", 2)[0], host, port, err)
		}
	}
	// Host header that disagrees with the absolute URL.
	r := readRequest(t, "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	r.Host = "evil.example"
	if _, _, err := destination(r); err == nil {
		t.Error("Host/URL mismatch accepted")
	}
}

func newTestProxy(t *testing.T) *Proxy {
	t.Helper()
	for _, v := range proxyEnvVars {
		t.Setenv(v, "")
	}
	cfg := &policy.Config{
		Listen:      &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS: []string{"127.0.0.1:53"},
		Callers: []policy.Caller{
			{Name: "alpha", IP: "172.30.0.16", Allow: []string{"api.example.com:443"}},
		},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{},
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{
		Policy:   pol,
		Resolver: upstream.New(pol.Upstreams(), time.Second),
		Stats:    stats.New(time.Now(), 0),
		SourceIP: func(ap netip.AddrPort) netip.Addr { return ap.Addr() },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			t.Fatalf("unexpected dial %s", addr)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeciderDeniesUnlessAllowlisted(t *testing.T) {
	p := newTestProxy(t)
	d := decider{p}
	connect := func(target, remote string, hdr ...string) *http.Request {
		raw := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" + strings.Join(hdr, "") + "\r\n"
		r := readRequest(t, raw)
		r.RemoteAddr = remote
		return r
	}
	allowed := connect("api.example.com:443", "172.30.0.16:5000")
	dec, err := d.Decide(acl.DecideArgs{Req: allowed, Service: "alpha", Host: "api.example.com"})
	if err != nil || dec.Result != acl.Allow {
		t.Fatalf("allowlisted: %+v %v", dec, err)
	}
	denials := map[string]acl.DecideArgs{
		"other host":     {Req: connect("www.example.com:443", "172.30.0.16:5000"), Service: "alpha"},
		"other port":     {Req: connect("api.example.com:80", "172.30.0.16:5000"), Service: "alpha"},
		"unknown source": {Req: connect("api.example.com:443", "172.30.0.99:5000"), Service: "alpha"},
		"role mismatch":  {Req: connect("api.example.com:443", "172.30.0.16:5000"), Service: "beta"},
		"upstream proxy": {Req: connect("api.example.com:443", "172.30.0.16:5000"), Service: "alpha", ConnectProxyHost: "proxy.example"},
		"proxy header":   {Req: connect("api.example.com:443", "172.30.0.16:5000", "X-Upstream-Https-Proxy: https://proxy.example\r\n"), Service: "alpha"},
		"mitm inner":     {Req: allowed, ConnectReq: allowed, Service: "alpha"},
		"nil request":    {Service: "alpha"},
	}
	for name, args := range denials {
		dec, err := d.Decide(args)
		if err != nil || dec.Result != acl.Deny {
			t.Errorf("%s: %+v %v, want Deny", name, dec, err)
		}
	}
	p.closing.Store(true)
	if dec, _ := d.Decide(acl.DecideArgs{Req: allowed, Service: "alpha"}); dec.Result != acl.Deny {
		t.Error("allowed while shutting down")
	}
}

func TestDialRechecksIP(t *testing.T) {
	p := newTestProxy(t)
	for _, addr := range []string{"169.254.169.254:80", "127.0.0.1:443", "10.0.0.1:443", "[fe80::1]:443", "api.example.com:443", "garbage"} {
		if _, err := p.dial(context.Background(), "tcp", addr, time.Second); err == nil {
			t.Errorf("dial(%s) allowed", addr)
		}
	}
}

func TestOnRejectRewritesOnlyPolicyDenials(t *testing.T) {
	p := newTestProxy(t)
	req := readRequest(t, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
	req.RemoteAddr = "172.30.0.16:5000"
	deny := &http.Response{StatusCode: http.StatusProxyAuthRequired, Header: http.Header{}, Request: req}
	p.onReject(nil, deny)
	if deny.StatusCode != http.StatusForbidden || deny.Header.Get("X-Sealed-Egress") != "blocked" {
		t.Errorf("deny response = %d %v", deny.StatusCode, deny.Header)
	}
	upstreamErr := &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{}, Request: req}
	p.onReject(nil, upstreamErr)
	if upstreamErr.StatusCode != http.StatusBadGateway {
		t.Error("upstream error rewritten")
	}
	s := p.opts.Stats.Snapshot()
	if s.Callers["alpha"].Blocked["*.example.com:443"] != 1 || s.Blocked.Total() != 1 {
		t.Errorf("blocked = %v", s.Callers)
	}
}

func TestNewRefusesProxyEnvironment(t *testing.T) {
	for _, v := range proxyEnvVars {
		t.Setenv(v, "")
	}
	t.Setenv("https_proxy", "http://203.0.113.1:3128")
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "https_proxy") {
		t.Fatalf("New = %v", err)
	}
}

func TestRuleRanges(t *testing.T) {
	r := ruleRanges([]netip.Prefix{netip.MustParsePrefix("169.254.169.254/32"), netip.MustParsePrefix("fe80::/10")})
	if r[0].Net.String() != "169.254.169.254/32" || r[1].Net.String() != "fe80::/10" {
		t.Errorf("ranges = %v %v", r[0].Net.String(), r[1].Net.String())
	}
	if !r[0].Net.Contains(net.ParseIP("169.254.169.254")) || r[0].Net.Contains(net.ParseIP("169.254.169.253")) {
		t.Error("IPv4 range built with the wrong mask")
	}
}
