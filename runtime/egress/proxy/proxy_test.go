package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"

	"github.com/sealedtempo/sealed/runtime/egress/auth"
	"github.com/sealedtempo/sealed/runtime/egress/limits"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	"github.com/sealedtempo/sealed/runtime/egress/stats"
	"github.com/sealedtempo/sealed/runtime/egress/upstream"
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

type testProxy struct {
	*Proxy
	authDir string
}

func newTestProxy(t *testing.T) *Proxy { return newTestProxyWith(t, false).Proxy }

// newTestProxyWith builds a proxy for alpha (172.30.0.16) and sealed-agent
// (172.30.0.3); withAuth makes alpha a proxyAuth caller.
func newTestProxyWith(t *testing.T, withAuth bool) testProxy {
	t.Helper()
	for _, v := range proxyEnvVars {
		t.Setenv(v, "")
	}
	cfg := &policy.Config{
		Listen:      &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS: []string{"127.0.0.1:53"},
		Callers: []policy.Caller{
			{Name: "alpha", IP: "172.30.0.16", Allow: []string{"api.example.com:443"}, ProxyAuth: withAuth},
			{Name: "sealed-agent", IP: "172.30.0.3", Allow: []string{}},
		},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{},
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tokens, err := auth.Provision(dir, pol.ProxyAuthCallers())
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{
		Tokens:   tokens,
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
	return testProxy{Proxy: p, authDir: dir}
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
		// As the raw IP itself, as an allowlisted name resolving to it, and
		// with no smokescreen decision at all.
		for _, ctx := range []context.Context{decisionCtx("alpha", addr), decisionCtx("alpha", "api.example.com:443"), context.Background()} {
			if _, err := p.dial(ctx, "tcp", addr, time.Second); err == nil {
				t.Errorf("dial(%s) allowed", addr)
			}
		}
	}
}

// decisionCtx is the context smokescreen hands to dial: the goproxy ctx
// carrying its decision for role and the requested host:port.
func decisionCtx(role, outboundHost string) context.Context {
	sctx := &smokescreen.SmokescreenContext{Decision: &smokescreen.ACLDecision{Role: role, OutboundHost: outboundHost}}
	return context.WithValue(context.Background(), goproxy.ProxyContextKey, &goproxy.ProxyCtx{UserData: sctx})
}

// TestDialChecksTheCallerAndRequestedHost: dial admits a private address
// only for the caller that lists it as a raw IP entry and only when the
// request named that address, never for a hostname (runtime-1).
func TestDialChecksTheCallerAndRequestedHost(t *testing.T) {
	for _, v := range proxyEnvVars {
		t.Setenv(v, "")
	}
	cfg := &policy.Config{
		Listen:      &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS: []string{"127.0.0.1:53"},
		Callers: []policy.Caller{
			{Name: "alpha", IP: "172.30.0.16", Allow: []string{"10.20.0.5:443", "api.example.com:443"}},
			{Name: "beta", IP: "172.30.0.17", Allow: []string{"beta-site.example:443"}},
		},
		AllowedPrivateCIDRs: []string{"10.20.0.0/16"},
		StatsReaders:        []string{},
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	p, err := New(Options{
		Policy:   pol,
		Resolver: upstream.New(pol.Upstreams(), time.Second),
		Stats:    stats.New(time.Now(), 0),
		SourceIP: func(ap netip.AddrPort) netip.Addr { return ap.Addr() },
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			c, peer := net.Pipe()
			peer.Close()
			return c, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ctx  context.Context
		addr string
		ok   bool
	}{
		{decisionCtx("alpha", "10.20.0.5:443"), "10.20.0.5:443", true},
		{decisionCtx("alpha", "api.example.com:443"), "203.0.113.10:443", true},
		{decisionCtx("beta", "beta-site.example:443"), "10.20.0.5:443", false}, // rebinding onto alpha's entry
		{decisionCtx("alpha", "api.example.com:443"), "10.20.0.5:443", false},  // rebinding onto its own entry
		{decisionCtx("beta", "10.20.0.5:443"), "10.20.0.5:443", false},         // not beta's entry
		{decisionCtx("alpha", "10.20.0.5:443"), "10.20.0.5:80", false},         // another port
		{decisionCtx("nobody", "10.20.0.5:443"), "10.20.0.5:443", false},       // unknown role
		{context.Background(), "203.0.113.10:443", false},                      // no decision
	}
	for _, c := range cases {
		conn, err := p.dial(c.ctx, "tcp", c.addr, time.Second)
		if conn != nil {
			conn.Close()
		}
		if (err == nil) != c.ok {
			t.Errorf("dial(%s) err = %v, want ok=%v", c.addr, err, c.ok)
		}
	}
	if fmt.Sprint(dialed) != "[10.20.0.5:443 203.0.113.10:443]" {
		t.Errorf("dialed = %v", dialed)
	}
	// Smokescreen's own rules: only the vpc instance admits a private
	// address, and only the listed ip:port.
	if len(p.cfgs[0].AllowRanges) != 0 {
		t.Errorf("names instance allows %v", p.cfgs[0].AllowRanges)
	}
	if r := p.cfgs[1].AllowRanges; len(r) != 1 || r[0].Net.String() != "10.20.0.5/32" || r[0].Port != 443 {
		t.Errorf("vpc instance allows %v", r)
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
	if s.Callers["alpha"].Blocked["unlisted:443"] != 1 || s.Blocked.Total() != 1 {
		t.Errorf("blocked = %v", s.Callers)
	}
}

func TestRequestKey(t *testing.T) {
	entries := []policy.Entry{}
	for _, s := range []string{"api.example.com:443", "198.51.100.7:443"} {
		e, err := policy.ParseEntry(s)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	allow := policy.NewAllowlist(entries)
	cases := map[string]string{
		"CONNECT secretpayload42.com:443 HTTP/1.1\r\nHost: secretpayload42.com:443\r\n\r\n":          "unlisted:443",
		"CONNECT api.example.com:22 HTTP/1.1\r\nHost: api.example.com:22\r\n\r\n":                    "api.example.com:other",
		"CONNECT 203.0.113.77:443 HTTP/1.1\r\nHost: 203.0.113.77:443\r\n\r\n":                        "ip-public:443",
		"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n":                                      "ip-loopback:443",
		"CONNECT [fd20:ce::254]:80 HTTP/1.1\r\nHost: [fd20:ce::254]:80\r\n\r\n":                      "ip-metadata:80",
		"GET http://169.254.169.254/computeMetadata/v1/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n":   "ip-metadata:80",
		"GET https://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n":                    "api.example.com:443",
		"GET https://exfil-abc123.evil.example/ HTTP/1.1\r\nHost: exfil-abc123.evil.example\r\n\r\n": "unlisted:443",
		"CONNECT api.example.com:0443 HTTP/1.1\r\nHost: api.example.com:0443\r\n\r\n":                "api.example.com:other",
		"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n":                              "invalid:443",
	}
	for raw, want := range cases {
		r := readRequest(t, raw)
		if got, _ := requestKey(allow, r); got != want {
			t.Errorf("requestKey(%q) = %q, want %q", strings.SplitN(raw, "\r\n", 2)[0], got, want)
		}
	}
}

func TestUnauthenticatedCallerGets407(t *testing.T) {
	p := newTestProxyWith(t, true)
	tok, err := os.ReadFile(filepath.Join(p.authDir, "alpha", auth.TokenFile))
	if err != nil {
		t.Fatal(err)
	}
	connect := func(hdr string) *http.Request {
		r := readRequest(t, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n"+hdr+"\r\n")
		r.RemoteAddr = "172.30.0.16:5000"
		return r
	}
	if _, err := p.roleFromRequest(connect("")); err == nil {
		t.Fatal("role granted without a credential")
	}
	creds := base64.StdEncoding.EncodeToString([]byte("alpha:" + string(tok)))
	if role, err := p.roleFromRequest(connect("Proxy-Authorization: Basic " + creds + "\r\n")); err != nil || role != "alpha" {
		t.Fatalf("role with credential = %q, %v", role, err)
	}
	resp := &http.Response{StatusCode: http.StatusProxyAuthRequired, Header: http.Header{}, Request: connect("")}
	p.onReject(nil, resp)
	if resp.StatusCode != http.StatusProxyAuthRequired || !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic") {
		t.Errorf("unauthenticated response = %d %v", resp.StatusCode, resp.Header)
	}
	if got := p.opts.Stats.Snapshot().Callers["alpha"].Blocked[policy.KeyUnauthenticated]; got != 1 {
		t.Errorf("unauthenticated not counted: %v", p.opts.Stats.Snapshot().Callers)
	}
}

func TestRateLimitIsPerCaller(t *testing.T) {
	p := newTestProxyWith(t, false)
	p.requests = limits.NewRate(0.001, 2)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := p.rateLimit(ok)
	send := func(remote string) int {
		r := readRequest(t, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 2; i++ {
		if code := send("172.30.0.16:5000"); code != http.StatusNoContent {
			t.Fatalf("request %d = %d", i, code)
		}
	}
	if code := send("172.30.0.16:5001"); code != http.StatusTooManyRequests {
		t.Fatalf("over the rate = %d, want 429", code)
	}
	if code := send("172.30.0.3:5000"); code != http.StatusNoContent {
		t.Fatalf("another caller limited by alpha's rate: %d", code)
	}
	if got := p.opts.Stats.Snapshot().Callers["alpha"].Blocked[policy.KeyRateLimited]; got != 1 {
		t.Errorf("rate-limited not counted: %v", p.opts.Stats.Snapshot().Callers)
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

func TestLimitListenerRefusesOverShareAndReleasesOnClose(t *testing.T) {
	p := newTestProxy(t)
	p.opts.SourceIP = func(netip.AddrPort) netip.Addr { return netip.MustParseAddr("172.30.0.16") }
	p.opts.Limits.ConnLifetime = 300 * time.Millisecond
	p.conns = limits.NewPool(1, 1, 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ll := &limitListener{Listener: ln, p: p}
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	first := dial()
	server := <-accepted
	second := dial()
	resp, err := http.ReadResponse(bufio.NewReader(second), nil)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("X-Sealed-Egress") != "limited" {
		t.Fatalf("over-share connection: %v %v", resp, err)
	}
	server.Close()
	third := dial()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released when the connection closed")
	}
	// The maximum lifetime closes a connection even while it is in use.
	_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still open after its lifetime")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("lifetime not enforced")
	}
	_ = first
}
