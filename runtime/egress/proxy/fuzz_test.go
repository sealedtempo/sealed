package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stripe/smokescreen/pkg/smokescreen/hostport"

	"github.com/sealedtempo/sealed/runtime/egress/auth"
	"github.com/sealedtempo/sealed/runtime/egress/limits"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	"github.com/sealedtempo/sealed/runtime/egress/stats"
)

// fuzzAllow is the allowlist of the fuzzed caller. rebind.example.com resolves
// to the metadata address, which must never be dialed.
var fuzzAllow = []string{
	"api.example.com:443", "*.wild.example.com:443", "example.org:80", "198.51.100.7:443",
	"plain.example.net:8080", "rebind.example.com:443", "xn--bcher-kva.example:443",
}

var fuzzRequestSeeds = []string{
	"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
	"CONNECT API.Example.COM.:443 HTTP/1.1\r\nHost: API.Example.COM.:443\r\n\r\n",
	"CONNECT a.wild.example.com:443 HTTP/1.1\r\nHost: a.wild.example.com:443\r\n\r\n",
	"CONNECT a.b.wild.example.com:443 HTTP/1.1\r\nHost: a.b.wild.example.com:443\r\n\r\n",
	"CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n",
	"CONNECT [::ffff:198.51.100.7]:443 HTTP/1.1\r\nHost: [::ffff:198.51.100.7]:443\r\n\r\n",
	"CONNECT rebind.example.com:443 HTTP/1.1\r\nHost: rebind.example.com:443\r\n\r\n",
	"CONNECT bücher.example:443 HTTP/1.1\r\nHost: bücher.example:443\r\n\r\n",
	"CONNECT api.example.com:0443 HTTP/1.1\r\nHost: api.example.com:0443\r\n\r\n",
	"CONNECT api.example.com:+443 HTTP/1.1\r\nHost: api.example.com:+443\r\n\r\n",
	"GET http://example.org/x?y=1 HTTP/1.1\r\nHost: example.org\r\n\r\n",
	"GET http://EXAMPLE.org./ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
	"GET http://plain.example.net:8080/ HTTP/1.1\r\nHost: plain.example.net:8080\r\n\r\n",
	"GET http://example.org:80@evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
	"GET http://ex%C3%A4mple.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
	"POST http://example.org/ HTTP/1.1\r\nHost: example.org\r\nContent-Length: 3\r\n\r\nabc",
	"GET https://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	"GET /relative HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
	"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nX-Upstream-Https-Proxy: https://proxy.example\r\n\r\n",
}

func fuzzAllowlist(t testing.TB) *policy.Allowlist {
	var es []policy.Entry
	for _, s := range fuzzAllow {
		e, err := policy.ParseEntry(s)
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
	}
	return policy.NewAllowlist(es)
}

// resolvedName is the name the upstream resolver would query for host as
// smokescreen passes it (upstream.Client.LookupIP normalizes the same way).
func resolvedName(host string) (string, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), true
	}
	n, err := policy.NormalizeHostname(host)
	return n, err == nil
}

// FuzzDestination: whenever destination accepts a request and the allowlist
// allows the result, smokescreen (which resolves and dials) must target
// exactly that host and port. A difference would mean the ACL judged one
// name and the proxy connects to another.
func FuzzDestination(f *testing.F) {
	for _, s := range fuzzRequestSeeds {
		f.Add([]byte(s))
	}
	allow := fuzzAllowlist(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		host, port, err := destination(r)
		if err != nil {
			if key, _ := requestKey(allow, r); !keyInVocabulary(allow, key) {
				t.Fatalf("requestKey %q is outside the stats vocabulary", key)
			}
			return
		}
		if again, err := policy.NormalizeHostname(host); err == nil && again != host {
			t.Fatalf("destination host %q is not normalized (%q)", host, again)
		}
		e, ok := allow.Match(host, port)
		if !ok {
			return
		}
		var hp hostport.HostPort
		if r.Method == http.MethodConnect {
			hp, err = hostport.New(r.Host, false)
		} else {
			hp, err = hostport.NewWithScheme(r.Host, r.URL.Scheme, false)
		}
		if err != nil {
			return // smokescreen refuses the request itself
		}
		name, ok := resolvedName(hp.Host)
		if !ok || name != host || hp.Port != int(port) {
			t.Fatalf("ACL allowed %s:%d by %v, but smokescreen targets %q (resolves %q) port %d", host, port, e, hp.Host, name, hp.Port)
		}
		if r.Method != http.MethodConnect {
			// http.Transport dials the URL's host; smokescreen re-resolves it
			// when it differs from the checked destination.
			tname, ok := resolvedName(r.URL.Hostname())
			if !ok || tname != host {
				t.Fatalf("ACL allowed %s:%d, but the transport dials %q", host, port, r.URL.Host)
			}
		}
	})
}

// fuzzProxy runs a real Proxy on loopback with a recording resolver and
// dialer, so the fuzzer drives smokescreen and goproxy's own request parsing.
type fuzzProxy struct {
	p     *Proxy
	ln    *memListener
	allow *policy.Allowlist
	st    *stats.Counter

	mu      sync.Mutex
	lookups []string
	dials   []string
}

const (
	fuzzNameIP     = "203.0.113.10"
	fuzzRebindName = "rebind.example.com"
)

func (fp *fuzzProxy) LookupPort(_ context.Context, _, service string) (int, error) {
	p, err := policy.ParsePort(service)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", service)
	}
	return int(p), nil
}

func (fp *fuzzProxy) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	fp.mu.Lock()
	fp.lookups = append(fp.lookups, host)
	fp.mu.Unlock()
	if ip, err := netip.ParseAddr(host); err == nil {
		return []net.IP{net.IP(ip.Unmap().AsSlice())}, nil
	}
	name, err := policy.NormalizeHostname(host)
	if err != nil {
		return nil, &net.DNSError{Err: "invalid hostname", Name: host, IsNotFound: true}
	}
	if name == fuzzRebindName {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	return []net.IP{net.ParseIP(fuzzNameIP)}, nil
}

func (fp *fuzzProxy) dial(_ context.Context, _, addr string) (net.Conn, error) {
	fp.mu.Lock()
	fp.dials = append(fp.dials, addr)
	fp.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		for {
			// Plain HTTP requests arrive right after the dial; a tunnel's
			// client sends nothing more, so the upstream hangs up quickly.
			_ = server.SetDeadline(time.Now().Add(50 * time.Millisecond))
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			if _, err := io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
				return
			}
		}
	}()
	return client, nil
}

func newFuzzProxy(f *testing.F) *fuzzProxy {
	for _, v := range proxyEnvVars {
		f.Setenv(v, "")
	}
	cfg := &policy.Config{
		Listen:              &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: "127.0.0.1:0"},
		UpstreamDNS:         []string{"127.0.0.1:53"},
		Callers:             []policy.Caller{{Name: "alpha", IP: "172.30.0.16", Allow: fuzzAllow}},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{},
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		f.Fatal(err)
	}
	tokens, err := auth.Provision(f.TempDir(), pol.ProxyAuthCallers())
	if err != nil {
		f.Fatal(err)
	}
	fp := &fuzzProxy{allow: fuzzAllowlist(f), st: stats.New(time.Now(), 0)}
	alpha := netip.MustParseAddr("172.30.0.16")
	p, err := New(Options{
		Tokens:   tokens,
		Policy:   pol,
		Resolver: fp,
		Stats:    fp.st,
		SourceIP: func(netip.AddrPort) netip.Addr { return alpha },
		Dial:     fp.dial,
		Limits: limits.Config{
			RequestRate: 1e9, RequestBurst: 1 << 30,
			ConnsPerCaller: 1 << 20, ConnsReserved: 1 << 20, ConnsShared: 1 << 20,
		},
		ConnectTimeout:    2 * time.Second,
		IdleTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	})
	if err != nil {
		f.Fatal(err)
	}
	ln := &memListener{ch: make(chan net.Conn), closed: make(chan struct{})}
	go func() { _ = p.Serve(ln) }()
	f.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	fp.p, fp.ln = p, ln
	return fp
}

// memListener hands in-memory connections to the proxy: a fuzz run makes
// hundreds of thousands of requests, more than loopback has ephemeral ports.
type memListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3128} }

// memConn is a client that sends raw, waits for the first answer bytes, then
// reads EOF, as a client that closes after the response. raw without a
// complete header block gets EOF at once (the server cannot answer it).
type memConn struct {
	r        *bytes.Reader
	complete bool
	mu       sync.Mutex
	out      bytes.Buffer
	wrote    chan struct{}
	done     chan struct{}
	wOnce    sync.Once
	cOnce    sync.Once
	// kick wakes a blocked Read when a past read deadline is set (net/http
	// does that to abort its background read before a CONNECT hijack).
	kick    chan struct{}
	expired atomic.Bool
}

func newMemConn(raw []byte) *memConn {
	complete := bytes.Contains(raw, []byte("\n\n")) || bytes.Contains(raw, []byte("\n\r\n"))
	return &memConn{r: bytes.NewReader(raw), complete: complete, wrote: make(chan struct{}), done: make(chan struct{}), kick: make(chan struct{}, 1)}
}

func (c *memConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.r.Len() > 0 {
		defer c.mu.Unlock()
		return c.r.Read(b)
	}
	c.mu.Unlock()
	if !c.complete {
		return 0, io.EOF
	}
	t := time.NewTimer(200 * time.Millisecond)
	defer t.Stop()
	for {
		if c.expired.Load() {
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case <-c.wrote:
			return 0, io.EOF
		case <-c.done:
			return 0, net.ErrClosed
		case <-c.kick:
		case <-t.C:
			return 0, io.EOF
		}
	}
}

func (c *memConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	c.out.Write(b)
	c.mu.Unlock()
	c.wOnce.Do(func() { close(c.wrote) })
	return len(b), nil
}

func (c *memConn) Close() error {
	c.cOnce.Do(func() { close(c.done) })
	return nil
}

func (c *memConn) LocalAddr() net.Addr           { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3128} }
func (c *memConn) RemoteAddr() net.Addr          { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000} }
func (c *memConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *memConn) SetReadDeadline(t time.Time) error {
	past := !t.IsZero() && !t.After(time.Now())
	c.expired.Store(past)
	if past {
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
	return nil
}

func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

// send gives raw to the proxy as one connection and waits until the proxy
// closes it.
func (fp *fuzzProxy) send(raw []byte) ([]byte, error) {
	c := newMemConn(raw)
	fp.ln.ch <- c
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		return nil, errors.New("connection still open after 5s")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.out.Bytes()), nil
}

func (fp *fuzzProxy) drain() (lookups, dials []string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	lookups, dials = fp.lookups, fp.dials
	fp.lookups, fp.dials = nil, nil
	return lookups, dials
}

// FuzzProxy sends arbitrary bytes to a running proxy. Properties: the
// resolver is only asked for names (or IPs) the caller's allowlist allows,
// only checked public addresses are dialed (never the metadata address an
// allowed name resolves to), and every stats key is in the fixed vocabulary.
func FuzzProxy(f *testing.F) {
	for _, s := range fuzzRequestSeeds {
		f.Add([]byte(s))
	}
	fp := newFuzzProxy(f)
	allowedPorts := map[string]bool{}
	for _, s := range fuzzAllow {
		_, port, _ := net.SplitHostPort(s)
		allowedPorts[port] = true
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, err := fp.send(raw); err != nil {
			t.Fatalf("proxy did not finish: %v", err)
		}
		lookups, dials := fp.drain()
		for _, h := range lookups {
			name, ok := resolvedName(h)
			if !ok {
				t.Fatalf("resolver asked for invalid host %q", h)
			}
			if ip, err := netip.ParseAddr(name); err == nil {
				if _, ok := fp.allow.Match(ip.String(), 443); !ok {
					t.Fatalf("resolver asked for IP %q, which no entry allows", h)
				}
				continue
			}
			if _, ok := fp.allow.MatchName(name); !ok {
				t.Fatalf("resolver asked for %q, which the allowlist does not list", h)
			}
		}
		for _, d := range dials {
			ap, err := netip.ParseAddrPort(d)
			if err != nil {
				t.Fatalf("dialed unresolved address %q", d)
			}
			port := fmt.Sprint(ap.Port())
			switch ap.Addr().String() {
			case "198.51.100.7":
				if ap.Port() != 443 {
					t.Fatalf("dialed %s, the IP entry allows only port 443", d)
				}
			case fuzzNameIP:
				if !allowedPorts[port] {
					t.Fatalf("dialed %s on a port no entry lists", d)
				}
			default:
				t.Fatalf("dialed %s, which no allowed name resolves to", d)
			}
		}
		snap := fp.st.Snapshot()
		for caller, cs := range snap.Callers {
			for key := range cs.Blocked {
				if !keyInVocabulary(fp.allow, key) {
					t.Fatalf("caller %s: stats key %q is outside the vocabulary", caller, key)
				}
			}
			for key := range cs.Allowed {
				if !isEntry(fp.allow, key) {
					t.Fatalf("caller %s: allowed key %q is not an entry", caller, key)
				}
			}
		}
	})
}

var ipClassNames = []string{"public", "private", "metadata", "loopback", "link-local", "unspecified", "multicast", "ipv4-embedding", "reserved", "vm-internal"}

func isEntry(allow *policy.Allowlist, key string) bool {
	for _, e := range allow.Entries() {
		if e.String() == key {
			return true
		}
	}
	return false
}

// keyInVocabulary reports whether a stats key is an allowlist entry, an
// entry pattern with a port token, or built from the fixed words (P5).
func keyInVocabulary(allow *policy.Allowlist, key string) bool {
	switch key {
	case policy.KeyUnauthenticated, policy.KeyRateLimited, policy.KeyRateLimitedDNS, "other:0", policy.KeyInvalid + ":0":
		return true
	}
	if isEntry(allow, key) {
		return true
	}
	pattern, tok, ok := cutLast(key, ":")
	if !ok {
		return false
	}
	if tok != policy.PortOther && allow.PortToken(parsePortOr0(tok)) != tok {
		return false
	}
	if pattern == policy.KeyUnlisted || pattern == policy.KeyInvalid {
		return true
	}
	if class, ok := strings.CutPrefix(pattern, "ip-"); ok {
		for _, c := range ipClassNames {
			if c == class {
				return true
			}
		}
		return false
	}
	for _, e := range allow.Entries() {
		if e.HostPattern() == pattern {
			return true
		}
	}
	return false
}

func cutLast(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

func parsePortOr0(s string) uint16 {
	p, err := policy.ParsePort(s)
	if err != nil {
		return 0
	}
	return p
}
