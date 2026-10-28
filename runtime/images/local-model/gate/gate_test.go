package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const gatewayIP = "172.30.0.20"

// upstream is a fake Ollama that records what reaches it.
type upstream struct {
	mu    sync.Mutex
	seen  []*http.Request
	auths []string
	srv   *httptest.Server
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r)
		u.auths = append(u.auths, r.Header.Get("Authorization"))
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("upstream " + r.Method + " " + r.URL.Path + " " + string(body)))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) hostPort() string { return strings.TrimPrefix(u.srv.URL, "http://") }

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.seen)
}

func fixedPeers(names map[string][]string) *peerSet {
	p := newPeerSet(sortedKeys(names), true)
	p.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		ips, ok := names[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		out := make([]net.IPAddr, 0, len(ips))
		for _, ip := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
		}
		return out, nil
	}
	return p
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func request(g http.Handler, method, target, from, body string, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = from + ":40000"
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestOnlyTheGatewayPeerIsServed(t *testing.T) {
	up := newUpstream(t, nil)
	g := newGate(up.hostPort(), fixedPeers(map[string][]string{"llm-gateway-litellm": {gatewayIP}}), nil, 1<<20)

	w := request(g, "POST", "/api/chat", "172.30.0.40", `{"model":"m"}`, nil) // another app (coding agent)
	if w.Code != http.StatusForbidden || up.count() != 0 {
		t.Fatalf("other app: got %d, upstream calls %d", w.Code, up.count())
	}
	w = request(g, "POST", "/api/chat", gatewayIP, `{"model":"m"}`, map[string]string{"Authorization": "Bearer sk-x"})
	if w.Code != http.StatusOK || w.Body.String() != `upstream POST /api/chat {"model":"m"}` {
		t.Fatalf("gateway: got %d %q", w.Code, w.Body.String())
	}
	if up.auths[0] != "" {
		t.Fatalf("Authorization forwarded to Ollama: %q", up.auths[0])
	}
}

func TestModelStoreAndUnknownRoutesAreRefused(t *testing.T) {
	up := newUpstream(t, nil)
	g := newGate(up.hostPort(), fixedPeers(map[string][]string{"llm-gateway-litellm": {gatewayIP}}), nil, 1<<20)
	for _, c := range []struct{ method, target string }{
		{"POST", "/api/pull"}, {"POST", "/api/push"}, {"POST", "/api/create"}, {"POST", "/api/copy"},
		{"DELETE", "/api/delete"}, {"POST", "/api/blobs/sha256:00"}, {"HEAD", "/api/blobs/sha256:00"},
		{"GET", "/api/chat"}, {"POST", "/api/chat/../pull"}, {"POST", "/api/%63hat"}, {"POST", "/api/chat%2F..%2Fpull"},
		{"GET", "/v1/models/a/b"}, {"POST", "/api/experimental/web_search"}, {"PUT", "/api/chat"},
	} {
		if w := request(g, c.method, c.target, gatewayIP, "", nil); w.Code != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", c.method, c.target, w.Code)
		}
	}
	if up.count() != 0 {
		t.Fatalf("refused routes reached Ollama %d times", up.count())
	}
}

func TestRouteAllowList(t *testing.T) {
	for _, c := range []struct {
		method, path string
		ok           bool
	}{
		{"POST", "/api/chat", true}, {"POST", "/api/generate", true}, {"POST", "/api/show", true},
		{"POST", "/api/embed", true}, {"GET", "/api/tags", true}, {"GET", "/api/version", true},
		{"GET", "/", true}, {"HEAD", "/", true}, {"POST", "/v1/chat/completions", true},
		{"GET", "/v1/models", true}, {"GET", "/v1/models/qwen3:4b-instruct-2507-q4_K_M", true},
		{"GET", "/v1/models/", false}, {"POST", "/api/pull", false}, {"GET", "/api/ps/x", false},
	} {
		u := &url.URL{Path: c.path}
		if got := routeAllowed(c.method, u); got != c.ok {
			t.Errorf("%s %s: got %v, want %v", c.method, c.path, got, c.ok)
		}
	}
}

func TestOptionalBearerKey(t *testing.T) {
	up := newUpstream(t, nil)
	g := newGate(up.hostPort(), fixedPeers(map[string][]string{"llm-gateway-litellm": {gatewayIP}}), []byte("k-0123456789abcdef"), 1<<20)
	for _, auth := range []string{"", "Bearer wrong", "k-0123456789abcdef", "Basic k-0123456789abcdef"} {
		if w := request(g, "POST", "/api/chat", gatewayIP, "{}", map[string]string{"Authorization": auth}); w.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: got %d", auth, w.Code)
		}
	}
	w := request(g, "POST", "/api/chat", gatewayIP, "{}", map[string]string{"Authorization": "Bearer k-0123456789abcdef"})
	if w.Code != http.StatusOK || up.auths[0] != "" {
		t.Fatalf("got %d, upstream auth %q", w.Code, up.auths)
	}
}

func TestPeersAreResolvedLazilyAndRateLimited(t *testing.T) {
	names := map[string][]string{}
	lookups := 0
	now := time.Unix(1000, 0)
	p := newPeerSet([]string{"llm-gateway-litellm"}, false)
	p.now = func() time.Time { return now }
	p.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if ips, ok := names[host]; ok {
			return []net.IPAddr{{IP: net.ParseIP(ips[0])}}, nil
		}
		return nil, errors.New("not running yet")
	}
	ctx := context.Background()
	if p.allowed(ctx, net.ParseIP(gatewayIP)) {
		t.Fatal("allowed before the gateway exists")
	}
	names["llm-gateway-litellm"] = []string{gatewayIP}
	if p.allowed(ctx, net.ParseIP(gatewayIP)) || lookups != 1 {
		t.Fatalf("re-resolved within the rate limit (lookups %d)", lookups)
	}
	now = now.Add(2 * time.Second)
	if !p.allowed(ctx, net.ParseIP(gatewayIP)) || lookups != 2 {
		t.Fatalf("not allowed after the gateway started (lookups %d)", lookups)
	}
	if !p.allowed(ctx, net.ParseIP("::ffff:"+gatewayIP)) || lookups != 2 {
		t.Fatal("IPv4-mapped address not matched from the cache")
	}
	if p.allowed(ctx, net.ParseIP("127.0.0.1")) {
		t.Fatal("loopback admitted although disabled")
	}
	names = map[string][]string{} // DNS hiccup keeps the last good set
	now = now.Add(2 * time.Second)
	p.allowed(ctx, net.ParseIP("172.30.0.99"))
	if !p.allowed(ctx, net.ParseIP(gatewayIP)) {
		t.Fatal("a failed refresh dropped the known peer")
	}
}

func TestHealthz(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("Ollama is running"))
	})
	g := newGate(up.hostPort(), fixedPeers(nil), nil, 1<<20)
	if w := request(g, "GET", "/healthz", "127.0.0.1", "", nil); w.Code != http.StatusOK {
		t.Fatalf("healthz: %d", w.Code)
	}
	if w := request(g, "GET", "/healthz", "172.30.0.40", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("healthz from another app: %d", w.Code)
	}
	up.srv.Close()
	if w := request(g, "GET", "/healthz", "127.0.0.1", "", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz with Ollama down: %d", w.Code)
	}
	if w := request(g, "POST", "/api/chat", "127.0.0.1", "{}", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("chat with Ollama down: %d", w.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	up := newUpstream(t, nil)
	g := newGate(up.hostPort(), fixedPeers(nil), nil, 8)
	if w := request(g, "POST", "/api/chat", "127.0.0.1", strings.Repeat("x", 64), nil); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", w.Code)
	}
}

func TestStreamsTokensAsTheyArrive(t *testing.T) {
	release := make(chan struct{})
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"token\":1}\n"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("{\"token\":2}\n"))
	})
	front := httptest.NewServer(newGate(up.hostPort(), fixedPeers(nil), nil, 1<<20))
	defer front.Close()
	resp, err := http.Post(front.URL+"/api/generate", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		if line != "{\"token\":1}\n" {
			t.Fatalf("first chunk %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first chunk was buffered until the response ended")
	}
	close(release)
	rest, _ := io.ReadAll(reader)
	if string(rest) != "{\"token\":2}\n" {
		t.Fatalf("rest %q", rest)
	}
}
