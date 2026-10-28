package composer

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/caddy"
)

// TestCaddyfileWithRealCaddy runs the generated Caddyfiles in a real Caddy
// when SEALED_CADDY_BIN points at a caddy v2.11.x binary (see README.md).
// Hosts become http://<route>.localhost:<port> and upstreams become local
// test servers; everything else is the measured file byte for byte. A fake
// sealed-agent implements the /v1/gate contract (D-044). The test checks
// the forward_auth gate (challenge, Basic success setting the cookie, the
// cookie path keeping the app's own Authorization header, the gate's Basic
// credentials never reaching the app, request bodies surviving the gate,
// 503 while bootstrap runs, spoofed relay headers), bearer passthrough, the
// public attest route, the admin socket mode and the payment-needed switch,
// and the relay route served on the attest host.
func TestCaddyfileWithRealCaddy(t *testing.T) {
	bin := os.Getenv("SEALED_CADDY_BIN")
	if bin == "" {
		t.Skip("SEALED_CADDY_BIN not set")
	}
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)

	hits := make(chan seen, 32)
	upstream := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(req.Body)
			cookie := req.Header.Get("Cookie")
			if _, present := req.Header["Cookie"]; present && cookie == "" {
				cookie = "(empty header)"
			}
			hits <- seen{req.Method, req.URL.RequestURI(), req.Header.Get("Authorization"), cookie, string(b), req.Header.Get("X-Sealed-Gate-Set-Cookie") + req.Header.Get(caddy.GateStripHeader)}
			fmt.Fprintf(w, "hello from %s", name)
		}))
	}
	web, gw, gwAdmin := upstream("notes-web"), upstream("gateway"), upstream("gateway-admin")
	defer web.Close()
	defer gw.Close()
	defer gwAdmin.Close()
	agent := newFakeGateAgent(hits)
	defer agent.srv.Close()

	c := startCaddy(t, bin, r, map[string]string{
		"llm-gateway-proxy:4001": gwAdmin.URL, "llm-gateway-proxy:4000": gw.URL,
		"notes-web:8080": web.URL, "sealed-agent:7070": agent.srv.URL,
	}, []string{"gateway", "tools", "attest"})
	defer c.stop()

	expectHit := func(want seen) {
		t.Helper()
		select {
		case h := <-hits:
			if h != want {
				t.Errorf("upstream saw %+v, want %+v", h, want)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("upstream not reached, want %+v", want)
		}
	}
	noHit := func() {
		t.Helper()
		select {
		case h := <-hits:
			t.Errorf("unexpected upstream request %+v", h)
		case <-time.After(150 * time.Millisecond):
		}
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("sealed:gate-pw"))

	// No credentials: the agent's challenge reaches the client.
	resp := c.do("tools", "GET", "/", nil, nil)
	if resp.code != 401 || resp.header.Get("WWW-Authenticate") != `Basic realm="sealed"` {
		t.Errorf("tools without credentials: %d %q", resp.code, resp.header.Get("WWW-Authenticate"))
	}
	noHit()
	// Basic success: the cookie is set on the client response and the gate
	// credentials are stripped before the app.
	resp = c.do("tools", "GET", "/notes?x=1", map[string]string{"Authorization": basic}, nil)
	if resp.code != 200 || resp.body != "hello from notes-web" || !strings.HasPrefix(resp.header.Get("Set-Cookie"), "sealed_gate=valid-cookie;") {
		t.Errorf("tools with password: %d %q set-cookie %q", resp.code, resp.body, resp.header.Get("Set-Cookie"))
	}
	expectHit(seen{method: "GET", path: "/notes?x=1"})
	if g := agent.last(); g.route != "tools" || g.uri != "/notes?x=1" || g.method != "GET" || g.path != caddy.DefaultGatePath {
		t.Errorf("gate request %+v", g)
	}
	// Cookie path: the app's own bearer header and the request body pass.
	resp = c.do("tools", "POST", "/api/items", map[string]string{"Cookie": "sealed_gate=valid-cookie", "Authorization": "Bearer app-token"}, []byte("payload"))
	if resp.code != 200 || resp.header.Get("Set-Cookie") != "" {
		t.Errorf("tools with cookie: %d set-cookie %q", resp.code, resp.header.Get("Set-Cookie"))
	}
	expectHit(seen{method: "POST", path: "/api/items", auth: "Bearer app-token", body: "payload"})
	if g := agent.last(); g.method != "POST" || g.auth != "Bearer app-token" {
		t.Errorf("gate saw %+v", g)
	}
	// The gate cookie never reaches an app (it would be valid on other
	// apps' routes); the app's own cookies do.
	c.do("tools", "GET", "/", map[string]string{"Cookie": "theme=dark; sealed_gate=valid-cookie; lang=en"}, nil)
	expectHit(seen{method: "GET", path: "/", cookie: "theme=dark; lang=en"})
	// Cookie plus the browser's cached gate credentials: still stripped.
	c.do("tools", "GET", "/", map[string]string{"Cookie": "sealed_gate=valid-cookie", "Authorization": "basic  " + strings.TrimPrefix(basic, "Basic ")}, nil)
	expectHit(seen{method: "GET", path: "/"})
	// Review C-3: credentials with a tab after "Basic" are accepted by the
	// agent and stripped too.
	resp = c.do("tools", "GET", "/tab", map[string]string{"Authorization": "Basic\t" + strings.TrimPrefix(basic, "Basic ")}, nil)
	if resp.code != 200 {
		t.Errorf("tab-separated credentials: %d", resp.code)
	}
	expectHit(seen{method: "GET", path: "/tab"})
	// The agent's strip signal removes Authorization even in a form the
	// prefix match does not cover...
	c.do("tools", "GET", "/signal", map[string]string{"Cookie": "sealed_gate=valid-cookie", "Authorization": "Token gate-ish", "X-Test-Strip": "1"}, nil)
	expectHit(seen{method: "GET", path: "/signal"})
	// ...but a client cannot send the signal itself to strip the app's own header.
	c.do("tools", "GET", "/nosignal", map[string]string{"Cookie": "sealed_gate=valid-cookie", "Authorization": "Bearer app-token", caddy.GateStripHeader: "1"}, nil)
	expectHit(seen{method: "GET", path: "/nosignal", auth: "Bearer app-token"})
	// A client cannot use the internal relay header to set cookies or reach the app with it.
	resp = c.do("tools", "GET", "/", map[string]string{"Cookie": "sealed_gate=valid-cookie", "X-Sealed-Gate-Set-Cookie": "evil=1"}, nil)
	if resp.code != 200 || resp.header.Get("Set-Cookie") != "" {
		t.Errorf("spoofed relay header: %d set-cookie %q", resp.code, resp.header.Get("Set-Cookie"))
	}
	expectHit(seen{method: "GET", path: "/"})
	// A wrong password and a foreign cookie stay out.
	if resp = c.do("tools", "GET", "/", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("sealed:nope"))}, nil); resp.code != 401 {
		t.Errorf("wrong password: %d", resp.code)
	}
	if resp = c.do("tools", "GET", "/", map[string]string{"Cookie": "sealed_gate=forged"}, nil); resp.code != 401 {
		t.Errorf("forged cookie: %d", resp.code)
	}
	noHit()

	// Bearer passthrough on the gateway API; the gate is not asked.
	calls := agent.count()
	if resp = c.do("gateway", "GET", "/v1/models", map[string]string{"Authorization": "Bearer sk-123", "Cookie": "sealed_gate=valid-cookie"}, nil); resp.code != 200 || resp.body != "hello from gateway" {
		t.Errorf("gateway bearer: %d %q", resp.code, resp.body)
	}
	expectHit(seen{method: "GET", path: "/v1/models", auth: "Bearer sk-123"})
	if agent.count() != calls {
		t.Error("bearer passthrough asked the gate")
	}
	if resp = c.do("gateway", "GET", "/ui", nil, nil); resp.code != 401 {
		t.Errorf("gateway UI without password: %d", resp.code)
	}
	if resp = c.do("gateway", "GET", "/admin/x", map[string]string{"Authorization": "Bearer sk-123"}, nil); resp.code != 401 {
		t.Errorf("gated path must not accept bearer only: %d", resp.code)
	}
	if g := agent.last(); g.route != "gateway" {
		t.Errorf("gate route %q", g.route)
	}
	if resp = c.do("gateway", "GET", "/admin/x", map[string]string{"Authorization": basic}, nil); resp.code != 200 || resp.body != "hello from gateway-admin" {
		t.Errorf("gateway admin with password: %d %q", resp.code, resp.body)
	}
	expectHit(seen{method: "GET", path: "/admin/x"})
	// Routes stay closed while the app's bootstrap runs.
	agent.setStarting("gateway", true)
	if resp = c.do("gateway", "GET", "/admin/x", map[string]string{"Authorization": basic}, nil); resp.code != 503 || resp.body != "starting" {
		t.Errorf("gateway while starting: %d %q", resp.code, resp.body)
	}
	agent.setStarting("gateway", false)
	noHit()

	if resp = c.do("attest", "GET", "/?nonce=0xab", nil, nil); resp.code != 200 {
		t.Errorf("attest: %d", resp.code)
	}
	expectHit(seen{method: "GET", path: "/attest?nonce=0xab"})
	if resp = c.do("attest", "GET", "/other", nil, nil); resp.code != 404 {
		t.Errorf("attest other path: %d", resp.code)
	}

	// The admin socket is reachable by the agent's group (mode 0660).
	if st, err := os.Stat(c.sock); err != nil || st.Mode().Perm() != 0o660 {
		t.Errorf("admin socket mode: %v %v", st, err)
	}
	// The agent's payment-needed switch: POST /load over the admin socket.
	c.load(c.localize(r.CaddyfilePaymentNeeded))
	if resp = c.do("tools", "GET", "/", map[string]string{"Authorization": basic}, nil); resp.code != 402 || !strings.Contains(resp.body, "Payment needed") {
		t.Errorf("tools in payment-needed mode: %d", resp.code)
	}
	if resp = c.do("gateway", "GET", "/v1/models", map[string]string{"Authorization": "Bearer sk-123"}, nil); resp.code != 402 || resp.body != caddy.PaymentMessage {
		t.Errorf("gateway API in payment-needed mode: %d %q", resp.code, resp.body)
	}
	if resp = c.do("attest", "GET", "/?nonce=0x01", nil, nil); resp.code != 200 {
		t.Errorf("attest must stay up: %d", resp.code)
	}
	expectHit(seen{method: "GET", path: "/attest?nonce=0x01"})
	c.load(c.localize(r.Caddyfile))
	if resp = c.do("tools", "GET", "/", map[string]string{"Cookie": "sealed_gate=valid-cookie"}, nil); resp.code != 200 {
		t.Errorf("tools after restore: %d", resp.code)
	}
	expectHit(seen{method: "GET", path: "/"})

	// The relay deployment: the relay route on the attest host (D-045).
	relay := buildFixture(t, "inference-relay")
	rr := mustCompose(t, testConfig(relay), relay)
	front := upstream("relay-front")
	defer front.Close()
	c2 := startCaddy(t, bin, rr, map[string]string{"inference-relay-front:8080": front.URL, "sealed-agent:7070": agent.srv.URL}, []string{"attest"})
	defer c2.stop()
	if resp = c2.do("attest", "POST", "/v1/chat/completions", map[string]string{"Authorization": "Payment abc"}, []byte("{}")); resp.code != 200 || resp.body != "hello from relay-front" {
		t.Errorf("relay on the attest host: %d %q", resp.code, resp.body)
	}
	expectHit(seen{method: "POST", path: "/v1/chat/completions", auth: "Payment abc", body: "{}"})
	if resp = c2.do("attest", "GET", "/attest?nonce=0x02", nil, nil); resp.code != 200 {
		t.Errorf("relay deployment attest: %d", resp.code)
	}
	expectHit(seen{method: "GET", path: "/attest?nonce=0x02"})
	if resp = c2.do("attest", "GET", "/v2/x", nil, nil); resp.code != 404 {
		t.Errorf("relay deployment other path: %d", resp.code)
	}
	noHit()
}

// fakeGateAgent implements sealed-agent's /v1/gate contract (D-044) and
// /attest for the Caddy test.
type fakeGateAgent struct {
	srv      *httptest.Server
	mu       sync.Mutex
	calls    []gateCall
	starting map[string]bool
}

type gateCall struct{ path, route, uri, method, auth string }

// seen is one request an upstream test server received; spoof holds any
// internal gate relay header that reached it.
type seen struct{ method, path, auth, cookie, body, spoof string }

func newFakeGateAgent(hits chan<- seen) *fakeGateAgent {
	a := &fakeGateAgent{starting: map[string]bool{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/attest" {
			hits <- seen{method: req.Method, path: req.URL.RequestURI()}
			fmt.Fprint(w, "attest ok")
			return
		}
		if req.URL.Path != caddy.DefaultGatePath {
			http.NotFound(w, req)
			return
		}
		route := req.URL.Query().Get("route")
		a.mu.Lock()
		a.calls = append(a.calls, gateCall{req.URL.Path, route, req.Header.Get("X-Forwarded-Uri"), req.Header.Get("X-Forwarded-Method"), req.Header.Get("Authorization")})
		starting := a.starting[route]
		a.mu.Unlock()
		if b, _ := io.ReadAll(req.Body); len(b) > 0 {
			http.Error(w, "the gate must not receive request bodies", 500)
			return
		}
		if starting {
			w.WriteHeader(503)
			fmt.Fprint(w, "starting")
			return
		}
		// Like sealed-agent: Basic with spaces or tabs, and on a 200 the
		// strip signal whenever the credentials name the gate user. The
		// X-Test-Strip request header lets the test ask for the signal on
		// a credential form Caddy's prefix match does not cover.
		user, pw, isBasic := parseGateBasic(req.Header.Get("Authorization"))
		strip := (isBasic && user == caddy.DefaultGateUser) || req.Header.Get("X-Test-Strip") != ""
		if strip {
			w.Header().Set(caddy.GateStripHeader, "1")
		}
		if ck, err := req.Cookie(caddy.DefaultGateCookie); err == nil && ck.Value == "valid-cookie" {
			w.WriteHeader(200)
			return
		}
		if isBasic && user == caddy.DefaultGateUser && pw == "gate-pw" {
			http.SetCookie(w, &http.Cookie{Name: caddy.DefaultGateCookie, Value: "valid-cookie", Path: "/", MaxAge: GateCookieMaxAge,
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			w.WriteHeader(200)
			return
		}
		w.Header().Del(caddy.GateStripHeader)
		w.Header().Set("WWW-Authenticate", `Basic realm="sealed"`)
		w.WriteHeader(401)
	}))
	return a
}

// parseGateBasic parses Basic credentials the way sealed-agent does:
// /^Basic[ \t]+([A-Za-z0-9+/=]+)[ \t]*$/i.
func parseGateBasic(h string) (user, pw string, ok bool) {
	m := regexp.MustCompile(`(?i)^Basic[ \t]+([A-Za-z0-9+/=]+)[ \t]*$`).FindStringSubmatch(h)
	if m == nil {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return "", "", false
	}
	user, pw, ok = strings.Cut(string(raw), ":")
	return user, pw, ok
}

func (a *fakeGateAgent) last() gateCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.calls) == 0 {
		return gateCall{}
	}
	return a.calls[len(a.calls)-1]
}

func (a *fakeGateAgent) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

func (a *fakeGateAgent) setStarting(route string, v bool) {
	a.mu.Lock()
	a.starting[route] = v
	a.mu.Unlock()
}

type caddyRun struct {
	t        *testing.T
	port     int
	sock     string
	localize func([]byte) []byte
	admin    *http.Client
	stop     func()
}

type caddyResp struct {
	code   int
	body   string
	header http.Header
}

// startCaddy runs a composed Caddyfile with hosts mapped to
// http://<route>.localhost:<port> and upstreams to test servers.
func startCaddy(t *testing.T, bin string, r *Result, upstreams map[string]string, routes []string) *caddyRun {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sealed-caddy-") // short path for the unix socket
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	sock := filepath.Join(dir, "admin.sock")
	_ = os.WriteFile(filepath.Join(dir, caddy.DefaultPageFile), caddy.PaymentNeededHTML, 0o644)
	localize := func(cf []byte) []byte {
		s := string(cf)
		for _, route := range routes {
			s = strings.ReplaceAll(s, route+".34-1-2-3.sslip.io {", fmt.Sprintf("http://%s.localhost:%d {", route, port))
		}
		for from, to := range upstreams {
			s = strings.ReplaceAll(s, from, strings.TrimPrefix(to, "http://"))
		}
		s = strings.ReplaceAll(s, caddy.DefaultAdminSocket, sock)
		s = strings.ReplaceAll(s, "root * "+caddy.DefaultPageDir, "root * "+dir)
		return []byte(s)
	}
	normal := filepath.Join(dir, "Caddyfile")
	_ = os.WriteFile(normal, localize(r.Caddyfile), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "run", "--config", normal, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir, "HTTP_PROXY=", "HTTPS_PROXY=")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &caddyRun{t: t, port: port, sock: sock, localize: localize}
	c.admin = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	c.stop = func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("caddy logs:\n%s", logs.String())
		}
		os.RemoveAll(dir)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if resp := c.do(routes[0], "GET", "/caddy-start-probe", nil, nil); resp.code != 0 {
			break
		}
		if time.Now().After(deadline) {
			c.stop()
			t.Fatalf("caddy did not start:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return c
}

func (c *caddyRun) do(route, method, path string, headers map[string]string, body []byte) caddyResp {
	req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", c.port, path), bytes.NewReader(body))
	req.Host = fmt.Sprintf("%s.localhost:%d", route, c.port)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return caddyResp{}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return caddyResp{resp.StatusCode, string(b), resp.Header}
}

func (c *caddyRun) load(body []byte) {
	c.t.Helper()
	resp, err := c.admin.Post("http://localhost/load", "text/caddyfile", bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.t.Fatalf("load: %d %s", resp.StatusCode, b)
	}
}
