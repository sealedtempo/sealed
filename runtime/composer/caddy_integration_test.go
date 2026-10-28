package composer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/caddy"
	"golang.org/x/crypto/bcrypt"
)

// TestCaddyfileWithRealCaddy runs the generated Caddyfiles in a real Caddy
// when SEALED_CADDY_BIN points at a caddy v2.11.x binary (see README.md).
// Hosts become http://<route>.localhost:<port> and upstreams become local
// test servers; everything else is the measured file byte for byte. It
// checks the gate, bearer passthrough, the public attest route and the
// payment-needed switch through the admin unix socket.
func TestCaddyfileWithRealCaddy(t *testing.T) {
	bin := os.Getenv("SEALED_CADDY_BIN")
	if bin == "" {
		t.Skip("SEALED_CADDY_BIN not set")
	}
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)

	type seen struct{ path, auth string }
	upstream := func(name string, ch chan<- seen) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ch <- seen{req.URL.RequestURI(), req.Header.Get("Authorization")}
			fmt.Fprintf(w, "hello from %s", name)
		}))
	}
	hits := make(chan seen, 16)
	web, gw, gwAdmin, agent := upstream("notes-web", hits), upstream("gateway", hits), upstream("gateway-admin", hits), upstream("agent", hits)
	defer web.Close()
	defer gw.Close()
	defer gwAdmin.Close()
	defer agent.Close()

	dir, err := os.MkdirTemp("/tmp", "sealed-caddy-") // short path for the unix socket
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	sock := filepath.Join(dir, "admin.sock")
	_ = os.WriteFile(filepath.Join(dir, caddy.DefaultPageFile), caddy.PaymentNeededHTML, 0o644)

	localize := func(cf []byte) []byte {
		s := string(cf)
		for _, route := range []string{"gateway", "tools", "attest"} {
			s = strings.ReplaceAll(s, route+".34-1-2-3.sslip.io {", fmt.Sprintf("http://%s.localhost:%d {", route, port))
		}
		host := func(u string) string { return strings.TrimPrefix(u, "http://") }
		s = strings.ReplaceAll(s, "llm-gateway-proxy:4001", host(gwAdmin.URL))
		s = strings.ReplaceAll(s, "llm-gateway-proxy:4000", host(gw.URL))
		s = strings.ReplaceAll(s, "notes-web:8080", host(web.URL))
		s = strings.ReplaceAll(s, "sealed-agent:7070", host(agent.URL))
		s = strings.ReplaceAll(s, caddy.DefaultAdminSocket, sock)
		s = strings.ReplaceAll(s, "root * "+caddy.DefaultPageDir, "root * "+dir)
		return []byte(s)
	}
	normal := filepath.Join(dir, "Caddyfile")
	_ = os.WriteFile(normal, localize(r.Caddyfile), 0o644)
	paymentNeeded := localize(r.CaddyfilePaymentNeeded)

	hash, err := bcrypt.GenerateFromPassword([]byte("gate-pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--config", normal, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "GATE_PASSWORD_BCRYPT="+string(hash), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("caddy logs:\n%s", logs.String())
		}
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	do := func(route, path, user, bearer string) (int, string) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
		req.Host = fmt.Sprintf("%s.localhost:%d", route, port)
		if user != "" {
			req.SetBasicAuth(user, "gate-pw")
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if code, _ := do("tools", "/", "", ""); code != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("caddy did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	expectHit := func(wantPath, wantAuth string) {
		t.Helper()
		select {
		case h := <-hits:
			if h.path != wantPath || h.auth != wantAuth {
				t.Errorf("upstream saw %+v, want path %q auth %q", h, wantPath, wantAuth)
			}
		case <-time.After(2 * time.Second):
			t.Error("upstream not reached")
		}
	}

	if code, _ := do("tools", "/", "", ""); code != 401 {
		t.Errorf("tools without password: %d", code)
	}
	if code, body := do("tools", "/notes", "sealed", ""); code != 200 || body != "hello from notes-web" {
		t.Errorf("tools with password: %d %q", code, body)
	}
	expectHit("/notes", "") // the gate credentials are stripped
	if code, body := do("gateway", "/v1/models", "", "sk-123"); code != 200 || body != "hello from gateway" {
		t.Errorf("gateway bearer: %d %q", code, body)
	}
	expectHit("/v1/models", "Bearer sk-123")
	if code, _ := do("gateway", "/ui", "", ""); code != 401 {
		t.Errorf("gateway UI without password: %d", code)
	}
	if code, _ := do("gateway", "/admin/x", "", "sk-123"); code != 401 {
		t.Errorf("gated path must not accept bearer only: %d", code)
	}
	if code, body := do("gateway", "/admin/x", "sealed", ""); code != 200 || body != "hello from gateway-admin" {
		t.Errorf("gateway admin with password: %d %q", code, body)
	}
	expectHit("/admin/x", "")
	if code, _ := do("attest", "/?nonce=0xab", "", ""); code != 200 {
		t.Errorf("attest: %d", code)
	}
	expectHit("/attest?nonce=0xab", "")
	if code, _ := do("attest", "/other", "", ""); code != 404 {
		t.Errorf("attest other path: %d", code)
	}

	// The agent's payment-needed switch: POST /load over the admin socket.
	admin := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	load := func(body []byte) {
		t.Helper()
		resp, err := admin.Post("http://localhost/load", "text/caddyfile", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("load: %d %s", resp.StatusCode, b)
		}
	}
	load(paymentNeeded)
	if code, body := do("tools", "/", "sealed", ""); code != 402 || !strings.Contains(body, "Payment needed") {
		t.Errorf("tools in payment-needed mode: %d", code)
	}
	if code, body := do("gateway", "/v1/models", "", "sk-123"); code != 402 || body != caddy.PaymentMessage {
		t.Errorf("gateway API in payment-needed mode: %d %q", code, body)
	}
	if code, _ := do("attest", "/?nonce=0x01", "", ""); code != 200 {
		t.Errorf("attest must stay up: %d", code)
	}
	expectHit("/attest?nonce=0x01", "")
	norm, _ := os.ReadFile(normal)
	load(norm)
	if code, _ := do("tools", "/", "sealed", ""); code != 200 {
		t.Errorf("tools after restore: %d", code)
	}
	expectHit("/", "")
}
