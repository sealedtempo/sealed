package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type recordingTransport struct{ out []*http.Request }

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.out = append(rt.out, r)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}, Request: r}, nil
}

// FuzzGate sends arbitrary requests from the gateway's address through the
// local-model gate. Properties: Ollama is reached only with the exact bearer
// key, never sees the Authorization header, and only on an allowed method and
// route, spelled on the wire exactly as the gate checked it.
func FuzzGate(f *testing.F) {
	for _, s := range []string{
		"POST /api/chat HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\nContent-Length: 2\r\n\r\n{}",
		"GET /v1/models/llama3 HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"GET /v1/models/a%2fb HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"GET /v1/models/.. HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"GET /api/tags?x=1 HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"POST /api/pull HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"POST http://evil/api/chat HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"GET //api/tags HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"GET /api/%74ags HTTP/1.1\r\nHost: m\r\nAuthorization: Bearer k3y\r\n\r\n",
		"HEAD / HTTP/1.1\r\nHost: m\r\nAuthorization: bearer k3y\r\n\r\n",
		"GET /healthz HTTP/1.1\r\nHost: m\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	const key = "k3y"
	rt := &recordingTransport{}
	g := newGate("127.0.0.1:11434", newPeerSet(nil, true), []byte(key), 1<<20)
	g.proxy.Transport = rt
	g.health.Transport = rt
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		r.RemoteAddr = "127.0.0.1:40000"
		rt.out = nil
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		for _, out := range rt.out {
			if r.URL.Path == "/healthz" && r.Method == http.MethodGet && out.URL.Path == "/" {
				continue // the gate's own readiness probe
			}
			if r.Header.Get("Authorization") != "Bearer "+key {
				t.Fatalf("request with Authorization %q reached Ollama", r.Header.Get("Authorization"))
			}
			if out.Header.Get("Authorization") != "" {
				t.Fatal("Authorization header forwarded to Ollama")
			}
			wire := out.URL.EscapedPath()
			path, err := url.PathUnescape(wire)
			if err != nil || path != r.URL.Path || path != out.URL.Path {
				t.Fatalf("checked %q, Ollama receives %q (decodes to %q, %v)", r.URL.Path, wire, path, err)
			}
			if out.Method != r.Method || !routeOK(out.Method, path) {
				t.Fatalf("Ollama receives %s %s, which is not an allowed route", out.Method, wire)
			}
		}
	})
}

// routeOK is the gate's allowlist written out: the fixed routes, plus GET
// /v1/models/<name> for a non-empty name without a slash or backslash.
func routeOK(method, path string) bool {
	fixed := map[string][]string{
		http.MethodGet:  {"/", "/api/tags", "/api/ps", "/api/version", "/v1/models"},
		http.MethodHead: {"/"},
		http.MethodPost: {"/api/chat", "/api/generate", "/api/embed", "/api/embeddings", "/api/show", "/v1/chat/completions", "/v1/completions", "/v1/embeddings"},
	}
	for _, p := range fixed[method] {
		if p == path {
			return true
		}
	}
	name, ok := strings.CutPrefix(path, "/v1/models/")
	return method == http.MethodGet && ok && name != "" && !strings.ContainsAny(name, "/\\")
}
