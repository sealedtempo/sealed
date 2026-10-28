package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/httpapi"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// serveFrom runs one request through the handler as if it came from remote (host:port), with optional headers.
func serveFrom(h http.Handler, remote, method, path string, body []byte, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = remote
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// D-061: with an allowlist, only the listed source addresses are served (in a stack: the payer). The TCP peer
// counts, never a forwarded header; loopback may only read /healthz.
func TestAllowedClients(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	clients, err := httpapi.ParseClients("172.30.0.5")
	if err != nil {
		t.Fatal(err)
	}
	h.srv.AllowedClients = clients
	handler := h.srv.Handler()
	bundle, _ := json.Marshal(h.b)
	for _, tc := range []struct {
		name, remote, method, path string
		header                     map[string]string
		status                     int
	}{
		{"payer", "172.30.0.5:40000", http.MethodPost, "/v1/verify/evidence", nil, 200},
		{"payer, IPv4-mapped", "[::ffff:172.30.0.5]:40000", http.MethodPost, "/v1/verify/evidence", nil, 200},
		{"payer reads healthz", "172.30.0.5:40000", http.MethodGet, "/healthz", nil, 200},
		{"an app primary on the apps network", "172.30.0.11:40000", http.MethodPost, "/v1/verify/evidence", nil, 403},
		{"an app primary composes", "172.30.0.11:40000", http.MethodPost, "/v1/compose", nil, 403},
		{"an app primary asks for a live fetch", "172.30.0.11:40000", http.MethodPost, "/v1/verify/live", nil, 403},
		{"an app primary claims to be the payer", "172.30.0.11:40000", http.MethodPost, "/v1/verify/evidence",
			map[string]string{"X-Forwarded-For": "172.30.0.5", "X-Real-Ip": "172.30.0.5", "Forwarded": "for=172.30.0.5"}, 403},
		{"an app reads healthz", "172.30.0.11:40000", http.MethodGet, "/healthz", nil, 403},
		{"loopback reads healthz", "127.0.0.1:40000", http.MethodGet, "/healthz", nil, 200},
		{"loopback verifies", "127.0.0.1:40000", http.MethodPost, "/v1/verify/evidence", nil, 403},
		{"unparsable peer", "somewhere", http.MethodGet, "/healthz", nil, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.method == http.MethodPost {
				body = bundle
			}
			w := serveFrom(handler, tc.remote, tc.method, tc.path, body, tc.header)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body)
			}
			if tc.status == 403 && !strings.Contains(w.Body.String(), "configured clients") {
				t.Fatalf("body %s", w.Body)
			}
		})
	}
	// Without an allowlist every source is served (the oracle's and the CLI's daemons).
	h.srv.AllowedClients = nil
	if w := serveFrom(h.srv.Handler(), "172.30.0.11:40000", http.MethodPost, "/v1/verify/evidence", bundle, nil); w.Code != 200 {
		t.Fatalf("no allowlist: %d", w.Code)
	}
}

func TestParseClients(t *testing.T) {
	got, err := httpapi.ParseClients(" 172.30.0.5, 10.8.0.0/16 ,, ::1 ,::ffff:172.31.0.0/120")
	want := []netip.Prefix{netip.MustParsePrefix("172.30.0.5/32"), netip.MustParsePrefix("10.8.0.0/16"), netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("172.31.0.0/24")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("ParseClients = %v, %v", got, err)
	}
	if got, err := httpapi.ParseClients(""); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	for _, bad := range []string{"nope", "172.30.0.5/33", "10.8.0.1/16", "fe80::1%eth0", "172.30.0.5:80", "https://172.30.0.5", "::ffff:0.0.0.0/80"} {
		if _, err := httpapi.ParseClients(bad); err == nil {
			t.Errorf("ParseClients(%q) accepted", bad)
		}
	}
}

// V-1: a server with DisableLiveFetch never fetches a caller's URL; caller-fetched attestations still verify.
func TestDisableLiveFetch(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	var hits int
	attestSrv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { hits++ }))
	defer attestSrv.Close()
	api := h.variant(t, func(s *httpapi.Server) { s.DisableLiveFetch = true })
	resp, raw := post(t, api.URL+"/v1/verify/live", map[string]any{"url": attestSrv.URL + "/attest"})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "caller-fetched") || hits != 0 {
		t.Fatalf("URL form on a no-fetch server: %d %s (hits %d)", resp.StatusCode, raw, hits)
	}
	nonce := sha256.Sum256([]byte("payer nonce"))
	observed := sha256.Sum256([]byte("relay certificate SPKI"))
	doc, _ := json.Marshal(h.w.LiveResponse(nonce, observed))
	resp, raw = post(t, api.URL+"/v1/verify/live", map[string]any{
		"attestUrl": "https://attest.34-1-2-3.sslip.io/attest", "nonce": hexb.Enc(nonce[:]), "attest": json.RawMessage(doc),
		"observedTlsPubKeyHash": hexb.Enc(observed[:]),
	})
	if rep := decodeReport(t, raw); resp.StatusCode != 200 || !rep.OK || rep.Mode != verify.ModeLiveSubmitted {
		t.Fatalf("submitted attestation on a no-fetch server: %d %v", resp.StatusCode, rep.Failed())
	}
	hresp, err := http.Get(api.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer hresp.Body.Close()
	var body map[string]any
	json.NewDecoder(hresp.Body).Decode(&body)
	if body["liveFetch"] != false {
		t.Fatalf("healthz %v", body)
	}
}

// D-060 through the API: the server's MaxChainHeadAge applies to every verification.
func TestServerChainHeadAge(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	h.m.HeadAt = func() time.Time { return time.Unix(int64(h.m.Now)+5, 0).Add(-30 * time.Second) }
	_, raw := post(t, h.api.URL+"/v1/verify/evidence", h.b)
	if rep := decodeReport(t, raw); !rep.OK {
		t.Fatalf("30 s old head with the default limit: %v", rep.Failed())
	}
	strict := h.variant(t, func(s *httpapi.Server) { s.MaxChainHeadAge = 10 * time.Second })
	_, raw = post(t, strict.URL+"/v1/verify/evidence", h.b)
	rep := decodeReport(t, raw)
	if c := rep.Check(verify.CheckChain); rep.OK || c.OK || c.Data["reason"] != "chain_stale" || c.Data["headLagSeconds"] != float64(30) {
		t.Fatalf("stale head accepted: %+v", rep.Check(verify.CheckChain))
	}
}

// V-3 through the API: only a dev daemon (simulated quotes allowed) opts in to simulated quotes.
func TestServerAcceptsSimulatedOnlyInDevMode(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	prod, err := attest.NewVerifier(attest.VerifierOptions{Getter: offline{}})
	if err != nil {
		t.Fatal(err)
	}
	api := h.variant(t, func(s *httpapi.Server) { s.Deps.Quotes = prod })
	_, raw := post(t, api.URL+"/v1/verify/evidence", h.b)
	if rep := decodeReport(t, raw); rep.OK || rep.Check(verify.CheckQuote).OK {
		t.Fatalf("production daemon accepted a simulated quote: %+v", rep.Check(verify.CheckQuote))
	}
}
