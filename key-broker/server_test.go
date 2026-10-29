package keybroker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
	"github.com/sealedtempo/sealed/verifier/attest"
)

// TestHTTPAPI drives the broker over HTTP like sealed-agent's HttpKeyBroker.
func TestHTTPAPI(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	h := newHarness(t, w, harnessOpts{})
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/nonce")
	if err != nil {
		t.Fatal(err)
	}
	var nr keybroker.NonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nr); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !regexp.MustCompile(`^0x[0-9a-f]{64}$`).MatchString(nr.Nonce) || nr.ExpiresAt != h.clock.now().Unix()+300 {
		t.Fatalf("nonce %d %+v", resp.StatusCode, nr)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", resp.Header)
	}
	nb, _ := decodeHex(nr.Nonce)
	a := kbtest.NewAttempt(t, s, [32]byte(nb))

	post := func(body []byte) (*http.Response, []byte) {
		r, err := http.Post(srv.URL+"/v1/release", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r, b
	}
	r, body := post(a.Body(t))
	if r.StatusCode != 200 || r.Header.Get("X-Request-Id") == "" {
		t.Fatalf("release %d %s", r.StatusCode, body)
	}
	// The body is exactly INTERFACES.md section 9's 200 shape.
	var shape map[string]any
	_ = json.Unmarshal(body, &shape)
	if len(shape) != 4 || shape["stackHash"] == nil || shape["deploymentId"] == nil || shape["enc"] == nil || shape["ciphertext"] == nil {
		t.Fatalf("200 body %s", body)
	}
	var rr keybroker.ReleaseResponse
	_ = json.Unmarshal(body, &rr)
	if pt := a.Open(t, &rr); pt.Secrets["notes"]["APP_SECRET"] != "notes-app-secret" {
		t.Fatalf("plaintext %+v", pt)
	}

	// Replaying the same body over HTTP: 403 with the denial shape.
	r, body = post(a.Body(t))
	var den map[string]any
	_ = json.Unmarshal(body, &den)
	if r.StatusCode != 403 || den["decision"] != "denied" || den["reason"] != "bad_nonce" {
		t.Fatalf("replay %d %s", r.StatusCode, body)
	}

	// Oversized body: 413.
	big := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{MaxBodyBytes: 1024}))
	defer big.Close()
	r2, err := http.Post(big.URL+"/v1/release", "application/json", strings.NewReader(strings.Repeat(" ", 2048)))
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized %d", r2.StatusCode)
	}

	// Wrong methods and paths.
	for _, c := range []struct{ method, path string }{{"POST", "/v1/nonce"}, {"GET", "/v1/release"}, {"GET", "/v1/secrets"}} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, nil)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusMethodNotAllowed && r.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s: %d", c.method, c.path, r.StatusCode)
		}
	}
	if r, _ := http.Get(srv.URL + "/healthz"); r == nil || r.StatusCode != 200 {
		t.Fatal("healthz")
	}
}

// blockingVerifier holds every verification until released.
type blockingVerifier struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingVerifier) VerifyQuote(ctx context.Context, raw []byte) (*attest.QuoteResult, error) {
	b.started <- struct{}{}
	<-b.release
	return nil, attest.ErrQuoteInvalid
}

// TestHTTPInFlightLimit: releases beyond MaxInFlight answer 429 with Retry-After instead of queueing.
func TestHTTPInFlightLimit(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	bv := &blockingVerifier{started: make(chan struct{}, 4), release: make(chan struct{})}
	h := newHarness(t, w, harnessOpts{quotes: bv})
	s := w.Compose(t, kbtest.StackOptions{})
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{MaxInFlight: 2}))
	defer srv.Close()

	var wg sync.WaitGroup
	for range 2 {
		body := h.attempt(t, s).Body(t)
		wg.Go(func() {
			r, err := http.Post(srv.URL+"/v1/release", "application/json", bytes.NewReader(body))
			if err == nil {
				r.Body.Close()
			}
		})
	}
	for range 2 {
		select {
		case <-bv.started:
		case <-time.After(5 * time.Second):
			t.Fatal("releases did not start")
		}
	}
	r, err := http.Post(srv.URL+"/v1/release", "application/json", bytes.NewReader(h.attempt(t, s).Body(t)))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Fatalf("third release: %d", r.StatusCode)
	}
	close(bv.release)
	wg.Wait()
}

// TestDecisionLogJSONLines runs a release against the local Cloud Logging fake and reads the file back.
func TestDecisionLogJSONLines(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	var buf bytes.Buffer
	h := newHarness(t, w, harnessOpts{log: keybroker.NewJSONLinesLog(&buf)})
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	for range 2 {
		a := h.attempt(t, s)
		expectAllowed(t, h.release(t, a), a)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d log lines", len(lines))
	}
	var first, second struct {
		Severity, Decision, Reason string
		Hashes                     keybroker.Hashes
		Checks                     []keybroker.Check
	}
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if first.Decision != "allowed" || first.Severity != "NOTICE" || first.Hashes.StackHash != s.Result.StackHash.Hex() || len(first.Checks) != len(allowedChecks) {
		t.Fatalf("first %+v", first)
	}
	if second.Decision != "allowed" {
		t.Fatalf("second %+v", second)
	}
}
