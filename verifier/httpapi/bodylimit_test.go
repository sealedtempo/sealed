package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/bundles"
	"github.com/sealedtempo/sealed/verifier/httpapi"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
)

// sendBody posts body to url, with Content-Length or chunked (no length known up front).
func sendBody(t *testing.T, url string, body []byte, chunked bool) (int, map[string]any) {
	t.Helper()
	var r io.Reader = bytes.NewReader(body)
	if chunked {
		r = io.MultiReader(r) // hides the length, so the client sends Transfer-Encoding: chunked
	}
	req, err := http.NewRequest(http.MethodPost, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestBodyLimit: every POST route takes bodies up to MaxBodyBytes (8 MiB) and answers a larger one with 413 and an
// error that names the limit (code body_too_large, limitBytes), with or without Content-Length. The platform api and
// Caddy forward evidence and verify bodies here, so the limit is part of the contract (merge-c-private open issue).
func TestBodyLimit(t *testing.T) {
	if httpapi.MaxBodyBytes != 8<<20 {
		t.Fatalf("MaxBodyBytes %d: the platform api and Caddy are aligned to 8 MiB", httpapi.MaxBodyBytes)
	}
	h := newHarness(t, fixture.Composer{})
	over := bytes.Repeat([]byte("a"), httpapi.MaxBodyBytes+1)
	exact := bytes.Repeat([]byte("a"), httpapi.MaxBodyBytes)
	for _, path := range []string{"/v1/verify/evidence", "/v1/verify/live", "/v1/compose"} {
		for _, chunked := range []bool{false, true} {
			code, out := sendBody(t, h.api.URL+path, over, chunked)
			msg, _ := out["error"].(string)
			if code != http.StatusRequestEntityTooLarge || out["code"] != "body_too_large" || out["limitBytes"] != float64(8<<20) ||
				!strings.Contains(msg, "8 MiB (8388608 bytes)") {
				t.Errorf("%s chunked=%v, one byte over: %d %v", path, chunked, code, out)
			}
		}
		// Exactly the limit is read (and refused for what it is, not for its size).
		if code, out := sendBody(t, h.api.URL+path, exact, false); code == http.StatusRequestEntityTooLarge {
			t.Errorf("%s at exactly 8 MiB: %d %v", path, code, out)
		}
	}
}

// TestOversizedBodyTakesNoSlot: a body whose Content-Length is over the limit is refused before a verification slot
// is taken, so it answers 413 even while every slot is busy.
func TestOversizedBodyTakesNoSlot(t *testing.T) {
	g := gatedComposer{started: make(chan struct{}, 1), release: make(chan struct{})}
	h := newHarness(t, g)
	api := h.variant(t, func(s *httpapi.Server) { s.MaxInFlight = 1 })
	done := make(chan int, 1)
	go func() {
		resp, err := http.Post(api.URL+"/v1/verify/evidence", "application/json", bytes.NewReader(mustJSON(h.b)))
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	<-g.started
	if code, out := sendBody(t, api.URL+"/v1/verify/evidence", bytes.Repeat([]byte("a"), httpapi.MaxBodyBytes+1), false); code != http.StatusRequestEntityTooLarge || out["code"] != "body_too_large" {
		t.Fatalf("oversized body while the slot is busy: %d %v", code, out)
	}
	if code, _ := sendBody(t, api.URL+"/v1/verify/evidence", mustJSON(h.b), false); code != http.StatusTooManyRequests {
		t.Fatalf("a normal body while the slot is busy: %d", code)
	}
	close(g.release)
	if code := <-done; code != 200 {
		t.Fatalf("first verification: %d", code)
	}
}

// TestHealthzComposerVersion: /healthz names the composerVersion configs must carry for this server's composer and
// the body limit, so the platform api can read both instead of pinning them.
func TestHealthzComposerVersion(t *testing.T) {
	get := func(t *testing.T, url string) map[string]any {
		t.Helper()
		resp, err := http.Get(url + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != 200 {
			t.Fatalf("healthz %d %v", resp.StatusCode, err)
		}
		return body
	}
	h := newHarness(t, &bundles.Composer{})
	body := get(t, h.api.URL)
	if body["composer"] != true || body["composerVersion"] != composer.Version || body["maxBodyBytes"] != float64(httpapi.MaxBodyBytes) {
		t.Fatalf("healthz with the runtime composer: %v", body)
	}
	if h.srv.ComposerVersion() != composer.Version {
		t.Fatalf("ComposerVersion %q", h.srv.ComposerVersion())
	}
	// Without a composer (or one that does not say) the version is empty: configs cannot be recomputed here.
	if body := get(t, newHarness(t, nil).api.URL); body["composer"] != false || body["composerVersion"] != "" {
		t.Fatalf("healthz without a composer: %v", body)
	}
}
