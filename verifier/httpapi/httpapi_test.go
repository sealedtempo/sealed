package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/httpapi"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

type offline struct{}

func (offline) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("offline")
}

var addrs = chain.Addresses{
	PlatformRegistry:   common.HexToAddress("0x00000000000000000000000000000000000000a1"),
	AppRegistry:        common.HexToAddress("0x00000000000000000000000000000000000000a2"),
	DeploymentRegistry: common.HexToAddress("0x00000000000000000000000000000000000000a3"),
}

type harness struct {
	w   *fixture.World
	m   *fixture.MemChain
	b   *verify.Bundle
	api *httptest.Server
	srv *httpapi.Server
}

func newHarness(t *testing.T, composer verify.Composer) *harness {
	t.Helper()
	w := fixture.NewWorld(4217, addrs, common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
		common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9"), fixture.SimImageID(false))
	m := fixture.NewMemChain(4217, addrs)
	b := w.Bundle(m.Now)
	w.Populate(m, b, true)
	q, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: true, Getter: offline{}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &httpapi.Server{
		Deps:            verify.Deps{Quotes: q, Chain: m, Composer: composer, Now: func() time.Time { return time.Unix(int64(m.Now)+5, 0) }},
		ChainID:         4217,
		LiveInsecureTLS: true,
		LiveTimeout:     5 * time.Second,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)
	return &harness{w: w, m: m, b: b, api: api, srv: srv}
}

func post(t *testing.T, url string, body any) (*http.Response, []byte) {
	t.Helper()
	var raw []byte
	switch v := body.(type) {
	case []byte:
		raw = v
	default:
		var err error
		if raw, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func decodeReport(t *testing.T, raw []byte) verify.Report {
	t.Helper()
	var rep verify.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return rep
}

func TestVerifyEvidenceEndpoint(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	// A bare bundle.
	resp, raw := post(t, h.api.URL+"/v1/verify/evidence", h.b)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if rep := decodeReport(t, raw); !rep.OK || !rep.Simulated || rep.DeploymentID != h.b.DeploymentID {
		t.Fatalf("report %+v", rep)
	}
	// Wrapped, with options: the oracle verifies before registering.
	delete(h.m.Deployments, mustID(t, h.b.DeploymentID))
	f := false
	_, raw = post(t, h.api.URL+"/v1/verify/evidence", map[string]any{"bundle": h.b, "options": httpapi.RequestOptions{RequireRecord: &f, MaxEvidenceAgeSeconds: 900}})
	rep := decodeReport(t, raw)
	if !rep.OK || rep.Check(verify.CheckFreshness) == nil {
		t.Fatalf("pre-registration verification: %+v", rep.Failed())
	}
	// Default requires the record.
	_, raw = post(t, h.api.URL+"/v1/verify/evidence", h.b)
	if rep := decodeReport(t, raw); rep.OK || rep.Failed()[0] != verify.CheckOnchainRecord {
		t.Fatalf("missing record accepted: %v", rep.Failed())
	}
	// Text format.
	resp, raw = post(t, h.api.URL+"/v1/verify/evidence?format=text", h.b)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") || !strings.Contains(string(raw), "Sealed verification (evidence): FAIL") {
		t.Fatalf("text report: %s", raw)
	}
}

func TestVerifyEvidenceBadRequests(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	for name, body := range map[string][]byte{
		"not json":     []byte("{"),
		"no bundle":    []byte(`{"options":{}}`),
		"bad option":   []byte(`{"bundle":{"schema":"x"},"options":{"deploymentId":"0x12"}}`),
		"negative age": []byte(`{"bundle":{"schema":"x"},"options":{"maxEvidenceAgeSeconds":-1}}`),
		"bad customer": []byte(`{"bundle":{"schema":"x"},"options":{"expectedCustomer":"nope"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			resp, raw := post(t, h.api.URL+"/v1/verify/evidence", body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
		})
	}
	big := bytes.Repeat([]byte("a"), httpapi.MaxBodyBytes+1)
	if resp, _ := post(t, h.api.URL+"/v1/verify/evidence", big); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", resp.StatusCode)
	}
	resp, err := http.Get(h.api.URL + "/v1/verify/evidence")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status %d", resp.StatusCode)
	}
	// A malformed bundle is a verification result, not a bad request.
	resp2, raw := post(t, h.api.URL+"/v1/verify/evidence", []byte(`{"schema":"sealed-evidence/v9"}`))
	if resp2.StatusCode != 200 || decodeReport(t, raw).OK {
		t.Fatalf("malformed bundle: %d %s", resp2.StatusCode, raw)
	}
}

func TestVerifyLiveEndpoint(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	var spki [32]byte
	attestSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		nonce, err := hexb.Decode32(r.URL.Query().Get("nonce"))
		if err != nil {
			http.Error(rw, "nonce", 400)
			return
		}
		json.NewEncoder(rw).Encode(h.w.LiveResponse(nonce, spki))
	}))
	attestSrv.StartTLS()
	defer attestSrv.Close()
	spki = sha256.Sum256(attestSrv.Certificate().RawSubjectPublicKeyInfo)

	resp, raw := post(t, h.api.URL+"/v1/verify/live", map[string]any{"url": attestSrv.URL + "/attest"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if rep := decodeReport(t, raw); !rep.OK || rep.Mode != verify.ModeLive || !rep.Simulated {
		t.Fatalf("live report failed: %v", rep.Failed())
	}
	// The payer's relay check: the stack must belong to the operator.
	_, raw = post(t, h.api.URL+"/v1/verify/live", map[string]any{"url": attestSrv.URL + "/attest", "options": map[string]any{"expectedCustomer": "0x000000000000000000000000000000000000dead"}})
	if rep := decodeReport(t, raw); rep.OK || rep.Check(verify.CheckExpectedCustomer).OK {
		t.Fatal("wrong owner accepted")
	}
	if resp, _ := post(t, h.api.URL+"/v1/verify/live", map[string]any{}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing url: %d", resp.StatusCode)
	}
}

func TestComposeEndpoint(t *testing.T) {
	off := newHarness(t, nil)
	if resp, _ := post(t, off.api.URL+"/v1/compose", map[string]any{"config": json.RawMessage(off.w.ConfigJSON())}); resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("unwired composer: %d", resp.StatusCode)
	}
	// Without a composer the evidence endpoint still answers, failing stack_recompute closed.
	_, raw := post(t, off.api.URL+"/v1/verify/evidence", off.b)
	if rep := decodeReport(t, raw); rep.OK || rep.Failed()[0] != verify.CheckStackRecompute {
		t.Fatalf("unwired composer: %v", rep.Failed())
	}

	h := newHarness(t, fixture.Composer{})
	for name, body := range map[string]any{
		"wrapped": map[string]any{"config": json.RawMessage(h.w.ConfigJSON())},
		"bare":    json.RawMessage(h.w.ConfigJSON()),
	} {
		t.Run(name, func(t *testing.T) {
			resp, raw := post(t, h.api.URL+"/v1/compose", body)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, raw)
			}
			var out struct{ AppCompose, StackHash, ConfigHash, DeploymentID string }
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.AppCompose != h.b.AppCompose || out.StackHash != h.b.StackHash || out.ConfigHash != h.b.ConfigHash || out.DeploymentID != h.b.DeploymentID {
				t.Fatalf("compose result %+v", out)
			}
		})
	}
	delete(h.m.Releases, h.w.Apps[0].ReleaseID())
	if resp, _ := post(t, h.api.URL+"/v1/compose", json.RawMessage(h.w.ConfigJSON())); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unknown release: %d", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil)
	resp, err := http.Get(h.api.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 200 || body["ok"] != true || body["allowSimulated"] != true || body["composer"] != false {
		t.Fatalf("healthz %d %v", resp.StatusCode, body)
	}
}

func mustID(t *testing.T, s string) [32]byte {
	b, err := hexb.Decode32(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
