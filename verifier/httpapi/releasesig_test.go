package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/httpapi"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
)

// TestReleaseSignatureInReports (supply-2): the daemon's reports carry release_signature. A dev daemon passes a
// release no CI signed and says so; a production daemon fails it, and /healthz says whether signatures are checked.
func TestReleaseSignatureInReports(t *testing.T) {
	h := newHarness(t, fixture.Composer{})
	unsigned := fixture.Signatures{Unsigned: map[[32]byte]bool{h.w.Apps[0].BundleHash: true}}

	h.srv.Deps.Signatures = fixture.Signatures{}
	_, raw := post(t, h.api.URL+"/v1/verify/evidence", h.b)
	rep := decodeReport(t, raw)
	if c := rep.Check(verify.CheckReleaseSignature); !rep.OK || c == nil || !c.OK || !strings.Contains(c.Detail, "signed by "+fixture.ReleaseSigner) {
		t.Fatalf("signed releases on a dev daemon:\n%s", rep.Text())
	}

	h.srv.Deps.Signatures = unsigned
	_, raw = post(t, h.api.URL+"/v1/verify/evidence", h.b)
	rep = decodeReport(t, raw)
	if c := rep.Check(verify.CheckReleaseSignature); !rep.OK || c == nil || !c.OK || !strings.HasPrefix(c.Detail, "DEV: ") {
		t.Fatalf("unsigned release on a dev daemon:\n%s", rep.Text())
	}

	q, err := attest.NewVerifier(attest.VerifierOptions{Getter: offline{}})
	if err != nil {
		t.Fatal(err)
	}
	prod := &httpapi.Server{
		Deps:    verify.Deps{Quotes: q, Chain: h.m, Composer: fixture.Composer{}, Signatures: unsigned, Now: func() time.Time { return time.Unix(int64(h.m.Now)+5, 0) }},
		ChainID: 4217, LiveTimeout: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	api := httptest.NewServer(prod.Handler())
	t.Cleanup(api.Close)
	_, raw = post(t, api.URL+"/v1/verify/evidence", h.b)
	rep = decodeReport(t, raw)
	if c := rep.Check(verify.CheckReleaseSignature); rep.OK || c == nil || c.OK || strings.Contains(c.Detail, "DEV") ||
		!strings.Contains(c.Detail, h.w.Apps[0].Slug+" "+h.w.Apps[0].Version+": ") {
		t.Fatalf("unsigned release on a production daemon:\n%s", rep.Text())
	}

	for _, tc := range []struct {
		srv  *httptest.Server
		want bool
	}{{api, true}, {h.api, true}} {
		resp, err := http.Get(tc.srv.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if body["releaseSignatures"] != tc.want {
			t.Fatalf("healthz %v", body)
		}
	}
	h.srv.Deps.Signatures = nil
	resp, err := http.Get(h.api.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["releaseSignatures"] != false {
		t.Fatalf("healthz without a signature verifier %v", body)
	}
}
