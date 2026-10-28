package verify_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// attestServer serves GET /attest like sealed-agent behind Caddy, binding the key of its own TLS certificate.
type attestServer struct {
	srv  *httptest.Server
	spki [32]byte
	// tweak edits the response before it is sent (tamper cases).
	tweak func(resp map[string]any, nonce [32]byte)
	// respond overrides the nonce and key hash the quote binds.
	bindNonce *[32]byte
	bindKey   *[32]byte
}

func newAttestServer(t *testing.T, w *fixture.World) *attestServer {
	t.Helper()
	as := &attestServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", func(rw http.ResponseWriter, r *http.Request) {
		nonce, err := hexb.Decode32(r.URL.Query().Get("nonce"))
		if err != nil {
			http.Error(rw, "bad nonce", http.StatusBadRequest)
			return
		}
		n, k := nonce, as.spki
		if as.bindNonce != nil {
			n = *as.bindNonce
		}
		if as.bindKey != nil {
			k = *as.bindKey
		}
		resp := w.LiveResponse(n, k)
		if as.tweak != nil {
			as.tweak(resp, nonce)
		}
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(resp)
	})
	mux.HandleFunc("/moved", func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, "/attest?"+r.URL.RawQuery, http.StatusFound)
	})
	as.srv = httptest.NewUnstartedServer(mux)
	as.srv.StartTLS()
	t.Cleanup(as.srv.Close)
	as.spki = sha256.Sum256(as.srv.Certificate().RawSubjectPublicKeyInfo)
	return as
}

func (as *attestServer) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(as.srv.Certificate())
	return p
}

func liveEnv(t *testing.T) (*env, *attestServer, verify.LiveOptions) {
	e := newEnv(t, false)
	as := newAttestServer(t, e.w)
	return e, as, verify.LiveOptions{Options: verify.Options{ChainID: 4217, RequireOnchainRecord: true}, RootCAs: as.roots(), Timeout: 10 * time.Second}
}

func runLive(t *testing.T, e *env, url string, opts verify.LiveOptions) *verify.Report {
	t.Helper()
	rep, err := verify.VerifyLive(context.Background(), url, e.deps, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestLiveHappyPath(t *testing.T) {
	e, as, opts := liveEnv(t)
	rep := runLive(t, e, as.srv.URL+"/attest", opts)
	if !rep.OK || !rep.Simulated || rep.Mode != verify.ModeLive {
		t.Fatalf("live verification failed:\n%s", rep.Text())
	}
	for _, name := range []string{verify.CheckLiveFetch, verify.CheckTLSBinding, verify.CheckFreshness, verify.CheckReportData,
		verify.CheckQuote, verify.CheckRTMR3, verify.CheckStackRecompute, verify.CheckStackApproved, verify.CheckOnchainRecord} {
		if c := rep.Check(name); c == nil || !c.OK {
			t.Errorf("check %s missing or failed", name)
		}
	}
	if rep.DeploymentID != e.b.DeploymentID || rep.StackHash != e.b.StackHash {
		t.Fatalf("ids %s %s", rep.DeploymentID, rep.StackHash)
	}
	if rep.Check(verify.CheckOnchainRecord).Data["eventLogMatchesRecord"] != true {
		t.Fatal("event log should match the registered one")
	}
}

func TestLiveTamper(t *testing.T) {
	otherKey := sha256.Sum256([]byte("attacker key"))
	fixedNonce := sha256.Sum256([]byte("replayed nonce"))
	cases := []struct {
		name  string
		setup func(e *env, as *attestServer, opts *verify.LiveOptions) string // returns the URL
		fail  []string
	}{
		{
			name: "claims a key it does not serve (relayed attestation)",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				as.bindKey = &otherKey
				as.tweak = func(resp map[string]any, _ [32]byte) { resp["tlsPubKeyHash"] = hexb.Enc(otherKey[:]) }
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckTLSBinding, verify.CheckFreshness, verify.CheckReportData},
		},
		{
			name: "replays a quote for another nonce",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				as.bindNonce = &fixedNonce
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckFreshness, verify.CheckReportData},
		},
		{
			name: "wrong enclave signer",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				e.w.EnclaveSigner = stranger
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckOnchainRecord},
		},
		{
			name: "release revoked since boot",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				e.m.Releases[e.w.Apps[0].ReleaseID()].Status = chain.ReleaseRevoked
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckReleasesActive, verify.CheckStackApproved},
		},
		{
			name: "operator expected (relay check), customer stack served",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.ExpectedCustomer = &stranger
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckExpectedCustomer},
		},
		{
			name: "releaseIds disagree with config",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				as.tweak = func(resp map[string]any, _ [32]byte) { resp["releaseIds"] = resp["releaseIds"].([]string)[:1] }
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckConfigBinding},
		},
		{
			name: "event log as a JSON string (dstack shape)",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				as.tweak = func(resp map[string]any, _ [32]byte) {
					raw, _ := json.Marshal(resp["eventLog"])
					resp["eventLog"] = string(raw)
				}
				return as.srv.URL + "/attest"
			},
		},
		{
			name: "untrusted certificate",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.RootCAs = x509.NewCertPool()
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckLiveFetch},
		},
		{
			name: "untrusted certificate with the dev skip flag still binds the key",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.RootCAs = x509.NewCertPool()
				opts.InsecureSkipTLSVerify = true
				return as.srv.URL + "/attest"
			},
		},
		{
			name: "plain http",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				return strings.Replace(as.srv.URL, "https", "http", 1) + "/attest"
			},
			fail: []string{verify.CheckLiveFetch},
		},
		{
			name:  "redirect",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string { return as.srv.URL + "/moved" },
			fail:  []string{verify.CheckLiveFetch},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, as, opts := liveEnv(t)
			url := tc.setup(e, as, &opts)
			rep := runLive(t, e, url, opts)
			got := rep.Failed()
			want := append([]string(nil), tc.fail...)
			sort.Strings(got)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Fatalf("failed checks %v, want %v\n%s", got, want, rep.Text())
			}
		})
	}
}
