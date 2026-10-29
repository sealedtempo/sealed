package verify_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/chain"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
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
	// redirect makes GET /attest answer with a redirect to another path.
	redirect bool
}

func newAttestServer(t *testing.T, w *fixture.World) *attestServer {
	t.Helper()
	as := &attestServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", func(rw http.ResponseWriter, r *http.Request) {
		if as.redirect {
			http.Redirect(rw, r, "/moved?"+r.URL.RawQuery, http.StatusFound)
			return
		}
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
		t.Errorf("a redirect was followed to %s", r.URL)
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
	// httptest listens on 127.0.0.1, which production fetches refuse.
	return e, as, verify.LiveOptions{Options: e.opts, RootCAs: as.roots(), Timeout: 10 * time.Second,
		AllowPrivateAddresses: true}
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
		// detail, when set, must appear in the live_fetch check's detail.
		detail string
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
			name: "redirect",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				as.redirect = true
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckLiveFetch},
		},
		{
			name: "expected deployment differs",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				other := mustID(otherHash(e.b.DeploymentID))
				opts.ExpectedDeploymentID = &other
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckDeploymentID},
		},
		{
			name: "expected deployment matches",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				id := mustID(e.b.DeploymentID)
				opts.ExpectedDeploymentID = &id
				return as.srv.URL + "/attest"
			},
		},
		{
			name: "expected app missing",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.ExpectedAppIDs = []string{"inference-relay"}
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckExpectedApps},
		},
		{
			// Port 443, so the URL rule passes and the dial-time address check refuses it.
			name: "loopback destination refused without the dev flag",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.AllowPrivateAddresses = false
				return "https://127.0.0.1/attest"
			},
			fail:   []string{verify.CheckLiveFetch},
			detail: "not a public address",
		},
		{
			name: "loopback name refused after resolution",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.AllowPrivateAddresses = false
				return "https://localhost:443/attest"
			},
			fail:   []string{verify.CheckLiveFetch},
			detail: "not a public address",
		},
		{
			name: "another port without the dev flag",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.AllowPrivateAddresses = false
				return as.srv.URL + "/attest"
			},
			fail:   []string{verify.CheckLiveFetch},
			detail: "port must be 443",
		},
		{
			name: "host outside the allowlist",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.AllowedHosts = []string{"*.sslip.io"}
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckLiveFetch},
		},
		{
			name: "host in the allowlist",
			setup: func(e *env, as *attestServer, opts *verify.LiveOptions) string {
				opts.AllowedHosts = []string{"*.sslip.io", "127.0.0.1"}
				return as.srv.URL + "/attest"
			},
		},
		{
			name: "response key spelled with another case",
			setup: func(e *env, as *attestServer, _ *verify.LiveOptions) string {
				as.tweak = func(resp map[string]any, _ [32]byte) { resp["EnclaveSigner"] = resp["enclaveSigner"] }
				return as.srv.URL + "/attest"
			},
			fail: []string{verify.CheckLiveFetch},
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
			if tc.detail != "" && !strings.Contains(rep.Check(verify.CheckLiveFetch).Detail, tc.detail) {
				t.Fatalf("live_fetch detail %q lacks %q", rep.Check(verify.CheckLiveFetch).Detail, tc.detail)
			}
		})
	}
}

// fetchDoc plays the payer: GET /attest with its own nonce, keeping the raw document.
func fetchDoc(t *testing.T, as *attestServer, nonce [32]byte) []byte {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: as.roots()}}}
	resp, err := client.Get(as.srv.URL + "/attest?nonce=" + hexb.Enc(nonce[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLiveSubmission(t *testing.T) {
	nonce := sha256.Sum256([]byte("payer nonce"))
	e, as, opts := liveEnv(t)
	opts.ExpectedCustomer = &customer
	submit := func(sub verify.LiveSubmission) *verify.Report {
		t.Helper()
		rep, err := verify.VerifyLiveSubmission(context.Background(), sub, e.deps, opts.Options)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	doc := fetchDoc(t, as, nonce)
	rep := submit(verify.LiveSubmission{AttestURL: as.srv.URL + "/attest", Nonce: nonce, ObservedTLSPubKeyHash: as.spki, Attest: doc})
	if !rep.OK || rep.Mode != verify.ModeLiveSubmitted || !rep.Simulated || rep.DeploymentID != e.b.DeploymentID {
		t.Fatalf("submitted attestation:\n%s", rep.Text())
	}
	for name, tc := range map[string]struct {
		sub  verify.LiveSubmission
		fail []string
	}{
		"another nonce":      {verify.LiveSubmission{Nonce: sha256.Sum256([]byte("other")), ObservedTLSPubKeyHash: as.spki, Attest: doc}, []string{verify.CheckFreshness, verify.CheckReportData}},
		"another served key": {verify.LiveSubmission{Nonce: nonce, ObservedTLSPubKeyHash: sha256.Sum256([]byte("k")), Attest: doc}, []string{verify.CheckTLSBinding, verify.CheckFreshness, verify.CheckReportData}},
		"not a document":     {verify.LiveSubmission{Nonce: nonce, ObservedTLSPubKeyHash: as.spki, Attest: []byte(`[1]`)}, []string{verify.CheckLiveFetch}},
	} {
		t.Run(name, func(t *testing.T) {
			got := submit(tc.sub).Failed()
			sort.Strings(got)
			want := append([]string(nil), tc.fail...)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Fatalf("failed %v, want %v", got, want)
			}
		})
	}
}

func TestHostAllowlistAndPublicAddresses(t *testing.T) {
	if !verify.HostAllowed("crm.34-1-2-3.sslip.io", []string{"*.sslip.io"}) || verify.HostAllowed("sslip.io", []string{"*.sslip.io"}) ||
		verify.HostAllowed("evil-sslip.io", []string{"*.sslip.io"}) || !verify.HostAllowed("Relay.Example.COM.", []string{"relay.example.com"}) ||
		!verify.HostAllowed("anything", nil) || verify.HostAllowed("relay.example.com.evil", []string{"relay.example.com"}) {
		t.Fatal("host patterns")
	}
	for addr, public := range map[string]bool{
		"34.1.2.3": true, "2600:1900::1": true, "127.0.0.1": false, "10.1.2.3": false, "172.20.0.1": false,
		"192.168.1.1": false, "169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "fd00::1": false, "::ffff:127.0.0.1": false, "::ffff:8.8.8.8": true, "224.0.0.1": false,
		"64:ff9b::a9fe:a9fe": false,
	} {
		if got := verify.IsPublicAddr(addr); got != public {
			t.Errorf("IsPublicAddr(%s) = %v", addr, got)
		}
	}
}
