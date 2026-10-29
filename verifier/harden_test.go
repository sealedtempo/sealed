package verify_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
)

func failedSorted(rep *verify.Report) []string {
	got := rep.Failed()
	sort.Strings(got)
	return got
}

// V-3: a simulated quote passes only when the verification opts in, so a consumer reading only "ok" never accepts
// one, even from a verifier whose quote verifier allows simulated quotes.
func TestSimulatedQuoteNeedsPerVerificationOptIn(t *testing.T) {
	e := newEnv(t, false)
	e.opts.AcceptSimulated = false
	rep := e.run(t)
	if rep.OK || !rep.Simulated || !slices.Equal(rep.Failed(), []string{verify.CheckQuote}) {
		t.Fatalf("evidence: ok=%v simulated=%v failed=%v", rep.OK, rep.Simulated, rep.Failed())
	}
	if !strings.Contains(rep.Check(verify.CheckQuote).Detail, "AcceptSimulated") {
		t.Fatalf("quote detail: %s", rep.Check(verify.CheckQuote).Detail)
	}
	var back verify.Report
	raw, _ := rep.JSON()
	if err := json.Unmarshal(raw, &back); err != nil || back.OK || !back.Simulated {
		t.Fatalf("JSON report %s", raw)
	}

	nonce := sha256.Sum256([]byte("payer nonce"))
	e, as, opts := liveEnv(t)
	opts.AcceptSimulated = false
	sub := verify.LiveSubmission{AttestURL: as.srv.URL + "/attest", Nonce: nonce, ObservedTLSPubKeyHash: as.spki, Attest: fetchDoc(t, as, nonce)}
	rep, err := verify.VerifyLiveSubmission(context.Background(), sub, e.deps, opts.Options)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || !slices.Equal(rep.Failed(), []string{verify.CheckQuote}) {
		t.Fatalf("live submission: ok=%v failed=%v", rep.OK, rep.Failed())
	}
	if rep := runLive(t, e, as.srv.URL+"/attest", opts); rep.OK || !slices.Equal(rep.Failed(), []string{verify.CheckQuote}) {
		t.Fatalf("live: ok=%v failed=%v", rep.OK, rep.Failed())
	}
}

// unpinnable hides every method but ChainReader's: a reader that cannot pin reads to a block.
type unpinnable struct{ verify.ChainReader }

// untimed pins reads but cannot tell the head's timestamp.
type untimed struct{ verify.ChainReader }

func (u untimed) PinHead(context.Context) (verify.ChainReader, uint64, error) {
	return unpinnable{u.ChainReader}, 100, nil
}

// lostHead pins reads to a block whose timestamp the RPC cannot return.
type lostHead struct{ verify.ChainReader }

func (l lostHead) PinHead(context.Context) (verify.ChainReader, uint64, error) { return l, 100, nil }

func (lostHead) BlockTime(context.Context, uint64) (uint64, error) {
	return 0, errors.New("eth_getBlockByNumber(100): block not found")
}

// D-060: every verification reads at a head block no older (and no further in the future) than
// Options.MaxChainHeadAge, reports the measured lag, and fails the chain check otherwise.
func TestChainHeadFreshness(t *testing.T) {
	lagged := func(lag time.Duration) func(e *env) {
		return func(e *env) { e.m.HeadAt = func() time.Time { return e.deps.Now().Add(-lag) } }
	}
	cases := []struct {
		name    string
		setup   func(e *env)
		fail    bool
		lag     any // headLagSeconds in the chain check's data, when the head was read
		limit   any // maxHeadLagSeconds
		reason  string
		message string
	}{
		{name: "59 s old", setup: lagged(59 * time.Second), lag: int64(59), limit: int64(60)},
		{name: "60 s old", setup: lagged(60 * time.Second), lag: int64(60), limit: int64(60)},
		{name: "61 s old", setup: lagged(61 * time.Second), fail: true, lag: int64(61), limit: int64(60), reason: "chain_stale", message: "head block 100 is 61s old, limit 60s"},
		{name: "an hour old", setup: lagged(time.Hour), fail: true, lag: int64(3600), limit: int64(60), reason: "chain_stale"},
		{name: "61 s in the future", setup: lagged(-61 * time.Second), fail: true, lag: int64(-61), limit: int64(60), reason: "chain_clock_skew", message: "61s in the future"},
		{name: "configured 300 s, 299 s old", setup: func(e *env) { e.opts.MaxChainHeadAge = 300 * time.Second; lagged(299 * time.Second)(e) }, lag: int64(299), limit: int64(300)},
		{name: "configured 300 s, 301 s old", setup: func(e *env) { e.opts.MaxChainHeadAge = 300 * time.Second; lagged(301 * time.Second)(e) }, fail: true, lag: int64(301), limit: int64(300), reason: "chain_stale"},
		{name: "configured above the 300 s cap", setup: func(e *env) { e.opts.MaxChainHeadAge = time.Hour; lagged(400 * time.Second)(e) }, fail: true, lag: int64(400), limit: int64(300), reason: "chain_stale"},
		{name: "configured 10 s", setup: func(e *env) { e.opts.MaxChainHeadAge = 10 * time.Second; lagged(11 * time.Second)(e) }, fail: true, lag: int64(11), limit: int64(10), reason: "chain_stale"},
		{name: "reader cannot pin a block", setup: func(e *env) { e.deps.Chain = unpinnable{e.m} }, fail: true, message: "cannot pin reads to a head block"},
		{name: "reader cannot read block times", setup: func(e *env) { e.deps.Chain = untimed{e.m} }, fail: true, message: "cannot read block timestamps"},
		{name: "head timestamp unavailable", setup: func(e *env) { e.deps.Chain = lostHead{e.m} }, fail: true, message: "timestamp of head block 100: eth_getBlockByNumber(100): block not found"},
		{name: "in-memory reader with WithHead", setup: func(e *env) {
			e.deps.Chain = verify.WithHead(unpinnable{e.m}, 100, func() time.Time { return e.deps.Now().Add(-3 * time.Second) })
		}, lag: int64(3), limit: int64(60)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, false)
			tc.setup(e)
			rep := e.run(t)
			c := rep.Check(verify.CheckChain)
			if tc.fail != !c.OK {
				t.Fatalf("chain ok=%v: %s", c.OK, c.Detail)
			}
			want := []string(nil)
			if tc.fail {
				want = []string{verify.CheckChain}
			}
			if got := failedSorted(rep); !slices.Equal(got, want) {
				t.Fatalf("failed %v, want %v\n%s", got, want, rep.Text())
			}
			if tc.lag != nil && (c.Data["headLagSeconds"] != tc.lag || c.Data["maxHeadLagSeconds"] != tc.limit) {
				t.Fatalf("data %v, want lag %v limit %v", c.Data, tc.lag, tc.limit)
			}
			if r, _ := c.Data["reason"].(string); r != tc.reason {
				t.Fatalf("reason %q, want %q", r, tc.reason)
			}
			if tc.message != "" && !strings.Contains(c.Detail, tc.message) {
				t.Fatalf("detail %q lacks %q", c.Detail, tc.message)
			}
			if tc.fail && rep.OK {
				t.Fatal("report OK with a failed chain check")
			}
		})
	}
}

// D-060 in live mode: a stale RPC fails the chain check of a live verification as well.
func TestLiveChainHeadFreshness(t *testing.T) {
	e, as, opts := liveEnv(t)
	e.m.HeadAt = func() time.Time { return e.deps.Now().Add(-5 * time.Minute) }
	rep := runLive(t, e, as.srv.URL+"/attest", opts)
	if c := rep.Check(verify.CheckChain); rep.OK || c.OK || c.Data["reason"] != "chain_stale" || c.Data["headLagSeconds"] != int64(300) {
		t.Fatalf("live with a stale head:\n%s", rep.Text())
	}
}

// D-060: the chain id must be the configured one, and 4217 when none is configured.
func TestChainIDDefaultsToMainnet(t *testing.T) {
	e := newEnv(t, false)
	e.opts.ChainID = 0
	if rep := e.run(t); !rep.OK {
		t.Fatalf("mainnet world with the default chain:\n%s", rep.Text())
	}
	e.m.ID = 31337
	rep := e.run(t)
	if c := rep.Check(verify.CheckChain); c.OK || !strings.Contains(c.Detail, "RPC is chain 31337, verifier expects 4217") {
		t.Fatalf("chain check on another chain: %s", c.Detail)
	}
}

// V-5: the report shows what the config asks for beyond its hash, without RPC keys or URL credentials.
func TestReportShowsApprovedConfig(t *testing.T) {
	e := newEnvWith(t, false, func(w *fixture.World) {
		w.ConfigEdit = func(doc map[string]any) {
			doc["debug"] = true
			doc["egressAdditions"] = map[string]any{"crm": []any{"api.hubspot.com:443", "smtp.example.com:587"}, "llm-gateway": []any{}}
			doc["allowedVpcRanges"] = []any{"10.8.0.0/16"}
			ep := doc["endpoints"].(map[string]any)
			ep["tempoRpc"] = "https://alice:pw@rpc.provider.example/v2/SECRET-KEY?token=abc"
			ep["keyBroker"] = "https://kb.example/v1?debug=1#frag"
		}
	})
	rep := e.run(t)
	if !rep.OK {
		t.Fatalf("report:\n%s", rep.Text())
	}
	c := rep.Config
	if c == nil || !c.Debug || c.Endpoints.KeyBroker != "https://kb.example/v1" || c.Endpoints.TempoRPC != "https://rpc.provider.example" ||
		c.Endpoints.Relay != "https://relay.example" || c.Endpoints.RelayAttest != "https://attest.relay.example/attest" ||
		c.Endpoints.PlatformAPI != "https://api.example" || !slices.Equal(c.EgressAdditions["crm"], []string{"api.hubspot.com:443", "smtp.example.com:587"}) ||
		len(c.EgressAdditions) != 1 || !slices.Equal(c.AllowedVpcRanges, []string{"10.8.0.0/16"}) || c.RelayOwner == "" {
		t.Fatalf("config summary %+v", c)
	}
	text := rep.Text()
	raw, _ := rep.JSON()
	for _, want := range []string{"key broker  https://kb.example/v1", "relay       https://relay.example", "crm may also reach api.hubspot.com:443, smtp.example.com:587",
		"vpc ranges  10.8.0.0/16", "NOTE: config.debug is on"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{"SECRET-KEY", "token=abc", "alice", "pw@", "debug=1", "frag"} {
		if strings.Contains(text, secret) || strings.Contains(string(raw), secret) {
			t.Errorf("report leaks %q", secret)
		}
	}
	if plain := newEnv(t, false).run(t); plain.Config == nil || plain.Config.Debug || strings.Contains(plain.Text(), "config.debug") {
		t.Fatalf("default config summary %+v", plain.Config)
	}
}

// V-1: a live fetch goes only to https://<host>[:443]/attest with the verifier's own nonce as the whole query. A
// caller cannot pick the path, the query, credentials or the port, so the verifier is not an HTTP client for whoever
// reaches its API (inside a CVM the fetch leaves under sealed-verifierd's egress rule, not the caller's).
func TestLiveFetchOnlyFetchesAttest(t *testing.T) {
	var hits []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.RequestURI())
		http.Error(w, "no", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	base := srv.URL // https://127.0.0.1:<port>
	hostPort := strings.TrimPrefix(base, "https://")
	e, _, opts := liveEnv(t)
	opts.InsecureSkipTLSVerify = true
	for _, tc := range []struct {
		url, want string
		public    bool // without the dev flag for private addresses and ports
	}{
		{url: base + "/collect/customer-data?leak=crm-export-row-1", want: "path must be /attest"},
		{url: base + "/attest/", want: "path must be /attest"},
		{url: base + "/%61ttest", want: "path must be /attest"},
		{url: base + "/attest/../attest", want: "path must be /attest"},
		{url: base + "/attest?leak=crm-export-row-1", want: "must not carry a query"},
		{url: base + "/attest?nonce=0x01", want: "must not carry a query"},
		{url: base + "/attest?", want: "must not carry a query"},
		{url: base + "/attest#frag", want: "must not carry a fragment"},
		{url: "https://user:pw@" + hostPort + "/attest", want: "must not carry credentials"},
		{url: "https:///attest", want: "no host"},
		{url: "http://" + hostPort + "/attest", want: "must be https"},
		{url: "https://attest.34-1-2-3.sslip.io:8443/attest", want: "port must be 443", public: true},
	} {
		t.Run(tc.url, func(t *testing.T) {
			o := opts
			if tc.public {
				o.AllowPrivateAddresses = false
			}
			rep := runLive(t, e, tc.url, o)
			c := rep.Check(verify.CheckLiveFetch)
			if rep.OK || c == nil || c.OK || !strings.Contains(c.Detail, tc.want) || len(rep.Checks) != 1 {
				t.Fatalf("live fetch of %s: %+v", tc.url, rep.Checks)
			}
		})
	}
	if len(hits) != 0 {
		t.Fatalf("the verifier sent requests the caller chose: %v", hits)
	}
	// The one accepted form reaches the server with only the nonce as query.
	rep := runLive(t, e, base+"/attest", opts)
	if len(hits) != 1 || !strings.HasPrefix(hits[0], "/attest?nonce=0x") || len(hits[0]) != len("/attest?nonce=0x")+64 {
		t.Fatalf("hits %v", hits)
	}
	if c := rep.Check(verify.CheckLiveFetch); c.OK || !strings.Contains(c.Detail, "HTTP 418") {
		t.Fatalf("live fetch: %+v", c)
	}
}
