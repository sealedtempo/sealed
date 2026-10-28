package keybroker_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	keybroker "github.com/sealed-dev/sealed/key-broker"
	"github.com/sealed-dev/sealed/key-broker/internal/kbtest"
	"github.com/sealed-dev/sealed/verifier/attest"
)

// TestChainFreshness (F3, D-060): a head block older than the bound (a lagging or stuck RPC that could hide a
// revocation) or ahead of the broker's clock is refused with 503 chain_stale before any registry read, and nothing
// is released; within the bound, and with a larger configured bound, the release goes through.
func TestChainFreshness(t *testing.T) {
	reg := kbtest.NewMemRegistrar()
	w := kbtest.NewWorld(t, reg)
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)

	for _, c := range []struct {
		name   string
		lag    time.Duration
		maxAge time.Duration
		ok     bool
	}{
		{"fresh head", 0, 0, true},
		{"head 50s old", 50 * time.Second, 0, true},
		{"head 2m old", 2 * time.Minute, 0, false},
		{"head 2m old, bound 3m", 2 * time.Minute, 3 * time.Minute, true},
		{"head stuck for an hour", time.Hour, keybroker.MaxMaxHeadAge, false},
		{"head 2m in the future", -2 * time.Minute, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			reg.C.SetHeadLag(c.lag)
			defer reg.C.SetHeadLag(0)
			h := newHarness(t, w, harnessOpts{edit: func(cfg *keybroker.Config) { cfg.MaxHeadAge = c.maxAge }})
			reads := w.Secrets.Reads("sealed-notes-APP_SECRET")
			a := h.attempt(t, s)
			out := h.release(t, a)
			if c.ok {
				expectAllowed(t, out, a)
				if out.Decision.Hashes.BlockTime == 0 {
					t.Fatal("block time not logged")
				}
				return
			}
			d := expectDenied(t, out, http.StatusServiceUnavailable, keybroker.ReasonChainStale)
			if out.Decision.Decision != keybroker.DecisionDenied || out.RetryAfter == 0 || out.Decision.Released != nil {
				t.Fatalf("decision %+v", out.Decision)
			}
			last := out.Decision.Checks[len(out.Decision.Checks)-1]
			if last.Name != keybroker.CheckChain || last.Data["ageSeconds"] == nil {
				t.Fatalf("failing check %+v (%s)", last, d.Detail)
			}
			if w.Secrets.Reads("sealed-notes-APP_SECRET") != reads {
				t.Fatal("secrets read on a stale chain")
			}
		})
	}
}

// pcsDown is the inner fetcher of a collateral cache during an Intel PCS outage.
type pcsDown struct{ calls int }

func (p *pcsDown) Get(string) (map[string][]string, []byte, error) {
	p.calls++
	return nil, nil, errors.New("pcs: HTTP 503")
}

// TestPCSOutageIsUnavailable (F6): when Intel PCS cannot serve collateral for a genuine quote, the answer is 503
// unavailable (the agent retries), not a 403 quote_invalid that reads like an attack.
func TestPCSOutageIsUnavailable(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	down := &pcsDown{}
	cache, err := attest.NewCachingGetter(attest.CacheOptions{Inner: down, FetchTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	qv, err := attest.NewVerifier(attest.VerifierOptions{Getter: keybroker.CollateralProbe{Inner: cache}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, w, harnessOpts{quotes: qv, disallowSim: true})
	a := h.attempt(t, s)
	quote, err := attest.TrimQuote(readTDXQuote(t, "v5_sample"))
	if err != nil {
		t.Fatal(err)
	}
	a.Quote = quote
	d := expectDenied(t, h.release(t, a), http.StatusServiceUnavailable, keybroker.ReasonUnavailable)
	if !strings.Contains(d.Detail, "Intel PCS") || down.calls == 0 {
		t.Fatalf("detail %q, %d fetches", d.Detail, down.calls)
	}

	// Without the probe the same failure is a denial, as before.
	qv2, _ := attest.NewVerifier(attest.VerifierOptions{Getter: cache})
	h2 := newHarness(t, w, harnessOpts{quotes: qv2, disallowSim: true})
	a2 := h2.attempt(t, s)
	a2.Quote = quote
	expectDenied(t, h2.release(t, a2), http.StatusForbidden, keybroker.ReasonQuoteInvalid)
}

// countingVerifier records whether it was reached.
type countingVerifier struct{ calls int }

func (c *countingVerifier) VerifyQuote(context.Context, []byte) (*attest.QuoteResult, error) {
	c.calls++
	return nil, attest.ErrQuoteInvalid
}

// TestPCKGate: a quote whose PCK chain does not end at the Intel SGX Root CA never reaches the verifier (which would
// fetch PCS collateral for its made-up FMSPC first); a genuine chain does. Simulated quotes pass to the verifier.
func TestPCKGate(t *testing.T) {
	quote, err := attest.TrimQuote(readTDXQuote(t, "v5_sample"))
	if err != nil {
		t.Fatal(err)
	}
	inner := &countingVerifier{}
	g, err := keybroker.NewPCKGate(inner)
	if err != nil {
		t.Fatal(err)
	}
	g.Now = func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) } // inside the PCK certificate's validity
	if _, err := g.VerifyQuote(context.Background(), quote); !errors.Is(err, attest.ErrQuoteInvalid) || inner.calls != 1 {
		t.Fatalf("genuine chain: %v, %d calls", err, inner.calls)
	}
	// The same chain against another root (a self-made "Intel" chain looks like this to the gate).
	g2 := &keybroker.PCKGate{Inner: inner, Roots: x509EmptyPool(), Now: g.Now}
	_, err = g2.VerifyQuote(context.Background(), quote)
	if !errors.Is(err, attest.ErrQuoteInvalid) || !strings.Contains(err.Error(), "Intel SGX Root CA") || inner.calls != 1 {
		t.Fatalf("foreign root: %v, %d calls", err, inner.calls)
	}
	if _, err := g.VerifyQuote(context.Background(), []byte("junk")); err == nil || inner.calls != 1 {
		t.Fatalf("junk: %v, %d calls", err, inner.calls)
	}
	sim := attest.NewSimQuote(attest.SimQuoteParams{})
	_, _ = g.VerifyQuote(context.Background(), sim)
	if inner.calls != 2 {
		t.Fatal("a simulated quote did not reach the verifier")
	}
}

func x509EmptyPool() *x509.CertPool { return x509.NewCertPool() }
