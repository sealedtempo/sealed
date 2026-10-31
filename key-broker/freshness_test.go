package keybroker_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/attest"
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

// fetchHook runs its hook once, on the first bundle fetch. The bundle fetches and the compose sit between the first
// pin and the approval read, and can take most of the 90 s release deadline.
type fetchHook struct {
	inner keybroker.BundleSource
	once  sync.Once
	hook  func()
}

func (f *fetchHook) Fetch(ctx context.Context, ref keybroker.BundleRef) (*composer.Bundle, error) {
	f.once.Do(f.hook)
	return f.inner.Fetch(ctx, ref)
}

// macHook runs its hook once, on the first KMS call, which comes after the secret reads and right before the seal.
type macHook struct {
	inner keybroker.MACSigner
	once  sync.Once
	hook  func()
}

func (m *macHook) MAC(ctx context.Context, data []byte) ([]byte, error) {
	m.once.Do(m.hook)
	return m.inner.MAC(ctx, data)
}

// chainChecks returns the decision's chain checks in order.
func chainChecks(d *keybroker.Decision) []keybroker.Check {
	var out []keybroker.Check
	for _, c := range d.Checks {
		if c.Name == keybroker.CheckChain {
			out = append(out, c)
		}
	}
	return out
}

func blockOf(t *testing.T, c keybroker.Check) uint64 {
	t.Helper()
	n, ok := c.Data["blockNumber"].(uint64)
	if !ok {
		t.Fatalf("chain check without blockNumber: %+v", c)
	}
	return n
}

// TestFreshnessAtApproval (kb-2): the approval and deployment reads are pinned again to the current head right before
// they are made, and that head must be within MaxHeadAge too. A revocation mined while the bundles were fetched is
// seen, and a release whose first pin aged past the bound during the fetch is refused, so the approval read is never
// more than MaxHeadAge old. Ported from the verifier's TestKBVerifyFreshnessCheckedOnlyAtPin, which got 200 for a
// stack revoked during the fetch with the broker's clock 85 s past the pinned head.
func TestFreshnessAtApproval(t *testing.T) {
	for name, mk := range registrars(t) {
		t.Run(name, func(t *testing.T) {
			w := kbtest.NewWorld(t, mk(t))
			for i, c := range []struct {
				name    string
				revoke  bool
				advance time.Duration
				reasons []string
			}{
				{"85 s pass during the fetch", false, 85 * time.Second, []string{keybroker.ReasonChainStale}},
				// On the memory chain every read sees the latest state, so only anvil shows the stale read here.
				{"revoked during the fetch", true, 0, []string{keybroker.ReasonStackNotApproved}},
				{"revoked and 85 s pass during the fetch", true, 85 * time.Second, []string{keybroker.ReasonChainStale, keybroker.ReasonStackNotApproved}},
			} {
				t.Run(c.name, func(t *testing.T) {
					salt := fmt.Sprintf("0x%064x", i+1)
					s := w.Compose(t, kbtest.StackOptions{Edit: func(cfg *composer.Config) { cfg.Salt = salt }})
					w.Approve(t, s)
					hook := &fetchHook{}
					h := newHarness(t, w, harnessOpts{bundles: hook})
					src, err := keybroker.NewHTTPBundleSource(keybroker.HTTPBundleSourceOptions{Base: h.bundles.Base()})
					if err != nil {
						t.Fatal(err)
					}
					hook.inner = src
					hook.hook = func() {
						if c.revoke {
							w.Reg.RevokeStack(t, kbtest.Customer, s.Result.StackHash)
						}
						h.clock.advance(c.advance)
					}
					reads := w.Secrets.Reads("sealed-notes-APP_SECRET")
					out := h.release(t, h.attempt(t, s))
					if out.Status == http.StatusOK || !slices.Contains(c.reasons, out.Decision.Reason) {
						t.Fatalf("got %d %s (%s), want one of %v", out.Status, out.Decision.Reason, out.Decision.Detail, c.reasons)
					}
					if out.Decision.Released != nil || w.Secrets.Reads("sealed-notes-APP_SECRET") != reads {
						t.Fatal("secrets read or released")
					}
					cc := chainChecks(out.Decision)
					if len(cc) != 2 || !cc[0].OK {
						t.Fatalf("chain checks %+v, want the first pin and the repin", cc)
					}
					if out.Decision.Reason == keybroker.ReasonStackNotApproved {
						// The approval was read at a block that includes the revocation, after the first pin.
						if !cc[1].OK || blockOf(t, cc[1]) <= blockOf(t, cc[0]) || out.Decision.Hashes.BlockNumber != blockOf(t, cc[1]) {
							t.Fatalf("approval not read at a newer head: %+v, logged block %d", cc, out.Decision.Hashes.BlockNumber)
						}
					}
				})
			}

			// Without delay or revocation the release goes through, with both pins logged.
			s := w.Compose(t, kbtest.StackOptions{})
			w.Approve(t, s)
			h := newHarness(t, w, harnessOpts{})
			a := h.attempt(t, s)
			out := h.release(t, a)
			expectAllowed(t, out, a)
			cc := chainChecks(out.Decision)
			if len(cc) != 2 || !cc[0].OK || !cc[1].OK || out.Decision.Hashes.BlockNumber != blockOf(t, cc[1]) {
				t.Fatalf("chain checks %+v, logged block %d", cc, out.Decision.Hashes.BlockNumber)
			}
		})
	}
}

// TestFreshnessAtSeal (kb-2): the release decision is made when the secrets are sealed. If the secret reads and the
// KMS derivation took so long that the head the approval was read at is now older than MaxHeadAge, nothing is
// sealed and the answer is 503 chain_stale.
func TestFreshnessAtSeal(t *testing.T) {
	for name, mk := range registrars(t) {
		t.Run(name, func(t *testing.T) {
			w := kbtest.NewWorld(t, mk(t))
			s := w.Compose(t, kbtest.StackOptions{})
			w.Approve(t, s)
			for _, c := range []struct {
				advance time.Duration
				ok      bool
			}{{30 * time.Second, true}, {70 * time.Second, false}} {
				t.Run(c.advance.String(), func(t *testing.T) {
					inner, err := keybroker.NewLocalHMAC(w.MACKey)
					if err != nil {
						t.Fatal(err)
					}
					mac := &macHook{inner: inner}
					h := newHarness(t, w, harnessOpts{mac: mac})
					mac.hook = func() { h.clock.advance(c.advance) }
					a := h.attempt(t, s)
					out := h.release(t, a)
					if c.ok {
						expectAllowed(t, out, a)
						return
					}
					expectDenied(t, out, http.StatusServiceUnavailable, keybroker.ReasonChainStale)
					last := out.Decision.Checks[len(out.Decision.Checks)-1]
					if last.Name != keybroker.CheckChain || last.Data["ageSeconds"] == nil || out.Decision.Released != nil || out.RetryAfter == 0 {
						t.Fatalf("failing check %+v, released %v", last, out.Decision.Released)
					}
					for _, ch := range out.Decision.Checks {
						if ch.Name == keybroker.CheckSeal {
							t.Fatal("sealed on a stale head")
						}
					}
				})
			}
		})
	}
}

// rewindingChain answers its second Pin with a head one block behind the first, like an RPC whose load balancer
// moved to a lagging backend.
type rewindingChain struct {
	*kbtest.MemChain
	mu   sync.Mutex
	pins int
}

func (c *rewindingChain) Pin(ctx context.Context) (keybroker.Registry, keybroker.Head, error) {
	reg, head, err := c.MemChain.Pin(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pins++
	if c.pins == 2 {
		head.Number--
	}
	return reg, head, err
}

// TestRepinKeepsNewerHead (kb-2): when the second pin comes back behind the first, the approval reads stay at the
// first pin's block, the newer view, and its age is checked again.
func TestRepinKeepsNewerHead(t *testing.T) {
	reg := kbtest.NewMemRegistrar()
	w := kbtest.NewWorld(t, reg)
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)
	rc := &rewindingChain{MemChain: reg.C}
	h := newHarness(t, w, harnessOpts{chain: rc})
	a := h.attempt(t, s)
	out := h.release(t, a)
	expectAllowed(t, out, a)
	cc := chainChecks(out.Decision)
	if rc.pins != 2 || len(cc) != 2 || blockOf(t, cc[1]) != blockOf(t, cc[0]) || out.Decision.Hashes.BlockNumber != blockOf(t, cc[0]) {
		t.Fatalf("%d pins, chain checks %+v, logged block %d", rc.pins, cc, out.Decision.Hashes.BlockNumber)
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
