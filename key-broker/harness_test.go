package keybroker_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	keybroker "github.com/sealed-dev/sealed/key-broker"
	"github.com/sealed-dev/sealed/key-broker/internal/anvil"
	"github.com/sealed-dev/sealed/key-broker/internal/kbtest"
	"github.com/sealed-dev/sealed/verifier/attest"
)

// harness is a broker over a world.
type harness struct {
	w       *kbtest.World
	b       *keybroker.Broker
	log     *keybroker.MemoryLog
	nonces  *keybroker.NonceStore
	bundles *kbtest.BundleServer
	clock   *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harnessOpts struct {
	quotes      keybroker.QuoteVerifier
	disallowSim bool
	secrets     keybroker.SecretStore
	mac         keybroker.MACSigner
	log         keybroker.DecisionLog
	customer    *[20]byte
	chain       keybroker.Chain
	bundles     keybroker.BundleSource
	// edit changes the broker config.
	edit func(c *keybroker.Config)
}

var (
	simVerifierOnce sync.Once
	simVerifierVal  *attest.Verifier
)

func simVerifier(t testing.TB) *attest.Verifier {
	t.Helper()
	simVerifierOnce.Do(func() {
		v, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: true})
		if err != nil {
			t.Fatal(err)
		}
		simVerifierVal = v
	})
	return simVerifierVal
}

func newHarness(t testing.TB, w *kbtest.World, o harnessOpts) *harness {
	t.Helper()
	// The clock starts at the wall clock (whole seconds), since the head block of a real chain carries real time.
	h := &harness{w: w, log: &keybroker.MemoryLog{}, clock: &clock{t: time.Now().Truncate(time.Second)}}
	h.bundles = kbtest.NewBundleServer(t)
	for _, b := range w.Bundles {
		h.bundles.Put(t, b)
	}
	h.nonces = keybroker.NewNonceStore(keybroker.NonceOptions{Now: h.clock.now})
	src, err := keybroker.NewHTTPBundleSource(keybroker.HTTPBundleSourceOptions{Base: h.bundles.Base()})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := keybroker.NewLocalHMAC(w.MACKey)
	if err != nil {
		t.Fatal(err)
	}
	deps := keybroker.Deps{Nonces: h.nonces, Quotes: simVerifier(t), Chain: w.Reg.Chain(), Bundles: src, Secrets: w.Secrets, MAC: mac, Log: h.log, Now: h.clock.now}
	if o.quotes != nil {
		deps.Quotes = o.quotes
	}
	if o.secrets != nil {
		deps.Secrets = o.secrets
	}
	if o.mac != nil {
		deps.MAC = o.mac
	}
	if o.log != nil {
		deps.Log = o.log
	}
	if o.chain != nil {
		deps.Chain = o.chain
	}
	if o.bundles != nil {
		deps.Bundles = o.bundles
	}
	cfg := keybroker.Config{Customer: kbtest.Customer, ChainID: w.Reg.ChainID(), Contracts: w.Reg.Contracts(), FeeSplitter: kbtest.FeeSplitter,
		FeeToken: kbtest.FeeToken, AllowSimulated: !o.disallowSim}
	if o.customer != nil {
		cfg.Customer = *o.customer
	}
	if o.edit != nil {
		o.edit(&cfg)
	}
	h.b, err = keybroker.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.b.Close(context.Background()) })
	return h
}

// flush waits for the decisions the broker logs in the background.
func (h *harness) flush(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.b.Flush(ctx); err != nil {
		t.Fatalf("decision log not flushed: %v", err)
	}
}

func (h *harness) nonce(t testing.TB) [32]byte {
	t.Helper()
	resp, err := h.b.IssueNonce()
	if err != nil {
		t.Fatal(err)
	}
	var n [32]byte
	b, err := decodeHex(resp.Nonce)
	if err != nil || len(b) != 32 {
		t.Fatalf("nonce %q", resp.Nonce)
	}
	copy(n[:], b)
	return n
}

func (h *harness) attempt(t testing.TB, s *kbtest.Stack) *kbtest.Attempt {
	t.Helper()
	return kbtest.NewAttempt(t, s, h.nonce(t))
}

// release runs one request and waits until its decision is in the log.
func (h *harness) release(t testing.TB, a *kbtest.Attempt) *keybroker.Outcome {
	t.Helper()
	out := h.b.Release(context.Background(), a.Body(t), "203.0.113.7")
	h.flush(t)
	return out
}

// expectAllowed requires a 200 and returns the opened plaintext.
func expectAllowed(t testing.TB, out *keybroker.Outcome, a *kbtest.Attempt) *keybroker.ReleasePlaintext {
	t.Helper()
	if out.Status != http.StatusOK {
		t.Fatalf("status %d: %+v", out.Status, out.Body)
	}
	resp, ok := out.Body.(*keybroker.ReleaseResponse)
	if !ok {
		t.Fatalf("body %T", out.Body)
	}
	return a.Open(t, resp)
}

// expectDenied requires the given status and reason.
func expectDenied(t testing.TB, out *keybroker.Outcome, status int, reason string) *keybroker.Denial {
	t.Helper()
	d, ok := out.Body.(*keybroker.Denial)
	if !ok {
		t.Fatalf("status %d, body %T %+v, want %d %s", out.Status, out.Body, out.Body, status, reason)
	}
	if out.Status != status || d.Reason != reason {
		t.Fatalf("got %d %s (%s), want %d %s", out.Status, d.Reason, d.Detail, status, reason)
	}
	if out.Decision.Reason != reason || out.Decision.HTTPStatus != status {
		t.Fatalf("decision log has %s/%d", out.Decision.Reason, out.Decision.HTTPStatus)
	}
	return d
}

func randomNonce(t testing.TB) [32]byte {
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	return n
}

func decodeHex(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, "0x")
	if !ok {
		return nil, errors.New("missing 0x")
	}
	return hex.DecodeString(rest)
}

// registrars returns the registries every table test runs against: in memory always, the real contracts on anvil
// when anvil and forge are installed.
func registrars(t *testing.T) map[string]func(t *testing.T) kbtest.Registrar {
	return map[string]func(t *testing.T) kbtest.Registrar{
		"memory": func(t *testing.T) kbtest.Registrar { return kbtest.NewMemRegistrar() },
		"anvil": func(t *testing.T) kbtest.Registrar {
			if testing.Short() {
				t.Skip("anvil tests skipped in -short mode")
			}
			return kbtest.NewAnvilRegistrar(t)
		},
	}
}

// repoPath returns a path under the repository root.
func repoPath(t testing.TB, parts ...string) string {
	t.Helper()
	root, err := anvil.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(append([]string{root}, parts...)...)
}
