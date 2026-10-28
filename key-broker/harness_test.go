package keybroker_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	keybroker "github.com/sealed-dev/sealed/key-broker"
	"github.com/sealed-dev/sealed/key-broker/internal/anvil"
	"github.com/sealed-dev/sealed/key-broker/internal/kbtest"
	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/verifier/attest"
)

// bundleServer serves release bundles at the release asset URL rule's paths, like GitHub release downloads.
type bundleServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	down  bool
}

func newBundleServer(t testing.TB) *bundleServer {
	s := &bundleServer{files: map[string][]byte{}, hits: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits[r.URL.Path]++
		b, ok := s.files[r.URL.Path]
		if s.down || !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *bundleServer) base() string { return s.srv.URL + "/releases/download" }

func (s *bundleServer) path(t testing.TB, app, version string) string {
	t.Helper()
	u, err := keybroker.BundleURL(s.base(), app, version)
	if err != nil {
		t.Fatal(err)
	}
	p, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return p.Path
}

func (s *bundleServer) put(t testing.TB, b *composer.Bundle) {
	s.serve(t, b.Manifest.ID, b.Version(), b.Tar)
}

func (s *bundleServer) serve(t testing.TB, app, version string, data []byte) {
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[p] = data
}

func (s *bundleServer) hitCount(t testing.TB, app, version string) int {
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[p]
}

// harness is a broker over a world.
type harness struct {
	w       *kbtest.World
	b       *keybroker.Broker
	log     *keybroker.MemoryLog
	nonces  *keybroker.NonceStore
	bundles *bundleServer
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
	h := &harness{w: w, log: &keybroker.MemoryLog{}, clock: &clock{t: time.Unix(1_800_000_000, 0)}}
	h.bundles = newBundleServer(t)
	for _, b := range w.Bundles {
		h.bundles.put(t, b)
	}
	h.nonces = keybroker.NewNonceStore(keybroker.NonceOptions{Now: h.clock.now})
	src, err := keybroker.NewHTTPBundleSource(keybroker.HTTPBundleSourceOptions{Base: h.bundles.base()})
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
	cfg := keybroker.Config{Customer: kbtest.Customer, ChainID: w.Reg.ChainID(), Contracts: w.Reg.Contracts(), AllowSimulated: !o.disallowSim}
	if o.customer != nil {
		cfg.Customer = *o.customer
	}
	h.b, err = keybroker.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	return h
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

func (h *harness) release(t testing.TB, a *kbtest.Attempt) *keybroker.Outcome {
	t.Helper()
	return h.b.Release(context.Background(), a.Body(t), "203.0.113.7")
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
