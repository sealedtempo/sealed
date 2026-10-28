// Package catalogtest builds real release bundles from the composer's fixture apps (runtime/composer/testdata/apps)
// and serves them from a local HTTP server laid out like a GitHub release asset base (D-046), so tests can run the
// real composer behind the bundle fetcher.
package catalogtest

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/verifier/bundles"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// Registry is the catalog registry the bundles are built for (config/defaults.yaml catalog.registry).
const Registry = "ghcr.io/sealedtempo"

// FixtureApps are the composer fixture apps, sorted by id. llm-gateway brings the payer and verifierd sidecars.
var FixtureApps = []string{"llm-gateway", "notes"}

// RepoRoot is the directory holding go.mod.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// Build builds the bundle of one fixture app (runtime/composer/testdata/apps/<app>), or of appDir when it is a path.
func Build(t testing.TB, app string) *composer.Bundle {
	t.Helper()
	dir := app
	if !strings.Contains(app, string(filepath.Separator)) {
		dir = filepath.Join(RepoRoot(t), "runtime", "composer", "testdata", "apps", app)
	}
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: dir, Registry: Registry})
	if err != nil {
		t.Fatalf("build bundle %s: %v", app, err)
	}
	return b
}

// CopyApp copies a fixture app directory into a temp dir so a test can change it, and returns the copy's path.
func CopyApp(t testing.TB, app string) string {
	t.Helper()
	src := filepath.Join(RepoRoot(t), "runtime", "composer", "testdata", "apps", app)
	dst := filepath.Join(t.TempDir(), app)
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// Bundles builds every fixture app, sorted by id.
func Bundles(t testing.TB) []*composer.Bundle {
	t.Helper()
	out := make([]*composer.Bundle, len(FixtureApps))
	for i, app := range FixtureApps {
		out[i] = Build(t, app)
	}
	return out
}

// Server is a release asset host: GET <Base>/<app>-v<version>/<app>-<version>.bundle.tar.
type Server struct {
	*httptest.Server
	Base string

	mu     sync.Mutex
	assets map[string][]byte // URL path -> body
	hits   map[string]int
	down   bool
}

// NewServer starts a release asset server; it stops when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	s := &Server{assets: map[string][]byte{}, hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	s.Base = s.URL + "/sealedtempo/sealed/releases/download"
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	body, ok := s.assets[r.URL.Path]
	down := s.down
	s.mu.Unlock()
	switch {
	case down:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	case r.Method != http.MethodGet:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	case !ok:
		http.NotFound(w, r)
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}
}

func (s *Server) path(t testing.TB, app, version string) string {
	t.Helper()
	u, err := bundles.AssetRule{Base: s.Base}.BundleURL(app, version)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(u, s.URL)
}

// Publish serves b at its release asset URL.
func (s *Server) Publish(t testing.TB, b *composer.Bundle) {
	t.Helper()
	s.PublishBytes(t, b.Manifest.ID, b.Version(), b.Tar)
}

// PublishBytes serves data as the bundle of (app, version).
func (s *Server) PublishBytes(t testing.TB, app, version string, data []byte) {
	t.Helper()
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[p] = bytes.Clone(data)
}

// Remove deletes the asset of (app, version).
func (s *Server) Remove(t testing.TB, app, version string) {
	t.Helper()
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assets, p)
}

// SetDown makes every request answer 503.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// Hits counts requests for the asset of (app, version).
func (s *Server) Hits(t testing.TB, app, version string) int {
	t.Helper()
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[p]
}

// TotalHits counts every request.
func (s *Server) TotalHits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hits {
		n += h
	}
	return n
}

// ConfigParams are the deployment-specific config fields.
type ConfigParams struct {
	ChainID  uint64
	Customer common.Address
	Salt     [32]byte
	ImageID  [32]byte
	Addrs    chain.Addresses
}

func lowerHex(b []byte) string { return fmt.Sprintf("0x%x", b) }

// Config returns the public config (sealed-config/v1) of a stack of bundles, in its canonical (normalized CJSON)
// form, so configHash is sha256 of the returned bytes.
func Config(t testing.TB, p ConfigParams, bs []*composer.Bundle) []byte {
	t.Helper()
	feeSplitter := p.Addrs.FeeSplitter
	if feeSplitter == (common.Address{}) {
		feeSplitter = common.HexToAddress("0x00000000000000000000000000000000000000e4")
	}
	c := &composer.Config{
		Schema:          composer.ConfigSchema,
		ChainID:         int64(p.ChainID),
		Customer:        lowerHex(p.Customer[:]),
		Salt:            lowerHex(p.Salt[:]),
		ImageID:         lowerHex(p.ImageID[:]),
		ComposerVersion: composer.Version,
		Hostnames:       composer.Hostnames{Scheme: composer.SchemeSslip, IP: "34.1.2.3"},
		EgressAdditions: map[string][]string{"notes": {"smtp.example.com:587"}},
		Endpoints: composer.Endpoints{
			KeyBroker:   "https://sealed-key-broker-xyz.a.run.app",
			PlatformAPI: "https://api.sealed.example",
			TempoRPC:    "https://rpc.tempo.xyz",
			Relay:       "https://relay.sealed.example",
			RelayAttest: "https://attest.relay.sealed.example/attest",
		},
		Contracts: composer.Contracts{
			PlatformRegistry:   lowerHex(p.Addrs.PlatformRegistry[:]),
			AppRegistry:        lowerHex(p.Addrs.AppRegistry[:]),
			DeploymentRegistry: lowerHex(p.Addrs.DeploymentRegistry[:]),
			FeeSplitter:        lowerHex(feeSplitter[:]),
		},
		FeeToken:   "0x20c000000000000000000000b9537d11c60e8b50",
		Settlement: composer.Settlement{Mode: "access-key", IntervalMinutes: 60, GracePeriodMinutes: 1440, SpendLimitPerDay: "2000000"},
		RelayOwner: "0x00000000000000000000000000000000000000b1",
	}
	for _, b := range bs {
		c.Apps = append(c.Apps, composer.ConfigApp{ID: b.Manifest.ID, ReleaseID: b.ReleaseID.Hex()})
	}
	sort.Slice(c.Apps, func(i, j int) bool { return c.Apps[i].ID < c.Apps[j].ID })
	raw, err := c.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := composer.ParseConfig(raw); err != nil {
		t.Fatalf("fixture config: %v", err)
	}
	return raw
}
