package kbtest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/runtime/composer"
)

// BundleServer serves release bundles at the release asset URL rule's paths, like GitHub release downloads.
type BundleServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	// Down makes every request answer 404.
	Down bool
}

// NewBundleServer starts an empty server.
func NewBundleServer(t testing.TB) *BundleServer {
	s := &BundleServer{files: map[string][]byte{}, hits: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits[r.URL.Path]++
		b, ok := s.files[r.URL.Path]
		if s.Down || !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// Base is the release asset base URL.
func (s *BundleServer) Base() string { return s.srv.URL + "/releases/download" }

func (s *BundleServer) path(t testing.TB, app, version string) string {
	t.Helper()
	u, err := keybroker.BundleURL(s.Base(), app, version)
	if err != nil {
		t.Fatal(err)
	}
	p, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return p.Path
}

// Put serves a bundle at its release URL.
func (s *BundleServer) Put(t testing.TB, b *composer.Bundle) {
	s.Serve(t, b.Manifest.ID, b.Version(), b.Tar)
}

// Serve serves data at the release URL of app and version.
func (s *BundleServer) Serve(t testing.TB, app, version string, data []byte) {
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[p] = data
}

// Hits counts requests for the release URL of app and version.
func (s *BundleServer) Hits(t testing.TB, app, version string) int {
	p := s.path(t, app, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[p]
}
