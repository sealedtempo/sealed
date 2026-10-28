package keybroker

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer"
)

func repoRootDir(t testing.TB) string {
	t.Helper()
	dir, _ := os.Getwd()
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

func notesBundle(t testing.TB) *composer.Bundle {
	t.Helper()
	ri, err := composer.LoadRuntimeImages()
	if err != nil {
		t.Fatal(err)
	}
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join(repoRootDir(t), "runtime", "composer", "testdata", "apps", "notes"), Registry: ri.Registry})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleURLRule(t *testing.T) {
	u, err := BundleURL("https://github.com/sealedtempo/sealed/releases/download/", "crm", "2.52.0-sealed.1")
	if err != nil {
		t.Fatal(err)
	}
	if u != "https://github.com/sealedtempo/sealed/releases/download/crm-v2.52.0-sealed.1/crm-2.52.0-sealed.1.bundle.tar" {
		t.Fatalf("url %s", u)
	}
	u, _ = BundleURL("https://example.com/r", "llm-gateway", "1.0.0+build.7")
	if u != "https://example.com/r/llm-gateway-v1.0.0+build.7/llm-gateway-1.0.0+build.7.bundle.tar" {
		t.Fatalf("url %s", u)
	}
	for _, bad := range []struct{ base, app, version string }{
		{"https://example.com", "Crm", "1"},
		{"https://example.com", "../x", "1"},
		{"https://example.com", "crm", "../../evil"},
		{"https://example.com", "crm", ""},
		{"ftp://example.com", "crm", "1"},
		{"not a url", "crm", "1"},
	} {
		if _, err := BundleURL(bad.base, bad.app, bad.version); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Characters that need escaping stay inside their path segment.
	u, _ = BundleURL("https://example.com", "crm", "1 2?x")
	if !strings.HasSuffix(u, "/crm-v1%202%3Fx/crm-1%202%3Fx.bundle.tar") {
		t.Fatalf("url %s", u)
	}
}

func TestHTTPBundleSource(t *testing.T) {
	b := notesBundle(t)
	ref := BundleRef{App: "notes", Version: b.Version(), BundleHash: b.Hash}
	var hits atomic.Int64
	release := make(chan struct{})
	var once sync.Once
	body := b.Tar
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		if r.URL.Path != "/rel/notes-v"+b.Version()+"/notes-"+b.Version()+".bundle.tar" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	src, err := NewHTTPBundleSource(HTTPBundleSourceOptions{Base: srv.URL + "/rel"})
	if err != nil {
		t.Fatal(err)
	}
	// Ten concurrent callers share one fetch.
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			got, err := src.Fetch(context.Background(), ref)
			if err != nil || got.Hash != b.Hash {
				t.Errorf("fetch: %v", err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	once.Do(func() { close(release) })
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("%d fetches, want 1", hits.Load())
	}
	// Cached by hash afterwards.
	if _, err := src.Fetch(context.Background(), ref); err != nil || hits.Load() != 1 {
		t.Fatalf("cache: %v, %d fetches", err, hits.Load())
	}
	// The cache answers only for the release it holds.
	if _, err := src.Fetch(context.Background(), BundleRef{App: "notes", Version: "other", BundleHash: b.Hash}); !errors.Is(err, ErrBundleInvalid) {
		t.Fatalf("version mismatch from cache: %v", err)
	}

	// Wrong bytes: hash mismatch. Missing: transport error.
	mu.Lock()
	body = append([]byte(nil), b.Tar...)
	body[len(body)-1] ^= 1
	mu.Unlock()
	src2, _ := NewHTTPBundleSource(HTTPBundleSourceOptions{Base: srv.URL + "/rel"})
	if _, err := src2.Fetch(context.Background(), ref); !errors.Is(err, ErrBundleHashMismatch) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := src2.Fetch(context.Background(), BundleRef{App: "notes", Version: "9", BundleHash: b.Hash}); err == nil ||
		errors.Is(err, ErrBundleHashMismatch) || errors.Is(err, ErrBundleInvalid) {
		t.Fatalf("404 must be a transport error: %v", err)
	}
	// A size cap: larger bodies are refused without hashing all of them.
	src3, _ := NewHTTPBundleSource(HTTPBundleSourceOptions{Base: srv.URL + "/rel", MaxBundleBytes: 512})
	if _, err := src3.Fetch(context.Background(), ref); !errors.Is(err, ErrBundleHashMismatch) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}
}

func TestHTTPBundleSourceRefusesHTTPRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer tls.Close()
	src, err := NewHTTPBundleSource(HTTPBundleSourceOptions{Base: tls.URL})
	if err != nil {
		t.Fatal(err)
	}
	src.client.Transport = tls.Client().Transport
	_, err = src.Fetch(context.Background(), BundleRef{App: "notes", Version: "1", BundleHash: sha256.Sum256([]byte("x"))})
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("redirect to http: %v", err)
	}
}

func TestBundleCacheIsBounded(t *testing.T) {
	c := newBundleCache(100)
	mk := func(n int, size int) (*composer.Bundle, [32]byte) {
		h := sha256.Sum256([]byte{byte(n)})
		return &composer.Bundle{Hash: h, Tar: make([]byte, size)}, h
	}
	b1, h1 := mk(1, 20) // counted twice: tar plus parsed files
	b2, h2 := mk(2, 20)
	b3, h3 := mk(3, 20)
	c.put(h1, b1)
	c.put(h2, b2)
	_ = c.get(h1) // h2 is now the least recently used
	c.put(h3, b3)
	if c.get(h2) != nil || c.get(h1) == nil || c.get(h3) == nil || c.used > 100 {
		t.Fatalf("lru state wrong, used %d", c.used)
	}
	big, hb := mk(4, 200)
	c.put(hb, big)
	if c.get(hb) != nil {
		t.Fatal("cached an entry larger than the cache")
	}
}
