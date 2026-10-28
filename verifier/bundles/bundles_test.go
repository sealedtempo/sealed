package bundles_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/sealed-dev/sealed/verifier/bundles"
)

func TestAssetRule(t *testing.T) {
	r := bundles.AssetRule{Base: "https://github.com/sealedtempo/sealed/releases/download/"}
	got, err := r.BundleURL("crm", "1.0.0")
	if want := "https://github.com/sealedtempo/sealed/releases/download/crm-v1.0.0/crm-1.0.0.bundle.tar"; err != nil || got != want {
		t.Fatalf("BundleURL = %q, %v; want %q", got, err, want)
	}
	got, err = r.BundleURL("llm-gateway", "1.83.4-sealed.2")
	if want := "https://github.com/sealedtempo/sealed/releases/download/llm-gateway-v1.83.4-sealed.2/llm-gateway-1.83.4-sealed.2.bundle.tar"; err != nil || got != want {
		t.Fatalf("BundleURL = %q, %v", got, err)
	}
	for _, bad := range [][2]string{
		{"../crm", "1.0.0"}, {"Crm", "1.0.0"}, {"c", "1.0.0"}, {"crm/x", "1.0.0"}, {"crm-", "1.0.0"}, {"", "1.0.0"},
		{"crm", ""}, {"crm", "1.0/2"}, {"crm", ".."}, {"crm", "1..0"}, {"crm", "-1"}, {"crm", "1.0.0?x=1"}, {"crm", "1.0.0#x"},
		{"crm", "v1 0"}, {"crm", strings.Repeat("1", 65)},
	} {
		if u, err := r.BundleURL(bad[0], bad[1]); err == nil || !errors.Is(err, bundles.ErrNoAssetURL) {
			t.Errorf("BundleURL(%q, %q) = %q, %v", bad[0], bad[1], u, err)
		}
	}
	if _, err := (bundles.AssetRule{}).BundleURL("crm", "1.0.0"); err == nil {
		t.Fatal("empty base accepted")
	}
}

func TestParseBases(t *testing.T) {
	got, err := bundles.ParseBases(" https://a.example/x/ ,https://b.example ,", false)
	if err != nil || len(got) != 2 || got[0] != "https://a.example/x" || got[1] != "https://b.example" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", ",", "http://a.example", "ftp://a.example", "https://", "https://u:p@a.example", "https://a.example/?q", "https://a.example/#f", "a.example/x"} {
		if _, err := bundles.ParseBases(bad, false); err == nil {
			t.Errorf("ParseBases(%q) accepted", bad)
		}
	}
	if got, err := bundles.ParseBases("http://127.0.0.1:9/r", true); err != nil || got[0] != "http://127.0.0.1:9/r" {
		t.Fatalf("insecure base: %v %v", got, err)
	}
}

func hashOf(b []byte) [32]byte { return sha256.Sum256(b) }

func TestStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundles")
	st, err := bundles.NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("bundle bytes")
	h := hashOf(data)
	if _, ok := st.Get(h); ok {
		t.Fatal("hit on an empty store")
	}
	if err := st.Put(h, []byte("other bytes")); !errors.Is(err, bundles.ErrHashMismatch) {
		t.Fatalf("Put of bytes under another hash: %v", err)
	}
	if err := st.Put(h, data); err != nil {
		t.Fatal(err)
	}
	got, ok := st.Get(h)
	if !ok || !bytes.Equal(got, data) {
		t.Fatal("memory hit")
	}
	got[0] ^= 0xff // callers get copies
	if again, _ := st.Get(h); !bytes.Equal(again, data) {
		t.Fatal("Get returned the stored slice")
	}
	file := filepath.Join(dir, hex.EncodeToString(h[:])+".bundle.tar")
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("disk entry %v %v", info, err)
	}
	if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir mode %v", d.Mode().Perm())
	}

	// A fresh store (a restart) reads the disk entry.
	st2, _ := bundles.NewStore(dir, 0)
	if got, ok := st2.Get(h); !ok || !bytes.Equal(got, data) {
		t.Fatal("disk hit after restart")
	}
	// A disk entry that no longer hashes to its name is never served and is removed.
	st3, _ := bundles.NewStore(dir, 0)
	if err := os.WriteFile(file, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := st3.Get(h); ok {
		t.Fatal("served a tampered disk entry")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("tampered disk entry kept")
	}
}

func TestStoreMemoryBound(t *testing.T) {
	st, _ := bundles.NewStore("", 10)
	a, b, big := []byte("aaaaaa"), []byte("bbbbbb"), []byte("0123456789abc")
	st.Put(hashOf(a), a)
	st.Put(hashOf(b), b) // evicts a
	st.Put(hashOf(big), big)
	if _, ok := st.Get(hashOf(a)); ok {
		t.Fatal("oldest entry not evicted")
	}
	if _, ok := st.Get(hashOf(b)); !ok {
		t.Fatal("newest entry evicted")
	}
	if _, ok := st.Get(hashOf(big)); ok {
		t.Fatal("entry over the memory bound kept in memory")
	}
}

// assetServer serves fixed bodies by path and counts requests.
type assetServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies map[string][]byte
	hits   atomic.Int64
	delay  time.Duration
}

func newAssetServer(t *testing.T) *assetServer {
	s := &assetServer{bodies: map[string][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		time.Sleep(s.delay)
		s.mu.Lock()
		b, ok := s.bodies[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *assetServer) put(path string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies[path] = b
}

func TestSourceFetchVerifyCache(t *testing.T) {
	srv := newAssetServer(t)
	data := []byte("crm bundle")
	ref := bundles.Ref{App: "crm", Version: "1.0.0", Hash: hashOf(data)}
	srv.put("/r/crm-v1.0.0/crm-1.0.0.bundle.tar", data)
	src := &bundles.Source{Rules: bundles.Rules([]string{srv.URL + "/r"}), Fetcher: bundles.HTTPFetcher{}}

	got, err := src.Get(context.Background(), ref)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("Get: %v", err)
	}
	if _, err := src.Get(context.Background(), ref); err != nil || srv.hits.Load() != 1 {
		t.Fatalf("second Get fetched again (%d requests): %v", srv.hits.Load(), err)
	}

	// Bytes that do not hash to the onchain bundleHash are refused and not cached.
	bad := bundles.Ref{App: "crm", Version: "1.0.1", Hash: hashOf([]byte("what the chain says"))}
	srv.put("/r/crm-v1.0.1/crm-1.0.1.bundle.tar", []byte("something else"))
	_, err = src.Get(context.Background(), bad)
	if !errors.Is(err, bundles.ErrUnavailable) || !errors.Is(err, bundles.ErrHashMismatch) {
		t.Fatalf("tampered asset: %v", err)
	}
	if _, ok := src.Store.Get(bad.Hash); ok {
		t.Fatal("tampered asset cached")
	}

	// A missing asset.
	_, err = src.Get(context.Background(), bundles.Ref{App: "crm", Version: "9.9.9", Hash: hashOf([]byte("x"))})
	if !errors.Is(err, bundles.ErrUnavailable) || !errors.Is(err, bundles.ErrNotFound) {
		t.Fatalf("missing asset: %v", err)
	}
	// A version the URL rule cannot express is never fetched.
	before := srv.hits.Load()
	if _, err := src.Get(context.Background(), bundles.Ref{App: "crm", Version: "../../x", Hash: hashOf([]byte("y"))}); !errors.Is(err, bundles.ErrNoAssetURL) || srv.hits.Load() != before {
		t.Fatalf("unsafe version: %v", err)
	}
}

func TestSourceMirrors(t *testing.T) {
	primary, mirror := newAssetServer(t), newAssetServer(t)
	data := []byte("notes bundle")
	ref := bundles.Ref{App: "notes", Version: "1.0.0-sealed.1", Hash: hashOf(data)}
	path := "/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar"
	primary.put(path, []byte("a substituted bundle"))
	mirror.put(path, data)
	src := &bundles.Source{Rules: bundles.Rules([]string{primary.URL, mirror.URL})}
	got, err := src.Get(context.Background(), ref)
	if err != nil || !bytes.Equal(got, data) || primary.hits.Load() != 1 || mirror.hits.Load() != 1 {
		t.Fatalf("mirror fallback: %v (primary %d, mirror %d)", err, primary.hits.Load(), mirror.hits.Load())
	}
	if _, err := (&bundles.Source{}).Get(context.Background(), ref); !errors.Is(err, bundles.ErrUnavailable) {
		t.Fatalf("no rules: %v", err)
	}
}

func TestSourceSharedDownload(t *testing.T) {
	srv := newAssetServer(t)
	srv.delay = 200 * time.Millisecond
	data := []byte("shared")
	ref := bundles.Ref{App: "crm", Version: "1.0.0", Hash: hashOf(data)}
	srv.put("/crm-v1.0.0/crm-1.0.0.bundle.tar", data)
	src := &bundles.Source{Rules: bundles.Rules([]string{srv.URL})}

	// The first caller gives up early; the shared download still completes for the others.
	quitter, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	wg.Add(1)
	go func() { defer wg.Done(); _, errs[0] = src.Get(quitter, ref) }()
	time.Sleep(5 * time.Millisecond)
	for i := 1; i < len(errs); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, errs[i] = src.Get(context.Background(), ref) }()
	}
	wg.Wait()
	if !errors.Is(errs[0], context.DeadlineExceeded) {
		t.Fatalf("quitting caller: %v", errs[0])
	}
	for _, err := range errs[1:] {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("%d downloads for one bundle", n)
	}
}

func TestHTTPFetcherLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write(bytes.Repeat([]byte("x"), 2048))
		case "/redirect":
			http.Redirect(w, r, "/small", http.StatusFound)
		case "/small":
			if r.Header.Get("User-Agent") != "sealed-test" {
				http.Error(w, "ua", http.StatusBadRequest)
				return
			}
			w.Write([]byte("ok"))
		case "/gone":
			http.Error(w, "gone", http.StatusGone)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	f := bundles.HTTPFetcher{MaxBytes: 1024, UserAgent: "sealed-test"}
	if _, err := f.Fetch(context.Background(), srv.URL+"/big"); err == nil {
		t.Fatal("body over the limit accepted")
	}
	if b, err := f.Fetch(context.Background(), srv.URL+"/redirect"); err != nil || string(b) != "ok" {
		t.Fatalf("redirect: %q %v", b, err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"/gone"); !errors.Is(err, bundles.ErrNotFound) {
		t.Fatalf("410: %v", err)
	}
	var he *bundles.HTTPError
	if _, err := f.Fetch(context.Background(), srv.URL+"/x"); !errors.As(err, &he) || he.Status != 500 || errors.Is(err, bundles.ErrNotFound) {
		t.Fatalf("500: %v", err)
	}
}
