package keybroker

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// Bundle fetch errors. ErrBundleHashMismatch answers bundle_hash_mismatch, ErrBundleInvalid compose_mismatch; any
// other fetch error is a transport failure (503, the agent retries).
var (
	ErrBundleHashMismatch = errors.New("bundle sha256 differs from the onchain bundleHash")
	ErrBundleInvalid      = errors.New("bundle is not a valid release bundle")
)

// BundleRef names one release bundle by its onchain record.
type BundleRef struct {
	App        string   // config.apps[].id, the app slug
	Version    string   // AppRegistry release version (the manifest's release_version)
	BundleHash [32]byte // AppRegistry release bundleHash
}

// BundleSource returns the loaded bundle whose sha256 equals ref.BundleHash.
type BundleSource interface {
	Fetch(ctx context.Context, ref BundleRef) (*composer.Bundle, error)
}

// BundleURL applies the release asset URL rule (D-046, brief item 18) through runtime/composer's
// NewReleaseAssets, the implementation verifierd, the CLI and release CI share:
// <release_asset_base>/<appId>-v<release_version>/<appId>-<release_version>.bundle.tar.
func BundleURL(base, app, version string) (string, error) {
	a, err := composer.NewReleaseAssets(base, app, version)
	if err != nil {
		return "", err
	}
	return a.Bundle, nil
}

// HTTPBundleSourceOptions configure an HTTPBundleSource.
type HTTPBundleSourceOptions struct {
	// Base is catalog.release_asset_base, set by the customer at bootstrap.
	Base string
	// Client fetches bundles; nil means a client with a 60 s timeout that follows only HTTPS redirects (HTTP
	// redirects too when Base is http, for local tests).
	Client *http.Client
	// MaxBundleBytes caps one bundle; 0 means 64 MiB.
	MaxBundleBytes int64
	// CacheBytes caps the content-addressed cache; 0 means 256 MiB.
	CacheBytes int64
	// FetchTimeout bounds one fetch shared by concurrent callers; 0 means 60 s.
	FetchTimeout time.Duration
}

// HTTPBundleSource fetches release bundles from the catalog's GitHub release assets, checks sha256 against the
// onchain bundleHash, loads them with the composer and caches them by hash. Concurrent requests for one bundle
// share a fetch. It is safe for concurrent use.
type HTTPBundleSource struct {
	base     string
	client   *http.Client
	maxBytes int64
	timeout  time.Duration
	cache    *bundleCache
	sf       singleflight.Group
}

// NewHTTPBundleSource validates the options.
func NewHTTPBundleSource(o HTTPBundleSourceOptions) (*HTTPBundleSource, error) {
	if _, err := BundleURL(o.Base, "probe-app", "0"); err != nil {
		return nil, err
	}
	s := &HTTPBundleSource{base: o.Base, client: o.Client, maxBytes: o.MaxBundleBytes, timeout: o.FetchTimeout}
	if s.maxBytes <= 0 {
		s.maxBytes = 64 << 20
	}
	if s.timeout <= 0 {
		s.timeout = 60 * time.Second
	}
	cacheBytes := o.CacheBytes
	if cacheBytes <= 0 {
		cacheBytes = 256 << 20
	}
	s.cache = newBundleCache(cacheBytes)
	if s.client == nil {
		allowHTTP := strings.HasPrefix(o.Base, "http://")
		s.client = &http.Client{
			Timeout: s.timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme != "https" && !allowHTTP {
					return fmt.Errorf("redirect to non-HTTPS URL %s", req.URL.Redacted())
				}
				return nil
			},
		}
	}
	return s, nil
}

// Fetch implements BundleSource.
func (s *HTTPBundleSource) Fetch(ctx context.Context, ref BundleRef) (*composer.Bundle, error) {
	if b := s.cache.get(ref.BundleHash); b != nil {
		return checkBundleRef(b, ref)
	}
	key := hex.EncodeToString(ref.BundleHash[:])
	ch := s.sf.DoChan(key, func() (any, error) {
		// Detached from the first caller so one cancelled request does not fail the others.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
		defer cancel()
		return s.fetch(fctx, ref)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return checkBundleRef(r.Val.(*composer.Bundle), ref)
	}
}

func (s *HTTPBundleSource) fetch(ctx context.Context, ref BundleRef) (*composer.Bundle, error) {
	u, err := BundleURL(s.base, ref.App, ref.Version)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleInvalid, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", u, resp.StatusCode)
	}
	tarBytes, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	if int64(len(tarBytes)) > s.maxBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrBundleHashMismatch, u, s.maxBytes)
	}
	if sum := sha256.Sum256(tarBytes); sum != ref.BundleHash {
		return nil, fmt.Errorf("%w: %s has sha256 0x%x, onchain bundleHash is 0x%x", ErrBundleHashMismatch, u, sum, ref.BundleHash)
	}
	b, err := composer.LoadBundle(tarBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBundleInvalid, u, err)
	}
	if _, err := checkBundleRef(b, ref); err != nil {
		return nil, err
	}
	s.cache.put(ref.BundleHash, b)
	return b, nil
}

// checkBundleRef requires the bundle to be the named app's release version.
func checkBundleRef(b *composer.Bundle, ref BundleRef) (*composer.Bundle, error) {
	if b.Hash != composer.Hash(ref.BundleHash) {
		return nil, fmt.Errorf("%w: loaded bundle hash %s", ErrBundleHashMismatch, b.Hash.Hex())
	}
	if b.Manifest.ID != ref.App || b.Version() != ref.Version {
		return nil, fmt.Errorf("%w: bundle with hash 0x%x is %s %s, the release is %s %s", ErrBundleInvalid, ref.BundleHash,
			b.Manifest.ID, b.Version(), ref.App, ref.Version)
	}
	return b, nil
}

// bundleCache is an LRU of loaded bundles keyed by bundleHash, bounded by approximate memory use.
type bundleCache struct {
	mu    sync.Mutex
	max   int64
	used  int64
	ll    *list.List
	items map[[32]byte]*list.Element
}

type cacheItem struct {
	hash [32]byte
	b    *composer.Bundle
	size int64
}

func newBundleCache(max int64) *bundleCache {
	return &bundleCache{max: max, ll: list.New(), items: map[[32]byte]*list.Element{}}
}

func (c *bundleCache) get(h [32]byte) *composer.Bundle {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[h]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*cacheItem).b
	}
	return nil
}

func (c *bundleCache) put(h [32]byte, b *composer.Bundle) {
	size := int64(len(b.Tar)) * 2 // the tar plus the parsed files
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[h]; ok || size > c.max {
		return
	}
	c.items[h] = c.ll.PushFront(&cacheItem{hash: h, b: b, size: size})
	c.used += size
	for c.used > c.max {
		e := c.ll.Back()
		it := e.Value.(*cacheItem)
		c.ll.Remove(e)
		delete(c.items, it.hash)
		c.used -= it.size
	}
}

// MemoryBundleSource serves loaded bundles by hash (tests and local tools). It applies the same checks as the HTTP
// source: unknown hashes are transport errors, and the bundle must be the named release.
type MemoryBundleSource struct {
	mu      sync.Mutex
	byHash  map[[32]byte]*composer.Bundle
	fetches int
}

// NewMemoryBundleSource holds the given bundles.
func NewMemoryBundleSource(bs ...*composer.Bundle) *MemoryBundleSource {
	m := &MemoryBundleSource{byHash: map[[32]byte]*composer.Bundle{}}
	for _, b := range bs {
		m.byHash[b.Hash] = b
	}
	return m
}

// Fetch implements BundleSource.
func (m *MemoryBundleSource) Fetch(_ context.Context, ref BundleRef) (*composer.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetches++
	b, ok := m.byHash[ref.BundleHash]
	if !ok {
		return nil, fmt.Errorf("bundle 0x%x not available", ref.BundleHash)
	}
	return checkBundleRef(b, ref)
}
