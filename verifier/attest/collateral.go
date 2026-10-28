package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/verify/trust"
	"golang.org/x/sync/singleflight"
)

// Intel PCS endpoints the TDX verifier fetches collateral from.
var DefaultCollateralURLPrefixes = []string{
	"https://api.trustedservices.intel.com/",
	"https://certificates.trustedservices.intel.com/",
}

// DefaultFetchTimeout bounds one shared PCS fetch (with its retries), independently of the callers waiting on it.
const DefaultFetchTimeout = 45 * time.Second

// DefaultCollateralTTL bounds how long fetched collateral is reused. The bodies are signed and re-verified on every
// use (including nextUpdate), so the TTL only controls how quickly TCB recoveries and new CRLs are picked up.
const DefaultCollateralTTL = time.Hour

// CacheOptions configure a CachingGetter.
type CacheOptions struct {
	// Inner fetches on a miss. Nil uses a retrying HTTPS getter bounded by the request context.
	Inner trust.HTTPSGetter
	// TTL of an entry; 0 means DefaultCollateralTTL.
	TTL time.Duration
	// Dir persists entries across restarts when non-empty (created with mode 0700).
	Dir string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// AllowedURLPrefixes restricts what may be fetched; nil means DefaultCollateralURLPrefixes.
	AllowedURLPrefixes []string
	// FetchTimeout bounds one fetch shared by concurrent callers; 0 means DefaultFetchTimeout.
	FetchTimeout time.Duration
}

// CachingGetter is a trust.HTTPSGetter that caches Intel PCS responses (headers and bodies) in memory and
// optionally on disk. Errors are never cached and expired entries are never served, so a PCS outage longer than
// the TTL fails verification closed.
type CachingGetter struct {
	inner    trust.HTTPSGetter
	ttl      time.Duration
	dir      string
	now      func() time.Time
	prefixes []string
	timeout  time.Duration

	mu  sync.Mutex
	mem map[string]cacheEntry
	sf  singleflight.Group
}

type cacheEntry struct {
	URL       string              `json:"url"`
	FetchedAt int64               `json:"fetchedAt"`
	Header    map[string][]string `json:"header"`
	Body      []byte              `json:"body"`
}

// NewCachingGetter returns a caching getter.
func NewCachingGetter(o CacheOptions) (*CachingGetter, error) {
	c := &CachingGetter{
		inner:    o.Inner,
		ttl:      o.TTL,
		dir:      o.Dir,
		now:      o.Now,
		prefixes: o.AllowedURLPrefixes,
		timeout:  o.FetchTimeout,
		mem:      map[string]cacheEntry{},
	}
	if c.timeout <= 0 {
		c.timeout = DefaultFetchTimeout
	}
	if c.inner == nil {
		c.inner = &trust.RetryHTTPSGetter{Timeout: 30 * time.Second, MaxRetryDelay: 5 * time.Second, Getter: &trust.SimpleHTTPSGetter{}}
	}
	if c.ttl <= 0 {
		c.ttl = DefaultCollateralTTL
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.prefixes == nil {
		c.prefixes = DefaultCollateralURLPrefixes
	}
	if c.dir != "" {
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			return nil, fmt.Errorf("collateral cache dir: %w", err)
		}
	}
	return c, nil
}

// Get implements trust.HTTPSGetter.
func (c *CachingGetter) Get(url string) (map[string][]string, []byte, error) {
	return c.GetContext(context.Background(), url)
}

// GetContext implements trust.ContextHTTPSGetter.
func (c *CachingGetter) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	if !c.allowed(url) {
		return nil, nil, fmt.Errorf("collateral URL not allowed: %s", url)
	}
	if e, ok := c.lookup(url); ok {
		return e.Header, e.Body, nil
	}
	// The fetch is shared by every caller of the same URL, so it must not die with the first caller's context: it
	// runs detached (keeping values such as trace ids) with its own timeout, and each caller waits on its own ctx.
	ch := c.sf.DoChan(url, func() (any, error) {
		if e, ok := c.lookup(url); ok {
			return e, nil
		}
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
		defer cancel()
		h, b, err := trust.GetWith(fctx, c.inner, url)
		if err != nil {
			return nil, err
		}
		e := cacheEntry{URL: url, FetchedAt: c.now().Unix(), Header: keepHeaders(h), Body: b}
		c.store(e)
		return e, nil
	})
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, nil, r.Err
		}
		e := r.Val.(cacheEntry)
		return e.Header, e.Body, nil
	}
}

// cachedHeaders are the response headers the verifier reads: the signing chains of the collateral bodies.
var cachedHeaders = []string{
	pcs.TcbInfoIssuerChainPhrase,
	pcs.SgxQeIdentityIssuerChainPhrase,
	pcs.SgxPckCrlIssuerChainPhrase,
	"Content-Type",
}

func keepHeaders(h map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, k := range cachedHeaders {
		if v, ok := h[k]; ok {
			out[k] = v
		}
	}
	return out
}

func (c *CachingGetter) allowed(url string) bool {
	for _, p := range c.prefixes {
		if strings.HasPrefix(url, p) {
			return true
		}
	}
	return false
}

func (c *CachingGetter) fresh(e cacheEntry) bool {
	age := c.now().Sub(time.Unix(e.FetchedAt, 0))
	return age >= -time.Minute && age < c.ttl
}

func (c *CachingGetter) lookup(url string) (cacheEntry, bool) {
	c.mu.Lock()
	e, ok := c.mem[url]
	c.mu.Unlock()
	if ok && c.fresh(e) {
		return e, true
	}
	if c.dir == "" {
		return cacheEntry{}, false
	}
	e, err := c.readDisk(url)
	if err != nil || !c.fresh(e) {
		return cacheEntry{}, false
	}
	c.mu.Lock()
	c.mem[url] = e
	c.mu.Unlock()
	return e, true
}

func (c *CachingGetter) store(e cacheEntry) {
	c.mu.Lock()
	c.mem[e.URL] = e
	c.mu.Unlock()
	if c.dir != "" {
		_ = c.writeDisk(e) // a failed write only costs a refetch
	}
}

func (c *CachingGetter) path(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

func (c *CachingGetter) readDisk(url string) (cacheEntry, error) {
	raw, err := os.ReadFile(c.path(url))
	if err != nil {
		return cacheEntry{}, err
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return cacheEntry{}, err
	}
	if e.URL != url {
		return cacheEntry{}, errors.New("cache entry URL mismatch")
	}
	return e, nil
}

func (c *CachingGetter) writeDisk(e cacheEntry) error {
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.dir, ".pcs-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path(e.URL))
}
