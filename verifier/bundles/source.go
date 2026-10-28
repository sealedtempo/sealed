package bundles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Ref names one release bundle as AppRegistry records it.
type Ref struct {
	App     string   // app slug (config.apps[].id)
	Version string   // release version (AppRegistry.getRelease.version)
	Hash    [32]byte // bundleHash = sha256(bundle.tar)
}

func (r Ref) String() string {
	return fmt.Sprintf("%s %s (bundleHash 0x%s)", r.App, r.Version, hex.EncodeToString(r.Hash[:]))
}

// ErrUnavailable is returned when no URL rule yielded the bundle.
var ErrUnavailable = errors.New("release bundle unavailable")

// Source returns verified bundle bytes: from the Store, else downloaded through each URL rule in order until one
// answers bytes whose sha256 is the onchain bundleHash. Concurrent requests for one bundle share one download.
type Source struct {
	// Rules are tried in order; the first is normally the catalog's release asset base, later ones mirrors.
	Rules []URLRule
	// Fetcher downloads; nil means HTTPFetcher{}.
	Fetcher Fetcher
	// Store caches verified bundles; nil means a memory-only store.
	Store *Store
	// FetchTimeout bounds one shared download over all rules; 0 means 2 x DefaultFetchTimeout.
	FetchTimeout time.Duration

	once sync.Once
	sf   singleflight.Group
}

// NewSource returns a Source over the release asset bases (see ParseBases) with an HTTP fetcher and a store
// (cacheDir may be empty for a memory-only cache).
func NewSource(bases []string, cacheDir string) (*Source, error) {
	st, err := NewStore(cacheDir, 0)
	if err != nil {
		return nil, err
	}
	return &Source{Rules: Rules(bases), Fetcher: HTTPFetcher{UserAgent: "sealed-verifier"}, Store: st}, nil
}

func (s *Source) store() *Store {
	s.once.Do(func() {
		if s.Store == nil {
			s.Store, _ = NewStore("", 0) // memory only: cannot fail
		}
	})
	return s.Store
}

// Get returns the bundle bytes for ref; sha256 of the result is always ref.Hash.
func (s *Source) Get(ctx context.Context, ref Ref) ([]byte, error) {
	st := s.store()
	if b, ok := st.Get(ref.Hash); ok {
		return b, nil
	}
	key := hex.EncodeToString(ref.Hash[:])
	ch := s.sf.DoChan(key, func() (any, error) {
		// Detached from the first caller: a caller giving up must not fail the others sharing this download.
		timeout := s.FetchTimeout
		if timeout <= 0 {
			timeout = 2 * DefaultFetchTimeout
		}
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		return s.download(fctx, ref)
	})
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("bundle %s: %w", ref, ctx.Err())
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		b := r.Val.([]byte)
		out := make([]byte, len(b))
		copy(out, b)
		return out, nil
	}
}

func (s *Source) download(ctx context.Context, ref Ref) ([]byte, error) {
	if len(s.Rules) == 0 {
		return nil, fmt.Errorf("bundle %s: %w: no release asset base configured", ref, ErrUnavailable)
	}
	f := s.Fetcher
	if f == nil {
		f = HTTPFetcher{UserAgent: "sealed-verifier"}
	}
	var errs []error
	for _, rule := range s.Rules {
		url, err := rule.BundleURL(ref.App, ref.Version)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		body, err := f.Fetch(ctx, url)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if got := sha256.Sum256(body); got != ref.Hash {
			errs = append(errs, fmt.Errorf("GET %s: %w (sha256 0x%s)", url, ErrHashMismatch, hex.EncodeToString(got[:])))
			continue
		}
		// The bytes are verified; a failed cache write (full disk) must not fail the verification.
		_ = s.store().Put(ref.Hash, body)
		return body, nil
	}
	return nil, fmt.Errorf("bundle %s: %w: %w", ref, ErrUnavailable, errors.Join(errs...))
}
