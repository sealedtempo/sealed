package attest

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const tcbURL = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00806f050000"

type countingGetter struct {
	calls atomic.Int32
	fail  bool
	gate  chan struct{} // when non-nil, Get blocks until closed
}

func (g *countingGetter) Get(url string) (map[string][]string, []byte, error) {
	g.calls.Add(1)
	if g.gate != nil {
		<-g.gate
	}
	if g.fail {
		return nil, nil, errors.New("pcs unavailable")
	}
	return map[string][]string{"Tcb-Info-Issuer-Chain": {"chain"}, "Set-Cookie": {"x"}}, []byte("body:" + url), nil
}

// offlineGetter fails every request, like a verifier with no network.
type offlineGetter struct{}

func (offlineGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("offline")
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestCachingGetterHitsAndTTL(t *testing.T) {
	inner := &countingGetter{}
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c, err := NewCachingGetter(CacheOptions{Inner: inner, TTL: time.Hour, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		h, b, err := c.Get(tcbURL)
		if err != nil || string(b) != "body:"+tcbURL || h["Tcb-Info-Issuer-Chain"][0] != "chain" {
			t.Fatalf("get: %v %q %v", err, b, h)
		}
		if _, ok := h["Set-Cookie"]; ok {
			t.Fatal("unneeded header cached")
		}
	}
	if n := inner.calls.Load(); n != 1 {
		t.Fatalf("inner calls = %d, want 1", n)
	}
	clk.add(59 * time.Minute)
	c.Get(tcbURL)
	if n := inner.calls.Load(); n != 1 {
		t.Fatalf("refetched before TTL")
	}
	clk.add(2 * time.Minute)
	c.Get(tcbURL)
	if n := inner.calls.Load(); n != 2 {
		t.Fatalf("not refetched after TTL: %d", n)
	}
}

func TestCachingGetterFailsClosed(t *testing.T) {
	inner := &countingGetter{}
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c, _ := NewCachingGetter(CacheOptions{Inner: inner, TTL: time.Hour, Now: clk.now})
	if _, _, err := c.Get(tcbURL); err != nil {
		t.Fatal(err)
	}
	inner.fail = true
	clk.add(2 * time.Hour)
	if _, _, err := c.Get(tcbURL); err == nil {
		t.Fatal("served an expired entry while PCS is down")
	}
	// Errors are not cached: once PCS recovers the next call succeeds.
	inner.fail = false
	if _, _, err := c.Get(tcbURL); err != nil {
		t.Fatal(err)
	}
}

func TestCachingGetterRejectsOtherHosts(t *testing.T) {
	inner := &countingGetter{}
	c, _ := NewCachingGetter(CacheOptions{Inner: inner})
	for _, u := range []string{"https://evil.example/tdx", "http://api.trustedservices.intel.com/x", "https://api.trustedservices.intel.com.evil.example/"} {
		if _, _, err := c.Get(u); err == nil {
			t.Fatalf("fetched %s", u)
		}
	}
	if inner.calls.Load() != 0 {
		t.Fatal("inner getter called")
	}
}

func TestCachingGetterDiskPersistence(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	first, _ := NewCachingGetter(CacheOptions{Inner: &countingGetter{}, Dir: dir, Now: clk.now})
	if _, _, err := first.Get(tcbURL); err != nil {
		t.Fatal(err)
	}
	// A new process with the network down serves the persisted entry within the TTL.
	second, _ := NewCachingGetter(CacheOptions{Inner: offlineGetter{}, Dir: dir, Now: clk.now})
	_, b, err := second.Get(tcbURL)
	if err != nil || string(b) != "body:"+tcbURL {
		t.Fatalf("disk entry not served: %v", err)
	}
	clk.add(DefaultCollateralTTL + time.Second)
	third, _ := NewCachingGetter(CacheOptions{Inner: offlineGetter{}, Dir: dir, Now: clk.now})
	if _, _, err := third.Get(tcbURL); err == nil {
		t.Fatal("expired disk entry served")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("cache file %s is group/world accessible", e.Name())
		}
	}
}

func TestCachingGetterSingleflight(t *testing.T) {
	inner := &countingGetter{gate: make(chan struct{})}
	c, _ := NewCachingGetter(CacheOptions{Inner: inner})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := c.GetContext(context.Background(), tcbURL); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(inner.gate)
	wg.Wait()
	if n := inner.calls.Load(); n != 1 {
		t.Fatalf("inner calls = %d, want 1", n)
	}
}

// TestCachingGetterSharedFetchOutlivesCaller: one caller giving up neither cancels the shared fetch nor fails the
// other callers waiting on it.
func TestCachingGetterSharedFetchOutlivesCaller(t *testing.T) {
	inner := &ctxGetter{gate: make(chan struct{})}
	c, _ := NewCachingGetter(CacheOptions{Inner: inner})
	first, cancelFirst := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, _, err := c.GetContext(first, tcbURL)
		firstErr <- err
	}()
	inner.waitStarted(t)
	secondErr := make(chan error, 1)
	go func() {
		_, b, err := c.GetContext(context.Background(), tcbURL)
		if err == nil && string(b) != "ok" {
			err = errors.New("wrong body")
		}
		secondErr <- err
	}()
	cancelFirst()
	if err := <-firstErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v", err)
	}
	close(inner.gate)
	if err := <-secondErr; err != nil {
		t.Fatalf("waiting caller failed with the first caller's context: %v", err)
	}
	if inner.calls.Load() != 1 {
		t.Fatalf("inner calls %d", inner.calls.Load())
	}
}

func TestCachingGetterFetchTimeout(t *testing.T) {
	inner := &ctxGetter{gate: make(chan struct{})} // never released: only the fetch timeout ends it
	c, _ := NewCachingGetter(CacheOptions{Inner: inner, FetchTimeout: 50 * time.Millisecond})
	if _, _, err := c.GetContext(context.Background(), tcbURL); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the fetch deadline", err)
	}
}

// ctxGetter blocks until gate closes or its context ends.
type ctxGetter struct {
	calls   atomic.Int32
	gate    chan struct{}
	started sync.Once
	startCh chan struct{}
	mu      sync.Mutex
}

func (g *ctxGetter) startedCh() chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.startCh == nil {
		g.startCh = make(chan struct{})
	}
	return g.startCh
}

func (g *ctxGetter) waitStarted(t *testing.T) {
	select {
	case <-g.startedCh():
	case <-time.After(5 * time.Second):
		t.Fatal("fetch never started")
	}
}

func (g *ctxGetter) Get(url string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), url)
}

func (g *ctxGetter) GetContext(ctx context.Context, _ string) (map[string][]string, []byte, error) {
	g.calls.Add(1)
	ch := g.startedCh()
	g.started.Do(func() { close(ch) })
	select {
	case <-g.gate:
		return map[string][]string{}, []byte("ok"), nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}
