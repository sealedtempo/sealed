package keybroker

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestNonceSingleUseAndLifetime(t *testing.T) {
	c := &testClock{t: time.Unix(1_800_000_000, 0)}
	s := NewNonceStore(NonceOptions{Now: c.now})
	n, exp, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if exp != c.now().Add(5*time.Minute) {
		t.Fatalf("expiry %v, want 5 minutes", exp)
	}
	if n == ([32]byte{}) {
		t.Fatal("zero nonce")
	}
	if err := s.Consume(n); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(n); !errors.Is(err, ErrNonceUnknown) {
		t.Fatalf("second use: %v", err)
	}
	if err := s.Consume([32]byte{1}); !errors.Is(err, ErrNonceUnknown) {
		t.Fatalf("unknown nonce: %v", err)
	}

	// Usable until just before the 5 minute mark, expired at it.
	n1, _, _ := s.Issue()
	n2, _, _ := s.Issue()
	c.add(5*time.Minute - time.Nanosecond)
	if err := s.Consume(n1); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}
	c.add(time.Nanosecond)
	if err := s.Consume(n2); !errors.Is(err, ErrNonceExpired) {
		t.Fatalf("at expiry: %v", err)
	}
	if err := s.Consume(n2); !errors.Is(err, ErrNonceUnknown) {
		t.Fatalf("an expired nonce must be gone after its failed use: %v", err)
	}
}

func TestNonceStoreIsBounded(t *testing.T) {
	c := &testClock{t: time.Unix(1_800_000_000, 0)}
	s := NewNonceStore(NonceOptions{Capacity: 4, Now: c.now})
	var issued [][32]byte
	for range 10 {
		n, _, err := s.Issue()
		if err != nil {
			t.Fatal(err)
		}
		issued = append(issued, n)
		if s.Len() > 4 {
			t.Fatalf("store holds %d nonces, capacity 4", s.Len())
		}
	}
	// The oldest were evicted; the newest four still work.
	for _, n := range issued[:6] {
		if err := s.Consume(n); !errors.Is(err, ErrNonceUnknown) {
			t.Fatalf("evicted nonce: %v", err)
		}
	}
	for _, n := range issued[6:] {
		if err := s.Consume(n); err != nil {
			t.Fatalf("newest nonce: %v", err)
		}
	}
	if s.Evicted() != 6 {
		t.Fatalf("evicted %d, want 6", s.Evicted())
	}
	// Expired nonces are pruned before anything is evicted.
	for range 4 {
		_, _, _ = s.Issue()
	}
	c.add(NonceLifetime)
	fresh, _, _ := s.Issue()
	if s.Len() != 1 || s.Evicted() != 6 {
		t.Fatalf("len %d evicted %d after expiry, want 1 and 6", s.Len(), s.Evicted())
	}
	if err := s.Consume(fresh); err != nil {
		t.Fatal(err)
	}
}

// TestNonceQueueStaysBounded: issuing and consuming at a high rate must not grow the queue without bound.
func TestNonceQueueStaysBounded(t *testing.T) {
	s := NewNonceStore(NonceOptions{Capacity: 8})
	keep, _, _ := s.Issue() // stays live at the front, so pruning alone cannot drop the consumed entries behind it
	for range 10_000 {
		n, _, err := s.Issue()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Consume(n); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	queued := len(s.order) - s.head
	s.mu.Unlock()
	if queued > 2*8+16+1 {
		t.Fatalf("queue holds %d entries", queued)
	}
	if err := s.Consume(keep); err != nil {
		t.Fatalf("the long-lived nonce was lost by compaction: %v", err)
	}
}

// TestNonceStoreConcurrency: under concurrent issue and consume (run with -race), every nonce is consumed exactly
// once even when many goroutines race for it, and no two issued nonces are equal.
func TestNonceStoreConcurrency(t *testing.T) {
	s := NewNonceStore(NonceOptions{Capacity: 1 << 20})
	const workers, perWorker, racers = 16, 200, 4
	var mu sync.Mutex
	seen := map[[32]byte]bool{}
	var successes, failures atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range perWorker {
				n, _, err := s.Issue()
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				if seen[n] {
					t.Error("duplicate nonce")
				}
				seen[n] = true
				mu.Unlock()
				var inner sync.WaitGroup
				for range racers {
					inner.Go(func() {
						if s.Consume(n) == nil {
							successes.Add(1)
						} else {
							failures.Add(1)
						}
					})
				}
				inner.Wait()
			}
		})
	}
	wg.Wait()
	if successes.Load() != workers*perWorker || failures.Load() != workers*perWorker*(racers-1) {
		t.Fatalf("successes %d failures %d, want %d and %d", successes.Load(), failures.Load(), workers*perWorker, workers*perWorker*(racers-1))
	}
	if s.Len() != 0 {
		t.Fatalf("%d nonces left", s.Len())
	}
}

type repeatReader struct{}

func (repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 7
	}
	return len(p), nil
}

func TestNonceStoreRefusesRepeatedRandomness(t *testing.T) {
	s := NewNonceStore(NonceOptions{Rand: repeatReader{}})
	if _, _, err := s.Issue(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Issue(); err == nil {
		t.Fatal("a broken randomness source handed out the same nonce twice")
	}
}
