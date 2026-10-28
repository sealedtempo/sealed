package keybroker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// NonceLifetime is how long an issued nonce can be used (INTERFACES.md section 9).
const NonceLifetime = 5 * time.Minute

// DefaultNonceCapacity bounds the number of live nonces held in memory.
const DefaultNonceCapacity = 100_000

// Nonce errors. Both map to bad_nonce.
var (
	ErrNonceUnknown = errors.New("nonce unknown or already used")
	ErrNonceExpired = errors.New("nonce expired")
)

// NonceOptions configure a NonceStore.
type NonceOptions struct {
	// Capacity bounds the live nonces; 0 means DefaultNonceCapacity. When full, the oldest nonce is evicted, so a
	// flood of GET /v1/nonce cannot stop new nonces from being issued: the agent uses its nonce within seconds,
	// while a flood would have to issue Capacity nonces inside that window to evict it.
	Capacity int
	// Lifetime of a nonce; 0 means NonceLifetime.
	Lifetime time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Rand is the randomness source; nil means crypto/rand.
	Rand io.Reader
}

type nonceEntry struct {
	n   [32]byte
	exp time.Time
}

// NonceStore issues single-use nonces. It is safe for concurrent use. Nonces live only in memory, so the key
// broker runs as a single Cloud Run instance (max-instances 1); a nonce issued by another instance or before a
// restart is unknown, and the agent then asks for a new one.
type NonceStore struct {
	capacity int
	lifetime time.Duration
	now      func() time.Time
	rand     io.Reader

	mu sync.Mutex
	// live maps each usable nonce to its expiry.
	live map[[32]byte]time.Time
	// order holds issued nonces oldest first. Entries whose nonce was consumed stay until they reach the front or
	// the slice is compacted; live is the source of truth.
	order   []nonceEntry
	head    int
	evicted uint64
}

// NewNonceStore returns an empty store.
func NewNonceStore(o NonceOptions) *NonceStore {
	s := &NonceStore{capacity: o.Capacity, lifetime: o.Lifetime, now: o.Now, rand: o.Rand, live: map[[32]byte]time.Time{}}
	if s.capacity <= 0 {
		s.capacity = DefaultNonceCapacity
	}
	if s.lifetime <= 0 {
		s.lifetime = NonceLifetime
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	return s
}

// Issue returns a fresh nonce and its expiry.
func (s *NonceStore) Issue() ([32]byte, time.Time, error) {
	var n [32]byte
	if _, err := io.ReadFull(s.rand, n[:]); err != nil {
		return n, time.Time{}, fmt.Errorf("nonce: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.live[n]; dup {
		// 2^-256; a broken randomness source would otherwise hand out the same nonce twice.
		return n, time.Time{}, errors.New("nonce: randomness source repeated a live nonce")
	}
	now := s.now()
	s.pruneLocked(now)
	for len(s.live) >= s.capacity {
		e := s.order[s.head]
		s.popLocked()
		if exp, ok := s.live[e.n]; ok && exp.Equal(e.exp) {
			delete(s.live, e.n)
			s.evicted++
		}
	}
	exp := now.Add(s.lifetime)
	s.live[n] = exp
	s.order = append(s.order, nonceEntry{n: n, exp: exp})
	if len(s.order)-s.head > 2*s.capacity+16 {
		s.compactLocked()
	}
	return n, exp, nil
}

// Consume uses up a nonce. A nonce succeeds at most once; a second use, an unknown nonce and an expired one fail.
func (s *NonceStore) Consume(n [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.live[n]
	if !ok {
		return ErrNonceUnknown
	}
	delete(s.live, n)
	if !s.now().Before(exp) {
		return ErrNonceExpired
	}
	return nil
}

// Len returns the number of live (issued, unused, possibly expired but not yet pruned) nonces.
func (s *NonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// Evicted returns how many unused nonces were evicted because the store was full.
func (s *NonceStore) Evicted() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

// pruneLocked drops expired and consumed entries from the front of the queue.
func (s *NonceStore) pruneLocked(now time.Time) {
	for s.head < len(s.order) {
		e := s.order[s.head]
		exp, ok := s.live[e.n]
		switch {
		case !ok || !exp.Equal(e.exp):
			s.popLocked() // consumed
		case !now.Before(exp):
			delete(s.live, e.n)
			s.popLocked()
		default:
			return
		}
	}
}

func (s *NonceStore) popLocked() {
	s.order[s.head] = nonceEntry{}
	s.head++
	if s.head == len(s.order) {
		s.order = s.order[:0]
		s.head = 0
	}
}

// compactLocked rebuilds the queue from live entries only, keeping the issue order.
func (s *NonceStore) compactLocked() {
	out := make([]nonceEntry, 0, len(s.live)+16)
	for _, e := range s.order[s.head:] {
		if exp, ok := s.live[e.n]; ok && exp.Equal(e.exp) {
			out = append(out, e)
		}
	}
	s.order = out
	s.head = 0
}
