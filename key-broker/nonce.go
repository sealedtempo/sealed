package keybroker

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// NonceLifetime is how long an issued nonce can be used (INTERFACES.md section 9).
const NonceLifetime = 5 * time.Minute

// DefaultNonceCapacity bounds the number of live nonces held in memory.
const DefaultNonceCapacity = 100_000

// Nonce errors. ErrNonceUnknown and ErrNonceExpired map to bad_nonce; ErrNonceStore (the journal could not be
// written) maps to 503.
var (
	ErrNonceUnknown = errors.New("nonce unknown or already used")
	ErrNonceExpired = errors.New("nonce expired")
	ErrNonceStore   = errors.New("nonce store unavailable")
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
	// Journal, when set (OpenNonceStore), is a file that records every issued and consumed nonce, so live nonces
	// survive a crash or a restart of the broker process (D-066). It only helps on durable storage: Cloud Run's own
	// filesystem is memory and is lost with the instance.
	Journal string
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

	journal *nonceJournal
}

// NewNonceStore returns an empty in-memory store (o.Journal is ignored; use OpenNonceStore).
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
	if s.journal != nil {
		if err := s.journal.append(recIssue, n, exp); err != nil {
			return n, time.Time{}, fmt.Errorf("%w: %v", ErrNonceStore, err)
		}
	}
	s.live[n] = exp
	s.order = append(s.order, nonceEntry{n: n, exp: exp})
	if len(s.order)-s.head > 2*s.capacity+16 {
		s.compactLocked()
	}
	if s.journal != nil && s.journal.records > 4*s.capacity+1024 {
		if err := s.rewriteJournalLocked(); err != nil {
			return n, time.Time{}, fmt.Errorf("%w: %v", ErrNonceStore, err)
		}
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
	// The consumption is recorded before it succeeds, so a crash right after cannot revive the nonce. A failed
	// write leaves the nonce unusable (it is already gone from memory).
	if s.journal != nil {
		if err := s.journal.append(recConsume, n, time.Time{}); err != nil {
			return fmt.Errorf("%w: %v", ErrNonceStore, err)
		}
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

// Journal records: one byte of kind, the nonce, the expiry (unix seconds, big endian; zero for a consumption).
const (
	recIssue   = 'I'
	recConsume = 'C'
	recLen     = 1 + 32 + 8
)

type nonceJournal struct {
	path    string
	f       *os.File
	records int
}

func (j *nonceJournal) append(kind byte, n [32]byte, exp time.Time) error {
	var rec [recLen]byte
	rec[0] = kind
	copy(rec[1:33], n[:])
	if !exp.IsZero() {
		binary.BigEndian.PutUint64(rec[33:], uint64(exp.Unix()))
	}
	if _, err := j.f.Write(rec[:]); err != nil {
		return err
	}
	j.records++
	return nil
}

// OpenNonceStore returns a store backed by the journal file o.Journal (created with mode 0600 if missing). Nonces
// issued and not consumed before a crash or restart stay usable until they expire; consumed ones stay consumed.
// Writes are not fsynced: the journal survives the broker process, not a host crash.
func OpenNonceStore(o NonceOptions) (*NonceStore, error) {
	if o.Journal == "" {
		return nil, errors.New("nonce store: no journal path")
	}
	s := NewNonceStore(o)
	raw, err := os.ReadFile(o.Journal)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("nonce journal: %w", err)
	}
	if err == nil {
		if info, serr := os.Stat(o.Journal); serr == nil && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("nonce journal %s is accessible by others (mode %v); chmod 600 it", o.Journal, info.Mode().Perm())
		}
	}
	now := s.now()
	type issued struct {
		n   [32]byte
		exp time.Time
	}
	var order []issued
	live := map[[32]byte]time.Time{}
	// A torn last record (a crash in the middle of a write) is ignored.
	for off := 0; off+recLen <= len(raw); off += recLen {
		rec := raw[off : off+recLen]
		n := [32]byte(rec[1:33])
		switch rec[0] {
		case recIssue:
			exp := time.Unix(int64(binary.BigEndian.Uint64(rec[33:])), 0)
			if _, dup := live[n]; !dup {
				order = append(order, issued{n, exp})
			}
			live[n] = exp
		case recConsume:
			delete(live, n)
		default:
			return nil, fmt.Errorf("nonce journal %s: unknown record at byte %d", o.Journal, off)
		}
	}
	for _, e := range order {
		exp, ok := live[e.n]
		if !ok || !exp.Equal(e.exp) || !now.Before(exp) || exp.Sub(now) > s.lifetime {
			continue
		}
		s.live[e.n] = exp
		s.order = append(s.order, nonceEntry{n: e.n, exp: exp})
	}
	for len(s.live) > s.capacity {
		e := s.order[s.head]
		s.popLocked()
		delete(s.live, e.n)
	}
	s.journal = &nonceJournal{path: o.Journal}
	if err := s.rewriteJournalLocked(); err != nil {
		return nil, fmt.Errorf("nonce journal: %w", err)
	}
	return s, nil
}

// rewriteJournalLocked replaces the journal with the live nonces only (temp file, fsync, rename).
func (s *NonceStore) rewriteJournalLocked() error {
	j := s.journal
	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(s.live)*recLen)
	n := 0
	for _, e := range s.order[s.head:] {
		if exp, ok := s.live[e.n]; ok && exp.Equal(e.exp) {
			var rec [recLen]byte
			rec[0] = recIssue
			copy(rec[1:33], e.n[:])
			binary.BigEndian.PutUint64(rec[33:], uint64(exp.Unix()))
			buf = append(buf, rec[:]...)
			n++
		}
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, j.path); err != nil {
		return err
	}
	nf, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if j.f != nil {
		_ = j.f.Close()
	}
	j.f, j.records = nf, n
	return nil
}

// Close closes the journal file, if any.
func (s *NonceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal == nil || s.journal.f == nil {
		return nil
	}
	err := s.journal.f.Close()
	s.journal.f = nil
	return err
}
