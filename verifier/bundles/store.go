package bundles

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DefaultMemoryBytes bounds the in-memory part of a Store.
const DefaultMemoryBytes = 128 << 20

// Store is a content-addressed cache of bundle.tar bytes keyed by bundleHash = sha256(bundle.tar). An entry is the
// content its key names, so entries never expire: Put refuses bytes that do not hash to the key, and a disk entry
// that no longer hashes to its name is deleted and treated as a miss.
type Store struct {
	dir    string
	maxMem int64

	mu       sync.Mutex
	mem      map[[32]byte][]byte
	order    [][32]byte // insertion order, oldest first, for eviction
	memBytes int64
}

// NewStore returns a store that keeps up to maxMemBytes in memory (0 means DefaultMemoryBytes) and, when dir is
// not empty, every entry on disk as <dir>/<hex bundleHash>.bundle.tar (directory mode 0700, files 0600).
func NewStore(dir string, maxMemBytes int64) (*Store, error) {
	if maxMemBytes <= 0 {
		maxMemBytes = DefaultMemoryBytes
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("bundle cache: %w", err)
		}
	}
	return &Store{dir: dir, maxMem: maxMemBytes, mem: map[[32]byte][]byte{}}, nil
}

// ErrHashMismatch is returned when bytes do not hash to the expected bundleHash.
var ErrHashMismatch = errors.New("sha256 does not match the onchain bundleHash")

func (s *Store) path(h [32]byte) string {
	return filepath.Join(s.dir, hex.EncodeToString(h[:])+".bundle.tar")
}

// Get returns a copy of the bundle with hash h.
func (s *Store) Get(h [32]byte) ([]byte, bool) {
	s.mu.Lock()
	b, ok := s.mem[h]
	s.mu.Unlock()
	if ok {
		return bytes.Clone(b), true
	}
	if s.dir == "" {
		return nil, false
	}
	b, err := os.ReadFile(s.path(h))
	if err != nil {
		return nil, false
	}
	if sha256.Sum256(b) != h {
		// Corrupted or replaced on disk: never serve it, refetch instead.
		_ = os.Remove(s.path(h))
		return nil, false
	}
	s.remember(h, b)
	return bytes.Clone(b), true
}

// Put stores data under h. It fails when sha256(data) != h.
func (s *Store) Put(h [32]byte, data []byte) error {
	if sha256.Sum256(data) != h {
		return ErrHashMismatch
	}
	data = bytes.Clone(data)
	s.remember(h, data)
	if s.dir == "" {
		return nil
	}
	if _, err := os.Stat(s.path(h)); err == nil {
		return nil
	}
	f, err := os.CreateTemp(s.dir, ".bundle-*")
	if err != nil {
		return fmt.Errorf("bundle cache: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp, 0o600)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("bundle cache: %w", err)
	}
	if err := os.Rename(tmp, s.path(h)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("bundle cache: %w", err)
	}
	return nil
}

// remember keeps b in memory, evicting the oldest entries beyond the memory bound. An entry larger than the bound
// is not kept in memory.
func (s *Store) remember(h [32]byte, b []byte) {
	n := int64(len(b))
	if n > s.maxMem {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mem[h]; ok {
		return
	}
	for s.memBytes+n > s.maxMem && len(s.order) > 0 {
		old := s.order[0]
		s.order = s.order[1:]
		s.memBytes -= int64(len(s.mem[old]))
		delete(s.mem, old)
	}
	s.mem[h] = b
	s.order = append(s.order, h)
	s.memBytes += n
}
