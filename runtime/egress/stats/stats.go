// Package stats counts allowed and blocked egress attempts per caller and
// destination key, and serves them to the stats readers. Keys come from the
// policy package's key grammar (allowlist entries or a fixed vocabulary);
// nothing else about a request (names, paths, queries, payloads) ever
// reaches this package.
package stats

import (
	"sync"
	"time"
)

// OverflowKey collects attempts once a caller has MaxKeys distinct capped
// keys.
const OverflowKey = "other:0"

// DefaultMaxKeys bounds the distinct capped keys per caller and verdict.
// Keys that are the caller's own allowlist entries are not capped: the
// config already bounds them (at most 1024 per caller), and capping them
// would let junk keys hide legitimate traffic.
const DefaultMaxKeys = 256

// Counts maps a destination key to an attempt count.
type Counts map[string]uint64

// CallerCounts are the counts for one caller.
type CallerCounts struct {
	Allowed Counts `json:"allowed"`
	Blocked Counts `json:"blocked"`
}

// Snapshot is the GET /v1/stats body. Allowed and Blocked aggregate all
// callers (the INTERFACES section 12 shape); Callers breaks them down.
type Snapshot struct {
	Since   int64                   `json:"since"`
	Allowed Counts                  `json:"allowed"`
	Blocked Counts                  `json:"blocked"`
	Callers map[string]CallerCounts `json:"callers"`
}

// Counter is safe for concurrent use.
type Counter struct {
	mu       sync.Mutex
	since    time.Time
	maxKeys  int
	total    map[string]*tally
	interval map[string]*tally
}

// tally is one caller's counts plus how many capped keys each verdict holds.
type tally struct {
	CallerCounts
	cappedAllowed, cappedBlocked int
}

// New returns a Counter whose snapshots report since as their start time.
// maxKeys <= 0 means DefaultMaxKeys.
func New(since time.Time, maxKeys int) *Counter {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	return &Counter{
		since:    since,
		maxKeys:  maxKeys,
		total:    map[string]*tally{},
		interval: map[string]*tally{},
	}
}

// Allow counts one allowed attempt. key is the allowlist entry that matched,
// so it is not capped.
func (c *Counter) Allow(caller, key string) { c.add(caller, key, true, false) }

// BlockEntry counts one blocked attempt whose key is one of the caller's
// allowlist entries (or derived one-to-one from one); it is not capped.
func (c *Counter) BlockEntry(caller, key string) { c.add(caller, key, false, false) }

// Block counts one blocked attempt under a capped key.
func (c *Counter) Block(caller, key string) { c.add(caller, key, false, true) }

func (c *Counter) add(caller, key string, allowed, capped bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, set := range []map[string]*tally{c.total, c.interval} {
		t := set[caller]
		if t == nil {
			t = &tally{CallerCounts: CallerCounts{Allowed: Counts{}, Blocked: Counts{}}}
			set[caller] = t
		}
		m, n := t.Blocked, &t.cappedBlocked
		if allowed {
			m, n = t.Allowed, &t.cappedAllowed
		}
		k := key
		if _, seen := m[k]; !seen && capped {
			if *n >= c.maxKeys {
				k = OverflowKey
			} else {
				*n++
			}
		}
		m[k]++
	}
}

// Snapshot returns all counts since start.
func (c *Counter) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return build(c.since, c.total)
}

// TakeInterval returns the counts since the previous call and resets them.
func (c *Counter) TakeInterval(start time.Time) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := build(start, c.interval)
	c.interval = map[string]*tally{}
	return s
}

func build(since time.Time, set map[string]*tally) Snapshot {
	s := Snapshot{
		Since:   since.Unix(),
		Allowed: Counts{},
		Blocked: Counts{},
		Callers: map[string]CallerCounts{},
	}
	for name, cc := range set {
		out := CallerCounts{Allowed: Counts{}, Blocked: Counts{}}
		for k, n := range cc.Allowed {
			out.Allowed[k] = n
			s.Allowed[k] += n
		}
		for k, n := range cc.Blocked {
			out.Blocked[k] = n
			s.Blocked[k] += n
		}
		s.Callers[name] = out
	}
	return s
}

// Total sums all counts in a Counts map.
func (m Counts) Total() uint64 {
	var t uint64
	for _, n := range m {
		t += n
	}
	return t
}
