// Package stats counts allowed and blocked egress attempts per caller and
// destination key, and serves them to the stats readers. Keys are
// "host:port" strings chosen by the proxy and DNS server; nothing else
// about a request (paths, queries, payloads) ever reaches this package.
package stats

import (
	"sync"
	"time"
)

// OverflowKey collects attempts once a caller has MaxKeys distinct keys.
const OverflowKey = "other:0"

// DefaultMaxKeys bounds distinct keys per caller and per verdict.
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
	total    map[string]*CallerCounts
	interval map[string]*CallerCounts
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
		total:    map[string]*CallerCounts{},
		interval: map[string]*CallerCounts{},
	}
}

// Allow counts one allowed attempt.
func (c *Counter) Allow(caller, key string) { c.add(caller, key, true) }

// Block counts one blocked attempt.
func (c *Counter) Block(caller, key string) { c.add(caller, key, false) }

func (c *Counter) add(caller, key string, allowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, set := range []map[string]*CallerCounts{c.total, c.interval} {
		cc := set[caller]
		if cc == nil {
			cc = &CallerCounts{Allowed: Counts{}, Blocked: Counts{}}
			set[caller] = cc
		}
		m := cc.Blocked
		if allowed {
			m = cc.Allowed
		}
		k := key
		if _, ok := m[k]; !ok && len(m) >= c.maxKeys {
			k = OverflowKey
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
	c.interval = map[string]*CallerCounts{}
	return s
}

func build(since time.Time, set map[string]*CallerCounts) Snapshot {
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
