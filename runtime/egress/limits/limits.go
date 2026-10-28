// Package limits keeps one container from starving the others. Every limit
// is per caller (keyed by caller name, so unknown sources share one bucket):
// open proxy connections, with a reserved share each caller always has;
// proxy request and DNS query rates; and in-flight upstream DNS queries.
// A global cap would let one app use it all and lock sealed-agent and the
// payer out, so there is none beyond the sum of these.
package limits

import (
	"sync"
	"time"
)

// Config holds every limit. Zero fields take the Defaults value.
type Config struct {
	// ConnsReserved is how many open proxy connections each caller can
	// always get, whatever the others do.
	ConnsReserved int
	// ConnsPerCaller is the most open proxy connections one caller may hold.
	ConnsPerCaller int
	// ConnsShared is the pool callers borrow from beyond ConnsReserved.
	ConnsShared int
	// ConnsUnknown caps connections from sources that are not a caller.
	ConnsUnknown int
	// ConnLifetime closes any proxy connection (tunnel or keep-alive) after
	// this long, even if it is busy.
	ConnLifetime time.Duration

	// RequestRate and RequestBurst bound proxy requests (CONNECT or plain
	// HTTP) per caller per second.
	RequestRate  float64
	RequestBurst int

	// DNSRate and DNSBurst bound DNS queries per caller per second.
	DNSRate  float64
	DNSBurst int
	// DNSInflight caps one caller's queries waiting on the upstreams.
	DNSInflight int
}

// Defaults are sized for a VM with a few dozen containers: a crawler gets
// hundreds of tunnels, and sealed-agent and the payer keep 32 each even
// when every other caller is at its maximum.
var Defaults = Config{
	ConnsReserved:  32,
	ConnsPerCaller: 512,
	ConnsShared:    2048,
	ConnsUnknown:   16,
	ConnLifetime:   12 * time.Hour,
	RequestRate:    100,
	RequestBurst:   200,
	DNSRate:        100,
	DNSBurst:       200,
	DNSInflight:    32,
}

// WithDefaults fills zero fields from Defaults.
func (c Config) WithDefaults() Config {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&c.ConnsReserved, Defaults.ConnsReserved)
	def(&c.ConnsPerCaller, Defaults.ConnsPerCaller)
	def(&c.ConnsShared, Defaults.ConnsShared)
	def(&c.ConnsUnknown, Defaults.ConnsUnknown)
	def(&c.RequestBurst, Defaults.RequestBurst)
	def(&c.DNSBurst, Defaults.DNSBurst)
	def(&c.DNSInflight, Defaults.DNSInflight)
	if c.ConnLifetime <= 0 {
		c.ConnLifetime = Defaults.ConnLifetime
	}
	if c.RequestRate <= 0 {
		c.RequestRate = Defaults.RequestRate
	}
	if c.DNSRate <= 0 {
		c.DNSRate = Defaults.DNSRate
	}
	if c.ConnsReserved > c.ConnsPerCaller {
		c.ConnsReserved = c.ConnsPerCaller
	}
	return c
}

// Pool bounds open connections per caller. Each caller has reserved slots
// nobody else can take and may borrow up to max-reserved more from a shared
// pool. Slots are fungible: a caller holding n slots is borrowing
// max(0, n-reserved) of them.
type Pool struct {
	mu         sync.Mutex
	reserved   int
	max        int
	shared     int
	sharedUsed int
	open       map[string]int
}

// NewPool returns a Pool. shared may be 0 (no borrowing).
func NewPool(reserved, max, shared int) *Pool {
	return &Pool{reserved: reserved, max: max, shared: shared, open: map[string]int{}}
}

// Acquire takes a slot for caller. It returns false when the caller holds
// its maximum, or needs to borrow and the shared pool is empty. release is
// safe to call more than once.
func (p *Pool) Acquire(caller string) (release func(), ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.open[caller]
	if n >= p.max {
		return nil, false
	}
	if n >= p.reserved {
		if p.sharedUsed >= p.shared {
			return nil, false
		}
		p.sharedUsed++
	}
	p.open[caller] = n + 1
	var once sync.Once
	return func() { once.Do(func() { p.release(caller) }) }, true
}

func (p *Pool) release(caller string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.open[caller]
	if n > p.reserved {
		p.sharedUsed--
	}
	if n <= 1 {
		delete(p.open, caller)
		return
	}
	p.open[caller] = n - 1
}

// Open reports how many slots caller holds.
func (p *Pool) Open(caller string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.open[caller]
}

// SharedInUse reports how many shared slots are borrowed.
func (p *Pool) SharedInUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sharedUsed
}

// Rate is a token bucket per key.
type Rate struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRate allows perSecond events per key on average and burst at once.
func NewRate(perSecond float64, burst int) *Rate {
	return &Rate{rate: perSecond, burst: float64(burst), now: time.Now, buckets: map[string]*bucket{}}
}

// Allow takes one token for key, reporting false when its bucket is empty.
// Keys are caller names, so the map stays as small as the config.
func (r *Rate) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	b := r.buckets[key]
	if b == nil {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(r.burst, b.tokens+elapsed*r.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Inflight caps concurrent operations per key.
type Inflight struct {
	mu   sync.Mutex
	max  int
	busy map[string]int
}

// NewInflight allows max concurrent operations per key.
func NewInflight(max int) *Inflight {
	return &Inflight{max: max, busy: map[string]int{}}
}

// Begin reserves one slot for key; call done when the operation ends.
func (f *Inflight) Begin(key string) (done func(), ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy[key] >= f.max {
		return nil, false
	}
	f.busy[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.busy[key]--; f.busy[key] <= 0 {
				delete(f.busy, key)
			}
		})
	}, true
}
