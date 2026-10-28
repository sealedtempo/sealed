package keybroker

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// clientLimiter is a token bucket per client address (F2, F10). Its map is bounded: when full, buckets that have
// refilled (idle clients) are dropped, and if every bucket is busy a new client is let through untracked, so the
// limiter never refuses because of its own size. The release slots and the body limit still bound the work.
type clientLimiter struct {
	rate  float64 // tokens per second
	burst float64
	max   int
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newClientLimiter(rate float64, burst, max int, now func() time.Time) *clientLimiter {
	if rate <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	if now == nil {
		now = time.Now
	}
	return &clientLimiter{rate: rate, burst: float64(burst), max: max, now: now, buckets: map[string]*bucket{}}
}

// allow takes one token for client. A nil limiter allows everything.
func (l *clientLimiter) allow(client string) bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[client]
	if !ok {
		if len(l.buckets) >= l.max {
			l.sweepLocked(now)
			if len(l.buckets) >= l.max {
				return true
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[client] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *clientLimiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// clientAddr is the caller's address: the last X-Forwarded-For hop, which Cloud Run's front end appends (every
// earlier hop is whatever the client sent), or the TCP peer without that header (F9). It is recorded in the decision
// log and keys the rate limit (limitKey); it never drives a release decision.
func clientAddr(r *http.Request) string {
	host := ""
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		last := xff[len(xff)-1]
		if i := strings.LastIndexByte(last, ','); i >= 0 {
			last = last[i+1:]
		}
		host = strings.TrimSpace(last)
	}
	if host == "" {
		h, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			h = r.RemoteAddr
		}
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) > 64 {
			host = host[:64]
		}
		return host
	}
	return ip.String()
}

// limitKey is the rate limit bucket of an address: IPv6 addresses count per /64, the unit one host usually controls.
func limitKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
