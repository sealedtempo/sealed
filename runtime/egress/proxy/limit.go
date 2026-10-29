package proxy

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sealedtempo/sealed/runtime/egress/policy"
)

// tooManyConns is written to a client that is over its connection share,
// before any request is read.
var tooManyConns = func() string {
	const body = "Too many open proxy connections from this caller; retry later.\n"
	return "HTTP/1.1 429 Too Many Requests\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Retry-After: 1\r\n" +
		"X-Sealed-Egress: limited\r\n" +
		"Connection: close\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}()

// limitListener bounds open connections per caller. Each accepted
// connection holds one slot of its caller's share until it closes, so the
// bound covers CONNECT tunnels (hijacked from the HTTP server), in-flight
// plain HTTP requests (one per connection) and idle keep-alives alike.
type limitListener struct {
	net.Listener
	p *Proxy
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, ok := l.p.acquireConn(c.RemoteAddr())
		if !ok {
			go refuse(c)
			continue
		}
		return newLimitedConn(c, release, l.p.opts.Limits.ConnLifetime), nil
	}
}

func (p *Proxy) acquireConn(remote net.Addr) (func(), bool) {
	if c, ok := p.callerOf(remote.String()); ok {
		return p.conns.Acquire(c.Name)
	}
	return p.unknownConns.Acquire(policy.UnknownCaller)
}

// refuse answers 429 without reading the request, then half-closes and
// drains briefly so the client reads the answer instead of a reset.
func refuse(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(c, tooManyConns); err != nil {
		return
	}
	if tc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = tc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 64<<10))
}

// limitedConn returns its slot when closed and is closed after the maximum
// lifetime even if traffic keeps it busy (idle timeouts reset on traffic).
type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
	mu      sync.Mutex // guards timer, which the timer's own callback reads
	timer   *time.Timer
}

func newLimitedConn(c net.Conn, release func(), lifetime time.Duration) *limitedConn {
	lc := &limitedConn{Conn: c, release: release}
	lc.mu.Lock()
	lc.timer = time.AfterFunc(lifetime, func() { _ = lc.Close() })
	lc.mu.Unlock()
	return lc
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.mu.Lock()
		c.timer.Stop()
		c.mu.Unlock()
		c.release()
	})
	return err
}

// rateLimit refuses requests over the caller's rate with 429 before
// smokescreen resolves anything, so one caller cannot flood the shared
// upstream resolvers through the proxy.
func (p *Proxy) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := policy.UnknownCaller
		if c, ok := p.callerOf(r.RemoteAddr); ok {
			caller = c.Name
		}
		if !p.requests.Allow(caller) {
			p.opts.Stats.Block(caller, policy.KeyRateLimited)
			w.Header().Set("Retry-After", "1")
			w.Header().Set("X-Sealed-Egress", "limited")
			http.Error(w, "Proxy request rate exceeded for this caller; retry later.", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
