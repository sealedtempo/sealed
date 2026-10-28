// Package egress runs sealed-egress (spec 5.4, INTERFACES sections 12 and
// 14): the HTTP proxy, the filtering DNS server and the stats endpoint, all
// driven by one measured config.
package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/sealed-dev/sealed/runtime/egress/dnsfilter"
	"github.com/sealed-dev/sealed/runtime/egress/policy"
	"github.com/sealed-dev/sealed/runtime/egress/proxy"
	"github.com/sealed-dev/sealed/runtime/egress/stats"
	"github.com/sealed-dev/sealed/runtime/egress/upstream"
)

// Options holds process-level settings that are not part of the measured
// config. The zero value is the production setup.
type Options struct {
	Logger *slog.Logger
	// StatsLogInterval is how often counts are logged (default 1 minute).
	StatsLogInterval time.Duration

	// SourceIP maps a client's remote address to the caller IP used for
	// policy. Tests only: production identifies callers by their real
	// source IP (nil keeps that).
	SourceIP func(netip.AddrPort) netip.Addr
	// Dial opens outbound connections after every policy check passed.
	// Tests only: nil uses a plain net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Service is a running sealed-egress.
type Service struct {
	ProxyAddr  net.Addr
	DNSUDPAddr net.Addr
	DNSTCPAddr net.Addr
	StatsAddr  net.Addr

	log         *slog.Logger
	counter     *stats.Counter
	proxy       *proxy.Proxy
	dns         *dnsfilter.Server
	statsServer *http.Server
	errs        chan error
	stopLog     context.CancelFunc
	logDone     chan struct{}
}

// RemoteIP is the production caller identity: the connection's source IP.
func RemoteIP(ap netip.AddrPort) netip.Addr { return ap.Addr().Unmap() }

// Start validates cfg, binds every listener and starts serving.
func Start(cfg *policy.Config, opts Options) (*Service, error) {
	pol, err := policy.Compile(cfg)
	if err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.StatsLogInterval <= 0 {
		opts.StatsLogInterval = time.Minute
	}
	if opts.SourceIP == nil {
		opts.SourceIP = RemoteIP
	}
	if opts.Dial == nil {
		d := &net.Dialer{}
		opts.Dial = d.DialContext
	}

	s := &Service{
		log:     opts.Logger,
		counter: stats.New(time.Now(), stats.DefaultMaxKeys),
		errs:    make(chan error, 4),
		logDone: make(chan struct{}),
	}
	up := upstream.New(pol.Upstreams(), 2*time.Second)

	s.proxy, err = proxy.New(proxy.Options{
		Policy:   pol,
		Resolver: up,
		Stats:    s.counter,
		SourceIP: opts.SourceIP,
		Dial:     opts.Dial,
	})
	if err != nil {
		return nil, err
	}

	var closers []func()
	fail := func(err error) (*Service, error) {
		for _, c := range closers {
			c()
		}
		return nil, err
	}

	proxyLn, err := net.Listen("tcp", cfg.Listen.Proxy)
	if err != nil {
		return fail(fmt.Errorf("listen proxy %s: %w", cfg.Listen.Proxy, err))
	}
	closers = append(closers, func() { proxyLn.Close() })
	s.ProxyAddr = proxyLn.Addr()

	dnsPC, dnsLn, err := listenDNS(cfg.Listen.DNS)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, func() { dnsPC.Close(); dnsLn.Close() })
	s.DNSUDPAddr, s.DNSTCPAddr = dnsPC.LocalAddr(), dnsLn.Addr()

	statsLn, err := net.Listen("tcp", cfg.Listen.Stats)
	if err != nil {
		return fail(fmt.Errorf("listen stats %s: %w", cfg.Listen.Stats, err))
	}
	s.StatsAddr = statsLn.Addr()

	go func() {
		if err := s.proxy.Serve(proxyLn); err != nil {
			s.report(fmt.Errorf("proxy: %w", err))
		}
	}()

	s.dns = dnsfilter.New(pol, up, s.counter, opts.SourceIP)
	s.dns.Serve(dnsPC, dnsLn, s.errs)

	s.statsServer = &http.Server{
		Handler: stats.Handler(s.counter, func(ap netip.AddrPort) bool {
			return pol.IsStatsReader(opts.SourceIP(ap))
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go func() {
		if err := s.statsServer.Serve(statsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.report(fmt.Errorf("stats: %w", err))
		}
	}()

	logCtx, stopLog := context.WithCancel(context.Background())
	s.stopLog = stopLog
	go func() {
		defer close(s.logDone)
		stats.LogEvery(logCtx, s.counter, opts.StatsLogInterval, s.log)
	}()
	return s, nil
}

// listenDNS binds UDP and TCP on the same port. With port 0 the TCP bind
// reuses the port the kernel picked for UDP, retrying on collisions.
func listenDNS(addr string) (net.PacketConn, net.Listener, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	attempts := 1
	if port == "0" {
		attempts = 10
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("listen dns udp %s: %w", addr, err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln, nil
		}
		pc.Close()
		lastErr = err
	}
	return nil, nil, fmt.Errorf("listen dns tcp %s: %w", addr, lastErr)
}

func (s *Service) report(err error) {
	select {
	case s.errs <- err:
	default:
	}
}

// Err delivers the first fatal serve error, if any.
func (s *Service) Err() <-chan error { return s.errs }

// Stats returns the counts since start.
func (s *Service) Stats() stats.Snapshot { return s.counter.Snapshot() }

// Shutdown stops all listeners, drains open tunnels until ctx ends and
// writes a final counts line.
func (s *Service) Shutdown(ctx context.Context) error {
	// DNS and stats stop at once on their own short deadline, so a long
	// tunnel drain cannot starve them.
	quick, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var dnsErr, statsErr error
	var wg sync.WaitGroup
	wg.Go(func() { dnsErr = s.dns.Shutdown(quick) })
	wg.Go(func() { statsErr = s.statsServer.Shutdown(quick) })
	proxyErr := s.proxy.Shutdown(ctx)
	wg.Wait()

	var errs []error
	if proxyErr != nil {
		errs = append(errs, fmt.Errorf("proxy: %w", proxyErr))
	}
	if dnsErr != nil {
		errs = append(errs, fmt.Errorf("dns: %w", dnsErr))
	}
	if statsErr != nil {
		errs = append(errs, fmt.Errorf("stats: %w", statsErr))
	}
	s.stopLog()
	<-s.logDone
	return errors.Join(errs...)
}
