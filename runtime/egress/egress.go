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

	"github.com/sealedtempo/sealed/runtime/egress/auth"
	"github.com/sealedtempo/sealed/runtime/egress/dnsfilter"
	"github.com/sealedtempo/sealed/runtime/egress/limits"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	"github.com/sealedtempo/sealed/runtime/egress/proxy"
	"github.com/sealedtempo/sealed/runtime/egress/stats"
	"github.com/sealedtempo/sealed/runtime/egress/upstream"
)

// DefaultAuthDir is where proxy credentials for proxyAuth callers are
// written (one subdirectory per caller, see package auth).
const DefaultAuthDir = "/run/sealed-egress/auth"

// Options holds process-level settings that are not part of the measured
// config. The zero value is the production setup.
type Options struct {
	Logger *slog.Logger
	// StatsLogInterval is how often counts are logged (default 1 minute).
	StatsLogInterval time.Duration
	// AuthDir receives the proxy credentials of proxyAuth callers
	// (default DefaultAuthDir). Unused when no caller sets proxyAuth.
	AuthDir string
	// Limits are the per-caller connection, rate and DNS limits; zero
	// fields take limits.Defaults.
	Limits limits.Config
	// LocalSubnets returns the egress container's own networks, which are
	// always denied as destinations. nil reads the interfaces
	// (InterfaceSubnets); tests pass a fixed list.
	LocalSubnets func() ([]netip.Prefix, error)

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

// InterfaceSubnets lists the networks of this host's (container's)
// interfaces. In the VM these are the apps and edge bridges; denying them
// keeps the bridge gateways and other containers unreachable through the
// proxy even if the composer renumbers the networks.
func InterfaceSubnets() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		ip = ip.Unmap()
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		if pfx, err := ip.Prefix(ones); err == nil {
			out = append(out, pfx)
		}
	}
	return out, nil
}

// Start validates cfg, binds every listener and starts serving.
func Start(cfg *policy.Config, opts Options) (*Service, error) {
	if opts.LocalSubnets == nil {
		opts.LocalSubnets = InterfaceSubnets
	}
	local, err := opts.LocalSubnets()
	if err != nil {
		return nil, fmt.Errorf("list local networks: %w", err)
	}
	pol, err := policy.Compile(cfg, local...)
	if err != nil {
		return nil, err
	}
	if opts.AuthDir == "" {
		opts.AuthDir = DefaultAuthDir
	}
	tokens, err := auth.Provision(opts.AuthDir, pol.ProxyAuthCallers())
	if err != nil {
		return nil, err
	}
	opts.Limits = opts.Limits.WithDefaults()
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
		Tokens:   tokens,
		Limits:   opts.Limits,
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

	s.dns = dnsfilter.New(pol, up, s.counter, opts.SourceIP, opts.Limits)
	s.dns.Serve(dnsPC, dnsLn, s.errs)

	s.statsServer = &http.Server{
		Handler:           stats.Handler(s.counter, statsAuthorizer(pol, tokens, opts.SourceIP)),
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

// statsAuthorizer admits GET /v1/stats from statsReaders. A reader that is
// also a proxyAuth caller must send Authorization: Bearer <its token>.
func statsAuthorizer(pol *policy.Policy, tokens *auth.Tokens, sourceIP func(netip.AddrPort) netip.Addr) func(*http.Request) bool {
	return func(r *http.Request) bool {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			return false
		}
		ip := sourceIP(ap)
		if !pol.IsStatsReader(ip) {
			return false
		}
		if c, ok := pol.CallerByIP(ip); ok {
			return tokens.CheckBearer(c.Name, r.Header)
		}
		return true
	}
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
