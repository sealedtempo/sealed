// Package proxy is the sealed-egress HTTP proxy: CONNECT tunnels and
// absolute-URI http:// forwarding, built on stripe/smokescreen embedded as a
// library. Smokescreen resolves each destination, checks every resolved IP
// and dials only the checked IP; this package supplies the per-caller
// allowlist decision, the always-deny ranges and the counters.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/hostport"

	"github.com/sealed-dev/sealed/runtime/egress/policy"
	"github.com/sealed-dev/sealed/runtime/egress/stats"
)

// DenyMessage is appended to every 403 body.
const DenyMessage = "Blocked by the Sealed egress allowlist for this container."

// proxyEnvVars would make goproxy chain through another proxy and skip our
// destination checks, so they must not be set for this process.
var proxyEnvVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"}

// Options configures a Proxy.
type Options struct {
	Policy   *policy.Policy
	Resolver smokescreen.Resolver
	Stats    *stats.Counter
	// SourceIP maps the client address to the caller IP used for policy.
	SourceIP func(netip.AddrPort) netip.Addr
	// Dial opens a TCP connection to an ip:port that passed every check.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	ConnectTimeout    time.Duration
	IdleTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	MaxTunnels        int
}

// Proxy serves the egress proxy on a listener.
type Proxy struct {
	opts    Options
	cfg     *smokescreen.Config
	gp      *goproxy.ProxyHttpServer
	server  *http.Server
	tracker *conntrack.Tracker
	closing atomic.Bool
}

// New builds a Proxy. It fails if proxy environment variables are set.
func New(opts Options) (*Proxy, error) {
	for _, v := range proxyEnvVars {
		if os.Getenv(v) != "" {
			return nil, fmt.Errorf("%s is set; sealed-egress must not run behind another proxy", v)
		}
	}
	if opts.Policy == nil || opts.Resolver == nil || opts.Stats == nil || opts.SourceIP == nil || opts.Dial == nil {
		return nil, errors.New("proxy: Policy, Resolver, Stats, SourceIP and Dial are required")
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 5 * time.Minute
	}
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = 30 * time.Second
	}
	if opts.MaxTunnels <= 0 {
		opts.MaxTunnels = 2048
	}
	p := &Proxy{opts: opts}

	// Smokescreen logs every request with hosts and addresses. Egress logs
	// only per-minute counts, so its logger is discarded.
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	quiet.SetLevel(logrus.PanicLevel)

	cfg := smokescreen.NewConfig()
	cfg.Log = quiet
	cfg.EgressACL = decider{p}
	cfg.RoleFromRequest = p.roleFromRequest
	cfg.AllowMissingRole = false
	cfg.Resolver = opts.Resolver
	cfg.Network = "ip"
	cfg.MostSpecificIPRules = true
	cfg.DenyRanges = ruleRanges(policy.AlwaysDeniedPrefixes())
	cfg.AllowRanges = ruleRanges(opts.Policy.IP().AllowedPrivate())
	cfg.ConnectTimeout = opts.ConnectTimeout
	cfg.IdleTimeout = opts.IdleTimeout
	cfg.ReadHeaderTimeout = opts.ReadHeaderTimeout
	cfg.ProxyDialTimeout = p.dial
	cfg.PostDecisionRequestHandler = p.countAllowed
	cfg.RejectResponseHandlerWithCtx = p.onReject
	cfg.AdditionalErrorMessageOnDeny = DenyMessage
	cfg.MaxConcurrentConnectTunnels = opts.MaxTunnels
	cfg.TunnelLimiter = smokescreen.NewTunnelLimiter(opts.MaxTunnels, cfg)
	cfg.ShuttingDown.Store(false)
	p.tracker = conntrack.NewTracker(cfg.IdleTimeout, cfg.MetricsClient, cfg.Log, atomic.Value{}, nil)
	cfg.ConnTracker = p.tracker
	if err := cfg.InitializeSelfConnectionDetection(); err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	p.cfg = cfg

	gp := smokescreen.BuildProxy(cfg)
	gp.Logger = log.New(io.Discard, "", 0)
	gp.Tr.Proxy = nil
	gp.Tr.TLSClientConfig = nil
	gp.ConnectDial = nil
	gp.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sealed-egress is a forward proxy; send CONNECT or an absolute http:// URL", http.StatusBadRequest)
	})
	p.gp = gp

	// No read or write timeout: tunnels and long plain-HTTP transfers are
	// bounded by the idle timeout instead (smokescreen wraps hijacked conns).
	p.server = &http.Server{
		Handler:           gp,
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		IdleTimeout:       opts.IdleTimeout,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return p, nil
}

// Serve accepts proxy clients on ln until Shutdown.
func (p *Proxy) Serve(ln net.Listener) error {
	err := p.server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting, waits for open tunnels to finish until ctx
// ends, then closes whatever is left.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.closing.Store(true)
	p.cfg.ShuttingDown.Store(true)
	err := p.server.Shutdown(ctx)
	drained := make(chan struct{})
	go func() {
		p.tracker.Wg().Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-ctx.Done():
	}
	p.tracker.Range(func(k, _ any) bool {
		_ = k.(*conntrack.InstrumentedConn).Close()
		return true
	})
	p.gp.Tr.CloseIdleConnections()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (p *Proxy) callerOf(r *http.Request) (*policy.CallerPolicy, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return nil, false
	}
	return p.opts.Policy.CallerByIP(p.opts.SourceIP(ap))
}

func (p *Proxy) roleFromRequest(r *http.Request) (string, error) {
	c, ok := p.callerOf(r)
	if !ok {
		return "", smokescreen.MissingRoleError("source is not a configured caller")
	}
	return c.Name, nil
}

// destination returns the normalized host and port a request targets.
// Absolute-URI requests must be http://; https goes through CONNECT so the
// proxy never sees or makes TLS on a client's behalf.
func destination(r *http.Request) (string, uint16, error) {
	var host, port string
	if r.Method == http.MethodConnect {
		h, pt, err := net.SplitHostPort(r.Host)
		if err != nil {
			return "", 0, errors.New("CONNECT target must be host:port")
		}
		host, port = h, pt
	} else {
		if r.URL == nil || r.URL.Scheme != "http" || r.URL.Host == "" {
			return "", 0, errors.New("only absolute http:// URLs may be proxied; use CONNECT for https")
		}
		if !strings.EqualFold(r.URL.Host, r.Host) {
			return "", 0, errors.New("request URL host and Host differ")
		}
		host, port = r.URL.Hostname(), r.URL.Port()
		if port == "" {
			port = "80"
		}
	}
	if strings.ContainsRune(host, ':') {
		return "", 0, errors.New("IPv6 literal destinations are not supported")
	}
	pn, err := policy.ParsePort(port)
	if err != nil || pn == 0 {
		return "", 0, errors.New("invalid destination port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), pn, nil
	}
	norm, err := hostport.NormalizeHost(host, false)
	if err != nil {
		return "", 0, err
	}
	norm, err = policy.NormalizeHostname(norm)
	if err != nil {
		return "", 0, err
	}
	return norm, pn, nil
}

// match returns the caller and the allowlist entry that permits r.
func (p *Proxy) match(r *http.Request) (*policy.CallerPolicy, policy.Entry, error) {
	c, ok := p.callerOf(r)
	if !ok {
		return nil, policy.Entry{}, errors.New("source is not a configured caller")
	}
	host, port, err := destination(r)
	if err != nil {
		return c, policy.Entry{}, err
	}
	e, ok := c.Allow.Match(host, port)
	if !ok {
		return c, policy.Entry{}, fmt.Errorf("%s is not on the allowlist", policy.UnmatchedKey(host, port))
	}
	return c, e, nil
}

type decider struct{ p *Proxy }

// Decide implements acl.Decider. Every path sets Result explicitly, since
// the zero value of acl.DecisionResult is Allow.
func (d decider) Decide(args acl.DecideArgs) (acl.Decision, error) {
	deny := func(reason string) (acl.Decision, error) {
		return acl.Decision{Result: acl.Deny, Reason: reason, Project: "sealed"}, nil
	}
	if d.p.closing.Load() {
		return deny("proxy is shutting down")
	}
	if args.Req == nil {
		return deny("no request")
	}
	if args.ConnectReq != nil {
		return deny("TLS interception is not supported")
	}
	if args.ConnectProxyHost != "" || args.Req.Header.Get(goproxy.PerRequestHTTPSProxyHeaderKey) != "" {
		return deny("client-selected upstream proxies are not allowed")
	}
	c, e, err := d.p.match(args.Req)
	if err != nil {
		return deny(err.Error())
	}
	if c.Name != args.Service {
		return deny("caller mismatch")
	}
	return acl.Decision{Result: acl.Allow, Reason: "allowed by " + e.String(), Project: "sealed"}, nil
}

// countAllowed runs after the allowlist and IP checks passed, just before
// the dial. Re-matching here doubles as a consistency check.
func (p *Proxy) countAllowed(r *http.Request) error {
	c, e, err := p.match(r)
	if err != nil {
		return err
	}
	p.opts.Stats.Allow(c.Name, e.String())
	return nil
}

// onReject turns smokescreen's policy denials (407) into 403, and counts
// them. Upstream failures (502, 504) and limits (429) are not blocks.
func (p *Proxy) onReject(_ *smokescreen.SmokescreenContext, resp *http.Response) {
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return
	}
	resp.StatusCode = http.StatusForbidden
	resp.Status = "403 Forbidden"
	resp.Header.Set("X-Sealed-Egress", "blocked")
	caller, key := policy.UnknownCaller, "invalid:0"
	if r := resp.Request; r != nil {
		c, e, err := p.match(r)
		switch {
		case c != nil && err == nil:
			// On the allowlist but blocked after resolution (metadata,
			// loopback, private range): count under the entry.
			caller, key = c.Name, e.String()
		default:
			if c != nil {
				caller = c.Name
			}
			key = blockedKey(c, r)
		}
	}
	p.opts.Stats.Block(caller, key)
}

// blockedKey is the stats key for a denied request. Names on the caller's
// allowlist (any port) keep their entry pattern; anything else is reduced
// by policy.UnmatchedKey.
func blockedKey(c *policy.CallerPolicy, r *http.Request) string {
	host, port, err := destination(r)
	if err != nil {
		h, pt, splitErr := net.SplitHostPort(r.Host)
		if splitErr != nil {
			h, pt = r.Host, "80"
		}
		pn, perr := policy.ParsePort(pt)
		if perr != nil {
			return "invalid:0"
		}
		return policy.UnmatchedKey(h, pn)
	}
	if c != nil {
		if e, ok := c.Allow.MatchName(host); ok {
			e.Port = port
			return e.String()
		}
	}
	return policy.UnmatchedKey(host, port)
}

// dial is smokescreen's ProxyDialTimeout. address is always the resolved
// ip:port smokescreen already checked; check it once more against the
// egress IP policy before dialing.
func (p *Proxy) dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("refusing to dial unresolved address %q", address)
	}
	if err := p.opts.Policy.IP().Check(ap.Addr()); err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.opts.Dial(dctx, network, address)
}

func ruleRanges(prefixes []netip.Prefix) []smokescreen.RuleRange {
	out := make([]smokescreen.RuleRange, 0, len(prefixes))
	for _, pfx := range prefixes {
		addr := pfx.Addr()
		out = append(out, smokescreen.RuleRange{Net: net.IPNet{
			IP:   net.IP(addr.AsSlice()),
			Mask: net.CIDRMask(pfx.Bits(), addr.BitLen()),
		}})
	}
	return out
}
