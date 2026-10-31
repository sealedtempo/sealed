// Package proxy is the sealed-egress HTTP proxy: CONNECT tunnels and
// absolute-URI http:// forwarding, built on stripe/smokescreen embedded as a
// library. Smokescreen resolves each destination, checks every resolved IP
// and dials only the checked IP; this package supplies caller identity
// (source IP, plus a credential for proxyAuth callers), the per-caller
// allowlist decision, the always-deny ranges, per-caller limits and the
// counters.
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

	"github.com/sealedtempo/sealed/runtime/egress/auth"
	"github.com/sealedtempo/sealed/runtime/egress/limits"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	"github.com/sealedtempo/sealed/runtime/egress/stats"
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
	// Tokens holds the credentials of proxyAuth callers (nil: none).
	Tokens *auth.Tokens
	// Limits bounds each caller's connections and request rate; zero
	// fields take limits.Defaults.
	Limits limits.Config

	ConnectTimeout    time.Duration
	IdleTimeout       time.Duration
	ReadHeaderTimeout time.Duration
}

// Proxy serves the egress proxy on a listener.
//
// Smokescreen's IP rules see only the resolved address, not whether the
// request named a hostname or an IP literal, so there are two smokescreen
// instances (runtime-1). names serves every request except one for a
// private IP literal, and its rules deny every private address: a hostname
// never reaches one, whatever its DNS answers. vpc serves requests for a
// private IP literal, and its rules admit only the private raw IP entries
// (ip and port); the decider has already checked that the caller lists the
// literal. dial checks the caller once more (Policy.CheckDial).
type Proxy struct {
	opts         Options
	cfgs         []*smokescreen.Config
	names        *goproxy.ProxyHttpServer
	vpc          *goproxy.ProxyHttpServer
	server       *http.Server
	tracker      *conntrack.Tracker
	closing      atomic.Bool
	conns        *limits.Pool
	unknownConns *limits.Pool
	requests     *limits.Rate
}

// Errors that decide how a refused request is answered and counted.
var (
	errUnknownSource   = errors.New("source is not a configured caller")
	errUnauthenticated = errors.New("missing or invalid proxy credential")
)

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
	opts.Limits = opts.Limits.WithDefaults()
	lim := opts.Limits
	p := &Proxy{
		opts:         opts,
		conns:        limits.NewPool(lim.ConnsReserved, lim.ConnsPerCaller, lim.ConnsShared),
		unknownConns: limits.NewPool(0, lim.ConnsUnknown, lim.ConnsUnknown),
		requests:     limits.NewRate(lim.RequestRate, lim.RequestBurst),
	}

	// Smokescreen logs every request with hosts and addresses. Egress logs
	// only per-minute counts, so its logger is discarded.
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	quiet.SetLevel(logrus.PanicLevel)

	deny := ruleRanges(append(opts.Policy.IP().DeniedPrefixes(), policy.PrivatePrefixes()...))
	names := p.smokescreenConfig(quiet, deny, nil)
	vpc := p.smokescreenConfig(quiet, deny, entryRanges(opts.Policy.PrivateEntries()))
	p.tracker = conntrack.NewTracker(names.IdleTimeout, names.MetricsClient, names.Log, atomic.Value{}, nil)
	for _, cfg := range []*smokescreen.Config{names, vpc} {
		cfg.ConnTracker = p.tracker
		if err := cfg.InitializeSelfConnectionDetection(); err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
	}
	p.cfgs = []*smokescreen.Config{names, vpc}
	p.names = buildProxy(names)
	p.vpc = buildProxy(vpc)

	// No read or write timeout: tunnels and long plain-HTTP transfers are
	// bounded by the idle timeout instead (smokescreen wraps hijacked conns).
	p.server = &http.Server{
		Handler:           p.rateLimit(http.HandlerFunc(p.route)),
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		IdleTimeout:       opts.IdleTimeout,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return p, nil
}

// smokescreenConfig is the smokescreen setup shared by both instances.
// Most-specific matching lets an allow rule for one private ip:port beat
// the deny rule for its range, and any deny rule for a smaller range
// (metadata, the VM and local networks) beat a broader allow.
func (p *Proxy) smokescreenConfig(quiet *logrus.Logger, deny, allow []smokescreen.RuleRange) *smokescreen.Config {
	cfg := smokescreen.NewConfig()
	cfg.Log = quiet
	cfg.EgressACL = decider{p}
	cfg.RoleFromRequest = p.roleFromRequest
	cfg.AllowMissingRole = false
	cfg.Resolver = p.opts.Resolver
	cfg.Network = "ip"
	cfg.MostSpecificIPRules = true
	cfg.DenyRanges = deny
	cfg.AllowRanges = allow
	cfg.ConnectTimeout = p.opts.ConnectTimeout
	cfg.IdleTimeout = p.opts.IdleTimeout
	cfg.ReadHeaderTimeout = p.opts.ReadHeaderTimeout
	cfg.ProxyDialTimeout = p.dial
	cfg.PostDecisionRequestHandler = p.countAllowed
	cfg.RejectResponseHandlerWithCtx = p.onReject
	cfg.AdditionalErrorMessageOnDeny = DenyMessage
	// No global tunnel or request limit: one caller could exhaust it and
	// lock out sealed-agent and the payer. Limits are per caller instead
	// (limitListener and rateLimit).
	cfg.MaxConcurrentConnectTunnels = 0
	cfg.TunnelLimiter = nil
	cfg.ShuttingDown.Store(false)
	return cfg
}

func buildProxy(cfg *smokescreen.Config) *goproxy.ProxyHttpServer {
	gp := smokescreen.BuildProxy(cfg)
	gp.Logger = log.New(io.Discard, "", 0)
	gp.Tr.Proxy = nil
	gp.Tr.TLSClientConfig = nil
	gp.ConnectDial = nil
	gp.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sealed-egress is a forward proxy; send CONNECT or an absolute http:// URL", http.StatusBadRequest)
	})
	return gp
}

// route sends a request for a private IP literal to the vpc instance and
// every other request, every hostname above all, to names (see Proxy).
func (p *Proxy) route(w http.ResponseWriter, r *http.Request) {
	if host, _, err := destination(r); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil && policy.Classify(ip) == policy.ClassPrivate {
			p.vpc.ServeHTTP(w, r)
			return
		}
	}
	p.names.ServeHTTP(w, r)
}

// Serve accepts proxy clients on ln until Shutdown.
func (p *Proxy) Serve(ln net.Listener) error {
	err := p.server.Serve(&limitListener{Listener: ln, p: p})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting, waits for open tunnels to finish until ctx
// ends, then closes whatever is left.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.closing.Store(true)
	for _, cfg := range p.cfgs {
		cfg.ShuttingDown.Store(true)
	}
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
	p.names.Tr.CloseIdleConnections()
	p.vpc.Tr.CloseIdleConnections()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// callerOf returns the caller a client address belongs to, by source IP.
func (p *Proxy) callerOf(remote string) (*policy.CallerPolicy, bool) {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return nil, false
	}
	return p.opts.Policy.CallerByIP(p.opts.SourceIP(ap))
}

// identify returns the caller that sent r. For proxyAuth callers the source
// IP only names the caller; the request must also carry its credential.
// On errUnauthenticated the caller is returned too, for counting.
func (p *Proxy) identify(r *http.Request) (*policy.CallerPolicy, error) {
	c, ok := p.callerOf(r.RemoteAddr)
	if !ok {
		return nil, errUnknownSource
	}
	if !p.opts.Tokens.CheckProxy(c.Name, r.Header) {
		return c, errUnauthenticated
	}
	return c, nil
}

func (p *Proxy) roleFromRequest(r *http.Request) (string, error) {
	c, err := p.identify(r)
	if errors.Is(err, errUnknownSource) {
		return "", smokescreen.MissingRoleError(err.Error())
	}
	if err != nil {
		return "", err
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
	c, err := p.identify(r)
	if err != nil {
		return c, policy.Entry{}, err
	}
	host, port, err := destination(r)
	if err != nil {
		return c, policy.Entry{}, err
	}
	e, ok := c.Allow.Match(host, port)
	if !ok {
		// The reason goes back to the client only (smokescreen's logs are
		// discarded), so it names what the client asked for.
		return c, policy.Entry{}, fmt.Errorf("%s:%d is not on the allowlist for %s", host, port, c.Name)
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

// onReject turns smokescreen's policy denials (407) into 403 and counts
// them, or keeps 407 with a challenge when a proxyAuth caller sent no valid
// credential. Upstream failures (502, 504) are not blocks.
func (p *Proxy) onReject(_ *smokescreen.SmokescreenContext, resp *http.Response) {
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return
	}
	r := resp.Request
	if r == nil {
		p.block(nil, policy.KeyInvalid+":0", false)
		toForbidden(resp)
		return
	}
	c, e, err := p.match(r)
	switch {
	case errors.Is(err, errUnauthenticated):
		const msg = "This caller must send its sealed-egress proxy credential.\n"
		resp.Status = "407 Proxy Authentication Required"
		resp.Header.Set("Proxy-Authenticate", `Basic realm="sealed-egress"`)
		resp.Header.Set("X-Sealed-Egress", "auth-required")
		resp.Header.Del("X-Smokescreen-Error")
		resp.Body = io.NopCloser(strings.NewReader(msg))
		resp.ContentLength = int64(len(msg))
		p.block(c, policy.KeyUnauthenticated, false)
	case err == nil:
		// On the allowlist but blocked after resolution (metadata, loopback,
		// a private or local range): count under the entry.
		toForbidden(resp)
		p.block(c, e.String(), true)
	default:
		toForbidden(resp)
		var allow *policy.Allowlist
		if c != nil {
			allow = c.Allow
		}
		key, listed := requestKey(allow, r)
		p.block(c, key, listed)
	}
}

func toForbidden(resp *http.Response) {
	resp.StatusCode = http.StatusForbidden
	resp.Status = "403 Forbidden"
	resp.Header.Set("X-Sealed-Egress", "blocked")
}

// block counts one blocked attempt. listed keys are allowlist entries and
// are not subject to the per-caller key cap.
func (p *Proxy) block(c *policy.CallerPolicy, key string, listed bool) {
	caller := policy.UnknownCaller
	if c != nil {
		caller = c.Name
	}
	if listed {
		p.opts.Stats.BlockEntry(caller, key)
		return
	}
	p.opts.Stats.Block(caller, key)
}

// requestKey is the stats key for a denied request (policy key grammar).
// Requests that destination rejects are keyed by whatever host and port
// they name, so an IPv6 literal still counts as ip-<class>.
func requestKey(allow *policy.Allowlist, r *http.Request) (string, bool) {
	if host, port, err := destination(r); err == nil {
		return allow.BlockedKey(host, port)
	}
	host, port := r.Host, ""
	if r.Method != http.MethodConnect && r.URL != nil && r.URL.Host != "" {
		host, port = r.URL.Hostname(), r.URL.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[r.URL.Scheme]
		}
	} else if h, pt, err := net.SplitHostPort(r.Host); err == nil {
		host, port = h, pt
	}
	pn, err := policy.ParsePort(port)
	if err != nil {
		pn = 0
	}
	return allow.BlockedKey(host, pn)
}

// dial is smokescreen's ProxyDialTimeout. address is always the resolved
// ip:port smokescreen already checked. Check it once more, for the caller
// and the host its request named (smokescreen's decision, carried in ctx),
// before dialing. smokescreen's rules already refuse every address this
// refuses, with a 403; reaching a refusal here means those rules are wrong,
// so it fails closed.
func (p *Proxy) dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("refusing to dial unresolved address %q", address)
	}
	if err := p.checkDial(ctx, ap); err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.opts.Dial(dctx, network, address)
}

// checkDial applies Policy.CheckDial to the caller (smokescreen's Role)
// and the requested host (OutboundHost) of the request being dialed.
func (p *Proxy) checkDial(ctx context.Context, ap netip.AddrPort) error {
	pctx, _ := ctx.Value(goproxy.ProxyContextKey).(*goproxy.ProxyCtx)
	if pctx == nil {
		return errors.New("refusing to dial without a proxy decision")
	}
	sctx, _ := pctx.UserData.(*smokescreen.SmokescreenContext)
	if sctx == nil || sctx.Decision == nil {
		return errors.New("refusing to dial without a proxy decision")
	}
	c, ok := p.opts.Policy.CallerByName(sctx.Decision.Role)
	if !ok {
		return errors.New("refusing to dial for a request with no caller")
	}
	host, _, err := net.SplitHostPort(sctx.Decision.OutboundHost)
	if err != nil {
		return fmt.Errorf("refusing to dial: requested host %q is not host:port", sctx.Decision.OutboundHost)
	}
	return p.opts.Policy.CheckDial(c, host, ap)
}

// entryRanges turns private raw IP entries into allow rules for exactly
// that address and port.
func entryRanges(entries []netip.AddrPort) []smokescreen.RuleRange {
	out := make([]smokescreen.RuleRange, 0, len(entries))
	for _, ap := range entries {
		addr := ap.Addr()
		out = append(out, smokescreen.RuleRange{
			Net:  net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())},
			Port: int(ap.Port()),
		})
	}
	return out
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
