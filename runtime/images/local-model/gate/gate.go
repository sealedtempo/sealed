package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Ollama endpoints that LiteLLM's ollama_chat provider and OpenAI-compatible clients use.
// Everything else (pull, push, create, copy, delete, blobs, experimental) is refused, so a
// peer can only run inference on the baked model, never change the model store.
var allowedRoutes = map[string]map[string]bool{
	http.MethodGet: {
		"/": true, "/api/tags": true, "/api/ps": true, "/api/version": true, "/v1/models": true,
	},
	http.MethodHead: {"/": true},
	http.MethodPost: {
		"/api/chat": true, "/api/generate": true, "/api/embed": true, "/api/embeddings": true,
		"/api/show": true, "/v1/chat/completions": true, "/v1/completions": true, "/v1/embeddings": true,
	},
}

func routeAllowed(method string, u *url.URL) bool {
	if u.RawPath != "" {
		return false // only canonical paths, so the upstream router sees exactly what was checked
	}
	if allowedRoutes[method][u.Path] {
		return true
	}
	name, ok := strings.CutPrefix(u.Path, "/v1/models/")
	return method == http.MethodGet && ok && name != "" && !strings.ContainsAny(name, "/\\")
}

// peerSet admits loopback (the container's own healthcheck) and the current addresses of
// a few service names, resolved through Docker's embedded DNS. Fixed service IPs and
// aliases come only from the composer, so an app cannot claim a name it does not own.
// Names are re-resolved on a miss (at most once per minInterval), because the gateway
// container usually starts after this one.
type peerSet struct {
	names       []string
	loopback    bool
	lookup      func(ctx context.Context, host string) ([]net.IPAddr, error)
	minInterval time.Duration
	now         func() time.Time

	mu   sync.Mutex
	ips  map[string]bool
	last time.Time
}

func newPeerSet(names []string, loopback bool) *peerSet {
	return &peerSet{
		names:       names,
		loopback:    loopback,
		lookup:      net.DefaultResolver.LookupIPAddr,
		minInterval: time.Second,
		now:         time.Now,
		ips:         map[string]bool{},
	}
}

func ipKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func (p *peerSet) allowed(ctx context.Context, ip net.IP) bool {
	if ip.IsLoopback() {
		return p.loopback
	}
	key := ipKey(ip)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ips[key] {
		return true
	}
	if !p.last.IsZero() && p.now().Sub(p.last) < p.minInterval {
		return false
	}
	p.refresh(ctx)
	return p.ips[key]
}

func (p *peerSet) refresh(ctx context.Context) {
	p.last = p.now()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	fresh := map[string]bool{}
	resolved := false
	for _, name := range p.names {
		addrs, err := p.lookup(ctx, name)
		if err != nil {
			continue
		}
		resolved = true
		for _, a := range addrs {
			fresh[ipKey(a.IP)] = true
		}
	}
	if resolved {
		p.ips = fresh
	}
}

type gate struct {
	peers   *peerSet
	key     []byte // optional bearer key; nil disables the check
	maxBody int64
	proxy   *httputil.ReverseProxy
	health  *http.Client
	base    string
}

func newGate(upstream string, peers *peerSet, key []byte, maxBody int64) *gate {
	target := &url.URL{Scheme: "http", Host: upstream}
	transport := &http.Transport{
		Proxy:               nil, // Ollama is on loopback; never use HTTP(S)_PROXY
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Del("Authorization")
		},
		FlushInterval: -1, // stream tokens as Ollama produces them
		Transport:     transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "local model unavailable", http.StatusBadGateway)
		},
	}
	return &gate{
		peers:   peers,
		key:     key,
		maxBody: maxBody,
		proxy:   proxy,
		health:  &http.Client{Timeout: 3 * time.Second, Transport: transport},
		base:    target.String(),
	}
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !g.peers.allowed(r.Context(), ip) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		g.healthz(w, r)
		return
	}
	if g.key != nil && !bearerMatches(r.Header.Get("Authorization"), g.key) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !routeAllowed(r.Method, r.URL) {
		http.Error(w, "not allowed through the Sealed local-model gate", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	g.proxy.ServeHTTP(w, r)
}

func (g *gate) healthz(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.base+"/", nil)
	if err == nil {
		var resp *http.Response
		if resp, err = g.health.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
				return
			}
		}
	}
	http.Error(w, "ollama not ready", http.StatusServiceUnavailable)
}

func bearerMatches(header string, key []byte) bool {
	token, ok := strings.CutPrefix(header, "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(token), key) == 1
}
