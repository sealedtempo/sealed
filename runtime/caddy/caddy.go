// Package caddy renders the in-VM Caddyfile from the template in this
// directory and embeds the static payment-needed page. The composer passes
// the results to Caddy (and to sealed-agent) as inline, measured compose
// configs.
package caddy

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

//go:embed Caddyfile.tmpl
var caddyfileTemplate string

// PaymentNeededHTML is the static page served while fees are unpaid.
//
//go:embed payment-needed.html
var PaymentNeededHTML []byte

// Route auth modes, matching the manifest's routes[].auth.
const (
	AuthGate              = "gate"
	AuthBearerPassthrough = "bearer-passthrough"
	AuthPublic            = "public"
)

// Defaults used by the composer.
const (
	// DefaultGateUser is the Basic auth user sealed-agent's gate accepts.
	DefaultGateUser = "sealed"
	// DefaultGatePath is sealed-agent's forward_auth endpoint (D-044).
	// Caddy calls <GatePath>?route=<route name> for every gated request.
	DefaultGatePath = "/v1/gate"
	// DefaultGateCookie is the session cookie sealed-agent sets on a Basic
	// success; Caddy passes it to the agent and never inspects it.
	DefaultGateCookie = "sealed_gate"
	// DefaultAdminSocket is Caddy's admin API, on a tmpfs owned by the
	// agent's uid; DefaultAdminSocketMode lets that uid connect.
	DefaultAdminSocket     = "/run/sealed/caddy-admin/admin.sock"
	DefaultAdminSocketMode = "0660"
	DefaultPageDir         = "/srv/sealed"
	DefaultPageFile        = "payment-needed.html"
	PaymentMessage         = "Payment needed: this deployment's usage fees are unpaid. The owner can raise the spending limit in the Sealed console."
)

// gateBasicPrefix is base64("sealed:") without its last, partial character
// group: every "Authorization: Basic" header whose user is sealed starts
// with it. Caddy strips such headers before proxying, so the gate password
// never reaches an app, while an app's own Authorization header (for
// example a Bearer token) passes through untouched.
const gateBasicPrefix = "c2VhbGVkO"

// GateBasicRegexp matches an Authorization header with Basic credentials of
// the gate user. Spaces or tabs may separate the scheme from the
// credentials, as sealed-agent's parser allows (review C-3); the agent's
// X-Sealed-Gate-Strip-Authorization answer covers any other form it accepts.
const GateBasicRegexp = `^[Bb][Aa][Ss][Ii][Cc][ \t]+` + gateBasicPrefix

// GateStripHeader is sealed-agent's answer header asking Caddy to remove the
// request's Authorization header before the app (value "1").
const GateStripHeader = "X-Sealed-Gate-Strip-Authorization"

// GateBearerQuery is added to the gate URI by bearer-passthrough handles
// (<GatePath>?route=<route>&bearer=1, review C-6). sealed-agent then answers
// 200 for a request with a Bearer token once the keys are released and the
// route's app finished its bootstrap, 503 before, 401 without a token and
// 403 for a route that is not bearer-passthrough. The app checks the token.
const GateBearerQuery = "bearer=1"

// Route is one upstream on a site. Path is "" for the whole host or a
// prefix such as /api (matching /api and /api/*). Name is the manifest
// route name, passed to the gate as ?route=<name>.
type Route struct {
	Name     string
	Path     string
	Upstream string // service:port
	Auth     string
}

// Site is one hostname with its routes.
type Site struct {
	Host   string
	Routes []Route
}

// Input is everything the template needs.
type Input struct {
	ComposerVersion string
	AdminSocket     string
	AdminSocketMode string
	// GateUpstream is sealed-agent's host:port; GatePath its gate endpoint.
	GateUpstream string
	GatePath     string
	PageDir      string
	PageFile     string
	AttestHost   string
	// AttestUpstream serves /attest (sealed-agent).
	AttestUpstream string
	// AttestRoutes are routes served on the attest host next to /attest
	// (manifest on_attest_host, D-045). Each needs a path prefix.
	AttestRoutes []Route
	Sites        []Site
}

type routeView struct {
	Route
	ID string // matcher id, unique per site
}

type siteView struct {
	Host          string
	Attest        bool
	Routes        []routeView
	HasBearer     bool
	HasGate       bool
	NeedsFallback bool
}

type view struct {
	Input
	Sites           []siteView
	PaymentNeeded   bool
	PaymentMessage  string
	GateBasicRegexp string
	GateBearerQuery string
	GateCookie      string
}

var (
	hostRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	upstreamRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?:[0-9]{1,5}$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-]$`)
	sockRe     = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	modeRe     = regexp.MustCompile(`^0[0-7]{3}$`)
	routeRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

var tmpl = template.Must(template.New("Caddyfile").Option("missingkey=error").Parse(caddyfileTemplate))

// Render returns the Caddyfile. With paymentNeeded every app route serves the
// payment-needed page (status 402), bearer API calls and attest-host routes
// get a plain 402; /attest is identical in both variants.
func Render(in Input, paymentNeeded bool) ([]byte, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	v := view{Input: in, PaymentNeeded: paymentNeeded, PaymentMessage: PaymentMessage,
		GateBasicRegexp: GateBasicRegexp, GateBearerQuery: GateBearerQuery, GateCookie: DefaultGateCookie}
	for _, s := range in.Sites {
		v.Sites = append(v.Sites, newSiteView(s.Host, s.Routes, false))
	}
	v.Sites = append(v.Sites, newSiteView(in.AttestHost, in.AttestRoutes, true))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("caddyfile: %w", err)
	}
	out := buf.Bytes()
	if bytes.ContainsRune(out, '\r') {
		return nil, fmt.Errorf("caddyfile: CR in output")
	}
	return out, nil
}

func newSiteView(host string, routes []Route, attest bool) siteView {
	sorted := append([]Route(nil), routes...)
	// Longest path first; the whole-host route (empty path) last.
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].Path, sorted[j].Path
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})
	sv := siteView{Host: host, Attest: attest, NeedsFallback: true}
	for i, r := range sorted {
		sv.Routes = append(sv.Routes, routeView{Route: r, ID: fmt.Sprintf("r%d", i)})
		switch r.Auth {
		case AuthBearerPassthrough:
			sv.HasBearer = true
			sv.HasGate = true
		case AuthGate:
			sv.HasGate = true
		}
		if r.Path == "" {
			sv.NeedsFallback = false
		}
	}
	return sv
}

func validate(in Input) error {
	checks := []struct {
		name, val string
		re        *regexp.Regexp
	}{
		{"admin socket", in.AdminSocket, sockRe},
		{"admin socket mode", in.AdminSocketMode, modeRe},
		{"gate upstream", in.GateUpstream, upstreamRe},
		{"gate path", in.GatePath, pathRe},
		{"page dir", in.PageDir, sockRe},
		{"attest host", in.AttestHost, hostRe},
		{"attest upstream", in.AttestUpstream, upstreamRe},
	}
	for _, c := range checks {
		if !c.re.MatchString(c.val) {
			return fmt.Errorf("caddyfile: invalid %s %q", c.name, c.val)
		}
	}
	if !regexp.MustCompile(`^[a-z0-9.-]+\.html$`).MatchString(in.PageFile) {
		return fmt.Errorf("caddyfile: invalid page file %q", in.PageFile)
	}
	if strings.ContainsAny(in.ComposerVersion, "\n\r") {
		return fmt.Errorf("caddyfile: invalid composer version")
	}
	hosts := map[string]bool{in.AttestHost: true}
	for _, s := range in.Sites {
		if !hostRe.MatchString(s.Host) {
			return fmt.Errorf("caddyfile: invalid host %q", s.Host)
		}
		if hosts[s.Host] {
			return fmt.Errorf("caddyfile: duplicate host %q", s.Host)
		}
		hosts[s.Host] = true
		if len(s.Routes) == 0 {
			return fmt.Errorf("caddyfile: site %q has no routes", s.Host)
		}
		if err := validateRoutes(s.Host, s.Routes, false); err != nil {
			return err
		}
	}
	return validateRoutes(in.AttestHost, in.AttestRoutes, true)
}

func validateRoutes(host string, routes []Route, attest bool) error {
	paths := map[string]bool{}
	for _, r := range routes {
		if !routeRe.MatchString(r.Name) {
			return fmt.Errorf("caddyfile: site %q: invalid route name %q", host, r.Name)
		}
		if r.Path != "" && !pathRe.MatchString(r.Path) {
			return fmt.Errorf("caddyfile: site %q: invalid path %q", host, r.Path)
		}
		if attest && (r.Path == "" || r.Path == "/attest" || strings.HasPrefix(r.Path, "/attest/")) {
			return fmt.Errorf("caddyfile: attest host route %q needs a path prefix other than /attest", r.Name)
		}
		if paths[r.Path] {
			return fmt.Errorf("caddyfile: site %q: duplicate path %q", host, r.Path)
		}
		paths[r.Path] = true
		if !upstreamRe.MatchString(r.Upstream) {
			return fmt.Errorf("caddyfile: site %q: invalid upstream %q", host, r.Upstream)
		}
		switch r.Auth {
		case AuthGate, AuthBearerPassthrough, AuthPublic:
		default:
			return fmt.Errorf("caddyfile: site %q: unknown auth %q", host, r.Auth)
		}
	}
	return nil
}
