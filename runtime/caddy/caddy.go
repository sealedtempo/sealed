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
	DefaultGateUser    = "sealed"
	DefaultGateEnv     = "GATE_PASSWORD_BCRYPT"
	DefaultAdminSocket = "/run/sealed/caddy-admin/admin.sock"
	DefaultPageDir     = "/srv/sealed"
	DefaultPageFile    = "payment-needed.html"
	PaymentMessage     = "Payment needed: this deployment's usage fees are unpaid. The owner can raise the spending limit in the Sealed console."
)

// Route is one upstream on a site. Path is "" for the whole host or a
// prefix such as /api (matching /api and /api/*).
type Route struct {
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
	GateUser        string
	GateEnv         string
	PageDir         string
	PageFile        string
	AttestHost      string
	AttestUpstream  string
	Sites           []Site
}

type siteView struct {
	Host          string
	Routes        []Route
	HasBearer     bool
	NeedsFallback bool
}

type view struct {
	Input
	Sites          []siteView
	PaymentNeeded  bool
	PaymentMessage string
}

var (
	hostRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	upstreamRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?:[0-9]{1,5}$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-]$`)
	sockRe     = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	envRe      = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	userRe     = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

var tmpl = template.Must(template.New("Caddyfile").Option("missingkey=error").Parse(caddyfileTemplate))

// Render returns the Caddyfile. With paymentNeeded every app route serves the
// payment-needed page (status 402) and bearer API calls get a plain 402;
// the attest site is identical in both variants.
func Render(in Input, paymentNeeded bool) ([]byte, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	v := view{Input: in, PaymentNeeded: paymentNeeded, PaymentMessage: PaymentMessage}
	for _, s := range in.Sites {
		sv := siteView{Host: s.Host, Routes: append([]Route(nil), s.Routes...), NeedsFallback: true}
		// Longest path first; the whole-host route (empty path) last.
		sort.SliceStable(sv.Routes, func(i, j int) bool {
			a, b := sv.Routes[i].Path, sv.Routes[j].Path
			if len(a) != len(b) {
				return len(a) > len(b)
			}
			return a < b
		})
		for _, r := range sv.Routes {
			if r.Auth == AuthBearerPassthrough {
				sv.HasBearer = true
			}
			if r.Path == "" {
				sv.NeedsFallback = false
			}
		}
		v.Sites = append(v.Sites, sv)
	}
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

func validate(in Input) error {
	checks := []struct {
		name, val string
		re        *regexp.Regexp
	}{
		{"admin socket", in.AdminSocket, sockRe},
		{"gate user", in.GateUser, userRe},
		{"gate env", in.GateEnv, envRe},
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
		paths := map[string]bool{}
		for _, r := range s.Routes {
			if r.Path != "" && !pathRe.MatchString(r.Path) {
				return fmt.Errorf("caddyfile: site %q: invalid path %q", s.Host, r.Path)
			}
			if paths[r.Path] {
				return fmt.Errorf("caddyfile: site %q: duplicate path %q", s.Host, r.Path)
			}
			paths[r.Path] = true
			if !upstreamRe.MatchString(r.Upstream) {
				return fmt.Errorf("caddyfile: site %q: invalid upstream %q", s.Host, r.Upstream)
			}
			switch r.Auth {
			case AuthGate, AuthBearerPassthrough, AuthPublic:
			default:
				return fmt.Errorf("caddyfile: site %q: unknown auth %q", s.Host, r.Auth)
			}
		}
	}
	return nil
}
