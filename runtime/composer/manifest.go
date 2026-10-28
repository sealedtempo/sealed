package composer

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sealed-dev/sealed/catalog/schema"
)

// Manifest is a catalog app manifest (catalog/schema/manifest.schema.json).
type Manifest struct {
	Schema             string            `json:"schema"`
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Category           string            `json:"category"`
	Description        string            `json:"description"`
	ReleaseVersion     string            `json:"release_version,omitempty"`
	Upstream           Upstream          `json:"upstream"`
	Maintainer         Maintainer        `json:"maintainer"`
	MaintainerShareBps int               `json:"maintainer_share_bps"`
	ComposeFragment    string            `json:"compose_fragment"`
	EgressPolicy       string            `json:"egress_policy"`
	PrimaryService     string            `json:"primary_service"`
	Images             []Image           `json:"images"`
	Resources          Resources         `json:"resources"`
	Routes             []Route           `json:"routes"`
	Healthcheck        Healthcheck       `json:"healthcheck"`
	Metering           Metering          `json:"metering"`
	Secrets            []Secret          `json:"secrets"`
	TelemetryOffEnv    map[string]string `json:"telemetry_off_env"`
	TelemetryNone      string            `json:"telemetry_none_reason,omitempty"`
	LicenseExclusions  []string          `json:"license_exclusions"`
	Bootstrap          *Bootstrap        `json:"bootstrap,omitempty"`
	Notes              string            `json:"notes,omitempty"`
}

type Upstream struct {
	Repo        string `json:"repo"`
	Version     string `json:"version"`
	LicenseSPDX string `json:"license_spdx"`
	SourceURL   string `json:"source_url"`
}

type Maintainer struct {
	Name          string `json:"name"`
	PayoutAddress string `json:"payout_address"`
}

type Image struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	Digest      string `json:"digest"`
	Platform    string `json:"platform,omitempty"`
	LicenseSPDX string `json:"license_spdx"`
	Ref         string `json:"ref,omitempty"`
}

// Unbuilt reports whether the image digest is the all-zero placeholder used
// until the runtime image workflow pins a real digest (D-028).
func (i Image) Unbuilt() bool { return i.Digest == zeroDigest }

type Resources struct {
	CPU      int `json:"cpu"`
	MemoryGB int `json:"memory_gb"`
	DiskGB   int `json:"disk_gb"`
}

// Route auth modes.
const (
	AuthGate              = "gate"
	AuthBearerPassthrough = "bearer-passthrough"
	AuthPublic            = "public"
)

// routeAuthExceptions are the only routes that may skip the password gate
// (spec 5.5, INTERFACES section 14): the gateway API authenticates with
// LiteLLM bearer keys, and the platform relay is a paid public endpoint that
// authenticates with MPP payments. Every other route uses AuthGate.
var routeAuthExceptions = map[string]string{
	"llm-gateway/gateway":   AuthBearerPassthrough,
	"inference-relay/relay": AuthPublic,
}

type Route struct {
	Name         string `json:"name"`
	Service      string `json:"service"`
	InternalPort int    `json:"internal_port"`
	PathOrHost   string `json:"path_or_host"`
	Auth         string `json:"auth"`
}

// PathPrefix returns the routed path prefix, or "" when the route owns its
// whole host (path_or_host is the route name or "/").
func (r Route) PathPrefix() string {
	if strings.HasPrefix(r.PathOrHost, "/") && r.PathOrHost != "/" {
		return strings.TrimRight(r.PathOrHost, "/")
	}
	return ""
}

type Healthcheck struct {
	Service      string `json:"service"`
	HTTP         string `json:"http"`
	Port         int    `json:"port,omitempty"`
	StartPeriodS int    `json:"start_period_s,omitempty"`
}

type Metering struct {
	Unit   string `json:"unit"`
	Source string `json:"source"`
}

type Secret struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Generate    string `json:"generate"`
	Optional    bool   `json:"optional,omitempty"`
}

type Bootstrap struct {
	Service  string `json:"service,omitempty"`
	DoneFile string `json:"done_file,omitempty"`
}

// Version is the release version hashed into releaseId.
func (m *Manifest) Version() string {
	if m.ReleaseVersion != "" {
		return m.ReleaseVersion
	}
	return m.Upstream.Version
}

// Image returns the manifest image with the given short name.
func (m *Manifest) Image(name string) (Image, bool) {
	for _, img := range m.Images {
		if img.Name == name {
			return img, true
		}
	}
	return Image{}, false
}

// Secret returns the declared secret with the given name.
func (m *Manifest) Secret(name string) (Secret, bool) {
	for _, s := range m.Secrets {
		if s.Name == name {
			return s, true
		}
	}
	return Secret{}, false
}

// ManifestError is a validation failure tied to a manifest field.
type ManifestError struct {
	App   string
	Field string
	Msg   string
}

func (e *ManifestError) Error() string {
	app := e.App
	if app == "" {
		app = "?"
	}
	if e.Field == "" {
		return fmt.Sprintf("manifest %q: %s", app, e.Msg)
	}
	return fmt.Sprintf("manifest %q: %s: %s", app, e.Field, e.Msg)
}

var (
	schemaOnce     sync.Once
	manifestSchema *jsonschema.Schema
	schemaErr      error
)

func compiledManifestSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.ManifestJSON))
		if err != nil {
			schemaErr = fmt.Errorf("manifest schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err := c.AddResource(schema.ManifestURL, doc); err != nil {
			schemaErr = fmt.Errorf("manifest schema: %w", err)
			return
		}
		manifestSchema, schemaErr = c.Compile(schema.ManifestURL)
	})
	return manifestSchema, schemaErr
}

// ParseManifest parses manifest.yaml, validates it against the JSON Schema
// and runs the semantic checks that do not need the fragment.
func ParseManifest(data []byte) (*Manifest, error) {
	v, err := decodeYAML("manifest.yaml", data)
	if err != nil {
		return nil, err
	}
	sch, err := compiledManifestSchema()
	if err != nil {
		return nil, err
	}
	appID := ""
	if obj, ok := v.(map[string]any); ok {
		appID, _ = obj["id"].(string)
	}
	if err := sch.Validate(v); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return nil, &ManifestError{App: appID, Msg: "schema: " + flattenSchemaError(ve)}
		}
		return nil, &ManifestError{App: appID, Msg: err.Error()}
	}
	var m Manifest
	if err := strictDecode(v, &m); err != nil {
		return nil, &ManifestError{App: appID, Msg: err.Error()}
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func flattenSchemaError(ve *jsonschema.ValidationError) string {
	var msgs []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			loc := "/" + strings.Join(e.InstanceLocation, "/")
			msgs = append(msgs, fmt.Sprintf("%s: %s", loc, e.ErrorKind))
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	return strings.Join(msgs, "; ")
}

var (
	serviceNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	envNameRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// reservedAppIDs cannot be used as app ids because they collide with sidecar
// names, network aliases or secret namespaces.
var reservedAppIDs = map[string]bool{"sealed": true, "caddy": true, "gate": true, "localhost": true}

// gateSecret is the secret that holds the bcrypt hash for the password gate.
const gateSecret = "GATE_PASSWORD_BCRYPT"

func (m *Manifest) validate() error {
	fail := func(field, format string, args ...any) error {
		return &ManifestError{App: m.ID, Field: field, Msg: fmt.Sprintf(format, args...)}
	}
	if reservedAppIDs[m.ID] || strings.HasPrefix(m.ID, "sealed-") {
		return fail("id", "%q is reserved", m.ID)
	}
	if m.Version() == "" {
		return fail("release_version", "empty release version")
	}
	if !strings.HasPrefix(m.PrimaryService, m.ID+"-") {
		return fail("primary_service", "%q must start with %q", m.PrimaryService, m.ID+"-")
	}
	seenImg := map[string]bool{}
	for i, img := range m.Images {
		f := fmt.Sprintf("images[%d]", i)
		if seenImg[img.Name] {
			return fail(f+".name", "duplicate image name %q", img.Name)
		}
		seenImg[img.Name] = true
		if img.Ref != "" && !strings.HasSuffix(img.Ref, "/"+img.Name+"@"+img.Digest) {
			return fail(f+".ref", "%q does not end in /%s@%s", img.Ref, img.Name, img.Digest)
		}
	}
	routeKeys := map[string]bool{}
	for i, r := range m.Routes {
		f := fmt.Sprintf("routes[%d]", i)
		if !strings.HasPrefix(r.Service, m.ID+"-") {
			return fail(f+".service", "%q must be a service of this app (prefix %q)", r.Service, m.ID+"-")
		}
		if r.PathOrHost != r.Name && !strings.HasPrefix(r.PathOrHost, "/") {
			return fail(f+".path_or_host", "%q must be the route name %q or a path starting with /", r.PathOrHost, r.Name)
		}
		if p := r.PathPrefix(); p != "" && !safePathRe.MatchString(p) {
			return fail(f+".path_or_host", "%q contains characters not allowed in a route path", r.PathOrHost)
		}
		if r.Auth != AuthGate && routeAuthExceptions[m.ID+"/"+r.Name] != r.Auth {
			return fail(f+".auth", "%q is not allowed for app %q route %q: every app UI sits behind the password gate (only llm-gateway/gateway may use %s and inference-relay/relay %s)",
				r.Auth, m.ID, r.Name, AuthBearerPassthrough, AuthPublic)
		}
		key := r.Name + " " + r.PathPrefix()
		if routeKeys[key] {
			return fail(f, "duplicate route %q path %q", r.Name, r.PathPrefix())
		}
		routeKeys[key] = true
	}
	if !strings.HasPrefix(m.Healthcheck.Service, m.ID+"-") {
		return fail("healthcheck.service", "%q must be a service of this app", m.Healthcheck.Service)
	}
	if !strings.HasPrefix(m.Healthcheck.HTTP, "/") || !safePathRe.MatchString(m.Healthcheck.HTTP) {
		return fail("healthcheck.http", "%q must be an absolute path", m.Healthcheck.HTTP)
	}
	if m.Healthcheck.Port < 0 || m.Healthcheck.Port > 65535 {
		return fail("healthcheck.port", "out of range")
	}
	if (m.Metering.Unit == "tokens" || m.Metering.Unit == "pages") && m.Metering.Source != "callback" {
		return fail("metering.source", "unit %q is counted by the app and needs source callback", m.Metering.Unit)
	}
	seenSecret := map[string]bool{}
	for i, s := range m.Secrets {
		f := fmt.Sprintf("secrets[%d].name", i)
		if seenSecret[s.Name] {
			return fail(f, "duplicate secret %q", s.Name)
		}
		if s.Name == gateSecret {
			return fail(f, "%q is reserved for the password gate", s.Name)
		}
		seenSecret[s.Name] = true
	}
	for _, k := range sortedKeys(m.TelemetryOffEnv) {
		if !envNameRe.MatchString(k) {
			return fail("telemetry_off_env", "%q is not a valid environment variable name", k)
		}
		if reservedEnv[k] {
			return fail("telemetry_off_env", "%q is set by the composer", k)
		}
	}
	if m.Bootstrap != nil && m.Bootstrap.Service != "" && !strings.HasPrefix(m.Bootstrap.Service, m.ID+"-") {
		return fail("bootstrap.service", "%q must be a service of this app", m.Bootstrap.Service)
	}
	if m.Bootstrap != nil && m.Bootstrap.DoneFile != "" {
		if err := checkDoneFileSyntax(m.Bootstrap.DoneFile); err != nil {
			return fail("bootstrap.done_file", "%v", err)
		}
		if strings.HasPrefix(m.Bootstrap.DoneFile, "/") && m.Bootstrap.Service == "" {
			return fail("bootstrap.done_file", "an absolute path is a path in bootstrap.service, which is not set")
		}
	}
	return nil
}

// checkDoneFileSyntax accepts the two forms of bootstrap.done_file:
// "<volume>/<path>" (relative to the app's data directory) or an absolute
// path inside bootstrap.service, which ResolveDoneFile checks against the
// service's mounts. Both are clean paths without "." or ".." segments.
func checkDoneFileSyntax(p string) error {
	if !donePathRe.MatchString(p) {
		return fmt.Errorf("%q contains characters not allowed in a path", p)
	}
	rel := strings.TrimPrefix(p, "/")
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%q must be a clean path without empty, . or .. segments", p)
		}
	}
	if !strings.Contains(rel, "/") {
		return fmt.Errorf("%q must name a file inside a volume (<volume>/<path> or an absolute path under a volume mount)", p)
	}
	return nil
}

var donePathRe = regexp.MustCompile(`^/?[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

var safePathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
