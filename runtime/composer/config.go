package composer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

// ConfigSchema is the public deployment config schema id (INTERFACES section 5).
const ConfigSchema = "sealed-config/v1"

// Config is the public deployment config. It never contains secrets.
type Config struct {
	Schema           string              `json:"schema"`
	ChainID          int64               `json:"chainId"`
	Customer         string              `json:"customer"`
	Salt             string              `json:"salt"`
	ImageID          string              `json:"imageId"`
	ComposerVersion  string              `json:"composerVersion"`
	Apps             []ConfigApp         `json:"apps"`
	Hostnames        Hostnames           `json:"hostnames"`
	EgressAdditions  map[string][]string `json:"egressAdditions"`
	AllowedVpcRanges []string            `json:"allowedVpcRanges"`
	Endpoints        Endpoints           `json:"endpoints"`
	Contracts        Contracts           `json:"contracts"`
	FeeToken         string              `json:"feeToken"`
	Settlement       Settlement          `json:"settlement"`
	RelayOwner       string              `json:"relayOwner,omitempty"`
}

type ConfigApp struct {
	ID        string `json:"id"`
	ReleaseID string `json:"releaseId"`
}

// Hostname schemes.
const (
	SchemeSslip  = "sslip"
	SchemeCustom = "custom"
)

type Hostnames struct {
	Scheme  string            `json:"scheme"`
	IP      string            `json:"ip,omitempty"`
	Domains map[string]string `json:"domains,omitempty"`
}

type Endpoints struct {
	KeyBroker   string `json:"keyBroker"`
	PlatformAPI string `json:"platformApi"`
	TempoRPC    string `json:"tempoRpc"`
	Relay       string `json:"relay,omitempty"`
	RelayAttest string `json:"relayAttest,omitempty"`
}

type Contracts struct {
	PlatformRegistry   string `json:"platformRegistry"`
	AppRegistry        string `json:"appRegistry"`
	DeploymentRegistry string `json:"deploymentRegistry"`
	FeeSplitter        string `json:"feeSplitter"`
}

type Settlement struct {
	Mode               string `json:"mode"`
	IntervalMinutes    int64  `json:"intervalMinutes"`
	GracePeriodMinutes int64  `json:"gracePeriodMinutes"`
	SpendLimitPerDay   string `json:"spendLimitPerDay"`
}

var decimalRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,77})$`)

// Config size bounds. Configs reach the key broker and the preview API from
// untrusted callers, and every egress addition is copied into the caller
// entry of each of the app's services.
const (
	MaxConfigBytes           = 128 << 10
	MaxConfigApps            = 16
	MaxEgressAdditionsPerApp = 64
	MaxEgressAdditionsTotal  = 256
	MaxAllowedVpcRanges      = 32
)

// ParseConfig parses a public config document. It rejects unknown fields,
// floats, duplicate keys and non-canonical encodings of values (mixed-case
// hex, unsorted apps); absent egressAdditions and allowedVpcRanges are
// normalized to empty values. Hostname coverage of routes is checked by
// Compose, which knows the stack's routes.
func ParseConfig(raw []byte) (*Config, error) {
	if len(raw) > MaxConfigBytes {
		return nil, fmt.Errorf("config: %d bytes, at most %d", len(raw), MaxConfigBytes)
	}
	v, err := cjson.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config: top level must be an object")
	}
	var c Config
	if err := strictDecode(obj, &c); err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	if c.EgressAdditions == nil {
		c.EgressAdditions = map[string][]string{}
	}
	if c.AllowedVpcRanges == nil {
		c.AllowedVpcRanges = []string{}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// CanonicalJSON is CJSON of the normalized config; configHash is its sha256.
// A Config built in Go and the same config parsed from JSON give the same
// bytes: nil egressAdditions and allowedVpcRanges encode as {} and [].
func (c *Config) CanonicalJSON() ([]byte, error) {
	n := *c
	n.EgressAdditions = map[string][]string{}
	for app, list := range c.EgressAdditions {
		n.EgressAdditions[app] = append([]string{}, list...)
	}
	if n.AllowedVpcRanges == nil {
		n.AllowedVpcRanges = []string{}
	}
	n.Apps = append([]ConfigApp{}, c.Apps...)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&n); err != nil {
		return nil, err
	}
	return cjson.Canonicalize(bytes.TrimRight(buf.Bytes(), "\n"))
}

// Hash returns configHash = sha256(CJSON(config)).
func (c *Config) Hash() (Hash, error) {
	b, err := c.CanonicalJSON()
	if err != nil {
		return Hash{}, err
	}
	return SHA256(b), nil
}

// Validate checks every field that does not depend on the release bundles.
func (c *Config) Validate() error {
	fail := func(field, format string, args ...any) error {
		return fmt.Errorf("config: %s: %s", field, fmt.Sprintf(format, args...))
	}
	if c.Schema != ConfigSchema {
		return fail("schema", "must be %q", ConfigSchema)
	}
	if c.ChainID <= 0 {
		return fail("chainId", "must be positive")
	}
	if c.ComposerVersion != Version {
		return fail("composerVersion", "%q does not match this composer (%s); recompute with composer %s", c.ComposerVersion, Version, c.ComposerVersion)
	}
	for field, val := range map[string]string{
		"customer": c.Customer, "feeToken": c.FeeToken,
		"contracts.platformRegistry": c.Contracts.PlatformRegistry, "contracts.appRegistry": c.Contracts.AppRegistry,
		"contracts.deploymentRegistry": c.Contracts.DeploymentRegistry, "contracts.feeSplitter": c.Contracts.FeeSplitter,
	} {
		if _, err := ParseAddress(val); err != nil {
			return fail(field, "%v", err)
		}
	}
	if c.RelayOwner != "" {
		if _, err := ParseAddress(c.RelayOwner); err != nil {
			return fail("relayOwner", "%v", err)
		}
	}
	if _, err := ParseHash(c.Salt); err != nil {
		return fail("salt", "%v", err)
	}
	if h, err := ParseHash(c.ImageID); err != nil || h.IsZero() {
		return fail("imageId", "must be a non-zero 32-byte hex id")
	}
	if len(c.Apps) == 0 || len(c.Apps) > MaxConfigApps {
		return fail("apps", "between 1 and %d apps are required", MaxConfigApps)
	}
	for i, a := range c.Apps {
		if i > 0 && c.Apps[i-1].ID >= a.ID {
			return fail("apps", "must be sorted by id without duplicates (%q after %q)", a.ID, c.Apps[i-1].ID)
		}
		if _, err := ParseHash(a.ReleaseID); err != nil {
			return fail(fmt.Sprintf("apps[%d].releaseId", i), "%v", err)
		}
	}
	if err := c.validateHostnames(); err != nil {
		return err
	}
	if len(c.AllowedVpcRanges) > MaxAllowedVpcRanges {
		return fail("allowedVpcRanges", "at most %d ranges", MaxAllowedVpcRanges)
	}
	var vpc []netip.Prefix
	for i, r := range c.AllowedVpcRanges {
		p, err := netip.ParsePrefix(r)
		if err != nil || !p.Addr().Is4() || p.Masked() != p || !p.Addr().IsPrivate() {
			return fail(fmt.Sprintf("allowedVpcRanges[%d]", i), "%q must be a canonical private IPv4 CIDR", r)
		}
		if last := lastAddr(p); !last.IsPrivate() {
			return fail(fmt.Sprintf("allowedVpcRanges[%d]", i), "%q extends beyond private address space", r)
		}
		for _, internal := range []string{AppsSubnet, EdgeSubnet} {
			if p.Overlaps(netip.MustParsePrefix(internal)) {
				return fail(fmt.Sprintf("allowedVpcRanges[%d]", i), "%q overlaps the VM's internal network %s", r, internal)
			}
		}
		vpc = append(vpc, p)
	}
	appIDs := map[string]bool{}
	for _, a := range c.Apps {
		appIDs[a.ID] = true
	}
	total := 0
	for _, app := range sortedKeys(c.EgressAdditions) {
		if !appIDs[app] {
			return fail("egressAdditions", "%q is not an app in this stack", app)
		}
		list := c.EgressAdditions[app]
		if len(list) > MaxEgressAdditionsPerApp {
			return fail("egressAdditions."+app, "%d entries, at most %d per app", len(list), MaxEgressAdditionsPerApp)
		}
		total += len(list)
		seen := map[string]bool{}
		for i, e := range list {
			if _, err := ParseHostPortIn(e, vpc); err != nil {
				return fail(fmt.Sprintf("egressAdditions.%s[%d]", app, i), "%v", err)
			}
			if seen[e] {
				return fail(fmt.Sprintf("egressAdditions.%s[%d]", app, i), "duplicate %q", e)
			}
			seen[e] = true
		}
	}
	if total > MaxEgressAdditionsTotal {
		return fail("egressAdditions", "%d entries, at most %d in total", total, MaxEgressAdditionsTotal)
	}
	for field, val := range map[string]string{
		"endpoints.keyBroker": c.Endpoints.KeyBroker, "endpoints.platformApi": c.Endpoints.PlatformAPI,
		"endpoints.tempoRpc": c.Endpoints.TempoRPC,
	} {
		if _, err := endpointHostPort(field, val); err != nil {
			return fmt.Errorf("config: %v", err)
		}
	}
	for field, val := range map[string]string{"endpoints.relay": c.Endpoints.Relay, "endpoints.relayAttest": c.Endpoints.RelayAttest} {
		if val == "" {
			continue
		}
		if _, err := endpointHostPort(field, val); err != nil {
			return fmt.Errorf("config: %v", err)
		}
	}
	s := c.Settlement
	if s.Mode != "access-key" && s.Mode != "enclave-account" {
		return fail("settlement.mode", "must be access-key or enclave-account")
	}
	if s.IntervalMinutes <= 0 || s.GracePeriodMinutes < 0 {
		return fail("settlement", "intervalMinutes must be positive and gracePeriodMinutes non-negative")
	}
	if !decimalRe.MatchString(s.SpendLimitPerDay) {
		return fail("settlement.spendLimitPerDay", "must be a decimal string of base units")
	}
	return nil
}

func (c *Config) validateHostnames() error {
	h := c.Hostnames
	switch h.Scheme {
	case SchemeSslip:
		addr, err := netip.ParseAddr(h.IP)
		if err != nil || !addr.Is4() || addr.String() != h.IP {
			return fmt.Errorf("config: hostnames.ip: %q must be an IPv4 address", h.IP)
		}
		if len(h.Domains) > 0 {
			return fmt.Errorf("config: hostnames.domains: only allowed with scheme custom")
		}
	case SchemeCustom:
		if h.IP != "" {
			if addr, err := netip.ParseAddr(h.IP); err != nil || !addr.Is4() || addr.String() != h.IP {
				return fmt.Errorf("config: hostnames.ip: %q must be an IPv4 address", h.IP)
			}
		}
		seen := map[string]string{}
		for _, route := range sortedKeys(h.Domains) {
			d := h.Domains[route]
			if !routeNames[route] {
				return fmt.Errorf("config: hostnames.domains: unknown route %q", route)
			}
			hp, err := ParseHostPort(d + ":443")
			if err != nil || hp.IP || hp.Wildcard {
				return fmt.Errorf("config: hostnames.domains.%s: %q must be a lowercase DNS name", route, d)
			}
			if other, dup := seen[d]; dup {
				return fmt.Errorf("config: hostnames.domains: %q is used by both %s and %s", d, other, route)
			}
			seen[d] = route
		}
	default:
		return fmt.Errorf("config: hostnames.scheme: must be sslip or custom")
	}
	return nil
}

// routeNames are the Caddy routes a stack can expose (manifest route names plus attest).
var routeNames = map[string]bool{"gateway": true, "scraper": true, "crm": true, "code": true, "tools": true, "relay": true, "attest": true}

// Hostname returns the public hostname for a route.
func (c *Config) Hostname(route string) (string, error) {
	switch c.Hostnames.Scheme {
	case SchemeSslip:
		return route + "." + strings.ReplaceAll(c.Hostnames.IP, ".", "-") + ".sslip.io", nil
	case SchemeCustom:
		d, ok := c.Hostnames.Domains[route]
		if !ok {
			return "", fmt.Errorf("config: hostnames.domains: route %q has no domain", route)
		}
		return d, nil
	}
	return "", fmt.Errorf("config: hostnames.scheme: unknown scheme %q", c.Hostnames.Scheme)
}

// AppIDs returns the config's app ids in order.
func (c *Config) AppIDs() []string {
	ids := make([]string, len(c.Apps))
	for i, a := range c.Apps {
		ids[i] = a.ID
	}
	return ids
}

// lastAddr is the highest address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= ^uint32(0) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// sortedStrings returns a sorted copy without duplicates.
func sortedStrings(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
