package lint

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

// OverridesFile is the reviewed override list embedded in this package. It
// lives next to the policy code so that every caller (CI, sealed-compose,
// the catalog tools) applies the same list and a change to it is reviewed
// like a policy change.
const OverridesFile = "runtime/composer/lint/license-overrides.yaml"

//go:embed license-overrides.yaml
var defaultOverridesYAML []byte

// LicenseOverride is one reviewed entry of license-overrides.yaml.
type LicenseOverride struct {
	PURL       string   `yaml:"purl"`
	AnyVersion bool     `yaml:"any_version,omitempty"`
	License    string   `yaml:"license"`
	Allow      []string `yaml:"allow,omitempty"`
	Reason     string   `yaml:"reason"`
	Evidence   string   `yaml:"evidence"`
	Reviewed   string   `yaml:"reviewed"`
}

type overridesDoc struct {
	Version   int               `yaml:"version"`
	Overrides []LicenseOverride `yaml:"overrides"`
}

// ParseLicenseOverrides parses and validates an override list
// ({version: 1, overrides: [...]}, unknown keys rejected).
func ParseLicenseOverrides(raw []byte) ([]LicenseOverride, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc overridesDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a valid override list: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("version must be 1")
	}
	if _, err := newOverrideSet(doc.Overrides); err != nil {
		return nil, err
	}
	return doc.Overrides, nil
}

var defaultOverrides = sync.OnceValues(func() ([]LicenseOverride, error) {
	return ParseLicenseOverrides(defaultOverridesYAML)
})

// DefaultLicenseOverrides returns the embedded reviewed overrides.
func DefaultLicenseOverrides() ([]LicenseOverride, error) { return defaultOverrides() }

type override struct {
	LicenseOverride
	allow map[string]bool
}

// overrideSet indexes overrides by canonical purl.
type overrideSet struct {
	exact map[string]*override // base@version
	any   map[string]*override // base, any_version entries
}

func newOverrideSet(list []LicenseOverride) (*overrideSet, error) {
	s := &overrideSet{exact: map[string]*override{}, any: map[string]*override{}}
	var errs []error
	for i, o := range list {
		bad := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("overrides[%d] (%s): %s", i, o.PURL, fmt.Sprintf(format, args...)))
		}
		base, version, ok := canonicalPURL(o.PURL)
		switch {
		case !ok:
			bad("purl must be a package URL (pkg:<type>/<name>@<version>)")
			continue
		case o.AnyVersion && version != "":
			bad("any_version needs a purl without a version")
		case !o.AnyVersion && version == "":
			bad("purl needs the exact version (or any_version: true for every version)")
		}
		ov := &override{LicenseOverride: o, allow: map[string]bool{}}
		n, err := parseSPDX(o.License)
		if err != nil {
			bad("license %q is not an SPDX expression: %v", o.License, err)
		} else {
			ids := map[string]bool{}
			n.licenseIDs(ids)
			for _, a := range o.Allow {
				switch {
				case isBanned(a):
					bad("allow: %s is banned and cannot be allowed", a)
				case allowedLicenses[a]:
					bad("allow: %s is already allowed everywhere", a)
				case !ids[a]:
					bad("allow: %s is not in the license expression", a)
				}
				ov.allow[a] = true
			}
			switch r := evaluateLicense(o.License, ov.allow); r.Status {
			case Banned:
				bad("license %q is banned", o.License)
			case Unknown:
				bad("license %q is not acceptable under the policy (add the reviewed ids to allow)", o.License)
			}
		}
		if len(strings.TrimSpace(o.Reason)) < 20 {
			bad("reason must say what was read and why (at least 20 characters)")
		}
		if u, err := url.Parse(o.Evidence); err != nil || u.Scheme != "https" || u.Host == "" {
			bad("evidence must be an https URL of the license at that version")
		}
		if _, err := time.Parse("2006-01-02", o.Reviewed); err != nil {
			bad("reviewed must be a date (YYYY-MM-DD)")
		}
		key, m := base+"@"+version, s.exact
		if o.AnyVersion {
			key, m = base, s.any
		}
		if _, dup := m[key]; dup {
			bad("duplicate entry")
		}
		m[key] = ov
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return s, nil
}

// lookup returns the override for any of a package's purls.
func (s *overrideSet) lookup(purls []string) *override {
	if s == nil {
		return nil
	}
	for _, p := range purls {
		base, version, ok := canonicalPURL(p)
		if !ok {
			continue
		}
		if o := s.exact[base+"@"+version]; o != nil && version != "" {
			return o
		}
		if o := s.any[base]; o != nil {
			return o
		}
	}
	return nil
}

// canonicalPURL splits a purl into a comparable base (pkg:type/namespace/name)
// and version: qualifiers and subpath dropped, percent-decoded, lower case,
// PyPI names with "_" and "." as "-".
func canonicalPURL(p string) (base, version string, ok bool) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "pkg:") {
		return "", "", false
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if d, err := url.PathUnescape(p); err == nil {
		p = d
	}
	p = strings.ToLower(p)
	if at := strings.LastIndex(p, "@"); at > strings.LastIndex(p, "/") {
		p, version = p[:at], p[at+1:]
	}
	typ, name, found := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	if !found || typ == "" || strings.Trim(name, "/") == "" {
		return "", "", false
	}
	if typ == "pypi" {
		name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	}
	return "pkg:" + typ + "/" + strings.Trim(name, "/"), version, true
}
