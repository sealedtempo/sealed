// Package lint checks catalog apps and release bundles against the catalog
// rules: schema and fragment rules (via the composer), the license policy of
// rule 9 and D-021, digest-pinned and built images, telemetry and egress
// settings, license exclusions for open-core upstreams, service naming,
// declared secrets, and SBOM package licenses. CI and the sealed CLI use it.
package lint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sealedtempo/sealed/runtime/composer"
	"go.yaml.in/yaml/v3"
)

// Severity of a finding. Errors block a release; warnings need a look.
type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

// Finding is one lint result.
type Finding struct {
	Severity Severity `json:"severity"`
	App      string   `json:"app"`
	File     string   `json:"file,omitempty"`
	Field    string   `json:"field,omitempty"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

func (f Finding) String() string {
	loc := f.App
	if f.File != "" {
		loc += "/" + f.File
	}
	if f.Field != "" {
		loc += " " + f.Field
	}
	return fmt.Sprintf("%s: %s [%s] %s", f.Severity, loc, f.Code, f.Message)
}

// Finding codes.
const (
	CodeManifest     = "manifest"
	CodeFragment     = "fragment"
	CodeEgress       = "egress"
	CodeLicense      = "license"
	CodeLicenseNote  = "license-election"
	CodeUnbuiltImage = "unbuilt-image"
	CodeImageSource  = "image-source"
	CodeUnusedImage  = "unused-image"
	CodeRegistry     = "registry"
	CodeTelemetry    = "telemetry"
	CodeExclusions   = "license-exclusions"
	CodeSecretUnused = "secret-unused"
	CodeSecretInEnv  = "secret-in-env"
	CodeSBOMMissing  = "sbom-missing"
	CodeSBOMInvalid  = "sbom-invalid"
	CodeSBOMLicense  = "sbom-license"
	CodeExcludedPath = "excluded-path"
	CodeMissingFile  = "missing-file"
	CodeDuplicateApp = "duplicate-app"
	CodeSharedRoute  = "shared-route"
	// Added with composer 1.2.0.
	CodeLicenseException = "license-exception"
	CodeExempt           = "license-exempt"
	CodeWaivers          = "waivers"
	CodeBootstrap        = "bootstrap"
	CodeReleaseVersion   = "release-version"
	CodeSameAs           = "same-as"
	// Added with the license audit fixes (F5).
	CodeSBOMNoLicense = "sbom-no-license"
	CodeOverrides     = "license-overrides"
)

// WaiversFile is the per-app Grype waiver list (spec 6.8).
const WaiversFile = "waivers.yaml"

// Options tune the policy. The zero value uses the defaults.
type Options struct {
	// OpenCoreRepos are upstream repository URLs (case-insensitive prefixes)
	// whose apps must declare license_exclusions.
	OpenCoreRepos []string
	// EnterprisePatterns are package names or paths that must never ship
	// (D-021), checked against SBOM packages and files in addition to each
	// app's license_exclusions, with the same glob rules (glob.go). Unlike
	// license_exclusions they are not applied to OS distribution packages
	// or to files only OS packages own.
	EnterprisePatterns []string
	// Overrides are the reviewed license overrides for SBOM packages. nil
	// means the embedded list (OverridesFile); an empty slice means none.
	Overrides []LicenseOverride
	// Registry is catalog.registry. Every resolved image ref in a bundle must
	// be exactly <Registry>/<name>@<digest>. Defaults to the registry of the
	// composer's runtime images, which is the registry stacks pull from.
	Registry string
	// RequireSBOM turns a missing SBOM into an error and an unrecognized
	// SBOM package license into an error (release builds).
	RequireSBOM bool
	// Now is the clock for waiver expiry; nil means time.Now.
	Now func() time.Time

	overrides    *overrideSet
	overridesErr error
}

// DefaultOpenCoreRepos lists upstreams with enterprise-licensed code.
var DefaultOpenCoreRepos = []string{
	"https://github.com/berriai/litellm",
	"https://github.com/twentyhq/twenty",
	"https://github.com/appsmithorg/appsmith",
	"https://github.com/all-hands-ai/openhands",
	"https://github.com/openhands/openhands",
	// ToolJet keeps enterprise code in ee/ submodules (server/ee, frontend/ee);
	// opencode has packages/enterprise (license audit F7).
	"https://github.com/tooljet/tooljet",
	"https://github.com/anomalyco/opencode",
}

// DefaultEnterprisePatterns are the D-021 hard-fail paths, as globs: the
// litellm_enterprise module and its dist-info, any enterprise/ or ee/
// directory (a whole path segment, so tree/ and free/ do not match; ee/ is
// the usual open-core layout, ToolJet's server/ee among them, license audit
// F7) and the Claude Agent SDK packages.
var DefaultEnterprisePatterns = []string{"litellm_enterprise*", "enterprise/", "ee/", "@anthropic-ai/claude-agent-sdk*"}

func (o Options) withDefaults() Options {
	if o.OpenCoreRepos == nil {
		o.OpenCoreRepos = DefaultOpenCoreRepos
	}
	if o.EnterprisePatterns == nil {
		o.EnterprisePatterns = DefaultEnterprisePatterns
	}
	if o.Registry == "" {
		if ri, err := composer.LoadRuntimeImages(); err == nil {
			o.Registry = ri.Registry
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	list, err := o.Overrides, error(nil)
	if list == nil {
		list, err = DefaultLicenseOverrides()
	}
	if err == nil {
		o.overrides, err = newOverrideSet(list)
	}
	if err != nil {
		o.overridesErr = err
		o.overrides = nil
	}
	return o
}

// HasErrors reports whether any finding is an error.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

type collector struct {
	app string
	out []Finding
}

func (c *collector) add(sev Severity, file, field, code, format string, args ...any) {
	c.out = append(c.out, Finding{Severity: sev, App: c.app, File: file, Field: field, Code: code, Message: fmt.Sprintf(format, args...)})
}

// LintApp checks a catalog source directory (catalog/apps/<id>).
func LintApp(dir string, opts Options) []Finding {
	opts = opts.withDefaults()
	c := &collector{app: filepath.Base(dir)}
	files := map[string][]byte{}
	for _, name := range []string{composer.ManifestFile, composer.FragmentFile, composer.EgressFile} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			code := CodeManifest
			if name == composer.EgressFile {
				code = CodeEgress
			}
			if name == composer.FragmentFile {
				code = CodeFragment
			}
			c.add(Error, name, "", code, "%s is missing", name)
			continue
		}
		files[name] = composer.NormalizeText(b)
	}
	for _, name := range []string{"README.md", "LICENSE-NOTICE"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			c.add(Warning, name, "", CodeMissingFile, "%s is missing", name)
		}
	}
	sboms := map[string][]byte{}
	if entries, err := os.ReadDir(filepath.Join(dir, "sbom")); err == nil {
		for _, e := range entries {
			if name, ok := strings.CutSuffix(e.Name(), ".spdx.json"); ok {
				if b, err := os.ReadFile(filepath.Join(dir, "sbom", e.Name())); err == nil {
					sboms[name] = b
				}
			}
		}
	}
	lintFiles(c, files, sboms, false, opts)
	if raw, err := os.ReadFile(filepath.Join(dir, WaiversFile)); err == nil {
		lintWaivers(c, raw, files[composer.ManifestFile], opts.Now())
	}
	sortFindings(c.out)
	return c.out
}

// LintBundle checks a loaded release bundle, including its resolved image
// refs and the SBOMs it carries.
func LintBundle(b *composer.Bundle, opts Options) []Finding {
	opts = opts.withDefaults()
	c := &collector{app: b.Manifest.ID}
	files := map[string][]byte{}
	sboms := map[string][]byte{}
	for name, data := range b.Files {
		if img, ok := strings.CutPrefix(name, "sbom/"); ok {
			sboms[strings.TrimSuffix(img, ".spdx.json")] = data
			continue
		}
		files[name] = data
	}
	lintFiles(c, files, sboms, true, opts)
	return c.out
}

// LintCatalog lints every app directory under root (catalog/apps) and the
// cross-app rules: unique ids and route names shared between apps.
func LintCatalog(root string, opts Options) ([]Finding, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []Finding
	routes := map[string][]string{}
	ids := map[string]string{}
	manifests := map[string]*composer.Manifest{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, e.Name())
		out = append(out, LintApp(dir, opts)...)
		raw, err := os.ReadFile(filepath.Join(dir, composer.ManifestFile))
		if err != nil {
			continue
		}
		m, err := composer.ParseManifest(raw)
		if err != nil {
			continue
		}
		if m.ID != e.Name() {
			out = append(out, Finding{Severity: Error, App: e.Name(), File: composer.ManifestFile, Field: "id", Code: CodeManifest,
				Message: fmt.Sprintf("id %q must match the directory name %q", m.ID, e.Name())})
		}
		if prev, dup := ids[m.ID]; dup {
			out = append(out, Finding{Severity: Error, App: m.ID, Code: CodeDuplicateApp, Message: "id also used by " + prev})
		}
		ids[m.ID] = e.Name()
		manifests[m.ID] = m
		seen := map[string]bool{}
		for _, r := range m.Routes {
			if !seen[r.Name] {
				routes[r.Name] = append(routes[r.Name], m.ID)
				seen[r.Name] = true
			}
		}
	}
	for _, name := range sortedKeys(routes) {
		if apps := routes[name]; len(apps) > 1 {
			out = append(out, Finding{Severity: Warning, App: strings.Join(apps, ","), Code: CodeSharedRoute,
				Message: fmt.Sprintf("route %q is used by %s; they cannot be deployed in the same stack", name, strings.Join(apps, " and "))})
		}
	}
	out = append(out, lintSameAs(manifests)...)
	return out, nil
}

// lintSameAs checks cross-app secret references (D-043) against the
// catalog: the referenced app exists and declares the secret, which is not
// itself a reference and lists the referencing app in share_with (D-059), as
// Compose and sealed secrets require. Compose repeats the check for each
// stack. A share_with entry that names no catalog app is a warning: it shares
// with nobody today, and is most likely a typo.
func lintSameAs(manifests map[string]*composer.Manifest) []Finding {
	var out []Finding
	for _, id := range sortedKeys(manifests) {
		for i, s := range manifests[id].Secrets {
			for j, peer := range s.ShareWith {
				if _, ok := manifests[peer]; !ok {
					out = append(out, Finding{Severity: Warning, App: id, File: composer.ManifestFile, Field: fmt.Sprintf("secrets[%d].share_with[%d]", i, j),
						Code: CodeSameAs, Message: fmt.Sprintf("%s is shared with %q, which is not a catalog app", s.Name, peer)})
				}
			}
			app, name, ok := s.SameAsRef()
			if !ok {
				continue
			}
			add := func(format string, args ...any) {
				out = append(out, Finding{Severity: Error, App: id, File: composer.ManifestFile, Field: fmt.Sprintf("secrets[%d].same_as", i),
					Code: CodeSameAs, Message: fmt.Sprintf(format, args...)})
			}
			target, ok := manifests[app]
			if !ok {
				add("%q: no catalog app %q", s.SameAs, app)
				continue
			}
			ref, ok := target.Secret(name)
			switch {
			case !ok:
				add("%q: app %q declares no secret %q", s.SameAs, app, name)
			case ref.SameAs != "":
				add("%q is itself a reference (same_as %q)", s.SameAs, ref.SameAs)
			case !ref.SharedWith(id):
				add("%q: %s does not share %s with %s (its share_with must list %q, D-059)", s.SameAs, app, name, id, id)
			case ref.Optional && !s.Optional:
				add("%q is optional in %s, but %s is required", s.SameAs, app, s.Name)
			}
		}
	}
	return out
}

func lintFiles(c *collector, files map[string][]byte, sboms map[string][]byte, isBundle bool, opts Options) {
	raw, ok := files[composer.ManifestFile]
	if !ok {
		return
	}
	m, err := composer.ParseManifest(raw)
	if err != nil {
		var me *composer.ManifestError
		field := ""
		if errors.As(err, &me) {
			field = me.Field
		}
		c.add(Error, composer.ManifestFile, field, CodeManifest, "%v", err)
		return
	}
	c.app = m.ID

	var frag *composer.Fragment
	if fb, ok := files[composer.FragmentFile]; ok {
		frag, err = composer.ParseFragment(m, fb)
		if err != nil {
			var fe *composer.FragmentError
			field := ""
			if errors.As(err, &fe) {
				field = strings.Trim(fe.Service+" "+fe.Key, " ")
			}
			c.add(Error, composer.FragmentFile, field, CodeFragment, "%v", err)
		}
	}
	if eb, ok := files[composer.EgressFile]; ok {
		p, _, err := composer.ParseEgressPolicy(eb)
		switch {
		case err != nil:
			c.add(Error, composer.EgressFile, "", CodeEgress, "%v", err)
		case strings.TrimSpace(p.Notes) == "":
			c.add(Warning, composer.EgressFile, "notes", CodeEgress, "explain why each entry exists")
		}
	}

	if err := composer.CheckReleaseVersion(m.Version()); err != nil {
		field := "release_version"
		if m.ReleaseVersion == "" {
			field = "upstream.version"
		}
		c.add(Error, composer.ManifestFile, field, CodeReleaseVersion, "%v (D-046 release assets)", err)
	}
	if m.Bootstrap != nil && strings.HasPrefix(m.Bootstrap.DoneFile, "/") {
		hint := ""
		if frag != nil {
			if p, err := composer.ResolveDoneFile(m, frag); err == nil {
				hint = fmt.Sprintf(" (here %q)", strings.TrimPrefix(p, composer.DataRoot+"/"+m.ID+"/"))
			}
		}
		c.add(Warning, composer.ManifestFile, "bootstrap.done_file", CodeBootstrap,
			"write done_file as <volume>/<path> relative to %s/%s/%s; the in-container absolute form is deprecated", composer.DataRoot, m.ID, hint)
	}
	exempt := checkExceptions(c, m)
	patterns := checkExclusions(c, m, opts.EnterprisePatterns)
	if opts.overridesErr != nil {
		c.add(Error, OverridesFile, "", CodeOverrides, "%v", opts.overridesErr)
	}

	checkLicense(c, composer.ManifestFile, "upstream.license_spdx", m.Upstream.LicenseSPDX)
	used := map[string]bool{}
	if frag != nil {
		for _, s := range frag.Services {
			used[s.Image] = true
		}
	}
	for i, img := range m.Images {
		field := fmt.Sprintf("images[%d]", i)
		checkLicense(c, composer.ManifestFile, field+".license_spdx", img.LicenseSPDX)
		if img.Unbuilt() {
			c.add(Error, composer.ManifestFile, field+".digest", CodeUnbuiltImage,
				"image %q has the all-zero placeholder digest: build it with the runtime image workflow and pin the digest before release", img.Name)
		}
		if !strings.HasPrefix(img.Source, "build:") && !imageSourceRe.MatchString(img.Source) {
			c.add(Warning, composer.ManifestFile, field+".source", CodeImageSource,
				"source %q should name the upstream image with a tag (or build:<dir>)", img.Source)
		}
		if frag != nil && !used[img.Name] {
			c.add(Warning, composer.ManifestFile, field, CodeUnusedImage, "image %q is not used by any fragment service", img.Name)
		}
		if want := opts.Registry + "/" + img.Name + "@" + img.Digest; isBundle && img.Ref != want {
			c.add(Error, composer.ManifestFile, field+".ref", CodeRegistry, "ref %q is not %q; VMs pull only from the catalog registry", img.Ref, want)
		}
		sbom, ok := sboms[img.Name]
		switch {
		case !ok && (isBundle || opts.RequireSBOM):
			c.add(Error, "sbom/"+img.Name+".spdx.json", "", CodeSBOMMissing, "image %q has no SBOM", img.Name)
		case !ok:
			c.add(Warning, "sbom/"+img.Name+".spdx.json", "", CodeSBOMMissing, "image %q has no SBOM yet (CI generates it with syft)", img.Name)
		default:
			lintSBOM(c, img.Name, sbom, patterns, exempt, opts.overrides, isBundle || opts.RequireSBOM)
		}
	}

	switch {
	case len(m.TelemetryOffEnv) == 0 && m.TelemetryNone == "":
		c.add(Error, composer.ManifestFile, "telemetry_off_env", CodeTelemetry,
			"empty: list the variables that disable telemetry and update checks (spec 5.3, 6.8), or set telemetry_none_reason to say why the app needs none")
	case len(m.TelemetryOffEnv) == 0 && len(strings.TrimSpace(m.TelemetryNone)) < 20:
		c.add(Error, composer.ManifestFile, "telemetry_none_reason", CodeTelemetry,
			"too short to review: say what was checked (upstream source, update checks, crash reporting)")
	case len(m.TelemetryOffEnv) > 0 && m.TelemetryNone != "":
		c.add(Warning, composer.ManifestFile, "telemetry_none_reason", CodeTelemetry,
			"set together with telemetry_off_env; keep only one")
	}
	if isOpenCore(m.Upstream.Repo, opts.OpenCoreRepos) && len(m.LicenseExclusions) == 0 {
		c.add(Error, composer.ManifestFile, "license_exclusions", CodeExclusions,
			"%s is open core: list the enterprise paths that are never shipped", m.Upstream.Repo)
	}

	if frag != nil {
		usedSecrets := map[string]bool{}
		for _, s := range frag.Services {
			for _, n := range s.Secrets {
				usedSecrets[n] = true
			}
			for _, k := range sortedKeys(s.Environment) {
				v := s.Environment[k]
				if secretNameRe.MatchString(k) && v != "" && !strings.HasPrefix(v, "/") {
					c.add(Warning, composer.FragmentFile, s.Name+" environment."+k, CodeSecretInEnv,
						"looks like a secret with a literal value; declare it in secrets and use x-sealed-secrets")
				}
			}
		}
		for i, s := range m.Secrets {
			if !usedSecrets[s.Name] {
				c.add(Warning, composer.ManifestFile, fmt.Sprintf("secrets[%d]", i), CodeSecretUnused,
					"secret %q is declared but no service lists it in x-sealed-secrets", s.Name)
			}
		}
	}
	for _, e := range exempt {
		if !e.used {
			c.add(Warning, composer.ManifestFile, "license_exceptions", CodeLicenseException,
				"path %q (%s) matched no SBOM package or file; remove it", e.path, e.decision)
		}
	}
	sortFindings(c.out)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity == Error && fs[j].Severity != Error })
}

// exemption is one accepted license_exceptions path.
type exemption struct {
	decision, path string
	pattern        *pathPattern
	used           bool
}

// checkExceptions validates license_exceptions (integration brief item 17)
// and returns the paths lint honours: only entries whose decision is in
// acceptedExceptionDecisions (empty today), every other entry is an error.
func checkExceptions(c *collector, m *composer.Manifest) []*exemption {
	var out []*exemption
	for i, e := range m.LicenseExceptions {
		field := fmt.Sprintf("license_exceptions[%d]", i)
		if !acceptedExceptionDecisions[e.Decision] {
			accepted := "none"
			if ids := AcceptedExceptionDecisions(); len(ids) > 0 {
				accepted = strings.Join(ids, ", ")
			}
			c.add(Error, composer.ManifestFile, field+".decision", CodeLicenseException,
				"%s is not an accepted license exception (runtime/composer/lint/exceptions.go accepts: %s)", e.Decision, accepted)
			continue
		}
		for j, p := range e.Paths {
			pat, err := compilePattern(p, false)
			if err != nil || pat.note {
				if err == nil {
					err = fmt.Errorf("%q names an upstream source path, not an image path", p)
				}
				c.add(Error, composer.ManifestFile, fmt.Sprintf("%s.paths[%d]", field, j), CodeLicenseException, "%v", err)
				continue
			}
			out = append(out, &exemption{decision: e.Decision, path: p, pattern: pat})
		}
	}
	return out
}

// checkExclusions compiles license_exclusions and the policy patterns
// (glob.go). A pattern that does not compile is an error.
func checkExclusions(c *collector, m *composer.Manifest, policy []string) []*pathPattern {
	var out []*pathPattern
	for i, raw := range m.LicenseExclusions {
		p, err := compilePattern(raw, false)
		if err != nil {
			c.add(Error, composer.ManifestFile, fmt.Sprintf("license_exclusions[%d]", i), CodeExclusions, "%v", err)
			continue
		}
		out = append(out, p)
	}
	for _, raw := range policy {
		p, err := compilePattern(raw, true)
		if err != nil {
			c.add(Error, "", "", CodeExclusions, "enterprise pattern: %v", err)
			continue
		}
		out = append(out, p)
	}
	return out
}

// exemptedPackage returns the exemption that covers a package.
func exemptedPackage(exempt []*exemption, name string, files []string) *exemption {
	for _, e := range exempt {
		if e.pattern.matchPackage(name, files) {
			e.used = true
			return e
		}
	}
	return nil
}

// exemptedFile returns the exemption that covers a file path.
func exemptedFile(exempt []*exemption, file string) *exemption {
	for _, e := range exempt {
		if e.pattern.matchFile(file) != "" {
			e.used = true
			return e
		}
	}
	return nil
}

// lintWaivers checks waivers.yaml (spec 6.8): either a list of waivers or
// {version: 1, waivers: [...]}; each waiver names a vulnerability id, a
// manifest image, a package, a reason and an expiry date that has not passed.
func lintWaivers(c *collector, raw, manifest []byte, now time.Time) {
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		c.add(Error, WaiversFile, "", CodeWaivers, "not valid YAML: %v", err)
		return
	}
	var list []any
	switch t := doc.(type) {
	case nil:
	case []any:
		list = t
	case map[string]any:
		for k := range t {
			if k != "version" && k != "waivers" {
				c.add(Error, WaiversFile, k, CodeWaivers, "unknown key %q", k)
			}
		}
		if v, ok := t["version"].(int); !ok || v != 1 {
			c.add(Error, WaiversFile, "version", CodeWaivers, "version must be 1")
		}
		l, ok := t["waivers"].([]any)
		if !ok && t["waivers"] != nil {
			c.add(Error, WaiversFile, "waivers", CodeWaivers, "waivers must be a list")
			return
		}
		list = l
	default:
		c.add(Error, WaiversFile, "", CodeWaivers, "must be a list of waivers or {version: 1, waivers: [...]}")
		return
	}
	images := map[string]bool{}
	if m, err := composer.ParseManifest(manifest); err == nil {
		for _, img := range m.Images {
			images[img.Name] = true
		}
	}
	today := now.UTC().Format("2006-01-02")
	for i, e := range list {
		field := fmt.Sprintf("waivers[%d]", i)
		w, ok := e.(map[string]any)
		if !ok {
			c.add(Error, WaiversFile, field, CodeWaivers, "must be a mapping")
			continue
		}
		for _, k := range sortedKeys(w) {
			switch k {
			case "id", "image", "package", "reason", "expires":
			default:
				c.add(Error, WaiversFile, field+"."+k, CodeWaivers, "unknown key %q", k)
			}
		}
		str := func(k string) string {
			s, _ := w[k].(string)
			return strings.TrimSpace(s)
		}
		if !vulnIDRe.MatchString(str("id")) {
			c.add(Error, WaiversFile, field+".id", CodeWaivers, "id %q must be a CVE or GHSA id", str("id"))
		}
		if img := str("image"); !images[img] {
			c.add(Error, WaiversFile, field+".image", CodeWaivers, "image %q is not a manifest image", img)
		}
		if str("package") == "" {
			c.add(Error, WaiversFile, field+".package", CodeWaivers, "package is required")
		}
		if len(str("reason")) < 10 {
			c.add(Error, WaiversFile, field+".reason", CodeWaivers, "say why the finding does not apply or what blocks the fix")
		}
		var expires string
		switch v := w["expires"].(type) {
		case time.Time:
			expires = v.UTC().Format("2006-01-02")
		case string:
			if d, err := time.Parse("2006-01-02", v); err == nil {
				expires = d.Format("2006-01-02")
			}
		}
		switch {
		case expires == "":
			c.add(Error, WaiversFile, field+".expires", CodeWaivers, "expires must be a date (YYYY-MM-DD)")
		case expires < today:
			c.add(Error, WaiversFile, field+".expires", CodeWaivers, "waiver for %s expired on %s", str("id"), expires)
		}
	}
}

var vulnIDRe = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)

var (
	imageSourceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})(@sha256:[0-9a-f]{64})?$`)
	secretNameRe  = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)$`)
)

func isOpenCore(repo string, list []string) bool {
	r := strings.TrimSuffix(strings.ToLower(repo), "/")
	r = strings.TrimSuffix(r, ".git")
	for _, p := range list {
		p = strings.TrimSuffix(strings.ToLower(p), "/")
		if r == p || strings.HasPrefix(r, p+"/") {
			return true
		}
	}
	return false
}

func checkLicense(c *collector, file, field, expr string) {
	r := EvaluateLicense(expr)
	switch r.Status {
	case Allowed:
		if len(r.Banned) > 0 {
			c.add(Warning, file, field, CodeLicenseNote, "%q offers banned alternatives (%s); it is used under %s, record that election in LICENSE-NOTICE",
				expr, strings.Join(r.Banned, ", "), r.Elected)
		}
	case SystemOnly:
		c.add(Error, file, field, CodeLicense, "%q is only acceptable for OS base-image packages, not for app code (rule 9, D-021)", expr)
	case FontOnly:
		c.add(Error, file, field, CodeLicense, "%q is only acceptable for fonts, not for app code (D-056)", expr)
	case DataOnly:
		c.add(Error, file, field, CodeLicense, "%q is only acceptable for data-only packages, not for app code (D-050)", expr)
	case Unknown:
		c.add(Error, file, field, CodeLicense, "%q is not on the license allowlist (rule 9, D-021)", expr)
	case Banned:
		c.add(Error, file, field, CodeLicense, "%q is banned (rule 9, D-021)", expr)
	}
}

type spdxDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		SourceInfo       string `json:"sourceInfo"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		ExternalRefs     []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Files []struct {
		SPDXID   string `json:"SPDXID"`
		FileName string `json:"fileName"`
	} `json:"files"`
	Relationships []struct {
		Element string `json:"spdxElementId"`
		Related string `json:"relatedSpdxElement"`
		Type    string `json:"relationshipType"`
	} `json:"relationships"`
	ExtractedLicenses []struct {
		LicenseID string   `json:"licenseId"`
		Name      string   `json:"name"`
		SeeAlsos  []string `json:"seeAlsos"`
	} `json:"hasExtractedLicensingInfos"`
}

// osPackageTypes are purl types of distribution packages (D-021 system components).
var osPackageTypes = []string{"pkg:deb/", "pkg:apk/", "pkg:rpm/", "pkg:alpm/"}

// rootPackageTypes are purl types of the scanned artifact itself, which syft
// lists as the document root package without a license.
var rootPackageTypes = []string{"pkg:oci/", "pkg:docker/"}

var noticeFileRe = regexp.MustCompile(`(?i)^NOTICE(\.(txt|md))?$`)

// noticeRefs returns the LicenseRef ids syft creates for license-like files
// it could not identify when every such file is a NOTICE file (for example
// the Apache-2.0 NOTICE of the Prometheus Go modules, scanned with
// --enrich golang). A NOTICE file is an attribution notice, not a license,
// so these ids are dropped from expressions. A LicenseRef for an
// unidentified LICENSE or COPYING file stays and needs review.
func noticeRefs(doc *spdxDoc) map[string]bool {
	out := map[string]bool{}
	for _, e := range doc.ExtractedLicenses {
		if !strings.HasPrefix(e.LicenseID, "LicenseRef-") || len(e.SeeAlsos) == 0 {
			continue
		}
		all := true
		for _, s := range e.SeeAlsos {
			if !noticeFileRe.MatchString(path.Base(strings.TrimPrefix(s, "file://"))) {
				all = false
			}
		}
		if all {
			out[e.LicenseID] = true
		}
	}
	return out
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// fileGroup collects the files under one excluded path.
type fileGroup struct {
	patterns []string
	files    map[string]bool
	example  string
}

// lintSBOM checks an SPDX JSON SBOM (as syft writes it): package licenses
// against the policy after the reviewed overrides, packages without license
// metadata, and packages and files that match an excluded path.
//
// Licenses: OS packages may use system-only and font licenses; an
// unrecognized license fails a release for non-OS packages and is a warning
// for OS packages until a decision covers it. A package with no license
// metadata and no override is an error in release mode for non-OS packages
// (license audit F5), a warning otherwise; OS packages without metadata get
// one warning per SBOM.
//
// Excluded paths: every pattern is checked against package names, the files
// in each package's sourceInfo and every file the SBOM lists (directories
// with entries below them are skipped, since their files are checked), and
// the files under one excluded directory are reported once. syft lists only
// files that a package owns unless file.metadata.selection is "all", which
// the release scan needs for paths no package owns (license audit F6).
func lintSBOM(c *collector, image string, raw []byte, patterns []*pathPattern, exempt []*exemption, overrides *overrideSet, release bool) {
	file := "sbom/" + image + ".spdx.json"
	var doc spdxDoc
	if err := json.Unmarshal(raw, &doc); err != nil || !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		c.add(Error, file, "", CodeSBOMInvalid, "not an SPDX JSON document")
		return
	}
	notices := noticeRefs(&doc)
	osPkgs := map[string]bool{}
	var osMissing []string
	for _, p := range doc.Packages {
		pkg := p.Name
		if p.VersionInfo != "" {
			pkg += "@" + p.VersionInfo
		}
		var purls []string
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" {
				purls = append(purls, ref.ReferenceLocator)
			}
		}
		isOS, isRoot := false, strings.HasPrefix(p.SPDXID, "SPDXRef-DocumentRoot-")
		for _, u := range purls {
			isOS = isOS || hasPrefixAny(u, osPackageTypes)
			isRoot = isRoot || hasPrefixAny(u, rootPackageTypes)
		}
		if isRoot {
			continue
		}
		if isOS {
			osPkgs[p.SPDXID] = true
		}
		sources := sourcePaths(p.SourceInfo)
		if e := exemptedPackage(exempt, p.Name, sources); e != nil {
			c.add(Warning, file, pkg, CodeExempt, "exempt from license and excluded-path checks under %s (license_exceptions %q)", e.decision, e.path)
			continue
		}
		for _, pat := range patterns {
			if pat.note || (pat.policy && isOS) {
				continue
			}
			if pat.matchPackage(p.Name, sources) {
				c.add(Error, file, pkg, CodeExcludedPath, "package matches excluded path %q", pat.raw)
			}
		}

		scanned := p.LicenseConcluded
		if scanned == "" || scanned == "NOASSERTION" || scanned == "NONE" {
			scanned = p.LicenseDeclared
		}
		if scanned == "NOASSERTION" || scanned == "NONE" {
			scanned = ""
		}
		scanned = pruneLicenseRefs(scanned, notices)
		expr, extra, via := scanned, map[string]bool(nil), ""
		if o := overrides.lookup(purls); o != nil {
			if scanned != "" && EvaluateLicense(scanned).Status == Banned {
				c.add(Error, file, pkg, CodeSBOMLicense, "license %q is banned; the override %s (%q) does not apply to a banned license: review the package again", scanned, o.PURL, o.License)
				continue
			}
			expr, extra, via = o.License, o.allow, " (reviewed override)"
		}
		if expr == "" {
			switch {
			case isOS:
				osMissing = append(osMissing, pkg)
			case release:
				c.add(Error, file, pkg, CodeSBOMNoLicense, "no license metadata: read the license at this version and add a reviewed entry to %s (license audit F5)", OverridesFile)
			default:
				c.add(Warning, file, pkg, CodeSBOMNoLicense, "no license metadata (an error in release builds): read the license at this version and add a reviewed entry to %s", OverridesFile)
			}
			continue
		}
		r := evaluateLicense(expr, extra)
		switch {
		case r.Status == Banned:
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q%s is banned", expr, via)
		case r.Status == SystemOnly && !isOS:
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q%s is only acceptable for OS packages", expr, via)
		case r.Status == FontOnly && !isOS && !isFontPackage(p.Name):
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q%s is only acceptable for the font packages %s and OS packages (D-056)", expr, via, strings.Join(FontPackages, ", "))
		case r.Status == DataOnly && !isDataOnlyPackage(p.Name):
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q%s is only acceptable for the data-only packages %s (D-050)", expr, via, strings.Join(DataOnlyPackages, ", "))
		case r.Status == Unknown && !isOS && release:
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q%s is not on the allowlist (rule 9, D-021)", expr, via)
		case r.Status == Unknown && isOS:
			c.add(Warning, file, pkg, CodeSBOMLicense, "OS package license %q is not OSI-approved or not recognized; it needs a recorded decision (D-021)", expr)
		case r.Status == Unknown:
			c.add(Warning, file, pkg, CodeSBOMLicense, "license %q%s needs review (an error in release builds)", expr, via)
		}
	}
	if len(osMissing) > 0 {
		sort.Strings(osMissing)
		c.add(Warning, file, "", CodeSBOMNoLicense, "%d OS packages have no license metadata (D-021 system components; check their copyright files or add reviewed overrides): %s",
			len(osMissing), strings.Join(osMissing, ", "))
	}

	// Files: owners (CONTAINS relationships) and directories with entries below them.
	owners := map[string][]string{}
	for _, r := range doc.Relationships {
		if r.Type == "CONTAINS" {
			owners[r.Related] = append(owners[r.Related], r.Element)
		}
	}
	names := make([]string, len(doc.Files))
	dirs := map[string]bool{}
	for i, f := range doc.Files {
		n := cleanPath(f.FileName)
		names[i] = n
		for j := 0; j < len(n); j++ {
			if n[j] == '/' {
				dirs[n[:j]] = true
			}
		}
	}
	matchers := make([]*fileMatcher, len(patterns))
	for i, pat := range patterns {
		matchers[i] = newFileMatcher(pat)
	}
	groups := map[string]*fileGroup{}
	for fi, f := range doc.Files {
		name := names[fi]
		if name == "" || dirs[name] {
			continue
		}
		if e := exemptedFile(exempt, name); e != nil {
			continue
		}
		osOwned := len(owners[f.SPDXID]) > 0
		for _, o := range owners[f.SPDXID] {
			osOwned = osOwned && osPkgs[o]
		}
		for i, pat := range patterns {
			if pat.note || (pat.policy && osOwned) {
				continue
			}
			root := matchers[i].match(name)
			if root == "" {
				continue
			}
			g := groups[root]
			if g == nil {
				g = &fileGroup{files: map[string]bool{}, example: name}
				groups[root] = g
			}
			g.files[name] = true
			if !slices.Contains(g.patterns, pat.raw) {
				g.patterns = append(g.patterns, pat.raw)
			}
		}
	}
	for _, root := range sortedKeys(groups) {
		g := groups[root]
		quoted := make([]string, len(g.patterns))
		for i, p := range g.patterns {
			quoted[i] = strconv.Quote(p)
		}
		what := "excluded path " + quoted[0]
		if len(quoted) > 1 {
			what = "excluded paths " + strings.Join(quoted, ", ")
		}
		switch {
		case len(g.files) == 1 && g.files[root]:
			c.add(Error, file, "/"+root, CodeExcludedPath, "file matches %s", what)
		case len(g.files) == 1:
			c.add(Error, file, "/"+root+"/", CodeExcludedPath, "1 file under this directory matches %s (/%s)", what, g.example)
		default:
			c.add(Error, file, "/"+root+"/", CodeExcludedPath, "%d files under this directory match %s (for example /%s)", len(g.files), what, g.example)
		}
	}
}

// isDataOnlyPackage reports whether a package is on the reviewed data-only list.
func isDataOnlyPackage(name string) bool {
	return slices.Contains(DataOnlyPackages, name)
}

// isFontPackage reports whether a package matches the reviewed font-only list.
func isFontPackage(name string) bool {
	for _, p := range FontPackages {
		if ok, _ := path.Match(p, strings.ToLower(name)); ok {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
