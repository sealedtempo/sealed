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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer"
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
)

// WaiversFile is the per-app Grype waiver list (spec 6.8).
const WaiversFile = "waivers.yaml"

// Options tune the policy. The zero value uses the defaults.
type Options struct {
	// OpenCoreRepos are upstream repository URLs (case-insensitive prefixes)
	// whose apps must declare license_exclusions.
	OpenCoreRepos []string
	// EnterprisePatterns are package names or paths that must never ship
	// (D-021), checked against SBOM packages in addition to each app's
	// license_exclusions.
	EnterprisePatterns []string
	// Registry is catalog.registry. Every resolved image ref in a bundle must
	// be exactly <Registry>/<name>@<digest>. Defaults to the registry of the
	// composer's runtime images, which is the registry stacks pull from.
	Registry string
	// RequireSBOM turns a missing SBOM into an error and an unrecognized
	// SBOM package license into an error (release builds).
	RequireSBOM bool
	// Now is the clock for waiver expiry; nil means time.Now.
	Now func() time.Time
}

// DefaultOpenCoreRepos lists upstreams with enterprise-licensed code.
var DefaultOpenCoreRepos = []string{
	"https://github.com/berriai/litellm",
	"https://github.com/twentyhq/twenty",
	"https://github.com/appsmithorg/appsmith",
	"https://github.com/all-hands-ai/openhands",
	"https://github.com/openhands/openhands",
}

// DefaultEnterprisePatterns are the D-021 hard-fail paths.
var DefaultEnterprisePatterns = []string{"litellm_enterprise", "enterprise/", "@anthropic-ai/claude-agent-sdk"}

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
// itself a reference. Compose repeats the check for each stack.
func lintSameAs(manifests map[string]*composer.Manifest) []Finding {
	var out []Finding
	for _, id := range sortedKeys(manifests) {
		for i, s := range manifests[id].Secrets {
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
			lintSBOM(c, img.Name, sbom, append(append([]string{}, m.LicenseExclusions...), opts.EnterprisePatterns...), exempt, isBundle || opts.RequireSBOM)
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
		for _, p := range e.Paths {
			out = append(out, &exemption{decision: e.Decision, path: p})
		}
	}
	return out
}

// exempted returns the exemption that covers a package name or file path.
func exempted(exempt []*exemption, name string, isFile bool) *exemption {
	for _, e := range exempt {
		if (isFile && strings.Contains(name, e.path)) || (!isFile && matchesExclusion(name, e.path)) {
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
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		ExternalRefs     []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Files []struct {
		FileName string `json:"fileName"`
	} `json:"files"`
}

// osPackageTypes are purl types of distribution packages (D-021 system components).
var osPackageTypes = []string{"pkg:deb/", "pkg:apk/", "pkg:rpm/", "pkg:alpm/"}

// lintSBOM checks an SPDX JSON SBOM: package licenses against the policy
// (OS packages may use system-only licenses) and excluded paths. An
// unrecognized license (not on the allowlist, not an OSI-approved system
// license, for example CC-BY-NC-4.0 or a LicenseRef) fails a release for
// non-OS packages; OS packages get a warning until a decision covers them.
func lintSBOM(c *collector, image string, raw []byte, exclusions []string, exempt []*exemption, release bool) {
	file := "sbom/" + image + ".spdx.json"
	var doc spdxDoc
	if err := json.Unmarshal(raw, &doc); err != nil || !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		c.add(Error, file, "", CodeSBOMInvalid, "not an SPDX JSON document")
		return
	}
	for _, p := range doc.Packages {
		pkg := p.Name
		if p.VersionInfo != "" {
			pkg += "@" + p.VersionInfo
		}
		if e := exempted(exempt, p.Name, false); e != nil {
			c.add(Warning, file, pkg, CodeExempt, "exempt from license and excluded-path checks under %s (license_exceptions %q)", e.decision, e.path)
			continue
		}
		for _, ex := range exclusions {
			if matchesExclusion(p.Name, ex) {
				c.add(Error, file, pkg, CodeExcludedPath, "package matches excluded path %q", ex)
			}
		}
		expr := p.LicenseConcluded
		if expr == "" || expr == "NOASSERTION" || expr == "NONE" {
			expr = p.LicenseDeclared
		}
		if expr == "" || expr == "NOASSERTION" || expr == "NONE" {
			continue // unknown licenses are reported by the scan review, not here
		}
		isOS := false
		for _, ref := range p.ExternalRefs {
			for _, t := range osPackageTypes {
				if ref.ReferenceType == "purl" && strings.HasPrefix(ref.ReferenceLocator, t) {
					isOS = true
				}
			}
		}
		r := EvaluateLicense(expr)
		switch {
		case r.Status == Banned:
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q is banned", expr)
		case r.Status == SystemOnly && !isOS:
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q is only acceptable for OS packages", expr)
		case r.Status == DataOnly && !isDataOnlyPackage(p.Name):
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q is only acceptable for the data-only packages %s (D-050)", expr, strings.Join(DataOnlyPackages, ", "))
		case r.Status == Unknown && !isOS && release:
			c.add(Error, file, pkg, CodeSBOMLicense, "license %q is not on the allowlist (rule 9, D-021)", expr)
		case r.Status == Unknown && isOS:
			c.add(Warning, file, pkg, CodeSBOMLicense, "OS package license %q is not OSI-approved or not recognized; it needs a recorded decision (D-021)", expr)
		case r.Status == Unknown:
			c.add(Warning, file, pkg, CodeSBOMLicense, "license %q needs review (an error in release builds)", expr)
		}
	}
	for _, f := range doc.Files {
		if e := exempted(exempt, f.FileName, true); e != nil {
			continue
		}
		for _, ex := range exclusions {
			if strings.Contains(f.FileName, ex) {
				c.add(Error, file, f.FileName, CodeExcludedPath, "file matches excluded path %q", ex)
			}
		}
	}
}

// isDataOnlyPackage reports whether a package is on the reviewed data-only list.
func isDataOnlyPackage(name string) bool {
	for _, p := range DataOnlyPackages {
		if name == p {
			return true
		}
	}
	return false
}

// matchesExclusion compares a package name with an excluded path, treating
// "-" and "_" alike (PyPI litellm-enterprise is module litellm_enterprise).
func matchesExclusion(pkg, pattern string) bool {
	norm := func(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", "-") }
	p, n := norm(strings.TrimSuffix(pattern, "/")), norm(pkg)
	if p == "" {
		return false
	}
	return n == p || strings.HasPrefix(n, p+"/") || strings.Contains(n, "/"+p+"/") || strings.HasSuffix(n, "/"+p)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
