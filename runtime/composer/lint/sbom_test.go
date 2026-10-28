package lint

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// testdata/syft-image/image.spdx.json is syft's own output for a synthetic
// image (make-image-sbom.sh) that copies the catalog's excluded paths, near
// misses that must not match, packages without license metadata, a Go binary
// that links go-ethereum and the Prometheus client, and Debian packages
// (redis-server, php8.4 under Zend-2.0, Ewe translations in an ee/ locale
// directory). repo-scan-excerpt.spdx.json is a verbatim excerpt of the
// license audit's repository scan (syft 1.55.0 --enrich golang,javascript).
const (
	syftImage   = "testdata/syft-image/image.spdx.json"
	repoExcerpt = "testdata/syft-image/repo-scan-excerpt.spdx.json"
)

// manifestPatterns are the license_exclusions of the six catalog apps when
// this test was written, plus the defaults.
var manifestPatterns = []string{
	"OpenHands/legacy:enterprise/", "/acp-node/**", "**/@anthropic-ai/claude-agent-sdk*/**", "**/litellm_enterprise/**",
	"anomalyco/opencode:packages/enterprise/", "/app/enterprise/**", "**/litellm_enterprise-*.dist-info/**", "BerriAI/litellm:enterprise/",
	"/usr/lib/ollama/cuda_v12/**", "/usr/lib/ollama/cuda_v13/**", "/usr/lib/ollama/mlx_cuda_v13/**", "/usr/lib/ollama/vulkan/**",
	"/app/server/ee/", "/app/frontend/ee/", "/app/server/dist/ee/", "/app/frontend/build/ee/", "/opt/oracle/",
	"/usr/bin/redis-server", "/usr/bin/redis-check-aof", "/usr/bin/redis-check-rdb", "/usr/bin/redis-benchmark", "/usr/bin/redis-cli",
	"/usr/lib/redis/", "/etc/redis/",
	"ms-playwright/chromium-*", "ms-playwright/chromium_headless_shell-*", "**/node_modules/@playwright/browser-chromium", "**/node_modules/idcac-playwright",
}

// nearMisses are paths and packages in the syft fixture that no pattern may report.
var nearMisses = []string{
	"firefox", "browser-firefox", "ee-first", "ee.config.js", "/tree/", "/free/", "enterprise_billing", "libggml-cpu", "libggml-base",
	"locale/ee", "iso-codes", "litellm@", "valkey",
}

func compileAll(t *testing.T, manifest []string, policy []string) []*pathPattern {
	t.Helper()
	var out []*pathPattern
	for _, p := range manifest {
		out = append(out, mustPattern(t, p, false))
	}
	for _, p := range policy {
		out = append(out, mustPattern(t, p, true))
	}
	return out
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runSBOM(t *testing.T, raw []byte, patterns []*pathPattern, overrides []LicenseOverride, release bool) []Finding {
	t.Helper()
	o := Options{Overrides: overrides, Registry: "x"}.withDefaults()
	if o.overridesErr != nil {
		t.Fatal(o.overridesErr)
	}
	c := &collector{app: "fixture"}
	lintSBOM(c, "img", raw, patterns, nil, o.overrides, release)
	return c.out
}

func fieldsOf(fs []Finding, code string, sev Severity) []string {
	var out []string
	for _, f := range fs {
		if f.Code == code && f.Severity == sev {
			out = append(out, f.Field)
		}
	}
	sort.Strings(out)
	return out
}

func TestSyftImageExcludedPaths(t *testing.T) {
	fs := runSBOM(t, readFixture(t, syftImage), compileAll(t, manifestPatterns, DefaultEnterprisePatterns), nil, true)
	var files, pkgs []string
	for _, f := range fs {
		if f.Code != CodeExcludedPath || f.Severity != Error {
			continue
		}
		if strings.HasPrefix(f.Field, "/") {
			files = append(files, f.Field)
		} else {
			pkgs = append(pkgs, f.Field+" "+f.Message[strings.Index(f.Message, `"`):])
		}
		for _, miss := range nearMisses {
			if strings.Contains(f.Field, miss) || strings.Contains(f.Message, miss) {
				t.Errorf("near miss %q reported: %v", miss, f)
			}
		}
	}
	sort.Strings(files)
	sort.Strings(pkgs)
	wantFiles := []string{
		"/acp-node/",
		"/acp-node/node_modules/@anthropic-ai/claude-agent-sdk/",
		"/app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.20.dist-info/",
		"/app/.venv/lib/python3.13/site-packages/litellm_enterprise/",
		"/app/enterprise/",
		"/app/frontend/build/ee/",
		"/app/frontend/ee/",
		"/app/node_modules/@playwright/browser-chromium/",
		"/app/node_modules/idcac-playwright/",
		"/app/server/dist/ee/",
		"/app/server/ee/",
		"/etc/redis/",
		"/ms-playwright/chromium-1187/",
		"/ms-playwright/chromium_headless_shell-1187/",
		"/opt/oracle/",
		"/root/.cache/ms-playwright/chromium-1187/",
		"/usr/bin/redis-benchmark",
		"/usr/bin/redis-check-aof",
		"/usr/bin/redis-check-rdb",
		"/usr/bin/redis-cli",
		"/usr/bin/redis-server",
		"/usr/lib/ollama/cuda_v12/",
		"/usr/lib/ollama/cuda_v13/",
		"/usr/lib/ollama/mlx_cuda_v13/",
		"/usr/lib/ollama/vulkan/",
		"/usr/lib/redis/",
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("excluded files:\n got %q\nwant %q", files, wantFiles)
	}
	wantPkgs := []string{
		`@anthropic-ai/claude-agent-sdk@0.2.9 "**/@anthropic-ai/claude-agent-sdk*/**"`,
		`@anthropic-ai/claude-agent-sdk@0.2.9 "/acp-node/**"`,
		`@anthropic-ai/claude-agent-sdk@0.2.9 "@anthropic-ai/claude-agent-sdk*"`,
		`@playwright/browser-chromium@1.62.1 "**/node_modules/@playwright/browser-chromium"`,
		`@zed-industries/claude-code-acp@0.10.0 "/acp-node/**"`,
		`idcac-playwright@0.1.3 "**/node_modules/idcac-playwright"`,
		`litellm-enterprise@0.1.20 "**/litellm_enterprise-*.dist-info/**"`,
		`litellm-enterprise@0.1.20 "**/litellm_enterprise/**"`,
		`litellm-enterprise@0.1.20 "litellm_enterprise*"`,
	}
	if !reflect.DeepEqual(pkgs, wantPkgs) {
		t.Errorf("excluded packages:\n got %q\nwant %q", pkgs, wantPkgs)
	}
	// One finding per excluded directory, with both patterns that cover it.
	for _, f := range fs {
		if f.Field == "/app/server/ee/" && !strings.Contains(f.Message, `"/app/server/ee/", "ee/"`) {
			t.Errorf("%v", f)
		}
		if f.Field == "/acp-node/" && !strings.HasPrefix(f.Message, "3 files under this directory") {
			t.Errorf("%v", f)
		}
	}
}

func TestSyftImageLicenses(t *testing.T) {
	raw := readFixture(t, syftImage)
	fs := runSBOM(t, raw, nil, nil, true)
	// With the reviewed overrides only the two enterprise packages fail; the
	// Prometheus NOTICE refs are dropped, go-ethereum's BSD-2-Clause-Views is
	// accepted for that module only, Zend-2.0 passes on an OS package and OFL
	// on a font package. OS packages without metadata get one warning.
	if got, want := fieldsOf(fs, CodeSBOMLicense, Error), []string{"@anthropic-ai/claude-agent-sdk@0.2.9", "litellm-enterprise@0.1.20"}; !reflect.DeepEqual(got, want) {
		t.Errorf("license errors: got %q, want %q (%v)", got, want, fs)
	}
	if got, want := fieldsOf(fs, CodeSBOMLicense, Warning), []string{"fonts-dejavu-core@2.37-8"}; !reflect.DeepEqual(got, want) {
		t.Errorf("license warnings: got %q, want %q", got, want)
	}
	if got := fieldsOf(fs, CodeSBOMNoLicense, Error); len(got) != 0 {
		t.Errorf("no-license errors despite overrides: %q", got)
	}
	nw := fieldsOf(fs, CodeSBOMNoLicense, Warning)
	if len(nw) != 1 || nw[0] != "" {
		t.Fatalf("want one aggregated OS warning: %v", fs)
	}
	for _, f := range fs {
		if f.Code == CodeSBOMNoLicense && !strings.Contains(f.Message, "2 OS packages") {
			t.Errorf("%v", f)
		}
	}

	// Without overrides: every package the audit lists (F4, F5) fails a
	// release, and this repository's main module too; outside release mode
	// they are warnings.
	fs = runSBOM(t, raw, nil, []LicenseOverride{}, true)
	wantMissing := []string{
		"aurelio-sdk@0.0.19", "github.com/sealed-dev/sealed@UNKNOWN", "google-crc32c@1.8.0", "llm-sandbox@0.3.39", "map-stream@0.1.0", "pause-stream@0.0.11",
	}
	if got := fieldsOf(fs, CodeSBOMNoLicense, Error); !reflect.DeepEqual(got, wantMissing) {
		t.Errorf("no-license errors: got %q, want %q", got, wantMissing)
	}
	if got, want := fieldsOf(fs, CodeSBOMLicense, Error), []string{"@anthropic-ai/claude-agent-sdk@0.2.9", "github.com/ethereum/go-ethereum@v1.17.10", "litellm-enterprise@0.1.20"}; !reflect.DeepEqual(got, want) {
		t.Errorf("license errors without overrides: got %q, want %q", got, want)
	}
	fs = runSBOM(t, raw, nil, []LicenseOverride{}, false)
	if got := fieldsOf(fs, CodeSBOMNoLicense, Error); len(got) != 0 {
		t.Errorf("no-license must be a warning outside release mode: %q", got)
	}
	if got := fieldsOf(fs, CodeSBOMNoLicense, Warning); len(got) != len(wantMissing)+1 {
		t.Errorf("no-license warnings: %q", got)
	}
}

func TestRepoScanExcerpt(t *testing.T) {
	raw := readFixture(t, repoExcerpt)
	if fs := runSBOM(t, raw, compileAll(t, nil, DefaultEnterprisePatterns), nil, true); len(fs) != 0 {
		t.Fatalf("with overrides: %v", fs)
	}
	fs := runSBOM(t, raw, nil, []LicenseOverride{}, true)
	if got, want := fieldsOf(fs, CodeSBOMNoLicense, Error), []string{
		"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime@v0.0.0-20251001021608-1fe7b43fc4d6", "map-stream@0.1.0", "pause-stream@0.0.11",
	}; !reflect.DeepEqual(got, want) {
		t.Errorf("no-license: got %q, want %q", got, want)
	}
	if got, want := fieldsOf(fs, CodeSBOMLicense, Error), []string{"github.com/ethereum/go-ethereum@v1.17.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("license errors: got %q, want %q", got, want)
	}
}

// TestCatalogPatternsMatchSyftImage lints each real catalog manifest with the
// syft fixture as the SBOM of every image: each of its patterns must report
// something, and no near miss may appear (license audit F6).
func TestCatalogPatternsMatchSyftImage(t *testing.T) {
	sbom := readFixture(t, syftImage)
	src := filepath.Join("..", "..", "..", "catalog", "apps")
	for app, m := range catalogApps(t) {
		dir := filepath.Join(t.TempDir(), app)
		if err := os.MkdirAll(filepath.Join(dir, "sbom"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{composer.ManifestFile, composer.FragmentFile, composer.EgressFile} {
			b, err := os.ReadFile(filepath.Join(src, app, name))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, name), string(b))
		}
		for _, img := range m.Images {
			writeFile(t, filepath.Join(dir, "sbom", img.Name+".spdx.json"), string(sbom))
		}
		fs := LintApp(dir, Options{RequireSBOM: true})
		reported := map[string]bool{}
		for _, f := range fs {
			if f.Code == CodeExclusions && strings.HasPrefix(f.Field, "license_exclusions[") {
				t.Errorf("%s: %v", app, f)
			}
			if f.Code != CodeExcludedPath {
				continue
			}
			for _, raw := range m.LicenseExclusions {
				if strings.Contains(f.Message, strconv.Quote(raw)) {
					reported[raw] = true
				}
			}
			for _, miss := range nearMisses {
				if strings.Contains(f.Field, miss) || strings.Contains(f.Message, miss) {
					t.Errorf("%s: near miss %q reported: %v", app, miss, f)
				}
			}
		}
		for _, raw := range m.LicenseExclusions {
			if p := mustPattern(t, raw, false); !p.note && !reported[raw] {
				t.Errorf("%s: pattern %q matched nothing in %s; add a path to make-image-sbom.sh", app, raw, syftImage)
			}
		}
	}
}

func TestOSPackagesAndDefaultPatterns(t *testing.T) {
	// An Ewe locale directory owned by a Debian package is not an ee/ open-core
	// directory, but the same path outside any OS package is reported, and a
	// manifest pattern applies to OS packages too.
	sbom := `{"spdxVersion":"SPDX-2.3","packages":[
	 {"SPDXID":"SPDXRef-iso","name":"iso-codes","versionInfo":"4.18.0-1","licenseDeclared":"LGPL-2.1-or-later","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/iso-codes@4.18.0-1?arch=amd64"}]},
	 {"SPDXID":"SPDXRef-ee","name":"ee","versionInfo":"1.0","licenseDeclared":"MIT","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/ee@1.0"}]}],
	 "files":[
	 {"SPDXID":"SPDXRef-F1","fileName":"usr/share/locale/ee/LC_MESSAGES/iso_639-2.mo"},
	 {"SPDXID":"SPDXRef-F2","fileName":"usr/share/locale/ee"},
	 {"SPDXID":"SPDXRef-F3","fileName":"app/locales/ee/billing.js"}],
	 "relationships":[{"spdxElementId":"SPDXRef-iso","relatedSpdxElement":"SPDXRef-F1","relationshipType":"CONTAINS"}]}`
	fs := runSBOM(t, []byte(sbom), compileAll(t, nil, DefaultEnterprisePatterns), nil, true)
	if got := fieldsOf(fs, CodeExcludedPath, Error); !reflect.DeepEqual(got, []string{"/app/locales/ee/"}) {
		t.Fatalf("got %q: %v", got, fs)
	}
	fs = runSBOM(t, []byte(sbom), compileAll(t, []string{"/usr/share/locale/ee/"}, nil), nil, true)
	if got := fieldsOf(fs, CodeExcludedPath, Error); !reflect.DeepEqual(got, []string{"/usr/share/locale/ee/"}) {
		t.Fatalf("manifest pattern on an OS file: got %q", got)
	}
}

func TestOverrideNeverHidesABannedLicense(t *testing.T) {
	sbom := `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-a","name":"map-stream","versionInfo":"0.1.0","licenseDeclared":"SSPL-1.0",
	 "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/map-stream@0.1.0"}]}]}`
	fs := runSBOM(t, []byte(sbom), nil, nil, true)
	if len(fs) != 1 || fs[0].Code != CodeSBOMLicense || fs[0].Severity != Error || !strings.Contains(fs[0].Message, "override") {
		t.Fatalf("%v", fs)
	}
}

func TestOverrideAllowIsPerPackage(t *testing.T) {
	// BSD-2-Clause-Views is accepted for go-ethereum v1.17.10 only.
	pkg := func(purl string) string {
		return `{"SPDXID":"SPDXRef-x","name":"m","versionInfo":"v1","licenseConcluded":"BSD-2-Clause-Views",
		 "externalRefs":[{"referenceType":"purl","referenceLocator":"` + purl + `"}]}`
	}
	for purl, want := range map[string]int{
		"pkg:golang/github.com/ethereum/go-ethereum@v1.17.10": 0,
		"pkg:golang/github.com/ethereum/go-ethereum@v1.17.11": 1,
		"pkg:golang/github.com/rcrowley/go-metrics@v0.1.0":    1,
	} {
		fs := runSBOM(t, []byte(`{"spdxVersion":"SPDX-2.3","packages":[`+pkg(purl)+`]}`), nil, nil, true)
		if got := len(fieldsOf(fs, CodeSBOMLicense, Error)); got != want {
			t.Errorf("%s: %d errors, want %d: %v", purl, got, want, fs)
		}
	}
}

func TestNoticeRefsOnly(t *testing.T) {
	// An unidentified LICENSE file stays a LicenseRef that needs review; an
	// unidentified NOTICE file is dropped.
	doc := func(seeAlso string) []byte {
		return []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-a","name":"github.com/x/y","versionInfo":"v1.0.0",
		 "licenseConcluded":"Apache-2.0 AND LicenseRef-abc","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/github.com/x/y@v1.0.0"}]}],
		 "hasExtractedLicensingInfos":[{"licenseId":"LicenseRef-abc","name":"sha256:abc","extractedText":"NOASSERTION","seeAlsos":["` + seeAlso + `"]}]}`)
	}
	if fs := runSBOM(t, doc("file://$GOPATH/pkg/mod/github.com/x/y@v1.0.0/NOTICE"), nil, nil, true); len(fs) != 0 {
		t.Errorf("NOTICE: %v", fs)
	}
	if fs := runSBOM(t, doc("file://$GOPATH/pkg/mod/github.com/x/y@v1.0.0/LICENSE"), nil, nil, true); len(fieldsOf(fs, CodeSBOMLicense, Error)) != 1 {
		t.Errorf("LICENSE: %v", fs)
	}
}
