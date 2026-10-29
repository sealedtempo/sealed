package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer"
)

const fixtures = "../testdata/apps"

func copyApp(t *testing.T, app string) string {
	t.Helper()
	src := filepath.Join(fixtures, app)
	dst := filepath.Join(t.TempDir(), app)
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func edit(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(b), old, new, 1)
	if s == string(b) {
		t.Fatalf("%s: %q not found", path, old)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func codes(fs []Finding, sev Severity) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		if f.Severity == sev {
			m[f.Code]++
		}
	}
	return m
}

func TestFixturesAreClean(t *testing.T) {
	for _, app := range []string{"notes", "llm-gateway"} {
		fs := LintApp(filepath.Join(fixtures, app), Options{RequireSBOM: true})
		if HasErrors(fs) {
			t.Errorf("%s: %v", app, fs)
		}
		for _, f := range fs {
			if f.Code != CodeMissingFile && f.Code != CodeLicenseNote {
				t.Errorf("%s: unexpected warning %v", app, f)
			}
		}
	}
}

// TestLeadingVVersionIsReleasable: a version such as v1.58.2 (coding-agent,
// llm-gateway, internal-tools) is tagged <appId>-v1.58.2 since composer
// 1.4.0, so lint no longer needs a release_version without the v.
func TestLeadingVVersionIsReleasable(t *testing.T) {
	for _, v := range []string{"v1.0.0", "V2", "v3.20.251-lts"} {
		dir := copyApp(t, "notes")
		edit(t, filepath.Join(dir, "manifest.yaml"), "release_version: 1.0.0-sealed.1", "release_version: "+v)
		if n := codes(LintApp(dir, Options{RequireSBOM: true}), Error)[CodeReleaseVersion]; n != 0 {
			t.Errorf("%s: %d release-version errors", v, n)
		}
	}
}

func TestLintFindsProblems(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		code  string
		sev   Severity
	}{
		{"unbuilt image", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "sha256:1111111111111111111111111111111111111111111111111111111111111111", "sha256:"+strings.Repeat("0", 64))
		}, CodeUnbuiltImage, Error},
		{"banned upstream license", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_spdx: MIT\n  source_url", "license_spdx: BUSL-1.1\n  source_url")
		}, CodeLicense, Error},
		{"unknown image license", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_spdx: PostgreSQL", "license_spdx: WTFPL")
		}, CodeLicense, Error},
		{"system-only app license", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_spdx: PostgreSQL", "license_spdx: GPL-2.0-only")
		}, CodeLicense, Error},
		{"license election", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_spdx: PostgreSQL", "license_spdx: LicenseRef-RSALv2 OR AGPL-3.0-only")
		}, CodeLicenseNote, Warning},
		{"open core without exclusions", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "repo: https://github.com/example/notes", "repo: https://github.com/twentyhq/twenty")
		}, CodeExclusions, Error},
		{"empty telemetry", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "telemetry_off_env:\n  NOTES_TELEMETRY: \"0\"\n  DO_NOT_TRACK: \"1\"", "telemetry_off_env: {}")
		}, CodeTelemetry, Error},
		{"telemetry reason too short", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "telemetry_off_env:\n  NOTES_TELEMETRY: \"0\"\n  DO_NOT_TRACK: \"1\"", "telemetry_off_env: {}\ntelemetry_none_reason: none")
		}, CodeTelemetry, Error},
		{"telemetry reason and env", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "telemetry_off_env:", "telemetry_none_reason: The upstream has no telemetry or update checks.\ntelemetry_off_env:")
		}, CodeTelemetry, Warning},
		{"public route", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "auth: gate", "auth: public")
		}, CodeManifest, Error},
		{"bearer route outside the gateway", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "auth: gate", "auth: bearer-passthrough")
		}, CodeManifest, Error},
		{"done file traversal", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_exclusions: []", "license_exclusions: []\nbootstrap: {service: notes-web, done_file: ../../../../etc/shadow}")
		}, CodeManifest, Error},
		{"tmpfs on the ready gate", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "compose.fragment.yaml"), "    shm_size: 128m", "    shm_size: 128m\n    tmpfs: [\"/run/sealed/ready\"]")
		}, CodeFragment, Error},
		{"metadata egress", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "egress.yaml"), `"api.example.com:443"`, `"api.example.com:443", "169.254.169.254:80"`)
		}, CodeEgress, Error},
		{"missing egress", func(t *testing.T, d string) { _ = os.Remove(filepath.Join(d, "egress.yaml")) }, CodeEgress, Error},
		{"egress without notes", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "egress.yaml"), `notes: "api.example.com serves the notes sync API; customers may add mail hosts"`, "")
		}, CodeEgress, Warning},
		{"bad service prefix", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "compose.fragment.yaml"), "  notes-db:", "  db:")
		}, CodeFragment, Error},
		{"forbidden key", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "compose.fragment.yaml"), "    user: \"1000\"", "    privileged: true")
		}, CodeFragment, Error},
		{"undeclared secret", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "compose.fragment.yaml"), "x-sealed-secrets: [DB_PASSWORD]", "x-sealed-secrets: [DB_PASSWORD, NOPE]")
		}, CodeFragment, Error},
		{"unused secret", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "compose.fragment.yaml"), "[APP_SECRET, DB_PASSWORD, SMTP_PASSWORD]", "[APP_SECRET, DB_PASSWORD]")
		}, CodeSecretUnused, Warning},
		{"literal secret in env", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "compose.fragment.yaml"), "NOTES_WORKERS: 2", "NOTES_WORKERS: 2\n      MAIL_PASSWORD: hunter2")
		}, CodeSecretInEnv, Warning},
		{"untagged source", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "source: docker.io/example/notes:1.0.0", "source: docker.io/example/notes")
		}, CodeImageSource, Warning},
		{"missing sbom", func(t *testing.T, d string) { _ = os.Remove(filepath.Join(d, "sbom", "postgres.spdx.json")) }, CodeSBOMMissing, Error},
		{"banned sbom package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"SSPL-1.0"`)
		}, CodeSBOMLicense, Error},
		{"unknown app package license", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"CC-BY-NC-4.0"`)
		}, CodeSBOMLicense, Error},
		{"source-available app package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"LicenseRef-BSL"`)
		}, CodeSBOMLicense, Error},
		{"unknown OS package license", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "postgres.spdx.json"), `"licenseDeclared":"GPL-2.0-only"`, `"licenseDeclared":"GPL-2.0-only AND LicenseRef-Distro-Odd"`)
		}, CodeSBOMLicense, Warning},
		{"distro license on an app package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"curl"`)
		}, CodeSBOMLicense, Error},
		{"data license on a code package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"CC-BY-4.0"`)
		}, CodeSBOMLicense, Error},
		{"data license for the app", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_spdx: PostgreSQL", "license_spdx: CC-BY-4.0")
		}, CodeLicense, Error},
		{"license exception without an accepted decision", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_exclusions: []", "license_exclusions: []\nlicense_exceptions:\n  - decision: D-019\n    paths: [\"packages/twenty-server/src/engine/core-modules/enterprise\"]\n    reason: Twenty enterprise files in the official image.")
		}, CodeLicenseException, Error},
		{"version with a build suffix", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "release_version: 1.0.0-sealed.1", "release_version: 1.0.0+sealed.1")
		}, CodeReleaseVersion, Error},
		{"version with a leading v before a letter", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "release_version: 1.0.0-sealed.1", "release_version: vnext")
		}, CodeReleaseVersion, Error},
		{"absolute done file", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_exclusions: []", "license_exclusions: []\nbootstrap: {service: notes-web, done_file: /var/lib/notes/uploads/.done}")
		}, CodeBootstrap, Warning},
		{"expired waiver", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "waivers.yaml"), "version: 1\nwaivers:\n  - {id: CVE-2026-12345, image: postgres, package: libx, reason: not reachable from the app, expires: 2026-01-31}\n")
		}, CodeWaivers, Error},
		{"waiver for an unknown image", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "waivers.yaml"), "- {id: CVE-2026-12345, image: nope, package: libx, reason: not reachable from the app, expires: 2099-01-31}\n")
		}, CodeWaivers, Error},
		{"waiver without a reason", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "waivers.yaml"), "- {id: GHSA-2345-6789-cfgh, image: postgres, package: libx, expires: 2099-01-31}\n")
		}, CodeWaivers, Error},
		{"waiver with a bad id", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "waivers.yaml"), "- {id: BUG-1, image: postgres, package: libx, reason: not reachable from the app, expires: 2099-01-31}\n")
		}, CodeWaivers, Error},
		{"waivers with an unknown key", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "waivers.yaml"), "version: 1\nwaivers: []\nextra: 1\n")
		}, CodeWaivers, Error},
		{"gpl2 app package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"GPL-2.0-only"`)
		}, CodeSBOMLicense, Error},
		{"enterprise package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"name":"notes"`, `"name":"litellm-enterprise"`)
		}, CodeExcludedPath, Error},
		{"invalid exclusion glob", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_exclusions: []", `license_exclusions: ["/app/[bad/**"]`)
		}, CodeExclusions, Error},
		{"exclusion that matches everything", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_exclusions: []", `license_exclusions: ["/**"]`)
		}, CodeExclusions, Error},
		{"ToolJet without exclusions", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "repo: https://github.com/example/notes", "repo: https://github.com/ToolJet/ToolJet")
		}, CodeExclusions, Error},
		{"opencode without exclusions", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "repo: https://github.com/example/notes", "repo: https://github.com/anomalyco/opencode.git")
		}, CodeExclusions, Error},
		{"font license for the app", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_spdx: PostgreSQL", "license_spdx: OFL-1.1")
		}, CodeLicense, Error},
		{"font license on a code package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"OFL-1.1"`)
		}, CodeSBOMLicense, Error},
		{"Zend license on an app package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"PHP-3.01 AND Zend-2.0"`)
		}, CodeSBOMLicense, Error},
		{"package without license metadata", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT","licenseDeclared":"MIT"`, `"licenseConcluded":"NOASSERTION","licenseDeclared":"NONE"`)
		}, CodeSBOMNoLicense, Error},
		{"ee directory in the image", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"name":"notes-web",`, `"name":"notes-web","files":[{"SPDXID":"SPDXRef-F","fileName":"app/server/ee/licensing/license.service.js"}],`)
		}, CodeExcludedPath, Error},
		{"excluded glob in the image", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "license_exclusions: []", `license_exclusions: ["ms-playwright/chromium-*"]`)
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"name":"notes-web",`, `"name":"notes-web","files":[{"SPDXID":"SPDXRef-F","fileName":"root/.cache/ms-playwright/chromium-1187/chrome-linux/chrome"}],`)
		}, CodeExcludedPath, Error},
		{"invalid sbom", func(t *testing.T, d string) {
			_ = os.WriteFile(filepath.Join(d, "sbom", "postgres.spdx.json"), []byte("{}"), 0o644)
		}, CodeSBOMInvalid, Error},
		{"schema violation", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "manifest.yaml"), "category: internal-tools", "category: games")
		}, CodeManifest, Error},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyApp(t, "notes")
			c.setup(t, dir)
			fs := LintApp(dir, Options{RequireSBOM: true})
			if codes(fs, c.sev)[c.code] == 0 {
				t.Fatalf("want %s %s, got %v", c.sev, c.code, fs)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDistroAndDataLicenses covers D-050 in SBOMs: free distro licenses on
// OS packages (also apk/apt packages added in our own layers, which carry
// apk/deb purls), CC-BY-4.0 on the reviewed data-only packages.
func TestDistroAndDataLicenses(t *testing.T) {
	dir := copyApp(t, "notes")
	sbom := `{"spdxVersion":"SPDX-2.3","packages":[` +
		`{"name":"notes","versionInfo":"1.0.0","licenseConcluded":"MIT"},` +
		`{"name":"git","versionInfo":"2.47.3","licenseDeclared":"GPL-2.0-only","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/alpine/git@2.47.3"}]},` +
		`{"name":"curl","versionInfo":"8.14.1","licenseDeclared":"curl","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/curl@8.14.1"}]},` +
		`{"name":"libjpeg","versionInfo":"9f","licenseDeclared":"IJG AND Libpng","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/libjpeg@9f"}]},` +
		`{"name":"caniuse-lite","versionInfo":"1.0.30001700","licenseDeclared":"CC-BY-4.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/caniuse-lite@1.0.30001700"}]},` +
		`{"name":"blueoak-thing","versionInfo":"1.0.0","licenseDeclared":"BlueOak-1.0.0"},` +
		// D-056: OFL on a font package; F11: Zend-2.0 on an OS package.
		`{"name":"@fontsource/inter","versionInfo":"5.2.8","licenseDeclared":"OFL-1.1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/%40fontsource/inter@5.2.8"}]},` +
		`{"name":"fonts-dejavu-core","versionInfo":"2.37-8","licenseDeclared":"OFL-1.1 AND GPL-2.0-only","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/fonts-dejavu-core@2.37-8"}]},` +
		`{"name":"php8.4-common","versionInfo":"8.4.11-1","licenseDeclared":"PHP-3.01 AND Zend-2.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/php8.4-common@8.4.11-1"}]}]}`
	writeFile(t, filepath.Join(dir, "sbom", "notes-web.spdx.json"), sbom)
	fs := LintApp(dir, Options{RequireSBOM: true})
	for _, f := range fs {
		if f.Code == CodeSBOMLicense {
			t.Errorf("unexpected finding %v", f)
		}
	}
}

func TestLicenseExceptions(t *testing.T) {
	dir := copyApp(t, "notes")
	edit(t, filepath.Join(dir, "sbom", "notes-web.spdx.json"), `"name":"notes"`, `"name":"vendor/enterprise/billing"`)
	edit(t, filepath.Join(dir, "manifest.yaml"), "license_exclusions: []",
		"license_exclusions: []\nlicense_exceptions:\n  - decision: D-999\n    paths: [vendor/enterprise/billing, never/matches]\n    reason: A recorded decision allows shipping this path.")
	// Not accepted: the exception is an error and the package still fails.
	fs := LintApp(dir, Options{RequireSBOM: true})
	if codes(fs, Error)[CodeLicenseException] != 1 || codes(fs, Error)[CodeExcludedPath] == 0 {
		t.Fatalf("unaccepted exception: %v", fs)
	}
	if len(AcceptedExceptionDecisions()) != 0 {
		t.Fatalf("the exception allowlist must start empty: %v", AcceptedExceptionDecisions())
	}
	// Accepted (as a decision would add it): the path is exempt, with a
	// warning, and an unused path is reported.
	acceptedExceptionDecisions["D-999"] = true
	defer delete(acceptedExceptionDecisions, "D-999")
	fs = LintApp(dir, Options{RequireSBOM: true})
	if HasErrors(fs) || codes(fs, Warning)[CodeExempt] != 1 || codes(fs, Warning)[CodeLicenseException] != 1 {
		t.Fatalf("accepted exception: %v", fs)
	}
	// An accepted exception path is a glob like license_exclusions; a bad one is an error.
	edit(t, filepath.Join(dir, "manifest.yaml"), "paths: [vendor/enterprise/billing, never/matches]", `paths: [vendor/enterprise/billing, "a//b"]`)
	fs = LintApp(dir, Options{RequireSBOM: true})
	if codes(fs, Error)[CodeLicenseException] != 1 || codes(fs, Warning)[CodeExempt] != 1 {
		t.Fatalf("bad exception path: %v", fs)
	}
	// The schema rejects malformed entries.
	edit(t, filepath.Join(dir, "manifest.yaml"), "decision: D-999", "decision: 19")
	if fs := LintApp(dir, Options{}); codes(fs, Error)[CodeManifest] == 0 {
		t.Fatalf("bad decision id: %v", fs)
	}
}

func TestWaivers(t *testing.T) {
	dir := copyApp(t, "notes")
	now := func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }
	for _, ok := range []string{
		"[]\n",
		"version: 1\nwaivers: []\n",
		"# comments only\n",
		"version: 1\nwaivers:\n  - id: CVE-2026-12345\n    image: postgres\n    package: libx\n    reason: not reachable from the app\n    expires: 2026-10-28\n",
		"- {id: GHSA-2345-6789-cfgh, image: notes-web, package: liby, reason: fixed upstream next release, expires: \"2027-01-01\"}\n",
	} {
		writeFile(t, filepath.Join(dir, "waivers.yaml"), ok)
		if fs := LintApp(dir, Options{RequireSBOM: true, Now: now}); codes(fs, Error)[CodeWaivers] != 0 {
			t.Errorf("%q: %v", ok, fs)
		}
	}
}

func TestLintCatalogSameAs(t *testing.T) {
	root := t.TempDir()
	for _, app := range []string{"notes", "llm-gateway"} {
		if err := os.Rename(copyApp(t, app), filepath.Join(root, app)); err != nil {
			t.Fatal(err)
		}
	}
	notes := filepath.Join(root, "notes")
	edit(t, filepath.Join(notes, "manifest.yaml"), "telemetry_off_env:", "  - name: LLM_KEY\n    description: x\n    generate: none\n    same_as: llm-gateway/MASTER_KEY\ntelemetry_off_env:")
	edit(t, filepath.Join(notes, "compose.fragment.yaml"), "x-sealed-secrets: [DB_PASSWORD]", "x-sealed-secrets: [DB_PASSWORD, LLM_KEY]")
	if fs, err := LintCatalog(root, Options{}); err != nil || HasErrors(fs) {
		t.Fatalf("valid same_as: %v %v", fs, err)
	}
	edit(t, filepath.Join(notes, "manifest.yaml"), "same_as: llm-gateway/MASTER_KEY", "same_as: llm-gateway/NOPE")
	if fs, _ := LintCatalog(root, Options{}); codes(fs, Error)[CodeSameAs] != 1 {
		t.Fatalf("missing secret: %v", fs)
	}
	edit(t, filepath.Join(notes, "manifest.yaml"), "same_as: llm-gateway/NOPE", "same_as: crm/APP_SECRET")
	if fs, _ := LintCatalog(root, Options{}); codes(fs, Error)[CodeSameAs] != 1 {
		t.Fatalf("missing app: %v", fs)
	}
}

func TestOSPackagesMayUseSystemLicenses(t *testing.T) {
	// postgres.spdx.json lists busybox (pkg:apk, GPL-2.0-only); that is fine.
	fs := LintApp(filepath.Join(fixtures, "notes"), Options{RequireSBOM: true})
	for _, f := range fs {
		if f.Code == CodeSBOMLicense {
			t.Fatalf("OS package flagged: %v", f)
		}
	}
}

func TestLintBundle(t *testing.T) {
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join(fixtures, "notes"), Registry: "ghcr.io/sealedtempo"})
	if err != nil {
		t.Fatal(err)
	}
	if fs := LintBundle(b, Options{}); HasErrors(fs) {
		t.Fatalf("%v", fs)
	}
	other, err := composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join(fixtures, "notes"), Registry: "docker.io/someone"})
	if err != nil {
		t.Fatal(err)
	}
	if codes(LintBundle(other, Options{}), Error)[CodeRegistry] != 2 {
		t.Fatal("refs outside ghcr.io must be flagged")
	}
	// Any other owner on ghcr.io is just as foreign.
	evil, err := composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join(fixtures, "notes"), Registry: "ghcr.io/evil"})
	if err != nil {
		t.Fatal(err)
	}
	if codes(LintBundle(evil, Options{}), Error)[CodeRegistry] != 2 {
		t.Fatal("refs under another ghcr.io owner must be flagged")
	}
	if fs := LintBundle(evil, Options{Registry: "ghcr.io/evil"}); codes(fs, Error)[CodeRegistry] != 0 {
		t.Fatalf("explicit registry not honored: %v", fs)
	}
}

func TestUnknownLicenseIsWarningOutsideRelease(t *testing.T) {
	dir := copyApp(t, "notes")
	edit(t, filepath.Join(dir, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"CC-BY-NC-4.0"`)
	if fs := LintApp(dir, Options{}); codes(fs, Error)[CodeSBOMLicense] != 0 || codes(fs, Warning)[CodeSBOMLicense] != 1 {
		t.Fatalf("%v", fs)
	}
}

func TestNoLicenseIsWarningOutsideRelease(t *testing.T) {
	dir := copyApp(t, "notes")
	edit(t, filepath.Join(dir, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT","licenseDeclared":"MIT"`, `"licenseConcluded":"NOASSERTION"`)
	if fs := LintApp(dir, Options{}); codes(fs, Error)[CodeSBOMNoLicense] != 0 || codes(fs, Warning)[CodeSBOMNoLicense] != 1 {
		t.Fatalf("%v", fs)
	}
	// OS packages without metadata are system components: one warning per SBOM, in release mode too.
	edit(t, filepath.Join(dir, "sbom", "postgres.spdx.json"), `"licenseDeclared":"GPL-2.0-only"`, `"licenseDeclared":"NOASSERTION"`)
	edit(t, filepath.Join(dir, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"NOASSERTION"`, `"licenseConcluded":"MIT"`)
	fs := LintApp(dir, Options{RequireSBOM: true})
	if codes(fs, Error)[CodeSBOMNoLicense] != 0 || codes(fs, Warning)[CodeSBOMNoLicense] != 1 {
		t.Fatalf("%v", fs)
	}
}

func TestTelemetryNoneReasonIsAccepted(t *testing.T) {
	dir := copyApp(t, "notes")
	edit(t, filepath.Join(dir, "manifest.yaml"), "telemetry_off_env:\n  NOTES_TELEMETRY: \"0\"\n  DO_NOT_TRACK: \"1\"",
		"telemetry_off_env: {}\ntelemetry_none_reason: Checked v1.0.0 source; no telemetry, update checks or crash reporting.")
	if fs := LintApp(dir, Options{RequireSBOM: true}); HasErrors(fs) || codes(fs, Warning)[CodeTelemetry] != 0 {
		t.Fatalf("%v", fs)
	}
}

func TestLintCatalog(t *testing.T) {
	root := t.TempDir()
	for _, app := range []string{"notes", "llm-gateway"} {
		src := copyApp(t, app)
		if err := os.Rename(src, filepath.Join(root, app)); err != nil {
			t.Fatal(err)
		}
	}
	fs, err := LintCatalog(root, Options{})
	if err != nil || HasErrors(fs) {
		t.Fatalf("%v %v", fs, err)
	}
	edit(t, filepath.Join(root, "notes", "manifest.yaml"), "  - name: tools\n", "  - name: gateway\n")
	edit(t, filepath.Join(root, "notes", "manifest.yaml"), "path_or_host: tools", "path_or_host: gateway")
	fs, _ = LintCatalog(root, Options{})
	if codes(fs, Warning)[CodeSharedRoute] != 1 {
		t.Fatalf("shared route not reported: %v", fs)
	}
	if err := os.Rename(filepath.Join(root, "notes"), filepath.Join(root, "notes2")); err != nil {
		t.Fatal(err)
	}
	fs, _ = LintCatalog(root, Options{})
	if codes(fs, Error)[CodeManifest] == 0 {
		t.Fatalf("id/directory mismatch not reported: %v", fs)
	}
}

func TestFindingString(t *testing.T) {
	f := Finding{Severity: Error, App: "crm", File: "manifest.yaml", Field: "images[0].digest", Code: CodeUnbuiltImage, Message: "x"}
	if f.String() != "error: crm/manifest.yaml images[0].digest [unbuilt-image] x" {
		t.Fatal(f.String())
	}
}
