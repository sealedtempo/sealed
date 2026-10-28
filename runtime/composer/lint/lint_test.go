package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		}, CodeTelemetry, Warning},
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
		{"gpl2 app package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"licenseConcluded":"MIT"`, `"licenseConcluded":"GPL-2.0-only"`)
		}, CodeSBOMLicense, Error},
		{"enterprise package", func(t *testing.T, d string) {
			edit(t, filepath.Join(d, "sbom", "notes-web.spdx.json"), `"name":"notes"`, `"name":"litellm-enterprise"`)
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
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join(fixtures, "notes"), Registry: "ghcr.io/sealed-dev"})
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
