package main

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestMain removes the binaries the script tests build once per process.
func TestMain(m *testing.M) {
	code := m.Run()
	for _, b := range []string{toolBin, composeBin} {
		if b != "" {
			_ = os.RemoveAll(filepath.Dir(b))
		}
	}
	os.Exit(code)
}

// repoRoot is the real repository root (three levels up from this package).
func repoRoot(t testing.TB) string {
	t.Helper()
	r, err := FindRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func copyTree(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		return copyFile(p, target)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, st.Mode().Perm())
}

func writeFile(t testing.TB, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const fixtureImagesYAML = `version: 1
builds:
  catalog/apps/llm-gateway/images/gateway: {context: dir}
  runtime/agent: {context: root}
  runtime/egress: {context: root}
  runtime/envexec: {context: root}
  runtime/mpp-payer: {context: root}
  verifier: {context: root}
extra:
  - name: sealed-key-broker
    dir: key-broker
    context: root
    optional: true
never_mirror:
  - repository: docker.io/example/forbidden
    decision: D-999
    reason: fixture license forbids redistribution
`

// fixtureRepo builds a small repository: the real config, runtime images and composer config template,
// the composer's two fixture apps (notes, llm-gateway) as the catalog, and stub Dockerfiles.
func fixtureRepo(t testing.TB) string {
	t.Helper()
	real := repoRoot(t)
	root := t.TempDir()
	for _, f := range []string{"go.mod", "config/defaults.yaml", RuntimeImagesFile, ComposeTemplate, ExtraImagesFile, RuntimeWaiversFile} {
		if err := copyFile(filepath.Join(real, f), filepath.Join(root, f)); err != nil {
			t.Fatal(err)
		}
	}
	// A fixture repo is a pre-release checkout: its built sidecars (and the key broker) are still placeholders, so
	// the pin and scan tests have zero digests to reason about even after the real files are pinned. The transform
	// restores the committed placeholder form (zero digest plus an "unbuilt": true line), which both the loose
	// runtime-images parser and the strict extra-images parser accept.
	makeSidecarsUnbuilt(t, filepath.Join(root, RuntimeImagesFile))
	makeSidecarsUnbuilt(t, filepath.Join(root, ExtraImagesFile))
	writeFile(t, filepath.Join(root, BuildsFile), fixtureImagesYAML)
	for _, app := range []string{"notes", "llm-gateway"} {
		copyTree(t, filepath.Join(real, "runtime/composer/testdata/apps", app), filepath.Join(root, CatalogDir, app))
		writeFile(t, filepath.Join(root, CatalogDir, app, "waivers.yaml"), "version: 1\nwaivers: []\n")
	}
	writeFile(t, filepath.Join(root, CatalogDir, "llm-gateway/images/gateway/Dockerfile"), "FROM scratch\n")
	for _, d := range []string{"runtime/agent", "runtime/egress", "runtime/envexec", "runtime/mpp-payer", "verifier"} {
		writeFile(t, filepath.Join(root, d, "Dockerfile"), "FROM scratch\n")
	}
	return root
}

// buildSidecarRe matches a build-sourced sidecar block in runtime-images.json: the digest line, its
// "source": "build:" line and its "license_spdx" line, capturing everything after the digest value so the
// value is zeroed and an "unbuilt": true line is appended (the committed placeholder form).
var buildSidecarRe = regexp.MustCompile(`("digest": ")sha256:[0-9a-f]{64}(",\n\s*"source": "build:[^"]*",\n\s*"license_spdx": "[^"]*")`)

// makeSidecarsUnbuilt resets every build-sourced sidecar in runtime-images.json to the all-zero placeholder and
// marks it unbuilt, leaving mirrored images (caddy) and all formatting untouched.
func makeSidecarsUnbuilt(t testing.TB, path string) {
	t.Helper()
	writeFile(t, path, buildSidecarRe.ReplaceAllString(readFile(t, path), "${1}"+zeroDigest+"${2},\n      \"unbuilt\": true"))
}

// yamlBuildDigestRe matches a manifest build image's pinned digest: a "source: build:" line followed by its
// "digest:" line, capturing everything up to the digest value so only the value is rewritten.
var yamlBuildDigestRe = regexp.MustCompile(`(source: build:\S*\n\s*digest: )sha256:[0-9a-f]{64}`)

// unbuiltManifest resets every build-sourced image digest in a manifest to the all-zero placeholder, so a test
// sees the pre-release manifest even after the real one is pinned.
func unbuiltManifest(src string) string {
	return yamlBuildDigestRe.ReplaceAllString(src, "${1}"+zeroDigest)
}

func mustContain(t testing.TB, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("expected %q in:\n%s", sub, s)
	}
}
