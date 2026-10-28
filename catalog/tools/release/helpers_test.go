package main

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func mustContain(t testing.TB, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("expected %q in:\n%s", sub, s)
	}
}
