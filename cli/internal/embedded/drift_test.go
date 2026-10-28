package embedded

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func sameFile(t *testing.T, got []byte, path string) {
	t.Helper()
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("embedded copy of %s is stale: run go generate ./cli/internal/embedded", path)
	}
}

func TestEmbeddedFilesMatchRepository(t *testing.T) {
	root := repoRoot(t)
	sameFile(t, DefaultsYAML, filepath.Join(root, "config", "defaults.yaml"))
	sameFile(t, MainnetDeployments, filepath.Join(root, "contracts", "deployments", "tempo-mainnet.json"))
	for _, c := range []string{"PlatformRegistry", "AppRegistry", "DeploymentRegistry"} {
		b, err := ABI(c)
		if err != nil {
			t.Fatal(err)
		}
		sameFile(t, b, filepath.Join(root, "contracts", "abi", c+".json"))
	}
}

// moduleFile reports whether sync.sh copies path (relative to the module directory).
func moduleFile(path string) bool {
	if strings.Contains(path, ".terraform/") {
		return false
	}
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".tf") || strings.HasSuffix(base, ".tftest.hcl") || base == ".terraform.lock.hcl" || base == "README.md"
}

func TestEmbeddedModuleMatchesRepository(t *testing.T) {
	src := filepath.Join(repoRoot(t), "infra", "terraform", "customer-bootstrap")
	var want []string
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".terraform" {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(src, p)
		if !d.IsDir() && moduleFile(filepath.ToSlash(rel)) {
			want = append(want, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	mod := BootstrapModule()
	if err := fs.WalkDir(mod, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			got = append(got, p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("embedded module files differ from %s: run go generate ./cli/internal/embedded\n got: %v\nwant: %v", src, got, want)
	}
	for _, p := range want {
		b, err := fs.ReadFile(mod, p)
		if err != nil {
			t.Fatal(err)
		}
		sameFile(t, b, filepath.Join(src, filepath.FromSlash(p)))
	}
	for _, required := range []string{"main.tf", "deployer.tf", "key_broker.tf", "modules/iam/main.tf", ".terraform.lock.hcl"} {
		if _, err := fs.Stat(mod, required); err != nil {
			t.Errorf("embedded module lacks %s", required)
		}
	}
}
