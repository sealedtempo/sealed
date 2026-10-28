package licenses

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
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

func TestIsLicenseFile(t *testing.T) {
	for name, want := range map[string]bool{
		"LICENSE": true, "LICENSE.md": true, "LICENSE-MIT": true, "LICENCE": true, "license.txt": true, "COPYING": true,
		"COPYING.LESSER": true, "NOTICE": true, "PATENTS": true, "AUTHORS": true, "UNLICENSE": true,
		"license.go": false, "licenses.json": false, "README.md": false, "LICENSES": false, "copying_test.go": false,
	} {
		if IsLicenseFile(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

// TestCollectTheCLI collects the real module set of the sealed binary for three release targets.
func TestCollectTheCLI(t *testing.T) {
	root := repoRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	gethVersion := regexp.MustCompile(`(?m)^\s*github\.com/ethereum/go-ethereum (v\S+)`).FindSubmatch(mod)
	if gethVersion == nil {
		t.Fatal("go.mod has no go-ethereum")
	}
	for _, target := range [][2]string{{"linux", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}} {
		set, err := Collect(context.Background(), Options{Dir: root, Packages: []string{"./cli/cmd/sealed"}, GOOS: target[0], GOARCH: target[1]})
		if err != nil {
			t.Fatal(err)
		}
		if len(set.Modules) < 10 {
			t.Fatalf("%v: only %d modules", target, len(set.Modules))
		}
		geth, ok := set.Module("github.com/ethereum/go-ethereum")
		if !ok || geth.Version != string(gethVersion[1]) {
			t.Fatalf("%v: go-ethereum %+v", target, geth)
		}
		have := map[string]string{}
		for _, f := range geth.Files {
			have[f.Name] = string(f.Data)
		}
		for name, text := range map[string]string{
			"COPYING.LESSER":  "GNU LESSER GENERAL PUBLIC LICENSE",
			"COPYING":         "GNU GENERAL PUBLIC LICENSE",
			"metrics/LICENSE": "Richard Crowley", // BSD-2-Clause-Views, only in the linked metrics package
		} {
			if !strings.Contains(have[name], text) {
				t.Errorf("%v: go-ethereum %s missing", target, name)
			}
		}
		if _, ok := set.Module("github.com/sealed-dev/sealed"); ok {
			t.Fatal("the main module is listed as third-party")
		}
		for _, m := range set.Modules {
			if len(m.Files) == 0 {
				t.Errorf("%s has no files", m.Path)
			}
		}
		if set.Go[0].Name != "LICENSE" || !strings.Contains(string(set.Go[0].Data), "The Go Authors") || set.GoVersion == "" {
			t.Fatalf("Go license %+v %q", set.Go, set.GoVersion)
		}
		readme := set.README(Notice{Program: "sealed", Version: "0.1.0", License: "the Apache License 2.0", SourceURL: "https://github.com/sealedtempo/sealed", SourceRef: "cli-v0.1.0", BuildPkg: "./cli/cmd/sealed"})
		for _, want := range []string{
			"GNU LGPL notice: github.com/ethereum/go-ethereum",
			"github.com/ethereum/go-ethereum " + string(gethVersion[1]) + ", which is covered by the GNU Lesser General",
			"licenses/github.com/ethereum/go-ethereum/COPYING.LESSER and the GPL text it builds on is licenses/github.com/ethereum/go-ethereum/COPYING",
			"Corresponding source: the complete source of this program is https://github.com/sealedtempo/sealed/tree/cli-v0.1.0.",
			"(" + target[0] + "/" + target[1] + ")",
			"go/LICENSE",
		} {
			if !strings.Contains(readme, want) {
				t.Errorf("%v: README lacks %q:\n%s", target, want, readme)
			}
		}
	}
}

func TestWriteDir(t *testing.T) {
	set := &Set{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.27.3",
		Modules: []Module{{Path: "example.com/a", Version: "v1.0.0", Files: []File{{Name: "LICENSE", Data: []byte("MIT")}, {Name: "sub/NOTICE", Data: []byte("n")}}}},
		Go:      []File{{Name: "LICENSE", Data: []byte("go")}}}
	dir := t.TempDir()
	if err := set.WriteDir(dir, Notice{Program: "sealed", Version: "0.1.0", SourceURL: "https://example.com/r", SourceRef: "t"}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"example.com/a/LICENSE": "MIT", "example.com/a/sub/NOTICE": "n", "go/LICENSE": "go"} {
		if b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name))); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", name, b, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "README")); strings.Contains(string(b), "LGPL") || !strings.Contains(string(b), "example.com/a v1.0.0: LICENSE, sub/NOTICE") {
		t.Fatalf("README without LGPL modules:\n%s", b)
	}
	bad := &Set{Modules: []Module{{Path: "../x", Files: []File{{Name: "LICENSE"}}}}}
	if err := bad.WriteDir(dir, Notice{}); err == nil {
		t.Fatal("a path outside the directory was written")
	}
}

// TestCollectFailsWithoutLicense: a linked module without any license text stops the release.
func TestCollectFailsWithoutLicense(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644)
	}
	write("go.mod", "module example.com/main\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n")
	write("main.go", "package main\n\nimport _ \"example.com/dep\"\n\nfunc main() {}\n")
	write("dep/go.mod", "module example.com/dep\n\ngo 1.26\n")
	write("dep/dep.go", "package dep\n")
	write("dep/AUTHORS", "someone\n")
	if _, err := Collect(context.Background(), Options{Dir: dir, Packages: []string{"."}}); err == nil || !strings.Contains(err.Error(), "no license file in example.com/dep") {
		t.Fatalf("want a missing-license error, got %v", err)
	}
	write("dep/LICENSE", "MIT License\n")
	set, err := Collect(context.Background(), Options{Dir: dir, Packages: []string{"."}})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := set.Module("example.com/dep"); !ok || len(m.Files) != 2 {
		t.Fatalf("replaced module %+v", set.Modules)
	}
}
