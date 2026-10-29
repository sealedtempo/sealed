package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/cli/internal/app"
	"github.com/sealedtempo/sealed/cli/internal/licenses"
)

func testOptions(t *testing.T, targets ...string) *options {
	t.Helper()
	o, err := parseFlags([]string{"--version", app.Version, "--root", filepath.Join("..", ".."), "--out", t.TempDir(), "--targets", strings.Join(targets, ",")}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// No compiler run in tests: the binary is a stand-in, the licenses are the real linked set.
	o.build = func(_ context.Context, _, goos, goarch, dst string) error {
		return os.WriteFile(dst, []byte("binary for "+goos+"/"+goarch), 0o755)
	}
	return o
}

type archived struct {
	mode int64
	data []byte
}

func readTarGz(t *testing.T, b []byte) map[string]archived {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]archived{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 315532800 {
			t.Fatalf("%s: owner %d:%d mtime %v", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		data, _ := io.ReadAll(tr)
		out[h.Name] = archived{h.Mode, data}
	}
}

func readZip(t *testing.T, b []byte) map[string]archived {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]archived{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = archived{int64(f.Mode().Perm()), data}
	}
	return out
}

// TestArchivesCarryTheLicenses: every release archive holds the binary, the repository LICENSE and licenses/ with
// go-ethereum's LGPL-3.0 and GPL-3.0 texts, the notice README and the Go LICENSE (license-audit F3), and two runs
// give identical bytes.
func TestArchivesCarryTheLicenses(t *testing.T) {
	ctx := context.Background()
	o := testOptions(t, "linux/amd64", "windows/amd64")
	if err := o.release(ctx); err != nil {
		t.Fatal(err)
	}
	o2 := testOptions(t, "linux/amd64", "windows/amd64")
	if err := o2.release(ctx); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(o.out, "SHA256SUMS"))
	sums2, _ := os.ReadFile(filepath.Join(o2.out, "SHA256SUMS"))
	if len(sums) == 0 || !bytes.Equal(sums, sums2) {
		t.Fatalf("archives differ between runs:\n%s\n%s", sums, sums2)
	}
	for _, tc := range []struct {
		name, bin string
		read      func(*testing.T, []byte) map[string]archived
	}{
		{"sealed_" + app.Version + "_linux_amd64.tar.gz", "sealed", readTarGz},
		{"sealed_" + app.Version + "_windows_amd64.zip", "sealed.exe", readZip},
	} {
		raw, err := os.ReadFile(filepath.Join(o.out, tc.name))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(raw)
		if !strings.Contains(string(sums), hex.EncodeToString(h[:])+"  "+tc.name+"\n") {
			t.Fatalf("SHA256SUMS lacks %s:\n%s", tc.name, sums)
		}
		files := tc.read(t, raw)
		base := strings.TrimSuffix(strings.TrimSuffix(tc.name, ".tar.gz"), ".zip") + "/"
		bin, ok := files[base+tc.bin]
		if !ok || bin.mode != 0o755 || !strings.HasPrefix(string(bin.data), "binary for ") {
			t.Fatalf("%s: binary %+v", tc.name, bin)
		}
		for _, want := range []struct{ path, text string }{
			{"LICENSE", "Apache License"},
			{"README.md", "sealed CLI"},
			{"licenses/README", "GNU Lesser General"},
			{"licenses/github.com/ethereum/go-ethereum/COPYING.LESSER", "GNU LESSER GENERAL PUBLIC LICENSE"},
			{"licenses/github.com/ethereum/go-ethereum/COPYING", "GNU GENERAL PUBLIC LICENSE"},
			{"licenses/github.com/ethereum/go-ethereum/metrics/LICENSE", "Richard Crowley"},
			{"licenses/go/LICENSE", "The Go Authors"},
		} {
			f, ok := files[base+want.path]
			if !ok || f.mode != 0o644 || !strings.Contains(string(f.data), want.text) {
				t.Errorf("%s: %s missing or wrong (mode %o)", tc.name, want.path, f.mode)
			}
		}
		readme := string(files[base+"licenses/README"].data)
		for _, want := range []string{"https://github.com/sealedtempo/sealed/tree/cli-v" + app.Version, "go mod edit -replace github.com/ethereum/go-ethereum=", "./cli/cmd/sealed"} {
			if !strings.Contains(readme, want) {
				t.Errorf("%s: licenses/README lacks %q", tc.name, want)
			}
		}
		if strings.Contains(readme, "\u2014") {
			t.Error("em-dash in licenses/README")
		}
	}
}

func TestLicensesOnly(t *testing.T) {
	dir := t.TempDir()
	o, err := parseFlags([]string{"--version", app.Version, "--root", filepath.Join("..", ".."), "--licenses-only", dir}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.targets) != 1 || o.targets[0] != hostTarget() {
		t.Fatalf("targets %v", o.targets)
	}
	if err := o.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"README", "go/LICENSE", "github.com/ethereum/go-ethereum/COPYING.LESSER"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(f))); err != nil {
			t.Errorf("licenses-only lacks %s", f)
		}
	}
}

func TestFlags(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	o, err := parseFlags([]string{"--version", app.Version}, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.tag != "cli-v"+app.Version || o.sourceURL != "https://github.com/sealedtempo/sealed" || len(o.targets) != len(DefaultTargets) || o.epoch.Unix() != 315532800 {
		t.Fatalf("defaults %+v", o)
	}
	if o, err := parseFlags([]string{"--version", app.Version}, env(map[string]string{"SOURCE_DATE_EPOCH": "1793200300"}), io.Discard); err != nil || o.epoch.Unix() != 1793200300 {
		t.Fatalf("SOURCE_DATE_EPOCH: %v", err)
	}
	for name, args := range map[string][]string{
		"no version":    {},
		"other version": {"--version", "9.9.9"},
		"http source":   {"--version", app.Version, "--source-url", "http://example.com/x"},
		"bad target":    {"--version", app.Version, "--targets", "linux"},
		"extra args":    {"--version", app.Version, "x"},
	} {
		if _, err := parseFlags(args, env(nil), io.Discard); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := parseFlags([]string{"--version", app.Version}, env(map[string]string{"SOURCE_DATE_EPOCH": "5"}), io.Discard); err == nil {
		t.Error("an epoch before 1980 accepted")
	}
}

// TestRefusesStaticGPL: a GPL-only or AGPL module would make the statically linked CLI a GPL work.
func TestRefusesStaticGPL(t *testing.T) {
	for name, text := range map[string]string{"gpl": "GNU GENERAL PUBLIC LICENSE\nVersion 3", "agpl": "GNU AFFERO GENERAL PUBLIC LICENSE"} {
		o := testOptions(t, "linux/amd64")
		o.collect = func(context.Context, licenses.Options) (*licenses.Set, error) {
			return &licenses.Set{GOOS: "linux", GOARCH: "amd64", Modules: []licenses.Module{{Path: "example.com/copyleft", Version: "v1.0.0", Files: []licenses.File{{Name: "LICENSE", Data: []byte(text)}}}},
				Go: []licenses.File{{Name: "LICENSE", Data: []byte("x")}}}, nil
		}
		if err := o.release(context.Background()); err == nil || !strings.Contains(err.Error(), "example.com/copyleft") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
