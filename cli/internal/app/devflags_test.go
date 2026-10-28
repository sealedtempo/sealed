package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/cli/internal/settings"
	"github.com/sealed-dev/sealed/cli/internal/testkit"
)

// unbuiltNotes copies the composer's notes fixture with its first image digest set to the all-zero placeholder.
func unbuiltNotes(t *testing.T, h *harness) string {
	t.Helper()
	catalog := filepath.Join(h.dir, "unbuilt-apps")
	copyDir(t, filepath.Join(testkit.RepoRoot(), "runtime", "composer", "testdata", "apps", "notes"), filepath.Join(catalog, "notes"))
	manifest := filepath.Join(catalog, "notes", "manifest.yaml")
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	real := "sha256:" + strings.Repeat("1", 64)
	if !bytes.Contains(b, []byte(real)) {
		t.Fatalf("fixture manifest no longer has digest %s", real)
	}
	zero := "sha256:" + strings.Repeat("0", 64)
	if err := os.WriteFile(manifest, bytes.Replace(b, []byte(real), []byte(zero), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	return catalog
}

// Regression (devnet-e2e): release build printed publishRelease arguments for bundles whose images still had the
// all-zero placeholder digest, which can never boot. It now refuses them unless the dev flag is given in dev mode.
func TestReleaseBuildRefusesUnbuiltImages(t *testing.T) {
	h := newHarness(t)
	catalog := unbuiltNotes(t, h)
	out := filepath.Join(h.dir, "notes.tar")

	code, stdout, errs := h.run("release", "build", "notes", "--catalog", catalog, "--out", out)
	if code != ExitFailed || !strings.Contains(errs, "placeholder digest") || !strings.Contains(errs, "notes-web") {
		t.Fatalf("unbuilt build: %d\n%s\n%s", code, stdout, errs)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused build must not write the bundle")
	}

	// The dev flag is refused outside dev mode.
	code, _, errs = h.run("release", "build", "notes", "--catalog", catalog, "--dev-allow-unbuilt")
	if code != ExitUsage || !strings.Contains(errs, "SEALED_DEV_SIM=1") {
		t.Fatalf("dev flag without dev mode: %d\n%s", code, errs)
	}

	// In dev mode the bundle builds and the JSON names the unbuilt image.
	h.env["SEALED_DEV_SIM"] = "1"
	code, stdout, errs = h.run("release", "build", "notes", "--catalog", catalog, "--dev-allow-unbuilt", "--out", out, "--json")
	if code != ExitOK {
		t.Fatalf("dev build: %d\n%s\n%s", code, stdout, errs)
	}
	var doc struct {
		Unbuilt []string `json:"unbuilt"`
		Release struct {
			BundleHash string `json:"bundleHash"`
		} `json:"release"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil || len(doc.Unbuilt) != 1 || doc.Unbuilt[0] != "notes-web" || doc.Release.BundleHash == "" {
		t.Fatalf("dev build output: %v %s", err, stdout)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}

	// A built manifest needs no flag.
	delete(h.env, "SEALED_DEV_SIM")
	if code, stdout, errs := h.run("release", "build", "notes", "--catalog", filepath.Join(testkit.RepoRoot(), "runtime", "composer", "testdata", "apps")); code != ExitOK {
		t.Fatalf("built manifest: %d\n%s\n%s", code, stdout, errs)
	}
}

// Regression (devnet-e2e): sealed verify could not fetch release bundles from a local devnet's plain http asset
// server (only tests could allow it). --dev-allow-http-assets allows it in dev mode only.
func TestDevAllowHTTPAssets(t *testing.T) {
	h := newHarness(t)
	code, _, errs := h.run("catalog", "list", "--dev-allow-http-assets")
	if code != ExitUsage || !strings.Contains(errs, "SEALED_DEV_SIM=1") {
		t.Fatalf("without dev mode: %d\n%s", code, errs)
	}

	e := &Env{Getenv: func(k string) string {
		if k == "SEALED_DEV_SIM" {
			return "1"
		}
		return ""
	}}
	s, err := settings.Load(settings.Options{})
	if err != nil {
		t.Fatal(err)
	}
	plain := commonFlags{assetBase: "http://127.0.0.1:1/releases/download"}
	if plain.fetcher(e, s).AllowHTTP {
		t.Fatal("http assets must stay refused without the flag")
	}
	dev := commonFlags{assetBase: "http://127.0.0.1:1/releases/download", devHTTPAssets: true}
	if _, err := dev.settings(e); err != nil {
		t.Fatalf("dev mode settings: %v", err)
	}
	if !dev.fetcher(e, s).AllowHTTP {
		t.Fatal("the dev flag must allow an http asset base")
	}
}
