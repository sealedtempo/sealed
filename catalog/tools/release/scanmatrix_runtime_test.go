package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// supply-5: Caddy, the sidecars and the key broker were in no scan matrix, so neither pull requests nor the
// weekly rescan scanned them (the verifier's zz_supply5_repro.sh, inverted). They are the sealed-runtime
// entry: in every full scan, and in a pull request that changes runtime-images.json.
func TestScanMatrixRuntimeImages(t *testing.T) {
	root := repoRoot(t)
	set, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	full := ScanMatrix(set, root, nil)
	rt := full[len(full)-1]
	if rt.App != RuntimeScanApp || rt.Waivers != RuntimeWaiversFile || rt.Dir != "" {
		t.Fatalf("the full matrix ends with the runtime entry: %+v", rt)
	}
	var pins struct {
		Images map[string]struct{ Digest, Source string } `json:"images"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(root, RuntimeImagesFile))), &pins); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for name := range pins.Images {
		want[name] = true
	}
	extra, err := loadExtraImages(root)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := LoadBuildSettings(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range settings.Extra {
		if fileExists(filepath.Join(root, e.Dir, "Dockerfile")) {
			want[e.Name] = true
		}
	}
	got := map[string]ScanImage{}
	for _, img := range rt.Images {
		got[img.Name] = img
	}
	if len(got) != len(want) || len(rt.Images) != len(want) {
		t.Fatalf("runtime entry %v, want every image of %s and %s: %v", rt.Images, RuntimeImagesFile, ExtraImagesFile, want)
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("%s is not scanned", name)
		}
	}
	repo, _, _ := splitSource(pins.Images["caddy"].Source)
	if c := got["caddy"]; c.Ref != repo+"@"+pins.Images["caddy"].Digest || c.Unbuilt {
		t.Errorf("caddy is scanned at its upstream digest: %+v", c)
	}
	for name, img := range got {
		digest := pins.Images[name].Digest
		if x, ok := extra.Images[name]; ok {
			digest = x.Digest
		}
		if img.Unbuilt != (digest == zeroDigest) || (img.Ref == "") != img.Unbuilt {
			t.Errorf("%s (pinned %s): %+v", name, digest, img)
		}
	}
	if !want["sealed-key-broker"] || !want["sealed-agent"] {
		t.Fatalf("the key broker and the agent are runtime images: %v", want)
	}
	for _, a := range full[:len(full)-1] {
		if a.App == RuntimeScanApp {
			t.Fatal("one runtime entry")
		}
	}
	if only := ScanMatrix(set, root, []string{RuntimeScanApp}); len(only) != 1 || only[0].App != RuntimeScanApp {
		t.Fatalf("--apps %s: %+v", RuntimeScanApp, only)
	}
	for _, a := range ScanMatrix(set, root, []string{"crm"}) {
		if a.App == RuntimeScanApp {
			t.Fatal("an app selection without sealed-runtime does not scan the runtime images")
		}
	}

	// A built sidecar is scanned at the catalog registry by digest.
	fx := fixtureRepo(t)
	p := filepath.Join(fx, RuntimeImagesFile)
	writeFile(t, p, strings.Replace(readFile(t, p), `"digest": "`+zeroDigest+`",
      "source": "build:runtime/agent"`, `"digest": "sha256:`+strings.Repeat("ab", 32)+`",
      "source": "build:runtime/agent"`, 1))
	fset, err := LoadImages(fx)
	if err != nil {
		t.Fatal(err)
	}
	fm := ScanMatrix(fset, fx, []string{RuntimeScanApp})
	for _, img := range fm[0].Images {
		if img.Name == "sealed-agent" && (img.Ref != "ghcr.io/sealedtempo/sealed-agent@sha256:"+strings.Repeat("ab", 32) || img.Unbuilt) {
			t.Errorf("built sealed-agent: %+v", img)
		}
	}
}

// supply-5 in the catalog workflow: a pull request that only changes runtime-images.json scanned nothing;
// now it scans the runtime images (and skips the per-app catalog lint, which has no app directory).
func TestCatalogWorkflowScansRuntimeImages(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "base")
	base := gitRun(t, root, "rev-parse", "HEAD")
	p := filepath.Join(root, RuntimeImagesFile)
	writeFile(t, p, strings.Replace(readFile(t, p), `"license_spdx": "Apache-2.0",
      "notes": "Index digest;`, `"license_spdx": "Apache-2.0",
      "notes": "Re-checked. Index digest;`, 1))
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "pr: caddy notes")

	f := newFakes(t)
	bins := t.TempDir()
	for src, dst := range map[string]string{releaseBin(t): "release", sealedComposeBin(t): "sealed-compose"} {
		if err := copyFile(src, filepath.Join(bins, dst)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(f.bin, "go"), fakeGo)
	_ = os.Chmod(filepath.Join(f.bin, "go"), 0o755)
	report := filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, report, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)

	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/catalog.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	sim := &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(), path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+report),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "pull_request", "token": "fake-token", "repository": "sealedtempo/sealed", "actor": "dev",
				"event": map[string]any{"pull_request": map[string]any{"base": map[string]any{"sha": base}}}},
			"inputs":  map[string]any{"apps": ""},
			"secrets": map[string]any{},
			"vars":    map[string]any{},
		},
		ifs:  map[string]bool{"github.event_name == 'pull_request'": true, "always()": true, "matrix.app != 'sealed-runtime'": false},
		skip: map[string]bool{"Schema and composer lint tests": true},
	}
	lint := sim.runJob("lint", nil)
	var matrix struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(lint["scan"])), &matrix); err != nil {
		t.Fatal(err)
	}
	if lint["count"] != "1" || matrix.Include[0]["app"] != RuntimeScanApp || matrix.Include[0]["waivers"] != RuntimeWaiversFile {
		t.Fatalf("a runtime-images.json change scans the runtime images: %v", lint)
	}
	sim.ctx["needs"] = map[string]any{"lint": map[string]any{"outputs": lint}}
	sim.runJob("scan", matrix.Include[0])
	var pins struct {
		Images map[string]struct{ Digest, Source string } `json:"images"`
	}
	if err := json.Unmarshal([]byte(readFile(t, p)), &pins); err != nil {
		t.Fatal(err)
	}
	repo, _, _ := splitSource(pins.Images["caddy"].Source)
	mustContain(t, f.calls(t), "syft scan registry:"+repo+"@"+pins.Images["caddy"].Digest)
	if !fileExists(filepath.Join(sim.artifacts, "scan-"+RuntimeScanApp, "summary/caddy.summary.json")) {
		t.Fatal("the caddy scan summary is in the scan artifact")
	}
}
