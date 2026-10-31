package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The pull request catalog checks in the emulator, on a fixture catalog whose PR unpins the gateway image:
// the lint gate defers the unbuilt image, the bump rule passes (nothing released yet), the compose check
// runs the real composer and docker compose config, and the scan job scans the pinned images and notes
// the unbuilt one.
func TestCatalogWorkflowEndToEnd(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "base")
	base := gitRun(t, root, "rev-parse", "HEAD")
	p := filepath.Join(root, CatalogDir, "llm-gateway/manifest.yaml")
	writeFile(t, p, strings.Replace(readFile(t, p), "sha256:"+strings.Repeat("2", 64), zeroDigest, 1))
	writeFile(t, filepath.Join(root, CatalogDir, "notes/README.md"), "notes\n")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "pr: unpin the gateway image, document notes")

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
	realDocker, _ := exec.LookPath("docker")

	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/catalog.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	sim := &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(), path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+report,
			"REAL_DOCKER="+realDocker),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "pull_request", "token": "fake-token", "repository": "sealedtempo/sealed", "actor": "dev",
				"event": map[string]any{"pull_request": map[string]any{"base": map[string]any{"sha": base}}}},
			"inputs":  map[string]any{"apps": ""},
			"secrets": map[string]any{},
			"vars":    map[string]any{},
		},
		ifs:  map[string]bool{"github.event_name == 'pull_request'": true, "always()": true, "matrix.app != 'sealed-runtime'": true},
		skip: map[string]bool{"Schema and composer lint tests": true, "Pinned Caddy binary": true, "Composer golden and compose tests": true},
	}
	lint := sim.runJob("lint", nil)
	var matrix struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(lint["scan"])), &matrix); err != nil {
		t.Fatal(err)
	}
	if lint["count"] != "2" || matrix.Include[0]["app"] != "llm-gateway" || matrix.Include[1]["app"] != "notes" {
		t.Fatalf("the PR changes llm-gateway and notes: %v", lint)
	}
	// Only the bundle input change (the gateway manifest) is subject to the bump rule.
	mustContain(t, f.calls(t), "gh release view llm-gateway-v2.3.4")
	if strings.Contains(f.calls(t), "gh release view notes-") {
		t.Fatal("a README change needs no version bump")
	}

	if realDocker != "" {
		sim.runJob("compose", nil)
	}

	sim.ctx["needs"] = map[string]any{"lint": map[string]any{"outputs": lint}}
	for _, e := range matrix.Include {
		sim.runJob("scan", e)
	}
	if dirExists(filepath.Join(sim.artifacts, "scan-llm-gateway")) {
		t.Fatal("the unbuilt gateway image is not scanned")
	}
	art := filepath.Join(sim.artifacts, "scan-notes")
	for _, f := range []string{"summary/notes-web.summary.json", "summary/postgres.summary.json", "sbom/postgres.spdx.json", "files/postgres.spdx.json", "scan/notes-web.json"} {
		if !fileExists(filepath.Join(art, f)) {
			t.Fatalf("%s missing from the scan artifact", f)
		}
	}
	// Mirrored images are scanned at their upstream digest.
	mustContain(t, f.calls(t), "syft scan registry:docker.io/library/postgres@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b")
}

// TestCatalogWorkflowFailsOnUnownedExcludedFile drives the PR catalog scan job with a syft that lists one
// file no package owns under an excluded path, but only in the every-file listing (files/), not in the
// shipped owned-by-package SBOM. The catalog lint step must copy files/ (not sbom/) into the lint dir, so
// the excluded-path check sees that file and the job fails. Reverting catalog.yml to copy sbom/ (the fix's
// old code) makes the file invisible to lint and the job passes, so this test fails on that revert.
func TestCatalogWorkflowFailsOnUnownedExcludedFile(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "base")
	base := gitRun(t, root, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(root, CatalogDir, "notes/README.md"), "notes\n")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "pr: document notes")

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
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+report,
			"FAKE_SYFT_UNOWNED=/app/enterprise/x.py"),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "pull_request", "token": "fake-token", "repository": "sealedtempo/sealed", "actor": "dev",
				"event": map[string]any{"pull_request": map[string]any{"base": map[string]any{"sha": base}}}},
			"inputs":  map[string]any{"apps": ""},
			"secrets": map[string]any{},
			"vars":    map[string]any{},
		},
		// This scan runs with the "notes" matrix entry, so the sealed-runtime guard on the catalog lint
		// step (supply-5) is true and the per-app catalog lint runs.
		ifs:  map[string]bool{"github.event_name == 'pull_request'": true, "always()": true, "matrix.app != 'sealed-runtime'": true},
		skip: map[string]bool{"Schema and composer lint tests": true, "Composer golden and compose tests": true},
	}
	lint := sim.runJob("lint", nil)
	var matrix struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(lint["scan"])), &matrix); err != nil {
		t.Fatal(err)
	}
	sim.ctx["needs"] = map[string]any{"lint": map[string]any{"outputs": lint}}
	var notes map[string]any
	for _, e := range matrix.Include {
		if e["app"] == "notes" {
			notes = e
		}
	}
	if notes == nil {
		t.Fatalf("no notes entry in the scan matrix: %v", matrix.Include)
	}
	_, err := sim.runJobErr("scan", notes)
	if err == nil {
		t.Fatal("the scan job passed, but the file listing has an excluded path no package owns")
	}
	if !strings.Contains(err.Error(), "excluded-path") {
		t.Fatalf("the scan job failed, but not on the excluded path: %v", err)
	}
}
