package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The runtime image workflow end to end in the emulator: plan every image, build and push each (fake
// docker and crane), scan it, then open the catalog and runtime pin PRs against a local git remote.
func TestImagesWorkflowEndToEnd(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	remote := t.TempDir()
	gitRun(t, remote, "init", "-q", "--bare")
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "fixture")
	gitRun(t, root, "remote", "add", "origin", remote)
	gitRun(t, root, "push", "-q", "origin", "main")
	commit := gitRun(t, root, "rev-parse", "HEAD")

	f := newFakes(t)
	installImageFakes(t, f) // the build job signs every pushed image
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
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/images.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	sim := &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(), path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+report,
			"GITHUB_SHA="+commit, "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/images.yml@refs/heads/main", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid"),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "workflow_dispatch", "token": "fake-token", "repository": "sealedtempo/sealed",
				"server_url": "https://github.com", "run_id": "7", "actor": "sealedtempo", "event": map[string]any{"before": ""}},
			"inputs":  map[string]any{"images": "all", "verify_reproducible": true},
			"secrets": map[string]any{},
			"vars":    map[string]any{},
		},
		ifs:  map[string]bool{"needs.build.result != 'success'": false, "env.DOCKERHUB_USERNAME != ''": false},
		skip: map[string]bool{"Free disk space": true},
	}
	plan := sim.runJob("plan", nil)
	var matrix struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(plan["matrix"])), &matrix); err != nil {
		t.Fatal(err)
	}
	if plan["count"] != "6" || len(matrix.Include) != 6 {
		t.Fatalf("plan: %v", plan)
	}
	sim.ctx["needs"] = map[string]any{"plan": map[string]any{"outputs": plan}, "build": map[string]any{"result": "success"}}
	for _, e := range matrix.Include {
		sim.runJob("build", e)
	}
	calls := f.calls(t)
	if n := strings.Count(calls, "--no-cache"); n != 6 {
		t.Fatalf("%d reproducibility rebuilds, want 6", n)
	}
	// Two syft runs per image: the shipped SBOM and the every-file listing for lint (review policy-1).
	if n := strings.Count(calls, "syft scan registry:ghcr.io/sealedtempo/"); n != 12 {
		t.Fatalf("%d scans, want 12", n)
	}
	if n := strings.Count(calls, "/scan/files/"); n != 6 {
		t.Fatalf("%d file listings, want 6", n)
	}
	sim.runJob("pin", nil)

	catalogBranch, runtimeBranch := "release/pin-catalog-"+commit[:12], "release/pin-runtime-"+commit[:12]
	if got := gitRun(t, remote, "show", "--name-only", "--format=", catalogBranch); got != "catalog/apps/llm-gateway/manifest.yaml" {
		t.Fatalf("catalog PR files: %q", got)
	}
	if got := gitRun(t, remote, "show", "--name-only", "--format=", runtimeBranch); got != RuntimeImagesFile {
		t.Fatalf("runtime PR files: %q", got)
	}
	ri := gitRun(t, remote, "show", runtimeBranch+":"+RuntimeImagesFile)
	if strings.Contains(ri, `"unbuilt"`) || strings.Count(ri, zeroDigest) != 0 {
		t.Fatalf("every sidecar is pinned:\n%s", ri)
	}
	manifest := gitRun(t, remote, "show", catalogBranch+":catalog/apps/llm-gateway/manifest.yaml")
	if strings.Contains(manifest, "sha256:"+strings.Repeat("2", 64)) {
		t.Fatal("the gateway digest must be the new build's")
	}
	if n := strings.Count(f.calls(t), "gh pr create --base main"); n != 2 {
		t.Fatalf("%d pin PRs, want 2", n)
	}
}
