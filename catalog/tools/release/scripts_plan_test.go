package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/runtime/composer"
)

func TestPlanReleasesScriptOnAnvil(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	requireJQ(t)
	c := deployContracts(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	env := f.env("GH_REPO=sealedtempo/sealed", "TEMPO_RPC_URL="+c.rpc, "EXPECT_CHAIN_ID=31337", "DEPLOYMENTS_FILE="+c.deployments)
	out := filepath.Join(t.TempDir(), "matrix.json")
	send := func(key string, args ...string) {
		t.Helper()
		full := append([]string{"send"}, args...)
		full = append(full, "--private-key", key, "--rpc-url", c.rpc, "--tempo.fee-token", alphaUSD)
		if b, err := exec.Command("cast", full...).CombinedOutput(); err != nil {
			t.Fatalf("cast %v: %v %s", args, err, b)
		}
	}
	send(devOwner, c.registry, "registerApp(bytes32,string,string,string,address,uint16,string)", composer.AppID("notes").Hex(), "notes", "Notes",
		"MIT", castAddr(t, devMaintainer), "2000", "https://example.invalid/notes")

	// llm-gateway (fixture) is not registered: the plan refuses it.
	r := runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "all", "--out", out)
	if r.code == 0 || !strings.Contains(r.output, "title=not-registered::llm-gateway is not registered") {
		t.Fatalf("unregistered: %d\n%s", r.code, r.output)
	}
	r = runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "notes", "--out", out)
	if r.code != 0 {
		t.Fatalf("plan: %d\n%s", r.code, r.output)
	}
	var m struct {
		Include []struct {
			PlannedRelease
			GithubRelease string `json:"githubRelease"`
		} `json:"include"`
		Count int `json:"count"`
	}
	if err := readJSONFile(out, &m); err != nil || m.Count != 1 || m.Include[0].App != "notes" || m.Include[0].GithubRelease != "none" ||
		m.Include[0].Tag != "notes-v1.0.0-sealed.1" || m.Include[0].Assets.Bundle != "notes-1.0.0-sealed.1.bundle.tar" {
		t.Fatalf("matrix %+v %v", m, err)
	}
	// Changed-file selection: a README change plans nothing.
	changed := filepath.Join(t.TempDir(), "changed.txt")
	writeFile(t, changed, "catalog/apps/notes/README.md\n")
	if r = runScriptIn(t, root, "plan-releases.sh", env, "release", "--changed", changed, "--out", out); r.code != 0 || !strings.Contains(r.output, "releases to run: none") {
		t.Fatalf("no bundle change: %d\n%s", r.code, r.output)
	}

	// Onchain but no GitHub Release: inconsistent, fails. With the GitHub Release: complete, dropped.
	bh := composer.SHA256([]byte("notes bundle"))
	send(devOps, c.registry, "publishRelease(bytes32,string,bytes32,bytes32,bytes32,string,string)", composer.AppID("notes").Hex(), "1.0.0-sealed.1",
		bh.Hex(), bh.Hex(), bh.Hex(), "https://example.invalid/p", "https://example.invalid/s")
	r = runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "notes", "--out", out)
	if r.code == 0 || !strings.Contains(r.output, "is published onchain") {
		t.Fatalf("incomplete: %d\n%s", r.code, r.output)
	}
	if err := os.MkdirAll(filepath.Join(f.state, "gh/notes-v1.0.0-sealed.1/assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	r = runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "notes", "--out", out)
	if r.code != 0 || !strings.Contains(r.output, "is released (onchain") || !strings.Contains(r.output, "releases to run: none") {
		t.Fatalf("complete: %d\n%s", r.code, r.output)
	}

	// pr-check: a released version cannot take a bundle change.
	writeFile(t, changed, "catalog/apps/notes/egress.yaml\ncatalog/apps/llm-gateway/compose.fragment.yaml\n")
	r = runScriptIn(t, root, "plan-releases.sh", env, "pr-check", "--changed", changed)
	if r.code != 1 || !strings.Contains(r.output, "notes 1.0.0-sealed.1 is already released (notes-v1.0.0-sealed.1); bump release_version") ||
		!strings.Contains(r.output, "ok   llm-gateway: llm-gateway-v2.3.4 is not released yet") {
		t.Fatalf("pr-check: %d\n%s", r.code, r.output)
	}
	// An app whose version cannot be released has no tag; pr-check skips it (plan warns) instead of
	// misreading its fields.
	writeFile(t, changed, "catalog/apps/notes/egress.yaml\n")
	np := filepath.Join(root, CatalogDir, "notes/manifest.yaml")
	orig := readFile(t, np)
	writeFile(t, np, strings.Replace(orig, "release_version: 1.0.0-sealed.1", "release_version: vnext", 1))
	r = runScriptIn(t, root, "plan-releases.sh", env, "pr-check", "--changed", changed)
	if r.code != 0 || strings.Contains(f.calls(t), "gh release view vnext") || !strings.Contains(r.output, "starts with \"v\"") {
		t.Fatalf("pr-check with a version problem: %d\n%s", r.code, r.output)
	}
	// v1.0.0 is tagged notes-v1.0.0 (one v), the tag of 1.0.0 too: once 1.0.0 is released, the other
	// spelling cannot be, and pr-check says so instead of letting the release job find the tag taken.
	writeFile(t, np, strings.Replace(orig, "release_version: 1.0.0-sealed.1", "release_version: v1.0.0", 1))
	r = runScriptIn(t, root, "plan-releases.sh", env, "pr-check", "--changed", changed)
	if r.code != 0 || !strings.Contains(r.output, "ok   notes: notes-v1.0.0 is not released yet") {
		t.Fatalf("pr-check v1.0.0: %d\n%s", r.code, r.output)
	}
	if err := os.MkdirAll(filepath.Join(f.state, "gh/notes-v1.0.0/assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	r = runScriptIn(t, root, "plan-releases.sh", env, "pr-check", "--changed", changed)
	if r.code != 1 || !strings.Contains(r.output, "notes v1.0.0 is already released (notes-v1.0.0); bump release_version") {
		t.Fatalf("pr-check v1.0.0 after 1.0.0: %d\n%s", r.code, r.output)
	}
	writeFile(t, np, orig)
	// Unbuilt images make --strict fail in release mode.
	p := filepath.Join(root, CatalogDir, "llm-gateway/manifest.yaml")
	writeFile(t, p, strings.Replace(readFile(t, p), "sha256:"+strings.Repeat("2", 64), zeroDigest, 1))
	r = runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "llm-gateway", "--out", out)
	if r.code == 0 || !strings.Contains(r.output, "all-zero placeholder digest") {
		t.Fatalf("unbuilt: %d\n%s", r.code, r.output)
	}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestOpenPinPRScript(t *testing.T) {
	requireJQ(t)
	if _, err := exec.LookPath("git"); err != nil {
		skipOrFail(t, "git not installed")
	}
	root := withScripts(t, fixtureRepo(t))
	remote := t.TempDir()
	gitRun(t, remote, "init", "-q", "--bare")
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "fixture")
	gitRun(t, root, "remote", "add", "origin", remote)
	gitRun(t, root, "push", "-q", "origin", "main")
	f := newFakes(t)
	results := t.TempDir()
	d1, d2 := "sha256:"+strings.Repeat("1a", 32), "sha256:"+strings.Repeat("2b", 32)
	writeFile(t, filepath.Join(results, "gateway.json"), mustJSON(t, BuildResult{Name: "gateway", Dir: "catalog/apps/llm-gateway/images/gateway", Digest: d1, Reproducible: boolPtr(true)}))
	writeFile(t, filepath.Join(results, "agent.json"), mustJSON(t, BuildResult{Name: "sealed-agent", Dir: "runtime/agent", Digest: d2}))
	commit := gitRun(t, root, "rev-parse", "HEAD")
	args := func(scope string) []string {
		return []string{"--scope", scope, "--results", results, "--run-url", "https://github.com/sealedtempo/sealed/actions/runs/7", "--commit", commit}
	}

	r := runScriptIn(t, root, "open-pin-pr.sh", f.env("DRY_RUN=1"), args("catalog")...)
	if r.code != 0 || !strings.Contains(r.output, "| gateway | `"+d1+"` | yes |") || gitRun(t, root, "status", "--porcelain") != "" {
		t.Fatalf("dry run: %d\n%s", r.code, r.output)
	}
	r = runScriptIn(t, root, "open-pin-pr.sh", f.env(), args("catalog")...)
	if r.code != 0 || !strings.HasSuffix(strings.TrimSpace(r.output), "https://github.com/sealedtempo/sealed/pull/42") {
		t.Fatalf("catalog PR: %d\n%s", r.code, r.output)
	}
	branch := "release/pin-catalog-" + commit[:12]
	files := gitRun(t, root, "show", "--name-only", "--format=", branch)
	if files != "catalog/apps/llm-gateway/manifest.yaml" {
		t.Fatalf("catalog PR files: %q", files)
	}
	if !strings.Contains(gitRun(t, remote, "branch", "--list", branch), branch) {
		t.Fatal("branch not pushed")
	}
	mustContain(t, f.calls(t), "gh pr create --base main --head "+branch+" --title catalog: pin image digests built from "+commit[:12])

	gitRun(t, root, "switch", "-q", "main")
	r = runScriptIn(t, root, "open-pin-pr.sh", f.env(), args("runtime")...)
	if r.code != 0 {
		t.Fatalf("runtime PR: %d\n%s", r.code, r.output)
	}
	files = gitRun(t, root, "show", "--name-only", "--format=", "release/pin-runtime-"+commit[:12])
	if files != RuntimeImagesFile {
		t.Fatalf("runtime PR files: %q", files)
	}
	mustContain(t, f.calls(t), "runtime: pin sidecar image digests built from")

	// Nothing to pin, no PR; a dirty tree is refused.
	gitRun(t, root, "switch", "-q", "main")
	empty := t.TempDir()
	if r = runScriptIn(t, root, "open-pin-pr.sh", f.env(), "--scope", "catalog", "--results", empty); r.code != 0 || !strings.Contains(r.output, "no catalog digest changed; no PR") {
		t.Fatalf("no change: %d\n%s", r.code, r.output)
	}
	writeFile(t, filepath.Join(root, "stray.txt"), "x")
	if r = runScriptIn(t, root, "open-pin-pr.sh", f.env(), args("catalog")...); r.code == 0 || !strings.Contains(r.output, "not clean") {
		t.Fatalf("dirty tree: %d\n%s", r.code, r.output)
	}
}

// A plan entry whose problem is an unbuilt image (all-zero placeholder digest) is skipped by
// `release --apps all --skip-unready` with a title=not-ready notice and left out of the matrix, while the
// same run without --skip-unready still fails (plan-releases.sh lines 89-92, supply-6 / G1). llm-gateway
// is registered here so it reaches the readiness check rather than the not-registered path.
func TestPlanReleasesScriptSkipsUnready(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	requireJQ(t)
	c := deployContracts(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	env := f.env("GH_REPO=sealedtempo/sealed", "TEMPO_RPC_URL="+c.rpc, "EXPECT_CHAIN_ID=31337", "DEPLOYMENTS_FILE="+c.deployments)
	out := filepath.Join(t.TempDir(), "matrix.json")

	// llm-gateway's only image keeps the all-zero placeholder digest: it is registered but not built.
	man := filepath.Join(root, CatalogDir, "llm-gateway", "manifest.yaml")
	writeFile(t, man, strings.Replace(readFile(t, man),
		"digest: sha256:2222222222222222222222222222222222222222222222222222222222222222",
		"digest: sha256:0000000000000000000000000000000000000000000000000000000000000000", 1))

	send := func(key string, args ...string) {
		t.Helper()
		full := append([]string{"send"}, args...)
		full = append(full, "--private-key", key, "--rpc-url", c.rpc, "--tempo.fee-token", alphaUSD)
		if b, err := exec.Command("cast", full...).CombinedOutput(); err != nil {
			t.Fatalf("cast %v: %v %s", args, err, b)
		}
	}
	for _, app := range []struct{ id, slug, name string }{{"notes", "notes", "Notes"}, {"llm-gateway", "llm-gateway", "Gateway"}} {
		send(devOwner, c.registry, "registerApp(bytes32,string,string,string,address,uint16,string)", composer.AppID(app.id).Hex(),
			app.slug, app.name, "MIT", castAddr(t, devMaintainer), "2000", "https://example.invalid/"+app.slug)
	}

	// --skip-unready: the unbuilt app is reported as not-ready, exits 0, and only notes is planned.
	r := runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "all", "--skip-unready", "--out", out)
	if r.code != 0 {
		t.Fatalf("--skip-unready must exit 0: %d\n%s", r.code, r.output)
	}
	if !strings.Contains(r.output, "title=not-ready::llm-gateway") || !strings.Contains(r.output, "all-zero placeholder digest") {
		t.Fatalf("--skip-unready must report llm-gateway as not-ready:\n%s", r.output)
	}
	var m struct {
		Include []struct {
			App string `json:"app"`
		} `json:"include"`
		Count int `json:"count"`
	}
	if err := readJSONFile(out, &m); err != nil || m.Count != 1 || len(m.Include) != 1 || m.Include[0].App != "notes" {
		t.Fatalf("an unbuilt app must be left out of the matrix: %+v %v\n%s", m, err, r.output)
	}

	// Without --skip-unready the same unbuilt app fails the plan.
	r = runScriptIn(t, root, "plan-releases.sh", env, "release", "--apps", "all", "--out", out)
	if r.code == 0 || !strings.Contains(r.output, "all-zero placeholder digest") {
		t.Fatalf("without --skip-unready an unbuilt app must fail: %d\n%s", r.code, r.output)
	}
}
