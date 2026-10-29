package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Runtime image CI after the pre-publish review (supply-4): images-pr.yml runs the no-cache rebuild check on
// pull requests.

func imagesSim(t *testing.T, file, root string, f *fakeEnv, event string, extraEnv ...string) *simulator {
	t.Helper()
	bins := t.TempDir()
	for src, dst := range map[string]string{releaseBin(t): "release", sealedComposeBin(t): "sealed-compose"} {
		if err := copyFile(src, filepath.Join(bins, dst)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(f.bin, "go"), fakeGo)
	_ = os.Chmod(filepath.Join(f.bin, "go"), 0o755)
	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows", file))), &wf); err != nil {
		t.Fatal(err)
	}
	return &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(), path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins,
			"GITHUB_SHA="+gitRun(t, root, "rev-parse", "HEAD")), extraEnv...),
		ctx: map[string]any{
			"github": map[string]any{"event_name": event, "token": "fake-token", "repository": "sealedtempo/sealed",
				"server_url": "https://github.com", "run_id": "8", "actor": "sealedtempo", "event": map[string]any{}},
			"inputs":  map[string]any{},
			"secrets": map[string]any{},
			"vars":    map[string]any{},
		},
		skip: map[string]bool{"Free disk space": true},
	}
}

func planNames(t *testing.T, plan map[string]any) []string {
	t.Helper()
	var m struct {
		Include []BuildImage `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(plan["matrix"])), &m); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range m.Include {
		names = append(names, b.Name)
	}
	return names
}

// supply-4: the pull request job rebuilds each changed image without cache and fails on a digest mismatch.
// It never pushes, signs or logs in, and it leaves out unbuilt images the pull request does not touch.
func TestImagesPRWorkflowChecksReproducibility(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "base")
	base := gitRun(t, root, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(root, CatalogDir, "llm-gateway/images/gateway/Dockerfile"), "FROM scratch\nLABEL x=y\n")
	gitRun(t, root, "commit", "-q", "-am", "pull request")

	for _, nondeterministic := range []bool{false, true} {
		f := newFakes(t)
		var extra []string
		if nondeterministic {
			extra = append(extra, "FAKE_DOCKER_NONDETERMINISTIC=1")
		}
		sim := imagesSim(t, "images-pr.yml", root, f, "pull_request", extra...)
		sim.ctx["github"].(map[string]any)["event"] = map[string]any{"pull_request": map[string]any{"base": map[string]any{"sha": base}}}
		plan := sim.runJob("plan", nil)
		// The five sidecars are unbuilt in the fixture; images.yml would build them, this check does not.
		if got := planNames(t, plan); plan["count"] != "1" || strings.Join(got, ",") != "gateway" {
			t.Fatalf("pull request plan: %v %v", plan["count"], got)
		}
		var m struct {
			Include []map[string]any `json:"include"`
		}
		if err := json.Unmarshal([]byte(toStr(plan["matrix"])), &m); err != nil {
			t.Fatal(err)
		}
		_, err := sim.runJobErr("reproducible", m.Include[0])
		calls := f.calls(t)
		if nondeterministic {
			if err == nil || !strings.Contains(err.Error(), "error: not reproducible") {
				t.Fatalf("a digest mismatch must fail the job: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if strings.Count(calls, "docker buildx build") != 2 || strings.Count(calls, "--no-cache") != 1 {
			t.Fatalf("want one build and one rebuild without cache:\n%s", calls)
		}
		for _, l := range strings.Split(calls, "\n") {
			for _, banned := range []string{"docker login", "crane ", "cosign ", "gh "} {
				if strings.HasPrefix(l, banned) || strings.Contains(l, "push=true") {
					t.Fatalf("the pull request job must not push, sign or log in: %s", l)
				}
			}
		}
	}
}

type shapeJob struct {
	Permissions map[string]string `yaml:"permissions"`
	Steps       []simStep         `yaml:"steps"`
}

type shapeWorkflow struct {
	On          map[string]any      `yaml:"on"`
	Permissions map[string]string   `yaml:"permissions"`
	Env         map[string]string   `yaml:"env"`
	Jobs        map[string]shapeJob `yaml:"jobs"`
}

func loadShape(t *testing.T, name string) (shapeWorkflow, string) {
	t.Helper()
	raw := readFile(t, filepath.Join(repoRoot(t), ".github/workflows", name))
	var w shapeWorkflow
	if err := yaml.Unmarshal([]byte(raw), &w); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(raw, "\u2014\u2013") {
		t.Errorf("%s contains an em-dash or en-dash", name)
	}
	return w, raw
}

func TestImagesPRWorkflowShape(t *testing.T) {
	pr, prRaw := loadShape(t, "images-pr.yml")
	images, _ := loadShape(t, "images.yml")
	if len(pr.On) != 1 || pr.On["pull_request"] == nil {
		t.Errorf("images-pr.yml runs on pull requests only: %v", pr.On)
	}
	paths := toStr(pr.On["pull_request"])
	for _, p := range []string{"**/Dockerfile", "catalog/apps/**/images/**", "catalog/tools/release/images.yaml", "scripts/release/build-image.sh"} {
		if !strings.Contains(paths, `"`+p+`"`) {
			t.Errorf("images-pr.yml does not run for %s: %s", p, paths)
		}
	}
	if len(pr.Permissions) != 0 {
		t.Errorf("images-pr.yml top-level permissions must be empty: %v", pr.Permissions)
	}
	for name, j := range pr.Jobs {
		if len(j.Permissions) != 1 || j.Permissions["contents"] != "read" {
			t.Errorf("images-pr.yml %s gets only contents: read, got %v", name, j.Permissions)
		}
	}
	for _, banned := range []string{"${{ secrets.", "--push", "sign-image.sh", "cosign", "login"} {
		if strings.Contains(prRaw, banned) {
			t.Errorf("images-pr.yml contains %q", banned)
		}
	}
	mustContain(t, prRaw, "--verify-reproducible")
	if pr.Env["BUILDKIT_IMAGE"] != images.Env["BUILDKIT_IMAGE"] || pr.Env["BUILDX_VERSION"] != images.Env["BUILDX_VERSION"] || pr.Env["BUILDKIT_IMAGE"] == "" {
		t.Errorf("both workflows build with the same BuildKit: %q %q", pr.Env["BUILDKIT_IMAGE"], images.Env["BUILDKIT_IMAGE"])
	}
}

func TestBuildMatrixChangedOnly(t *testing.T) {
	root := fixtureRepo(t)
	changed := filepath.Join(t.TempDir(), "changed.txt")
	writeFile(t, changed, "catalog/apps/llm-gateway/images/gateway/Dockerfile\n")
	plan := func(args ...string) ([]string, error) {
		var out, errb bytes.Buffer
		if err := cmdImages(append([]string{"--root", root, "--format", "build-matrix"}, args...), &out, &errb); err != nil {
			return nil, err
		}
		names := planNames(t, map[string]any{"matrix": out.String()})
		return names, nil
	}
	got, err := plan("--changed", changed)
	if err != nil || len(got) != 6 {
		t.Fatalf("--changed plans the change and every unbuilt image: %v %v", got, err)
	}
	if got, err = plan("--changed", changed, "--changed-only"); err != nil || strings.Join(got, ",") != "gateway" {
		t.Fatalf("--changed-only: %v %v", got, err)
	}
	writeFile(t, changed, "docs/x.md\n")
	if got, err = plan("--changed", changed, "--changed-only"); err != nil || len(got) != 0 {
		t.Fatalf("--changed-only with nothing relevant: %v %v", got, err)
	}
	for _, bad := range [][]string{{"--changed-only"}, {"--changed", changed, "--changed-only", "--all"}, {"--changed", changed, "--changed-only", "--names", "gateway"}} {
		if _, err := plan(bad...); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
}
