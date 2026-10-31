package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Runtime image CI after the pre-publish review (supply-3, supply-4 and supply-6, images.yml half):
// images.yml signs every pushed digest keyless and plans from the last successful push run, and
// images-pr.yml runs the no-cache rebuild check on pull requests.

const mainImagesIdentity = "https://github.com/sealedtempo/sealed/.github/workflows/images.yml@refs/heads/main"

// fakeCosignImages adds `sign` and `verify` for image references to the shared fake cosign. sign records the
// identity Fulcio would certify (https://github.com/$GITHUB_WORKFLOW_REF) for the reference; verify passes
// only for a signed reference whose identity and issuer match the flags. Other commands go to the shared fake.
const fakeCosignImages = `#!/usr/bin/env bash
set -euo pipefail
key() { printf '%s' "$1" | tr '/:@' '___'; }
case "$1" in
sign)
  echo "cosign $*" >>"$FAKE_LOG"
  ref="${!#}"
  mkdir -p "$FAKE_STATE/cosign-images"
  printf '%s\n' "https://github.com/$GITHUB_WORKFLOW_REF" >"$FAKE_STATE/cosign-images/$(key "$ref")" ;;
verify)
  echo "cosign $*" >>"$FAKE_LOG"
  [ "${FAKE_COSIGN_VERIFY_FAIL:-0}" = 1 ] && { echo "no matching signatures" >&2; exit 1; }
  ident="" issuer="" ref=""
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
    --certificate-identity) ident="$2"; shift 2 ;;
    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
    -*) shift ;;
    *) ref="$1"; shift ;;
    esac
  done
  f="$FAKE_STATE/cosign-images/$(key "$ref")"
  [ -f "$f" ] || { echo "no signatures found for $ref" >&2; exit 1; }
  [ "$issuer" = https://token.actions.githubusercontent.com ] && [ "$(cat "$f")" = "$ident" ] ||
    { echo "none of the expected identities matched" >&2; exit 1; } ;;
*) exec "$(dirname "$0")/cosign-base" "$@" ;;
esac
`

// fakeGhAPI answers `gh api <path> [--jq <filter>]` from $FAKE_STATE/gh-api.json (with the real jq), or fails
// like a token without actions: read when the file does not exist. Other commands go to the shared fake.
const fakeGhAPI = `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = api ]; then
  echo "gh $*" >>"$FAKE_LOG"
  [ -f "$FAKE_STATE/gh-api.json" ] || { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
  shift
  q=""
  while [ $# -gt 0 ]; do case "$1" in --jq) q="$2"; shift 2 ;; *) shift ;; esac; done
  if [ -n "$q" ]; then jq -r "$q" "$FAKE_STATE/gh-api.json"; else cat "$FAKE_STATE/gh-api.json"; fi
  exit 0
fi
exec "$(dirname "$0")/gh-base" "$@"
`

// installImageFakes puts the image signing cosign and the gh api fake in front of the shared fakes.
func installImageFakes(t *testing.T, f *fakeEnv) {
	t.Helper()
	for name, body := range map[string]string{"cosign-base": fakeCosign, "gh-base": fakeGh, "cosign": fakeCosignImages, "gh": fakeGhAPI} {
		p := filepath.Join(f.bin, name)
		writeFile(t, p, body)
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignImageScript(t *testing.T) {
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	installImageFakes(t, f)
	ref := "ghcr.io/sealedtempo/sealed-agent@sha256:" + strings.Repeat("ab", 32)
	mainRef := "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/images.yml@refs/heads/main"

	r := runScriptIn(t, root, "sign-image.sh", f.env(mainRef), "--ref", ref)
	if r.code != 0 {
		t.Fatalf("sign: %d\n%s", r.code, r.output)
	}
	calls := f.calls(t)
	mustContain(t, calls, "cosign sign --yes "+ref+"\n")
	mustContain(t, calls, "cosign verify --certificate-identity "+mainImagesIdentity+" --certificate-oidc-issuer https://token.actions.githubusercontent.com "+ref+"\n")

	// Refused before cosign runs: a tag instead of a digest, another workflow, another branch, no workflow.
	for name, c := range map[string]struct{ ref, env string }{
		"tag":            {"ghcr.io/sealedtempo/sealed-agent:latest", mainRef},
		"release.yml":    {ref, "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main"},
		"a branch":       {ref, "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/images.yml@refs/heads/feature"},
		"a pull request": {ref, "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/images.yml@refs/pull/7/merge"},
		"no workflow":    {ref, "GITHUB_WORKFLOW_REF="},
	} {
		before := strings.Count(f.calls(t), "cosign sign")
		if r := runScriptIn(t, root, "sign-image.sh", f.env(c.env), "--ref", c.ref); r.code != 2 {
			t.Errorf("%s: %d\n%s", name, r.code, r.output)
		}
		if strings.Count(f.calls(t), "cosign sign") != before {
			t.Errorf("%s: cosign sign ran", name)
		}
	}
	// A signature that does not verify for the main identity fails the step.
	r = runScriptIn(t, root, "sign-image.sh", f.env(mainRef, "FAKE_COSIGN_VERIFY_FAIL=1"), "--ref", ref)
	if r.code != 1 || !strings.Contains(r.output, "does not verify for identity "+mainImagesIdentity) {
		t.Fatalf("verify failure: %d\n%s", r.code, r.output)
	}
}

// pinFixtureDigests gives every sidecar in the fixture a real-looking digest, so only changed images are
// planned (unbuilt images are always planned on main).
func pinFixtureDigests(t *testing.T, root string) {
	t.Helper()
	p := filepath.Join(root, RuntimeImagesFile)
	s := readFile(t, p)
	for i := 1; strings.Contains(s, zeroDigest); i++ {
		s = strings.Replace(s, zeroDigest, "sha256:"+strings.Repeat(string("3456789abc"[i%10]), 64), 1)
	}
	writeFile(t, p, s)
}

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
		ifs:  map[string]bool{"env.DOCKERHUB_USERNAME != ''": false}, // no Docker Hub creds in tests
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

// supply-6: a push whose run was replaced in the single concurrency slot (or failed) is built by the next
// run, because the plan diffs from the last successful push run, not from the push's own before.
func TestImagesWorkflowPlansFromLastSuccessfulRun(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	pinFixtureDigests(t, root)
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "A: last successful run")
	a := gitRun(t, root, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(root, CatalogDir, "llm-gateway/images/gateway/extra.txt"), "changed\n")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "B: its run was replaced by C's")
	b := gitRun(t, root, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(root, "docs/note.md"), "docs only\n")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "C")
	c := gitRun(t, root, "rev-parse", "HEAD")
	// D is a later push whose run succeeded; the workspace stays at C, as in a re-run of C's run.
	writeFile(t, filepath.Join(root, "runtime/agent/later.txt"), "later\n")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "D")
	d := gitRun(t, root, "rev-parse", "HEAD")
	gitRun(t, root, "reset", "-q", "--hard", c)

	f := newFakes(t)
	installImageFakes(t, f)
	sim := imagesSim(t, "images.yml", root, f, "push")
	sim.ctx["github"].(map[string]any)["event"] = map[string]any{"before": b}
	runs := func(body string) map[string]any {
		if body == "" {
			_ = os.Remove(filepath.Join(f.state, "gh-api.json"))
		} else {
			writeFile(t, filepath.Join(f.state, "gh-api.json"), body)
		}
		return sim.runJob("plan", nil)
	}

	plan := runs(`{"total_count":1,"workflow_runs":[{"head_sha":"` + a + `","conclusion":"success"}]}`)
	if got := planNames(t, plan); plan["count"] != "1" || strings.Join(got, ",") != "gateway" {
		t.Fatalf("plan from the last successful run %s: %v %v", a[:12], plan["count"], got)
	}
	mustContain(t, f.calls(t), "gh api repos/sealedtempo/sealed/actions/workflows/images.yml/runs?branch=main&event=push&status=success&per_page=1 --jq .workflow_runs[0].head_sha // \"\"")

	// Nothing changed since the last successful run, or a re-run of an older push: only unbuilt images (none).
	for name, head := range map[string]string{"same head": c, "a re-run behind it": d} {
		if plan := runs(`{"workflow_runs":[{"head_sha":"` + head + `"}]}`); plan["count"] != "0" {
			t.Errorf("%s: plan %v %v, want nothing", name, plan["count"], planNames(t, plan))
		}
	}

	// No successful run yet, a head that is not an ancestor (history rewritten), or no API access: every image.
	for name, body := range map[string]string{
		"no successful run": `{"total_count":0,"workflow_runs":[]}`,
		"not an ancestor":   `{"workflow_runs":[{"head_sha":"` + strings.Repeat("d", 40) + `"}]}`,
		"no API access":     "",
	} {
		if plan := runs(body); plan["count"] != "6" {
			t.Errorf("%s: plan %v %v, want every image", name, plan["count"], planNames(t, plan))
		}
	}
}

// supply-3: every image the build job pushes is signed by images.yml on main, and the signature self-verifies
// for the identity that catalog.yml and release.yml are meant to check. Those jobs do not verify image
// signatures yet (the supply-3 verify half is not implemented); this test covers the signing half only.
func TestImagesWorkflowSignsEveryPushedImage(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-q", "-m", "fixture")
	f := newFakes(t)
	installImageFakes(t, f)
	report := filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, report, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)
	sim := imagesSim(t, "images.yml", root, f, "workflow_dispatch", "FAKE_GRYPE_REPORT="+report,
		"GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/images.yml@refs/heads/main")
	sim.ctx["inputs"] = map[string]any{"images": "all", "verify_reproducible": true}
	plan := sim.runJob("plan", nil)
	names := planNames(t, plan)
	if len(names) != 6 {
		t.Fatalf("plan: %v", names)
	}
	sim.ctx["needs"] = map[string]any{"plan": map[string]any{"outputs": plan}}
	var m struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(plan["matrix"])), &m); err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Include {
		sim.runJob("build", e)
	}
	for _, e := range m.Include {
		var res BuildResult
		if err := readJSONFile(filepath.Join(sim.artifacts, "image-"+toStr(e["name"]), "results", toStr(e["name"])+".json"), &res); err != nil {
			t.Fatal(err)
		}
		ref := res.Repository + "@" + res.Digest
		mustContain(t, f.calls(t), "cosign sign --yes "+ref+"\n")
		// What a consumer runs: cosign verify with the images.yml@refs/heads/main identity.
		cmd := exec.Command(filepath.Join(f.bin, "cosign"), "verify", "--certificate-identity", mainImagesIdentity,
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", ref)
		cmd.Env = f.env()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s does not verify for %s: %v %s", ref, mainImagesIdentity, err, out)
		}
		// And it does not verify for any other workflow.
		other := strings.Replace(mainImagesIdentity, "images.yml", "release.yml", 1)
		cmd = exec.Command(filepath.Join(f.bin, "cosign"), "verify", "--certificate-identity", other,
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", ref)
		cmd.Env = f.env()
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Errorf("%s verifies for %s: %s", ref, other, out)
		}
	}
	// Signing comes after the reproducibility rebuild and before the scan, in every build.
	calls := f.calls(t)
	if strings.Count(calls, "cosign sign --yes") != 6 || strings.Count(calls, "cosign verify --certificate-identity "+mainImagesIdentity) < 6 {
		t.Fatalf("signing calls:\n%s", calls)
	}
	for _, chunk := range strings.Split(calls, "--no-cache")[1:] {
		sign, scan := strings.Index(chunk, "cosign sign --yes"), strings.Index(chunk, "syft scan")
		if sign < 0 || scan < 0 || sign > scan {
			t.Fatalf("each build signs after its rebuild and before its scan:\n%s", calls)
		}
	}
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

func TestImagesWorkflowShape(t *testing.T) {
	images, imagesRaw := loadShape(t, "images.yml")
	if _, ok := images.On["pull_request"]; ok {
		t.Error("images.yml pushes and signs; pull requests run images-pr.yml")
	}
	if p := images.Jobs["build"].Permissions; p["id-token"] != "write" || p["packages"] != "write" {
		t.Errorf("images.yml build signs keyless and pushes: %v", p)
	}
	if p := images.Jobs["plan"].Permissions; p["actions"] != "read" || len(p) != 2 {
		t.Errorf("images.yml plan reads the last successful run and nothing else: %v", p)
	}
	for _, j := range []string{"plan", "pin"} {
		if _, ok := images.Jobs[j].Permissions["id-token"]; ok {
			t.Errorf("images.yml %s must not get id-token", j)
		}
	}
	signAt, scanAt, buildAt := -1, -1, -1
	for i, st := range images.Jobs["build"].Steps {
		switch {
		case strings.Contains(st.Run, "scripts/release/sign-image.sh"):
			signAt = i
		case strings.Contains(st.Run, "scripts/release/scan-image.sh"):
			scanAt = i
		case strings.Contains(st.Run, "scripts/release/build-image.sh"):
			buildAt = i
		}
	}
	if !(buildAt >= 0 && buildAt < signAt && signAt < scanAt) {
		t.Errorf("images.yml build: build (%d), then sign (%d), then scan (%d)", buildAt, signAt, scanAt)
	}
	if strings.Contains(imagesRaw, "github.event.before") {
		t.Error("images.yml must not plan from the push's own before (supply-6)")
	}
	if strings.ContainsAny(readFile(t, filepath.Join(repoRoot(t), "scripts/release/sign-image.sh")), "\u2014\u2013") {
		t.Error("sign-image.sh contains an em-dash or en-dash")
	}
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
	// Every image directory the release tool builds must be covered by a paths glob, or a change inside
	// that directory never runs the check although --changed-only would select it (supply-4).
	globs := prPathGlobs(t, pr.On["pull_request"])
	set, err := LoadImages(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range set.Build {
		probe := b.Dir + "/deep/file.txt"
		covered := false
		for _, g := range globs {
			if ghPathMatch(g, probe) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("images-pr.yml paths do not cover a change under %s (image %s): %v", b.Dir, b.Name, globs)
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

// prPathGlobs pulls the pull_request paths list out of a parsed on: block.
func prPathGlobs(t *testing.T, trigger any) []string {
	t.Helper()
	m, ok := trigger.(map[string]any)
	if !ok {
		t.Fatalf("pull_request trigger is not a map: %T", trigger)
	}
	raw, ok := m["paths"].([]any)
	if !ok {
		t.Fatalf("pull_request has no paths list: %v", m)
	}
	var globs []string
	for _, p := range raw {
		globs = append(globs, fmt.Sprint(p))
	}
	return globs
}

// ghPathMatch reports whether a GitHub Actions path-filter glob matches path. "**" matches any run of
// characters including "/"; "*" matches a run within one segment; "?" matches a single non-slash character.
func ghPathMatch(glob, p string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(p)
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
