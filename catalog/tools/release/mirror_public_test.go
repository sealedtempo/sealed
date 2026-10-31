package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestMirrorPublicCheck drives mirror-images.sh --check-public (spec 5.3.1, G21): after the images are
// mirrored, every target must resolve with an ANONYMOUS crane digest (empty DOCKER_CONFIG), proving the
// GHCR package is public. A target that is not anonymously pullable, or resolves to another digest, fails
// the check with a pointer to the make-it-public step.
func TestMirrorPublicCheck(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))

	matrix := filepath.Join(t.TempDir(), "mirror.json")
	var so, se strings.Builder
	if err := run([]string{"images", "--root", root, "--format", "mirror-matrix"}, &so, &se); err != nil {
		t.Fatal(err)
	}
	writeFile(t, matrix, so.String())
	var mm struct {
		Include []struct {
			Name, Target, Digest string
		} `json:"include"`
	}
	if err := json.Unmarshal([]byte(so.String()), &mm); err != nil {
		t.Fatal(err)
	}
	if len(mm.Include) != 3 {
		t.Fatalf("fixture mirror matrix has %d images, want 3", len(mm.Include))
	}

	// Before anything is mirrored the targets do not resolve, so the public check fails (not pullable).
	f0 := newFakes(t)
	r := runScriptIn(t, root, "mirror-images.sh", f0.env(), matrix, "--check-public")
	if r.code == 0 || !strings.Contains(r.output, "is not publicly pullable") || !strings.Contains(r.output, "github-readiness D1") {
		t.Fatalf("unmirrored targets must fail the public check: %d\n%s", r.code, r.output)
	}

	// Mirror the images, then the public check passes and runs anonymously (empty DOCKER_CONFIG).
	f := newFakes(t)
	if r = runScriptIn(t, root, "mirror-images.sh", f.env(), matrix); r.code != 0 {
		t.Fatalf("mirror: %d\n%s", r.code, r.output)
	}
	r = runScriptIn(t, root, "mirror-images.sh", f.env("FAKE_CRANE_LOG_CONFIG=1"), matrix, "--check-public")
	if r.code != 0 || !strings.Contains(r.output, "public-visibility: 3 of 3 images are anonymously pullable") {
		t.Fatalf("public check after mirror: %d\n%s", r.code, r.output)
	}
	for _, e := range mm.Include {
		mustContain(t, r.output, "ok   public "+e.Name+": "+e.Target)
		mustContain(t, f.calls(t), "crane digest "+e.Target)
	}
	// The anonymous config directory the check used holds no config.json (no credentials were offered).
	cfg := ""
	for _, l := range strings.Split(f.calls(t), "\n") {
		if d, ok := strings.CutPrefix(l, "crane-config "); ok {
			cfg = strings.TrimSpace(d)
		}
	}
	if cfg == "" || cfg == "unset" {
		t.Fatalf("check-public must set DOCKER_CONFIG to an empty dir, logged %q", cfg)
	}
	if fileExists(filepath.Join(cfg, "config.json")) {
		t.Fatalf("DOCKER_CONFIG %s has a config.json; the check must be anonymous", cfg)
	}

	// A mirrored image whose GHCR package is still private resolves for an authenticated pull but not an
	// anonymous one: the check must catch it and point at the make-it-public step.
	private := mm.Include[1].Target
	r = runScriptIn(t, root, "mirror-images.sh", f.env("FAKE_CRANE_PRIVATE="+private), matrix, "--check-public")
	if r.code == 0 || !strings.Contains(r.output, mm.Include[1].Name+": "+private+" is not publicly pullable") ||
		!strings.Contains(r.output, "visibility to public") {
		t.Fatalf("a private package must fail the public check: %d\n%s", r.code, r.output)
	}

	// A target that resolves anonymously to another digest (something moved under the ref) is caught too.
	wrong := "sha256:" + strings.Repeat("9", 64)
	key := strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(mm.Include[0].Target)
	writeFile(t, filepath.Join(f.state, "crane", key), wrong)
	r = runScriptIn(t, root, "mirror-images.sh", f.env(), matrix, "--check-public")
	if r.code == 0 || !strings.Contains(r.output, "resolves anonymously to "+wrong) {
		t.Fatalf("a target under a different digest must fail: %d\n%s", r.code, r.output)
	}
}
