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

// supply-3: a built image (manifest `source: build:`) is scanned or released only when its digest carries
// the cosign signature of images.yml on main. The verifier's repro pinned an arbitrary digest and the
// image gate passed; these tests pin the fixture gateway (sha256:2222...) and expect the scan and the
// release build to stop until images.yml on main signed that digest.

const (
	gatewayRef      = "ghcr.io/sealedtempo/gateway@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	imagesIdentity  = "https://github.com/sealedtempo/sealed/.github/workflows/images.yml@refs/heads/main"
	notSignedByMain = " is not signed by " + imagesIdentity
)

func TestVerifyImageScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	env := f.env("GH_REPO=sealedtempo/sealed")

	r := runScriptIn(t, root, "verify-image.sh", env, "--ref", gatewayRef)
	if r.code != 1 || !strings.Contains(r.output, "::error title=image-signature::"+gatewayRef+notSignedByMain) {
		t.Fatalf("unsigned digest: %d\n%s", r.code, r.output)
	}
	for _, other := range []string{
		"https://github.com/sealedtempo/sealed/.github/workflows/images.yml@refs/heads/feature", // a branch run
		"https://github.com/sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main",   // another workflow
		"https://github.com/mallory/sealed/.github/workflows/images.yml@refs/heads/main",        // a fork
	} {
		f.fakeSignImage(t, gatewayRef, other)
		if r = runScriptIn(t, root, "verify-image.sh", env, "--ref", gatewayRef); r.code != 1 || !strings.Contains(r.output, notSignedByMain) {
			t.Fatalf("signed by %s: %d\n%s", other, r.code, r.output)
		}
	}
	f.fakeSignImage(t, gatewayRef, imagesIdentity)
	if r = runScriptIn(t, root, "verify-image.sh", env, "--ref", gatewayRef); r.code != 0 || !strings.Contains(r.output, "ok   "+gatewayRef+" is signed by "+imagesIdentity) {
		t.Fatalf("signed on main: %d\n%s", r.code, r.output)
	}
	mustContain(t, f.calls(t), "cosign verify --certificate-identity "+imagesIdentity+" --certificate-oidc-issuer https://token.actions.githubusercontent.com "+gatewayRef)
	// Without GH_REPO the repository comes from config/defaults.yaml.
	if r = runScriptIn(t, root, "verify-image.sh", f.env(), "--ref", gatewayRef); r.code != 0 {
		t.Fatalf("default repository: %d\n%s", r.code, r.output)
	}
	// Only digest references.
	if r = runScriptIn(t, root, "verify-image.sh", env, "--ref", "ghcr.io/sealedtempo/gateway:latest"); r.code != 2 {
		t.Fatalf("a tag must be refused: %d\n%s", r.code, r.output)
	}
}

// The catalog workflow's scan job checks the signature before it scans a built image, and leaves
// mirrored images alone (their digest is the upstream one).
func TestCatalogScanRequiresImagesSignature(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
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

	out, err := exec.Command(releaseBin(t), "images", "--root", root, "--format", "scan-matrix").Output()
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal(out, &m); err != nil || len(m.Include) != 2 || m.Include[0]["app"] != "llm-gateway" {
		t.Fatalf("scan matrix: %s %v", out, err)
	}
	if img := m.Include[0]["images"].([]any)[0].(map[string]any); img["built"] != true || img["ref"] != gatewayRef {
		t.Fatalf("the gateway is a built image: %v", img)
	}

	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/catalog.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	sim := &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(), path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+report),
		ctx: map[string]any{
			"github":  map[string]any{"event_name": "pull_request", "token": "fake-token", "repository": "sealedtempo/sealed", "actor": "dev"},
			"inputs":  map[string]any{"apps": ""},
			"secrets": map[string]any{},
			"vars":    map[string]any{},
		},
		ifs: map[string]bool{"always()": true},
	}
	gateway, notes := m.Include[0], m.Include[1]

	// A digest nobody signed (a pull request pinning its own build) fails before it is scanned.
	if _, err := sim.runJobErr("scan", gateway); err == nil || !strings.Contains(err.Error(), gatewayRef+notSignedByMain) {
		t.Fatalf("scan of an unsigned built image: %v", err)
	}
	if strings.Contains(f.calls(t), "syft scan registry:"+gatewayRef) {
		t.Fatal("an unsigned built image must not be scanned")
	}
	f.fakeSignImage(t, gatewayRef, "https://github.com/sealedtempo/sealed/.github/workflows/images.yml@refs/heads/feature")
	if _, err := sim.runJobErr("scan", gateway); err == nil || !strings.Contains(err.Error(), notSignedByMain) {
		t.Fatalf("scan of an image signed on a branch: %v", err)
	}
	f.fakeSignImage(t, gatewayRef, imagesIdentity)
	sim.runJob("scan", gateway)
	mustContain(t, f.calls(t), "syft scan registry:"+gatewayRef)

	seen := len(f.calls(t))
	sim.runJob("scan", notes)
	if strings.Contains(f.calls(t)[seen:], "cosign verify") {
		t.Fatal("mirrored images keep their upstream digest and need no images.yml signature")
	}
}

// The release workflow's build job checks the same signature before the SBOM, the scan and the bundle.
func TestReleaseBuildRequiresImagesSignature(t *testing.T) {
	requireJQ(t)
	requireTools(t, "openssl")
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	bins := t.TempDir()
	for src, dst := range map[string]string{releaseBin(t): "release", sealedComposeBin(t): "sealed-compose"} {
		if err := copyFile(src, filepath.Join(bins, dst)); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(bins, dst), 0o755)
	}
	writeFile(t, filepath.Join(f.bin, "go"), fakeGo)
	_ = os.Chmod(filepath.Join(f.bin, "go"), 0o755)
	report := filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, report, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)

	out, err := exec.Command(releaseBin(t), "plan", "--root", root, "--apps", "llm-gateway", "--strict").Output()
	if err != nil {
		t.Fatal(err)
	}
	var plan []map[string]any
	if err := json.Unmarshal(out, &plan); err != nil || len(plan) != 1 {
		t.Fatalf("plan: %s %v", out, err)
	}
	entry := plan[0]
	if ref := entry["imageRefs"].([]any)[0].(map[string]any); ref["built"] != true || ref["ref"] != gatewayRef {
		t.Fatalf("the gateway is a built image: %v", ref)
	}

	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/release.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	sim := &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(), path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+report,
			"GITHUB_SHA="+strings.Repeat("e", 40), "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main"),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "workflow_dispatch", "token": "fake-token", "repository": "sealedtempo/sealed",
				"server_url": "https://github.com", "run_id": "99", "actor": "sealedtempo"},
			"inputs":  map[string]any{"apps": "llm-gateway"},
			"secrets": map[string]any{},
			"vars":    map[string]any{"ALLOW_MISSING_SEALED_CLI": "1"},
		},
	}
	const step = `step "Built images are signed by images.yml on main" failed`
	if _, err := sim.runJobErr("build", entry); err == nil || !strings.Contains(err.Error(), step) || !strings.Contains(err.Error(), gatewayRef+notSignedByMain) {
		t.Fatalf("build with an unsigned built image: %v", err)
	}
	if strings.Contains(f.calls(t), "syft scan") || strings.Contains(f.calls(t), "cosign sign-blob") {
		t.Fatal("nothing is scanned or signed before the image signature passes")
	}
	f.fakeSignImage(t, gatewayRef, imagesIdentity)
	if _, err := sim.runJobErr("build", entry); err != nil && strings.Contains(err.Error(), step) {
		t.Fatalf("build with a signed image: %v", err)
	}
	mustContain(t, f.calls(t), "syft scan registry:"+gatewayRef)
}
