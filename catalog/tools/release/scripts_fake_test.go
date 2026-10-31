package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/runtime/composer"
)

func requireJQ(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		skipOrFail(t, "jq not installed")
	}
}

func TestMirrorImagesScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	matrix := filepath.Join(t.TempDir(), "mirror.json")
	var so, se strings.Builder
	if err := run([]string{"images", "--root", root, "--format", "mirror-matrix"}, &so, &se); err != nil {
		t.Fatal(err)
	}
	writeFile(t, matrix, so.String())

	r := runScriptIn(t, root, "mirror-images.sh", f.env("DRY_RUN=1"), matrix)
	if r.code != 0 || countLines(r.output, "plan ") != 3 || strings.Contains(f.calls(t), "crane copy") {
		t.Fatalf("dry run: %d\n%s", r.code, r.output)
	}
	r = runScriptIn(t, root, "mirror-images.sh", f.env(), matrix)
	if r.code != 0 || !strings.Contains(r.output, "mirror: 3 copied, 0 already present, 3 total") {
		t.Fatalf("copy: %d\n%s", r.code, r.output)
	}
	mustContain(t, f.calls(t), "crane copy docker.io/library/postgres@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b ghcr.io/sealedtempo/postgres:17.11-alpine-266d3c257594")
	r = runScriptIn(t, root, "mirror-images.sh", f.env(), matrix)
	if r.code != 0 || !strings.Contains(r.output, "mirror: 0 copied, 3 already present") {
		t.Fatalf("second run copies nothing: %d\n%s", r.code, r.output)
	}
	// A digest that exists under another tag is tagged, not copied again.
	tags, _ := filepath.Glob(filepath.Join(f.state, "crane", "*caddy_2.11.7*"))
	for _, p := range tags {
		_ = os.Remove(p)
	}
	r = runScriptIn(t, root, "mirror-images.sh", f.env(), matrix)
	if r.code != 0 || !strings.Contains(r.output, "tag  caddy:") {
		t.Fatalf("retag: %d\n%s", r.code, r.output)
	}

	// A copy that changes the digest is caught.
	f2 := newFakes(t)
	r = runScriptIn(t, root, "mirror-images.sh", f2.env("FAKE_CRANE_WRONG_DIGEST=sha256:"+strings.Repeat("9", 64)), matrix)
	if r.code == 0 || !strings.Contains(r.output, "the mirror must keep the digest") {
		t.Fatalf("digest change: %d\n%s", r.code, r.output)
	}

	// Images under never_mirror fail before anything is copied.
	p := filepath.Join(root, CatalogDir, "notes/manifest.yaml")
	writeFile(t, p, strings.Replace(readFile(t, p), "docker.io/example/notes:1.0.0", "docker.io/example/forbidden:1.0.0", 1))
	so.Reset()
	if err := run([]string{"images", "--root", root, "--format", "mirror-matrix"}, &so, &se); err != nil {
		t.Fatal(err)
	}
	writeFile(t, matrix, so.String())
	f3 := newFakes(t)
	r = runScriptIn(t, root, "mirror-images.sh", f3.env(), matrix)
	if r.code == 0 || !strings.Contains(r.output, "notes-web (docker.io/example/forbidden:1.0.0): D-999") || strings.Contains(f3.calls(t), "crane") {
		t.Fatalf("blocked: %d\n%s\n%s", r.code, r.output, f3.calls(t))
	}
	r = runScriptIn(t, root, "mirror-images.sh", f3.env(), matrix, "--skip-blocked")
	if r.code != 0 || !strings.Contains(r.output, "warn not mirrored: notes-web") || !strings.Contains(r.output, "2 total") {
		t.Fatalf("skip blocked: %d\n%s", r.code, r.output)
	}
	if err := run([]string{"images", "--root", root, "--format", "mirror-matrix", "--apps", "notes", "--fail-on-blocked"}, &so, &se); err == nil {
		t.Fatal("--fail-on-blocked must fail for notes")
	}
}

func buildEntry(t *testing.T, root, name string) string {
	t.Helper()
	set, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range set.Build {
		if b.Name == name {
			return mustJSON(t, b)
		}
	}
	t.Fatalf("no build %s", name)
	return ""
}

func TestBuildImageScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	out := filepath.Join(t.TempDir(), "result.json")
	commit := strings.Repeat("ab", 20)
	entry := buildEntry(t, root, "sealed-agent")

	r := runScriptIn(t, root, "build-image.sh", f.env(), "--entry", entry, "--out", out, "--push", "--verify-reproducible", "--commit", commit)
	if r.code != 0 {
		t.Fatalf("build: %d\n%s", r.code, r.output)
	}
	var res BuildResult
	if err := readJSONFile(out, &res); err != nil {
		t.Fatal(err)
	}
	if res.Name != "sealed-agent" || res.Dir != "runtime/agent" || res.Tag != "git-abababababab" || !digestRe.MatchString(res.Digest) ||
		res.Reproducible == nil || !*res.Reproducible || res.RebuildDigest != res.Digest || res.Commit != commit {
		t.Fatalf("result %+v", res)
	}
	calls := f.calls(t)
	for _, want := range []string{"--platform linux/amd64", "--build-arg SOURCE_DATE_EPOCH=0",
		"--build-arg BUILDKIT_SYNTAX=docker.io/docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
		"--provenance=false --sbom=false", "type=image,name=ghcr.io/sealedtempo/sealed-agent:git-abababababab,push=true,rewrite-timestamp=true,oci-mediatypes=true",
		"--no-cache", "crane digest ghcr.io/sealedtempo/sealed-agent@" + res.Digest} {
		mustContain(t, calls, want)
	}
	// A root-context image builds with the repository root as its context.
	mustContain(t, calls, " "+root+"/.\n")
	// The result is a valid pin input.
	results := filepath.Dir(out)
	if _, err := LoadBuildResults(results); err != nil {
		t.Fatal(err)
	}

	// A rebuild with another digest fails, unless images.yaml records why.
	r = runScriptIn(t, root, "build-image.sh", f.env("FAKE_DOCKER_NONDETERMINISTIC=1"), "--entry", entry, "--out", out, "--verify-reproducible", "--commit", commit)
	if r.code != 4 || !strings.Contains(r.output, "error: not reproducible") {
		t.Fatalf("nondeterministic: %d\n%s", r.code, r.output)
	}
	_ = readJSONFile(out, &res)
	if res.Reproducible == nil || *res.Reproducible {
		t.Fatalf("result must record the mismatch: %+v", res)
	}
	accepted := strings.Replace(entry, `"name":"sealed-agent"`, `"name":"sealed-agent","nonreproducible":"pnpm writes a timestamp, fix pending"`, 1)
	r = runScriptIn(t, root, "build-image.sh", f.env("FAKE_DOCKER_NONDETERMINISTIC=1"), "--entry", accepted, "--out", out, "--verify-reproducible", "--commit", commit)
	if r.code != 0 || !strings.Contains(r.output, "accepted in images.yaml: pnpm writes a timestamp") {
		t.Fatalf("accepted nondeterminism: %d\n%s", r.code, r.output)
	}
	// An app-directory image builds with its own directory as context; no tag without a commit.
	gw := buildEntry(t, root, "gateway")
	r = runScriptIn(t, root, "build-image.sh", f.env(), "--entry", gw, "--out", out, "--tag", "pr-check")
	if r.code != 0 || !strings.Contains(f.calls(t), filepath.Join(root, "catalog/apps/llm-gateway/images/gateway")) {
		t.Fatalf("dir context: %d\n%s", r.code, r.output)
	}
	if r = runScriptIn(t, root, "build-image.sh", f.env(), "--entry", gw, "--out", out); r.code != 2 {
		t.Fatalf("missing tag and commit: %d\n%s", r.code, r.output)
	}
}

func TestScanImageScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	report := filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, report, grypeFixture)
	out := t.TempDir()
	waivers := filepath.Join(root, CatalogDir, "notes/waivers.yaml")
	ref := "ghcr.io/sealedtempo/notes-web@sha256:" + strings.Repeat("1", 64)
	args := []string{"--image", "notes-web", "--ref", ref, "--waivers", waivers, "--out", out}

	r := runScriptIn(t, root, "scan-image.sh", f.env("FAKE_GRYPE_REPORT="+report), args...)
	if r.code != 5 || !strings.Contains(r.output, "has critical findings that") {
		t.Fatalf("unwaived: %d\n%s", r.code, r.output)
	}
	for _, p := range []string{"sbom/notes-web.spdx.json", "files/notes-web.spdx.json", "scan/notes-web.json", "summary/notes-web.summary.json"} {
		if !fileExists(filepath.Join(out, p)) {
			t.Fatalf("%s missing", p)
		}
	}
	calls := f.calls(t)
	// -c scripts/release/syft.yaml pins the config (syftenv_test.go checks it shuts out a planted .syft.yaml).
	cfg := filepath.Join(root, "scripts/release/syft.yaml")
	mustContain(t, calls, "syft scan registry:"+ref+" -c "+cfg+" --platform linux/amd64 -o spdx-json="+filepath.Join(out, "sbom/notes-web.spdx.json"))
	// The every-file listing for lint (review policy-1); syftenv_test.go checks the settings of both runs.
	mustContain(t, calls, "syft scan registry:"+ref+" -c "+cfg+" --platform linux/amd64 -o spdx-json="+filepath.Join(out, "files/notes-web.spdx.json")+" -q")
	mustContain(t, calls, "grype sbom:")

	writeFile(t, waivers, `version: 1
waivers:
  - {id: CVE-2026-1000, image: notes-web, package: openssl, reason: not reachable from the app, expires: 2099-01-01}
`)
	// A waiver further out than 90 days is invalid, so the gate cannot run.
	r = runScriptIn(t, root, "scan-image.sh", f.env("FAKE_GRYPE_REPORT="+report), args...)
	if r.code == 0 || r.code == 5 {
		t.Fatalf("invalid waivers: %d\n%s", r.code, r.output)
	}
	writeFile(t, report, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)
	writeFile(t, waivers, "version: 1\nwaivers: []\n")
	r = runScriptIn(t, root, "scan-image.sh", f.env("FAKE_GRYPE_REPORT="+report), args...)
	if r.code != 0 || !strings.Contains(r.output, "ok   notes-web") {
		t.Fatalf("clean: %d\n%s", r.code, r.output)
	}
	if r = runScriptIn(t, root, "scan-image.sh", f.env("FAKE_GRYPE_REPORT="+report), "--image", "notes-web", "--ref", "ghcr.io/sealedtempo/notes-web:latest", "--waivers", waivers, "--out", out); r.code != 2 {
		t.Fatalf("a tag reference must be refused: %d\n%s", r.code, r.output)
	}
}

func TestSignBundleScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "notes-1.0.0-sealed.1.bundle.tar")
	writeFile(t, bundle, "bundle bytes")
	sb, _ := fakeSigstoreBundle(t, []byte("bundle bytes"), "777")
	sbFile := filepath.Join(t.TempDir(), "sb.json")
	writeFile(t, sbFile, string(sb))
	identity := "https://github.com/sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main"
	env := f.env("FAKE_SIGSTORE_BUNDLE="+sbFile, "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main")

	r := runScriptIn(t, root, "sign-bundle.sh", env, "--bundle", bundle)
	if r.code != 0 || !strings.Contains(r.output, "Rekor https://search.sigstore.dev/?logIndex=777") {
		t.Fatalf("sign: %d\n%s", r.code, r.output)
	}
	for _, ext := range []string{".sigstore.json", ".sig", ".crt", ".rekor.json"} {
		if !fileExists(bundle + ext) {
			t.Fatalf("%s missing", ext)
		}
	}
	mustContain(t, f.calls(t), "cosign sign-blob --yes --bundle "+bundle+".sigstore.json "+bundle)
	mustContain(t, f.calls(t), "--certificate-identity "+identity+" --certificate-oidc-issuer https://token.actions.githubusercontent.com")

	if r = runScriptIn(t, root, "sign-bundle.sh", append(env, "FAKE_VERIFY_FAIL=1"), "--bundle", bundle); r.code == 0 {
		t.Fatal("a signature that does not verify must fail")
	}
	writeFile(t, bundle, "changed bytes")
	if r = runScriptIn(t, root, "sign-bundle.sh", env, "--bundle", bundle); r.code == 0 || !strings.Contains(r.output, "does not match") {
		t.Fatalf("a Sigstore bundle for other bytes: %d\n%s", r.code, r.output)
	}
}

func TestGithubReleaseScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	assets := t.TempDir()
	writeFile(t, filepath.Join(assets, "notes-1.0.0.bundle.tar"), "bundle")
	writeFile(t, filepath.Join(assets, "sbom.notes-web.spdx.json"), "{}")
	notes := filepath.Join(t.TempDir(), "notes.md")
	writeFile(t, notes, "first notes")
	commit := strings.Repeat("c", 40)
	env := f.env("GH_REPO=sealedtempo/sealed")
	pub := []string{"publish", "--tag", "notes-v1.0.0", "--target", commit, "--notes", notes, "--assets", assets}

	if r := runScriptIn(t, root, "github-release.sh", env, "state", "--tag", "notes-v1.0.0"); strings.TrimSpace(r.output) != "none" {
		t.Fatalf("state: %s", r.output)
	}
	r := runScriptIn(t, root, "github-release.sh", env, pub...)
	if r.code != 0 || !strings.HasSuffix(strings.TrimSpace(r.output), "created") {
		t.Fatalf("publish: %d\n%s", r.code, r.output)
	}
	mustContain(t, f.calls(t), "gh release create notes-v1.0.0 "+filepath.Join(assets, "notes-1.0.0.bundle.tar")+" "+filepath.Join(assets, "sbom.notes-web.spdx.json")+" --draft --title notes-v1.0.0 --notes-file "+notes+" --target "+commit+" --latest=false --repo sealedtempo/sealed")
	if strings.TrimSpace(runScriptIn(t, root, "github-release.sh", env, "state", "--tag", "notes-v1.0.0").output) != "published" {
		t.Fatal("published after publish")
	}
	// A published release is never changed.
	writeFile(t, filepath.Join(assets, "notes-1.0.0.bundle.tar"), "other bundle")
	r = runScriptIn(t, root, "github-release.sh", env, pub...)
	if r.code != 0 || !strings.HasSuffix(strings.TrimSpace(r.output), "exists") ||
		readFile(t, filepath.Join(f.state, "gh/notes-v1.0.0/assets/notes-1.0.0.bundle.tar")) != "bundle" {
		t.Fatalf("existing release: %d\n%s", r.code, r.output)
	}
	// Fetch by URL with the sha256 check.
	out := filepath.Join(t.TempDir(), "dl.tar")
	url := "https://github.com/sealedtempo/sealed/releases/download/notes-v1.0.0/notes-1.0.0.bundle.tar"
	sum := composerSHA("bundle")
	if r = runScriptIn(t, root, "github-release.sh", env, "fetch", "--url", url, "--sha256", sum, "--out", out); r.code != 0 || readFile(t, out) != "bundle" {
		t.Fatalf("fetch: %d\n%s", r.code, r.output)
	}
	if r = runScriptIn(t, root, "github-release.sh", env, "fetch", "--url", url, "--sha256", composerSHA("nope"), "--out", out); r.code == 0 {
		t.Fatal("a sha256 mismatch must fail")
	}
	// Notes update.
	writeFile(t, notes, "notes with the tx hash")
	if r = runScriptIn(t, root, "github-release.sh", env, "notes", "--tag", "notes-v1.0.0", "--notes", notes); r.code != 0 ||
		readFile(t, filepath.Join(f.state, "gh/notes-v1.0.0/notes")) != "notes with the tx hash" {
		t.Fatalf("notes: %d\n%s", r.code, r.output)
	}
	// A draft left behind is updated and published.
	if err := os.MkdirAll(filepath.Join(f.state, "gh/notes-v2/assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.state, "gh/notes-v2/draft"), "")
	r = runScriptIn(t, root, "github-release.sh", env, "publish", "--tag", "notes-v2", "--target", commit, "--notes", notes, "--assets", assets)
	if r.code != 0 || !strings.Contains(r.output, "update draft release notes-v2") || fileExists(filepath.Join(f.state, "gh/notes-v2/draft")) {
		t.Fatalf("draft: %d\n%s", r.code, r.output)
	}
	// Asset names GitHub would rename are refused.
	writeFile(t, filepath.Join(assets, "bad name.json"), "{}")
	if r = runScriptIn(t, root, "github-release.sh", env, "publish", "--tag", "notes-v3", "--target", commit, "--notes", notes, "--assets", assets); r.code == 0 {
		t.Fatal("asset with a space must fail")
	}
}

func composerSHA(s string) string { return composer.SHA256([]byte(s)).Hex() }

func TestBuildBundleScript(t *testing.T) {
	requireJQ(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	app := filepath.Join(root, CatalogDir, "notes")
	out := filepath.Join(t.TempDir(), "notes-1.0.0-sealed.1.bundle.tar")
	info := filepath.Join(t.TempDir(), "info.json")
	files := t.TempDir()
	copyTree(t, filepath.Join(app, "sbom"), files)
	args := []string{"--app", "notes", "--sbom-dir", filepath.Join(app, "sbom"), "--files-dir", files, "--scan-dir", filepath.Join(app, "scan"), "--out", out, "--info", info}
	compose := "SEALED_COMPOSE_BIN=" + sealedComposeBin(t)

	// No CLI: refused unless explicitly allowed.
	r := runScriptIn(t, root, "build-bundle.sh", f.env(compose), args...)
	if r.code == 0 || !strings.Contains(r.output, "sealed release build is not available") {
		t.Fatalf("no CLI: %d\n%s", r.code, r.output)
	}
	r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "ALLOW_MISSING_SEALED_CLI=1"), args...)
	if r.code != 0 || !strings.Contains(r.output, "warn sealed release build is not available") {
		t.Fatalf("allowed without CLI: %d\n%s", r.code, r.output)
	}
	var bi BundleInfo
	if err := readJSONFile(info, &bi); err != nil || bi.Slug != "notes" || bi.File != out || !fileExists(out) {
		t.Fatalf("info %+v %v", bi, err)
	}

	// A CLI that reproduces the bundle passes; one that differs fails.
	good := filepath.Join(t.TempDir(), "sealed")
	writeFile(t, good, `#!/usr/bin/env bash
set -euo pipefail
echo "sealed $*" >>"$FAKE_LOG"
app="$3"; shift 3; sbom="" scan="" out=""
while [ $# -gt 0 ]; do case "$1" in --sbom-dir) sbom="$2"; shift 2 ;; --scan-dir) scan="$2"; shift 2 ;; --out) out="$2"; shift 2 ;; *) shift 2 ;; esac; done
"$SEALED_RELEASE_BIN" bundle --app "$app" --sbom-dir "$sbom" --scan-dir "$scan" --out "$out" >/dev/null
[ "${FAKE_CLI_DIFFERENT:-0}" = 1 ] && printf x >>"$out"
exit 0
`)
	_ = os.Chmod(good, 0o755)
	r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "SEALED_CLI="+good), args...)
	if r.code != 0 || !strings.Contains(r.output, "reproduces the bundle byte for byte") {
		t.Fatalf("CLI: %d\n%s", r.code, r.output)
	}
	mustContain(t, f.calls(t), "sealed release build notes --catalog catalog/apps --sbom-dir")
	r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "SEALED_CLI="+good, "FAKE_CLI_DIFFERENT=1"), args...)
	if r.code == 0 || !strings.Contains(r.output, "built different bundles") {
		t.Fatalf("differing CLI: %d\n%s", r.code, r.output)
	}

	// The bundle's SBOMs list only the files a package owns. The every-file listing shows an enterprise
	// tree that no package owns, and the second lint pass blocks it (review policy-1, license audit F6).
	listing := filepath.Join(files, "notes-web.spdx.json")
	clean := readFile(t, listing)
	writeFile(t, listing, strings.TrimSuffix(strings.TrimSpace(clean), "}")+`,"files":[{"SPDXID":"SPDXRef-F1","fileName":"/app/enterprise/billing.py"}]}`)
	r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "ALLOW_MISSING_SEALED_CLI=1"), args...)
	if r.code == 0 || !strings.Contains(r.output, "the images' file listings fail the release lint") || !strings.Contains(r.output, "/app/enterprise/") {
		t.Fatalf("unowned enterprise file: %d\n%s", r.code, r.output)
	}
	writeFile(t, listing, clean)
	noFiles := append([]string{}, args...)
	noFiles[5] = t.TempDir()
	if r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "ALLOW_MISSING_SEALED_CLI=1"), noFiles...); r.code == 0 || !strings.Contains(r.output, "holds no file listing") {
		t.Fatalf("empty --files-dir: %d\n%s", r.code, r.output)
	}
	if r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "ALLOW_MISSING_SEALED_CLI=1"), append(args[:4:4], args[6:]...)...); r.code != 2 {
		t.Fatalf("missing --files-dir: %d\n%s", r.code, r.output)
	}

	// The release-mode lint on the bundle blocks a license the policy bans.
	sbom := filepath.Join(app, "sbom/notes-web.spdx.json")
	writeFile(t, sbom, strings.Replace(readFile(t, sbom), `"licenseConcluded":"MIT","licenseDeclared":"MIT"`, `"licenseConcluded":"SSPL-1.0","licenseDeclared":"SSPL-1.0"`, 1))
	r = runScriptIn(t, root, "build-bundle.sh", f.env(compose, "ALLOW_MISSING_SEALED_CLI=1"), args...)
	if r.code == 0 || !strings.Contains(r.output, "the bundle fails the release lint") || !strings.Contains(r.output, "SSPL-1.0") {
		t.Fatalf("banned license: %d\n%s", r.code, r.output)
	}
}
