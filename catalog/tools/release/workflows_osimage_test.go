package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runStepScript runs a workflow `run:` script with GitHub's bash flags in dir.
func runStepScript(t *testing.T, dir, script string, env ...string) (string, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "step.sh")
	writeFile(t, p, script)
	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", p)
	cmd.Dir = dir
	cmd.Env = append(cleanEnv(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// supply-7: an os-image-v* tag on any commit used to publish that commit's image. The release job now
// refuses a commit that is not on main, signs every disk tarball and identity file keyless before the
// upload, and is the only job that can sign.
func TestOSImageReleaseOnlyFromMainAndSigned(t *testing.T) {
	jobs := loadWorkflowJobs(t, "os-image.yml")
	rel := jobs["release"]
	if rel.Permissions["id-token"] != "write" || rel.Permissions["contents"] != "write" {
		t.Fatalf("release job permissions %v", rel.Permissions)
	}
	for name, j := range jobs {
		if name != "release" && j.Permissions["id-token"] != "" {
			t.Errorf("%s must not get id-token", name)
		}
	}
	if co := rel.Steps[0]; !strings.HasPrefix(co.Uses, "actions/checkout@") || co.With["fetch-depth"] != "0" {
		t.Fatalf("the release job checks out full history to see main: %+v", co)
	}
	onMain := stepIndex(t, rel, "The tagged commit is on main")
	sign := stepIndex(t, rel, "Sign the disk tarballs and identities (cosign keyless, Rekor)")
	create := stepIndex(t, rel, "Create the release")
	if !(onMain < sign && sign < create) {
		t.Fatalf("order: main check %d, sign %d, create %d", onMain, sign, create)
	}

	// The main check, on a repository with a commit on main and one only on a side branch.
	repo := t.TempDir()
	gitRun(t, repo, "init", "-q", "-b", "main")
	gitRun(t, repo, "commit", "-q", "--allow-empty", "-m", "on main")
	mainCommit := gitRun(t, repo, "rev-parse", "HEAD")
	gitRun(t, repo, "update-ref", "refs/remotes/origin/main", mainCommit)
	gitRun(t, repo, "checkout", "-q", "-b", "side")
	gitRun(t, repo, "commit", "-q", "--allow-empty", "-m", "side")
	side := gitRun(t, repo, "rev-parse", "HEAD")
	check := rel.Steps[onMain].Run
	out, err := runStepScript(t, repo, check, "GITHUB_SHA="+side, "TAG=os-image-v9.9.9-s9")
	if err == nil || !strings.Contains(out, "::error::os-image-v9.9.9-s9 is "+side+", which is not on main") {
		t.Fatalf("a tag on a side commit must stop the release: %v\n%s", err, out)
	}
	if out, err := runStepScript(t, repo, check, "GITHUB_SHA="+mainCommit, "TAG=os-image-v9.9.9-s9"); err != nil {
		t.Fatalf("a tag on main publishes: %v\n%s", err, out)
	}

	// The signing step, with a cosign that logs and can refuse one blob.
	work := t.TempDir()
	if err := copyFile(filepath.Join(repoRoot(t), "runtime/images/dstack-os/upstream.env"), filepath.Join(work, "runtime/images/dstack-os/upstream.env")); err != nil {
		t.Fatal(err)
	}
	env := readFile(t, filepath.Join(work, "runtime/images/dstack-os/upstream.env"))
	val := func(k string) string {
		for _, l := range strings.Split(env, "\n") {
			if v, ok := strings.CutPrefix(l, k+"="); ok {
				return v
			}
		}
		t.Fatalf("no %s in upstream.env", k)
		return ""
	}
	var blobs []string
	for _, name := range []string{val("SEALED_IMAGE_NAME_PROD"), val("SEALED_IMAGE_NAME_DEBUG")} {
		for _, suffix := range []string{"-gce.tar.gz", "-identity.tar.gz", "-identity.json"} {
			b := "dist/" + name + "-" + val("SEALED_OS_VERSION") + suffix
			writeFile(t, filepath.Join(work, b), "asset")
			blobs = append(blobs, b)
		}
	}
	bin := t.TempDir()
	logf := filepath.Join(t.TempDir(), "cosign.log")
	writeFile(t, filepath.Join(bin, "cosign"), `#!/usr/bin/env bash
echo "cosign $*" >>"$COSIGN_LOG"
for last in "$@"; do :; done
if [ "$1" = sign-blob ]; then echo '{}' >"$4"; fi
if [ "$1" = verify-blob ] && [ "$last" = "${COSIGN_REFUSE:-}" ]; then exit 1; fi
`)
	if err := os.Chmod(filepath.Join(bin, "cosign"), 0o755); err != nil {
		t.Fatal(err)
	}
	ref := "sealedtempo/sealed/.github/workflows/os-image.yml@refs/tags/os-image-v" + val("SEALED_OS_VERSION")
	stepEnv := []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "COSIGN_LOG=" + logf, "GITHUB_WORKFLOW_REF=" + ref}
	if out, err := runStepScript(t, work, rel.Steps[sign].Run, stepEnv...); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}
	log := readFile(t, logf)
	for _, b := range blobs {
		mustContain(t, log, "cosign sign-blob --yes --bundle "+b+".sigstore.json "+b+"\n")
		mustContain(t, log, "cosign verify-blob --bundle "+b+".sigstore.json --certificate-identity https://github.com/"+ref+
			" --certificate-oidc-issuer https://token.actions.githubusercontent.com "+b+"\n")
		if !fileExists(filepath.Join(work, b+".sigstore.json")) {
			t.Errorf("%s.sigstore.json is not in dist, so it would not be uploaded", b)
		}
	}
	if out, err := runStepScript(t, work, rel.Steps[sign].Run, append(stepEnv, "COSIGN_REFUSE="+blobs[4])...); err == nil {
		t.Fatalf("a signature that does not verify must stop the release:\n%s", out)
	}
	mustContain(t, rel.Steps[create].Run, `gh release create "$TAG" dist/*`)
}
