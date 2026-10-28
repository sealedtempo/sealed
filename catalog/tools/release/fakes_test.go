package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Fake crane, docker, syft, grype, cosign, gh and curl for the script tests. Each records its arguments in
// $FAKE_LOG and keeps state under $FAKE_STATE, so a test can drive the scripts' logic without registries,
// a Docker daemon, Sigstore or GitHub.

const fakeCrane = `#!/usr/bin/env bash
set -euo pipefail
echo "crane $*" >>"$FAKE_LOG"
key() { printf '%s' "$1" | tr '/:@' '___'; }
case "$1" in
digest)
  f="$FAKE_STATE/crane/$(key "$2")"
  [ -f "$f" ] || { echo "MANIFEST_UNKNOWN: $2" >&2; exit 1; }
  cat "$f" ;;
copy)
  src="$2" dst="$3"
  d="${src##*@}"
  [ -n "${FAKE_CRANE_WRONG_DIGEST:-}" ] && d="$FAKE_CRANE_WRONG_DIGEST"
  mkdir -p "$FAKE_STATE/crane"
  printf '%s' "$d" >"$FAKE_STATE/crane/$(key "$dst")"
  printf '%s' "$d" >"$FAKE_STATE/crane/$(key "${dst%:*}@$d")" ;;
auth) cat >/dev/null ;;
tag)
  d="${2##*@}"
  mkdir -p "$FAKE_STATE/crane"
  printf '%s' "$d" >"$FAKE_STATE/crane/$(key "${2%@*}:$3")" ;;
*) echo "fake crane: unsupported $1" >&2; exit 2 ;;
esac
`

// fakeDocker answers `docker buildx build`: the digest is the sha256 of the Dockerfile path and context
// (deterministic), or random for --no-cache rebuilds when FAKE_DOCKER_NONDETERMINISTIC=1. A push records the
// digest for the fake crane.
const fakeDocker = `#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >>"$FAKE_LOG"
[ "$1" = login ] && { cat >/dev/null; exit 0; }
[ "$1 $2" = "buildx build" ] || { echo "fake docker: unsupported $*" >&2; exit 2; }
shift 2
meta="" output="" nocache=0 file="" ctx=""
while [ $# -gt 0 ]; do
  case "$1" in
  --metadata-file) meta="$2"; shift 2 ;;
  --output) output="$2"; shift 2 ;;
  --file) file="$2"; shift 2 ;;
  --platform|--build-arg) shift 2 ;;
  --no-cache) nocache=1; shift ;;
  --provenance=false|--sbom=false) shift ;;
  -*) echo "fake docker: unknown flag $1" >&2; exit 2 ;;
  *) ctx="$1"; shift ;;
  esac
done
seed="$file|$(basename "$ctx")"
if [ "$nocache" = 1 ] && [ "${FAKE_DOCKER_NONDETERMINISTIC:-0}" = 1 ]; then seed="$seed|$RANDOM$RANDOM"; fi
d="sha256:$(printf '%s' "$seed" | (sha256sum 2>/dev/null || shasum -a 256) | cut -d' ' -f1)"
printf '{"containerimage.digest":"%s","image.name":"x"}' "$d" >"$meta"
case "$output" in
*push=true*)
  name="${output#*name=}"; name="${name%%,*}"
  key() { printf '%s' "$1" | tr '/:@' '___'; }
  mkdir -p "$FAKE_STATE/crane"
  printf '%s' "$d" >"$FAKE_STATE/crane/$(key "${name%:*}@$d")" ;;
*dest=*)
  dest="${output#*dest=}"; dest="${dest%%,*}"; : >"$dest" ;;
esac
`

const fakeSyft = `#!/usr/bin/env bash
set -euo pipefail
echo "syft $*" >>"$FAKE_LOG"
[ "$1" = scan ] || exit 2
for a in "$@"; do
  case "$a" in
  spdx-json=*) printf '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x","packages":[]}' >"${a#spdx-json=}" ;;
  syft-json=*) printf '{"artifacts":[],"source":{},"distro":{}}' >"${a#syft-json=}" ;;
  esac
done
`

const fakeGrype = `#!/usr/bin/env bash
set -euo pipefail
echo "grype $*" >>"$FAKE_LOG"
cat "$FAKE_GRYPE_REPORT"
`

// fakeCosign copies $FAKE_SIGSTORE_BUNDLE, or writes a structurally valid Sigstore v0.3 bundle for the blob
// (right digest, a placeholder certificate, a Rekor entry) when it is not set.
const fakeCosign = `#!/usr/bin/env bash
set -euo pipefail
echo "cosign $*" >>"$FAKE_LOG"
case "$1" in
sign-blob)
  out=""; prev=""; blob=""
  for a in "$@"; do [ "$prev" = --bundle ] && out="$a"; prev="$a"; blob="$a"; done
  if [ -n "${FAKE_SIGSTORE_BUNDLE:-}" ]; then cp "$FAKE_SIGSTORE_BUNDLE" "$out"; exit 0; fi
  d="$(openssl dgst -sha256 -binary "$blob" | base64 | tr -d '\n')"
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"MIIBfake"},"tlogEntries":[{"logIndex":"424242","integratedTime":"1761667200"}]},"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"%s"},"signature":"c2lnbmF0dXJl"}}' "$d" >"$out" ;;
verify-blob)
  [ "${FAKE_VERIFY_FAIL:-0}" = 1 ] && { echo "none of the expected identities matched" >&2; exit 1; }
  exit 0 ;;
*) exit 2 ;;
esac
`

// fakeGh keeps releases as directories: $FAKE_STATE/gh/<tag>/{draft,assets/,notes}.
const fakeGh = `#!/usr/bin/env bash
set -euo pipefail
echo "gh $*" >>"$FAKE_LOG"
root="$FAKE_STATE/gh"
mkdir -p "$root"
tag="${3:-}"
case "$1 $2" in
"release view")
  [ -d "$root/$tag" ] || { echo "release not found" >&2; exit 1; }
  if [ -f "$root/$tag/draft" ]; then echo true; else echo false; fi ;;
"release create")
  [ ! -d "$root/$tag" ] || { echo "already exists" >&2; exit 1; }
  mkdir -p "$root/$tag/assets"
  shift 3
  draft=0
  while [ $# -gt 0 ]; do
    case "$1" in
    --draft) draft=1; shift ;;
    --notes-file) cp "$2" "$root/$tag/notes"; shift 2 ;;
    --title|--target|--repo) shift 2 ;;
    --latest=false) shift ;;
    *) cp "$1" "$root/$tag/assets/"; shift ;;
    esac
  done
  [ "$draft" = 1 ] && : >"$root/$tag/draft"; exit 0 ;;
"release upload")
  shift 3
  while [ $# -gt 0 ]; do case "$1" in --clobber) shift ;; --repo) shift 2 ;; *) cp "$1" "$root/$tag/assets/"; shift ;; esac; done ;;
"release edit")
  shift 3
  while [ $# -gt 0 ]; do
    case "$1" in
    --draft=false) rm -f "$root/$tag/draft"; shift ;;
    --notes-file) cp "$2" "$root/$tag/notes"; shift 2 ;;
    --latest=false) shift ;;
    --repo) shift 2 ;;
    *) echo "fake gh: unknown $1" >&2; exit 2 ;;
    esac
  done ;;
"pr view") exit 1 ;;
"pr create")
  echo "https://github.com/sealedtempo/sealed/pull/42" ;;
*) echo "fake gh: unsupported $*" >&2; exit 2 ;;
esac
`

// fakeCurl serves release assets from the fake gh state: <base>/<tag>/<asset>.
const fakeCurl = `#!/usr/bin/env bash
set -euo pipefail
echo "curl $*" >>"$FAKE_LOG"
out="" url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; --proto|--max-time) shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done
asset="${url##*/}"; rest="${url%/*}"; tag="${rest##*/}"
f="$FAKE_STATE/gh/$tag/assets/$asset"
[ -f "$f" ] && [ ! -f "$FAKE_STATE/gh/$tag/draft" ] || { echo "curl: (22) 404" >&2; exit 22; }
cp "$f" "$out"
`

type fakeEnv struct {
	bin, state, log string
}

// newFakes writes the fake tools into a directory that goes first on PATH.
func newFakes(t *testing.T) *fakeEnv {
	t.Helper()
	dir := t.TempDir()
	f := &fakeEnv{bin: filepath.Join(dir, "bin"), state: filepath.Join(dir, "state"), log: filepath.Join(dir, "calls.log")}
	for name, body := range map[string]string{"crane": fakeCrane, "docker": fakeDocker, "syft": fakeSyft, "grype": fakeGrype,
		"cosign": fakeCosign, "gh": fakeGh, "curl": fakeCurl} {
		p := filepath.Join(f.bin, name)
		writeFile(t, p, body)
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(f.state, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.log, "")
	return f
}

func (f *fakeEnv) env(extra ...string) []string {
	return append([]string{"PATH=" + f.bin + ":" + os.Getenv("PATH"), "FAKE_STATE=" + f.state, "FAKE_LOG=" + f.log}, extra...)
}

func (f *fakeEnv) calls(t *testing.T) string { return readFile(t, f.log) }

// withScripts copies scripts/release into a fixture repository, so RELEASE_ROOT is the fixture.
func withScripts(t *testing.T, root string) string {
	t.Helper()
	copyTree(t, filepath.Join(repoRoot(t), "scripts/release"), filepath.Join(root, "scripts/release"))
	return root
}

func runScriptIn(t *testing.T, root, script string, env []string, args ...string) scriptResult {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(root, "scripts/release", script)}, args...)...)
	cmd.Env = append(cleanEnv(), append(env, "SEALED_RELEASE_BIN="+releaseBin(t))...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return scriptResult{code, string(out)}
}

var (
	composeOnce sync.Once
	composeBin  string
	composeErr  error
)

// sealedComposeBin builds the composer's CLI from the real repository once.
func sealedComposeBin(t *testing.T) string {
	t.Helper()
	composeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sealed-compose-test")
		if err != nil {
			composeErr = err
			return
		}
		composeBin = filepath.Join(dir, "sealed-compose")
		cmd := exec.Command("go", "build", "-o", composeBin, "./runtime/composer/cmd/sealed-compose")
		cmd.Dir = repoRoot(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			composeErr = &exec.Error{Name: "go build sealed-compose", Err: os.ErrInvalid}
			t.Logf("%s", out)
		}
	})
	if composeErr != nil {
		t.Fatal(composeErr)
	}
	return composeBin
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func countLines(s, prefix string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}
