package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Review policy-1: every SBOM comes from one syft setup (scripts/release/syft-env.sh). scan-image.sh writes
// the shipped SBOM and an every-file listing for lint, and the lint fixture
// (runtime/composer/lint/testdata/syft-image/make-image-sbom.sh) must be made exactly as scan-image.sh lists
// files, or the lint tests pass on an SBOM the release never produces (Go modules without licenses, files no
// package owns left out).

// fakeSyftRecorder records each call's arguments and SYFT_* environment under $FAKE_SYFT_DIR (<n>.args,
// <n>.env) and writes minimal SPDX and Syft JSON outputs.
const fakeSyftRecorder = `#!/usr/bin/env bash
set -euo pipefail
n=$(( $(cat "$FAKE_SYFT_DIR/seq" 2>/dev/null || echo 0) + 1 ))
echo "$n" >"$FAKE_SYFT_DIR/seq"
printf '%s\n' "$@" >"$FAKE_SYFT_DIR/$n.args"
{ env | grep '^SYFT_' || true; } | LC_ALL=C sort >"$FAKE_SYFT_DIR/$n.env"
for a in "$@"; do
  case "$a" in
  spdx-json=*) printf '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x","packages":[]}' >"${a#spdx-json=}" ;;
  syft-json=*) printf '{"artifacts":[],"source":{},"distro":{}}' >"${a#syft-json=}" ;;
  esac
done
`

// fakeGoBuild and fakeCraneAppend stand in for the two tools make-image-sbom.sh runs besides syft: they only
// create the file named by -o.
const fakeGoBuild = `#!/usr/bin/env bash
set -euo pipefail
[ "$1" = build ] || { echo "fake go: unsupported $1" >&2; exit 2; }
while [ $# -gt 0 ]; do [ "$1" = -o ] && { printf 'ELF' >"$2"; exit 0; }; shift; done
exit 2
`

const fakeCraneAppend = `#!/usr/bin/env bash
set -euo pipefail
[ "$1" = append ] || { echo "fake crane: unsupported $1" >&2; exit 2; }
while [ $# -gt 0 ]; do [ "$1" = -o ] && { printf 'tar' >"$2"; exit 0; }; shift; done
exit 2
`

// The settings every scan resolves to, and the two file selections.
var (
	wantSyftCommon = map[string]string{
		"SYFT_CHECK_FOR_APP_UPDATE":                     "false",
		"SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES":   "true",
		"SYFT_GOLANG_SEARCH_REMOTE_LICENSES":            "true",
		"SYFT_GOLANG_PROXY":                             "https://proxy.golang.org",
		"SYFT_GOLANG_NO_PROXY":                          "",
		"SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_CONTENTS": "true",
	}
	wantSyftShipped = withSyft(map[string]string{"SYFT_FILE_METADATA_SELECTION": "owned-by-package", "SYFT_FILE_METADATA_DIGESTS": "sha1,sha256"})
	wantSyftFiles   = withSyft(map[string]string{"SYFT_FILE_METADATA_SELECTION": "all", "SYFT_FILE_METADATA_DIGESTS": ""})
)

func withSyft(extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range wantSyftCommon {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// hostileSyftEnv is a caller environment that would change what syft lists. Only registry access survives.
var hostileSyftEnv = []string{
	"SYFT_FILE_METADATA_SELECTION=owned-by-package", "SYFT_FILE_METADATA_DIGESTS=md5", "SYFT_ENRICH=all",
	"SYFT_SCOPE=all-layers", "SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false", "SYFT_EXCLUDE=./app/**",
	"GOPROXY=off", "GONOPROXY=example.com", "SYFT_REGISTRY_AUTH_AUTHORITY=ghcr.io",
}

type syftCall struct {
	args []string
	env  map[string]string
}

func newSyftRecorder(t *testing.T) (bin, dir string) {
	t.Helper()
	root := t.TempDir()
	bin, dir = filepath.Join(root, "bin"), filepath.Join(root, "calls")
	for name, body := range map[string]string{"syft": fakeSyftRecorder, "go": fakeGoBuild, "crane": fakeCraneAppend} {
		writeFile(t, filepath.Join(bin, name), body)
		if err := os.Chmod(filepath.Join(bin, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

func readSyftCalls(t *testing.T, dir string) []syftCall {
	t.Helper()
	var calls []syftCall
	for n := 1; ; n++ {
		p := filepath.Join(dir, strconv.Itoa(n))
		if !fileExists(p + ".args") {
			return calls
		}
		c := syftCall{args: strings.Split(strings.TrimSuffix(readFile(t, p+".args"), "\n"), "\n"), env: map[string]string{}}
		for _, line := range strings.Split(strings.TrimSpace(readFile(t, p+".env")), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				c.env[k] = v
			}
		}
		calls = append(calls, c)
	}
}

// syftFlags drops the parts of a syft call that name what is scanned and where the output goes (the source,
// -o, --source-name, --source-version), leaving the flags that decide what the SBOM lists.
func syftFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch {
		case i == 1:
		case args[i] == "-o" || args[i] == "--source-name" || args[i] == "--source-version":
			i++
		default:
			out = append(out, args[i])
		}
	}
	return out
}

func checkSyftEnv(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		for k := range want {
			if _, ok := got[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var diff []string
		for _, k := range keys {
			if g, w := quoteOrMissing(got, k), quoteOrMissing(want, k); g != w {
				diff = append(diff, k+": got "+g+", want "+w)
			}
		}
		t.Errorf("%s: syft environment differs:\n  %s", what, strings.Join(diff, "\n  "))
	}
}

func quoteOrMissing(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return `"` + v + `"`
	}
	return "(unset)"
}

func TestSyftEnvSettings(t *testing.T) {
	bin, dir := newSyftRecorder(t)
	cmd := exec.Command("bash", "-c", `set -euo pipefail; . scripts/release/syft-env.sh
sealed_syft_sbom registry:example.test/a@sha256:1 -o "spdx-json=$OUT/a.spdx.json"
sealed_syft_files registry:example.test/a@sha256:1 -o "spdx-json=$OUT/b.spdx.json"`)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(cleanEnv(), append(hostileSyftEnv, "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_SYFT_DIR="+dir, "OUT="+t.TempDir())...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	calls := readSyftCalls(t, dir)
	if len(calls) != 2 {
		t.Fatalf("%d syft calls, want 2", len(calls))
	}
	registry := map[string]string{"SYFT_REGISTRY_AUTH_AUTHORITY": "ghcr.io"}
	checkSyftEnv(t, "sealed_syft_sbom", calls[0].env, merge(wantSyftShipped, registry))
	checkSyftEnv(t, "sealed_syft_files", calls[1].env, merge(wantSyftFiles, registry))
	// Every scan passes -c scripts/release/syft.yaml, so a planted .syft.yaml cannot change what it lists.
	cfg := filepath.Join(repoRoot(t), "scripts/release/syft.yaml")
	for i, c := range calls {
		if got, want := syftFlags(c.args), []string{"scan", "-c", cfg, "--platform", "linux/amd64", "-q"}; !reflect.DeepEqual(got, want) {
			t.Errorf("call %d: flags %q, want %q", i+1, got, want)
		}
	}
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// TestScanImageAndLintFixtureShareSyftSettings runs scan-image.sh and make-image-sbom.sh with a recording
// syft: the fixture's scan must resolve to exactly the settings and flags of scan-image.sh's file listing.
func TestScanImageAndLintFixtureShareSyftSettings(t *testing.T) {
	requireJQ(t)
	requireTools(t, "python3", "tar")
	bin, scanCalls := newSyftRecorder(t)

	// scan-image.sh, as the release, catalog and image workflows run it.
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)
	report := filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, report, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)
	out := t.TempDir()
	ref := "ghcr.io/sealedtempo/notes-web@sha256:" + strings.Repeat("1", 64)
	env := append(f.env("FAKE_GRYPE_REPORT="+report, "FAKE_SYFT_DIR="+scanCalls), hostileSyftEnv...)
	env = append(env, "PATH="+bin+":"+f.bin+":"+os.Getenv("PATH"))
	r := runScriptIn(t, root, "scan-image.sh", env, "--image", "notes-web", "--ref", ref,
		"--waivers", filepath.Join(root, CatalogDir, "notes/waivers.yaml"), "--out", out)
	if r.code != 0 {
		t.Fatalf("scan-image.sh: %d\n%s", r.code, r.output)
	}
	scan := readSyftCalls(t, scanCalls)
	if len(scan) != 2 {
		t.Fatalf("scan-image.sh made %d syft calls, want 2 (the shipped SBOM and the file listing)", len(scan))
	}
	registry := map[string]string{"SYFT_REGISTRY_AUTH_AUTHORITY": "ghcr.io"}
	checkSyftEnv(t, "scan-image.sh shipped SBOM", scan[0].env, merge(wantSyftShipped, registry))
	checkSyftEnv(t, "scan-image.sh file listing", scan[1].env, merge(wantSyftFiles, registry))
	// scan-image.sh here runs from the withScripts copy (root), make-image-sbom.sh from the real repo, so
	// each -c resolves to its own checkout's scripts/release/syft.yaml.
	scanCfg := filepath.Join(root, "scripts/release/syft.yaml")
	mustContain(t, strings.Join(scan[0].args, " "), "scan registry:"+ref+" -c "+scanCfg+" --platform linux/amd64 -o spdx-json="+filepath.Join(out, "sbom/notes-web.spdx.json"))
	mustContain(t, strings.Join(scan[1].args, " "), "scan registry:"+ref+" -c "+scanCfg+" --platform linux/amd64 -o spdx-json="+filepath.Join(out, "files/notes-web.spdx.json"))
	for _, p := range []string{"sbom/notes-web.spdx.json", "files/notes-web.spdx.json"} {
		if !fileExists(filepath.Join(out, p)) {
			t.Errorf("%s missing", p)
		}
	}

	// make-image-sbom.sh, as a maintainer regenerates the lint fixture (same hostile environment).
	_, fixtureCalls := newSyftRecorder(t)
	repo := repoRoot(t)
	sbom := filepath.Join(t.TempDir(), "image.spdx.json")
	cmd := exec.Command("bash", filepath.Join(repo, "runtime/composer/lint/testdata/syft-image/make-image-sbom.sh"), repo, sbom)
	cmd.Dir = t.TempDir()
	cmd.Env = append(cleanEnv(), append(hostileSyftEnv, "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_SYFT_DIR="+fixtureCalls, "TMPDIR="+t.TempDir())...)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make-image-sbom.sh: %v\n%s", err, o)
	}
	fixture := readSyftCalls(t, fixtureCalls)
	if len(fixture) != 1 || !fileExists(sbom) {
		t.Fatalf("make-image-sbom.sh made %d syft calls, want 1 and the SBOM", len(fixture))
	}
	checkSyftEnv(t, "lint fixture vs scan-image.sh file listing", fixture[0].env, scan[1].env)
	// Flags must match once the -c path (each checkout's own) is normalized: the fixture is made exactly as
	// the release lists files, including the pinned config.
	if got, want := normConfigFlag(syftFlags(fixture[0].args)), normConfigFlag(syftFlags(scan[1].args)); !reflect.DeepEqual(got, want) {
		t.Errorf("lint fixture flags %q, scan-image.sh file listing flags %q", got, want)
	}
	// Both scripts must pin scripts/release/syft.yaml with -c, or a planted .syft.yaml could make them list
	// different files (the release scan and the lint fixture would diverge).
	for _, c := range []struct {
		what string
		args []string
	}{{"scan-image.sh shipped SBOM", scan[0].args}, {"scan-image.sh file listing", scan[1].args}, {"lint fixture", fixture[0].args}} {
		if got := configFlag(c.args); !strings.HasSuffix(got, "/scripts/release/syft.yaml") {
			t.Errorf("%s: -c %q, want a path ending in scripts/release/syft.yaml", c.what, got)
		}
	}
}

// configFlag returns the value of the -c flag in a syft call, or "" if there is none.
func configFlag(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-c" {
			return args[i+1]
		}
	}
	return ""
}

// normConfigFlag replaces the absolute -c path (each checkout's own) with a placeholder, so two scans from
// different checkouts compare equal on everything but that path.
func normConfigFlag(flags []string) []string {
	out := append([]string(nil), flags...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "-c" {
			out[i+1] = "<cfg>"
		}
	}
	return out
}

// TestSyftReadsTheSettings checks, with the real syft when it is installed, that syft resolves the two
// environments to the intended configuration (an empty digest list, both Go license sources, the proxy) and
// that the -c scripts/release/syft.yaml the scripts pass makes syft ignore every auto-discovered config: a
// hostile .syft.yaml in the working directory and in HOME must not change exclude, scope, select-catalogers
// or enrich. The fake syft forwards the -c flag (the only part of the call it needs) to `config --load`, so
// without -c this test would read the planted configs and fail.
func TestSyftReadsTheSettings(t *testing.T) {
	real, err := exec.LookPath("syft")
	if err != nil {
		t.Skip("syft not installed")
	}
	bin := filepath.Join(t.TempDir(), "bin")
	writeFile(t, filepath.Join(bin, "syft"), `#!/usr/bin/env bash
set -euo pipefail
args=()
while [ $# -gt 0 ]; do
  case "$1" in
  -c) args+=(-c "$2"); shift 2 ;;
  *) shift ;;
  esac
done
exec "$REAL_SYFT" config --load ${args[@]+"${args[@]}"}
`)
	if err := os.Chmod(filepath.Join(bin, "syft"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A hostile .syft.yaml in the working directory and in HOME. -c must shut both out.
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".syft.yaml"), "scope: all-layers\nenrich: [all]\nselect-catalogers: [\"-go-module-binary-cataloger\"]\n")
	writeFile(t, filepath.Join(home, ".config/syft/config.yaml"), "scope: all-layers\n")
	work := t.TempDir()
	writeFile(t, filepath.Join(work, ".syft.yaml"), "exclude:\n  - \"**/app/**\"\nscope: all-layers\nselect-catalogers: [\"-go-module-binary-cataloger\"]\n")
	envScript := filepath.Join(repoRoot(t), "scripts/release/syft-env.sh")

	for fn, want := range map[string]map[string]any{
		"sealed_syft_sbom":  {"selection": "owned-by-package", "digests": []any{"sha1", "sha256"}},
		"sealed_syft_files": {"selection": "all", "digests": []any{}},
	} {
		cmd := exec.Command("bash", "-c", `. "`+envScript+`"; `+fn+" registry:example.test/a@sha256:1")
		cmd.Dir = work
		cmd.Env = append(cleanEnv(), append(hostileSyftEnv, "PATH="+bin+":"+os.Getenv("PATH"), "REAL_SYFT="+real, "HOME="+home)...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", fn, err)
		}
		var cfg struct {
			Config string `yaml:"config"`
			File   struct {
				Metadata struct {
					Selection string `yaml:"selection"`
					Digests   []any  `yaml:"digests"`
				} `yaml:"metadata"`
			} `yaml:"file"`
			Golang struct {
				Local    bool   `yaml:"search-local-mod-cache-licenses"`
				Remote   bool   `yaml:"search-remote-licenses"`
				Proxy    string `yaml:"proxy"`
				NoProxy  string `yaml:"no-proxy"`
				MainMods struct {
					FromContents bool `yaml:"from-contents"`
				} `yaml:"main-module-version"`
			} `yaml:"golang"`
			Scope            string `yaml:"scope"`
			Enrich           []any  `yaml:"enrich"`
			Exclude          []any  `yaml:"exclude"`
			SelectCatalogers []any  `yaml:"select-catalogers"`
		}
		if err := yaml.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("%s: %v\n%s", fn, err, out)
		}
		if cfg.File.Metadata.Digests == nil {
			cfg.File.Metadata.Digests = []any{}
		}
		if cfg.File.Metadata.Selection != want["selection"] || !reflect.DeepEqual(cfg.File.Metadata.Digests, want["digests"]) {
			t.Errorf("%s: file metadata %+v, want %v", fn, cfg.File.Metadata, want)
		}
		if g := cfg.Golang; !g.Local || !g.Remote || g.Proxy != "https://proxy.golang.org" || g.NoProxy != "" || !g.MainMods.FromContents {
			t.Errorf("%s: golang %+v", fn, g)
		}
		// syft loaded our pinned config, not a discovered one.
		if !strings.HasSuffix(cfg.Config, "scripts/release/syft.yaml") {
			t.Errorf("%s: syft loaded config %q, want scripts/release/syft.yaml", fn, cfg.Config)
		}
		// None of the planted .syft.yaml settings apply.
		if cfg.Scope != "squashed" {
			t.Errorf("%s: a planted .syft.yaml changed scope to %q (want squashed)", fn, cfg.Scope)
		}
		if len(cfg.Enrich) != 0 {
			t.Errorf("%s: a planted .syft.yaml set enrich %v", fn, cfg.Enrich)
		}
		if len(cfg.Exclude) != 0 {
			t.Errorf("%s: a planted .syft.yaml set exclude %v", fn, cfg.Exclude)
		}
		if len(cfg.SelectCatalogers) != 0 {
			t.Errorf("%s: a planted .syft.yaml set select-catalogers %v", fn, cfg.SelectCatalogers)
		}
	}
}
