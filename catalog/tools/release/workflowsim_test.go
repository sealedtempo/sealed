package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// A small GitHub Actions emulator for the release workflow: it runs the real `run:` scripts of
// .github/workflows/release.yml with GitHub's bash flags, evaluates the `${{ }}` expressions they use,
// passes outputs between steps and jobs, and emulates the actions (checkout and setup actions are no-ops,
// artifacts are directories). Tools come from the fakes and a fake `go` that serves prebuilt binaries;
// the chain is a local Tempo node with the real contracts. This tests the workflow's glue (file names,
// JSON fields, step order), not GitHub itself.

type simStep struct {
	ID   string            `yaml:"id"`
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type simJob struct {
	Uses    string            `yaml:"uses"`
	Steps   []simStep         `yaml:"steps"`
	Env     map[string]string `yaml:"env"`
	Outputs map[string]string `yaml:"outputs"`
}

type simWorkflow struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]simJob `yaml:"jobs"`
}

type simulator struct {
	t         *testing.T
	wf        simWorkflow
	workspace string
	temp      string // RUNNER_TEMP root; each job gets its own
	artifacts string
	path      string // PATH for steps (fakes first)
	baseEnv   []string
	ctx       map[string]any  // github, secrets, vars, inputs, needs
	ifs       map[string]bool // values of the step `if:` conditions the test expects
	skip      map[string]bool // step names that must not run here (they change the host)
	runs      int
}

var exprRe = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

func lookup(ctx map[string]any, path string) (any, bool) {
	var cur any = ctx
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func toStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool, float64, int:
		return fmt.Sprint(x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// eval supports the expressions the release workflow uses: dotted paths, toJSON(path), join(path, 'sep')
// and `a || b`. Anything else fails the test, so the emulator never guesses.
func (s *simulator) eval(ctx map[string]any, expr string) string {
	if parts := strings.Split(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			if v := s.eval(ctx, strings.TrimSpace(p)); v != "" && v != "false" {
				return v
			}
		}
		return ""
	}
	if m := regexp.MustCompile(`^([\w.-]+) (==|!=) '([^']*)'$`).FindStringSubmatch(expr); m != nil {
		v, _ := lookup(ctx, m[1])
		return fmt.Sprint((toStr(v) == m[3]) == (m[2] == "=="))
	}
	if m := regexp.MustCompile(`^toJSON\(([\w.-]+)\)$`).FindStringSubmatch(expr); m != nil {
		v, _ := lookup(ctx, m[1])
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	}
	if m := regexp.MustCompile(`^join\(([\w.-]+), '([^']*)'\)$`).FindStringSubmatch(expr); m != nil {
		v, _ := lookup(ctx, m[1])
		var out []string
		for _, x := range v.([]any) {
			out = append(out, toStr(x))
		}
		return strings.Join(out, m[2])
	}
	if regexp.MustCompile(`^[\w.-]+$`).MatchString(expr) {
		v, _ := lookup(ctx, expr)
		return toStr(v)
	}
	s.t.Fatalf("emulator: unsupported expression %q", expr)
	return ""
}

func (s *simulator) expand(ctx map[string]any, in string) string {
	return exprRe.ReplaceAllStringFunc(in, func(m string) string { return s.eval(ctx, exprRe.FindStringSubmatch(m)[1]) })
}

func readKV(t *testing.T, p string) map[string]any {
	out := map[string]any{}
	f, err := os.Open(p)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[k] = v
		}
	}
	return out
}

// runJob runs one job with the given matrix entry (nil for none) and returns its outputs.
func (s *simulator) runJob(name string, matrix map[string]any) map[string]any {
	s.t.Helper()
	job, ok := s.wf.Jobs[name]
	if !ok {
		s.t.Fatalf("no job %s", name)
	}
	s.runs++
	temp := filepath.Join(s.temp, fmt.Sprintf("%s-%d", name, s.runs))
	if err := os.MkdirAll(temp, 0o755); err != nil {
		s.t.Fatal(err)
	}
	ctx := map[string]any{}
	for k, v := range s.ctx {
		ctx[k] = v
	}
	ctx["matrix"] = matrix
	ctx["runner"] = map[string]any{"temp": temp}
	envCtx := map[string]any{}
	for k, v := range s.wf.Env {
		envCtx[k] = v
	}
	ctx["env"] = envCtx
	steps := map[string]any{}
	ctx["steps"] = steps
	path := s.path
	for i, st := range job.Steps {
		label := st.Name
		if label == "" {
			label = st.Uses + st.Run
		}
		if s.skip[st.Name] {
			continue
		}
		if st.If != "" {
			run, ok := s.ifs[st.If]
			if !ok {
				s.t.Fatalf("%s step %q: condition %q has no value in the test", name, label, st.If)
			}
			if !run {
				continue
			}
		}
		if st.Uses != "" {
			s.useAction(ctx, st)
			continue
		}
		dir := filepath.Join(temp, ".sim")
		_ = os.MkdirAll(dir, 0o755)
		outFile, pathFile, summary := filepath.Join(dir, fmt.Sprintf("out%d", i)), filepath.Join(dir, fmt.Sprintf("path%d", i)), filepath.Join(temp, "summary.md")
		for _, f := range []string{outFile, pathFile} {
			writeFile(s.t, f, "")
		}
		script := filepath.Join(dir, fmt.Sprintf("step%d.sh", i))
		writeFile(s.t, script, s.expand(ctx, st.Run))
		cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", script)
		cmd.Dir = s.workspace
		env := append([]string{}, s.baseEnv...)
		for k, v := range s.wf.Env {
			env = append(env, k+"="+v)
		}
		for k, v := range job.Env {
			env = append(env, k+"="+s.expand(ctx, v))
		}
		for k, v := range st.Env {
			env = append(env, k+"="+s.expand(ctx, v))
		}
		env = append(env, "PATH="+path, "RUNNER_TEMP="+temp, "GITHUB_OUTPUT="+outFile, "GITHUB_PATH="+pathFile,
			"GITHUB_STEP_SUMMARY="+summary, "GITHUB_WORKSPACE="+s.workspace)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			s.t.Fatalf("job %s step %q failed: %v\n%s", name, label, err, out)
		}
		if st.ID != "" {
			steps[st.ID] = map[string]any{"outputs": readKV(s.t, outFile)}
		}
		for _, l := range strings.Split(readFile(s.t, pathFile), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				path = l + ":" + path
			}
		}
	}
	outs := map[string]any{}
	for k, v := range job.Outputs {
		outs[k] = s.expand(ctx, v)
	}
	return outs
}

func (s *simulator) useAction(ctx map[string]any, st simStep) {
	s.t.Helper()
	name := st.Uses[:strings.Index(st.Uses, "@")]
	with := map[string]string{}
	for k, v := range st.With {
		with[k] = s.expand(ctx, v)
	}
	switch name {
	case "actions/checkout", "actions/setup-go", "foundry-rs/foundry-toolchain", "anchore/sbom-action/download-syft",
		"anchore/scan-action/download-grype", "sigstore/cosign-installer", "docker/setup-buildx-action":
		return // the workspace is the fixture; tools come from the fakes
	case "actions/upload-artifact":
		paths := strings.Fields(with["path"])
		root := paths[0]
		if len(paths) > 1 {
			root = filepath.Dir(paths[0])
		}
		dst := filepath.Join(s.artifacts, with["name"])
		for _, p := range paths {
			rel, _ := filepath.Rel(root, p)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				copyTree(s.t, p, filepath.Join(dst, rel))
			} else if err := copyFile(p, filepath.Join(dst, rel)); err != nil {
				s.t.Fatal(err)
			}
		}
	case "actions/download-artifact":
		if pat := with["pattern"]; pat != "" {
			matches, _ := filepath.Glob(filepath.Join(s.artifacts, pat))
			for _, m := range matches {
				copyTree(s.t, m, filepath.Join(with["path"], filepath.Base(m)))
			}
			return
		}
		copyTree(s.t, filepath.Join(s.artifacts, with["name"]), with["path"])
	default:
		s.t.Fatalf("emulator: action %s is not emulated", name)
	}
}

// fakeGo answers `go build -o <out> <pkg>` and `go run <pkg> args...` with prebuilt binaries
// ($FAKE_GO_BINS/<last path element>), and `go install .../crane@...` with the fake crane already on PATH.
const fakeGo = `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
build)
  [ "$2" = -o ] || { echo "fake go: only 'go build -o <out> <pkg>'" >&2; exit 2; }
  mkdir -p "$(dirname "$3")"
  cp "$FAKE_GO_BINS/$(basename "$4")" "$3" ;;
run)
  pkg="$2"; shift 2
  exec "$FAKE_GO_BINS/$(basename "$pkg")" "$@" ;;
install) exit 0 ;;
*) echo "fake go: unsupported $*" >&2; exit 2 ;;
esac
`

func TestReleaseWorkflowEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	requireJQ(t)
	requireTools(t, "openssl")
	c := deployContracts(t)
	root := withScripts(t, fixtureRepo(t))
	f := newFakes(t)

	// Prebuilt tools for the fake go.
	bins := t.TempDir()
	if err := copyFile(releaseBin(t), filepath.Join(bins, "release")); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(sealedComposeBin(t), filepath.Join(bins, "sealed-compose")); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"release", "sealed-compose"} {
		_ = os.Chmod(filepath.Join(bins, b), 0o755)
	}
	writeFile(t, filepath.Join(f.bin, "go"), fakeGo)
	_ = os.Chmod(filepath.Join(f.bin, "go"), 0o755)

	// OWNER registers the app, as register-apps.sh would.
	if out, err := exec.Command("cast", "send", c.registry, "registerApp(bytes32,string,string,string,address,uint16,string)",
		composer.AppID("notes").Hex(), "notes", "Notes", "MIT", castAddr(t, devMaintainer), "2000", "https://example.invalid/notes",
		"--private-key", devOwner, "--rpc-url", c.rpc, "--tempo.fee-token", alphaUSD).CombinedOutput(); err != nil {
		t.Fatalf("registerApp: %v %s", err, out)
	}

	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/release.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("e", 40)
	grypeReport := filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, grypeReport, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)
	sim := &simulator{t: t, wf: wf, workspace: root, temp: t.TempDir(), artifacts: t.TempDir(),
		path: f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+f.state, "FAKE_LOG="+f.log, "FAKE_GO_BINS="+bins, "FAKE_GRYPE_REPORT="+grypeReport,
			"GITHUB_SHA="+commit, "GITHUB_WORKFLOW_REF=sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main",
			// Test-only: the scripts default to Tempo mainnet; here they target the local node.
			"EXPECT_CHAIN_ID=31337", "DEPLOYMENTS_FILE="+c.deployments, "FEE_TOKEN_ADDRESS="+thetaUSD),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "workflow_dispatch", "token": "fake-token", "repository": "sealedtempo/sealed",
				"server_url": "https://github.com", "run_id": "99", "actor": "sealedtempo", "event": map[string]any{"before": ""}},
			"inputs":  map[string]any{"apps": "notes"},
			"secrets": map[string]any{"TEMPO_RPC_URL": c.rpc, "OPS_PRIVATE_KEY": devOps},
			"vars":    map[string]any{"ALLOW_MISSING_SEALED_CLI": "1"},
		},
	}

	plan := sim.runJob("plan", nil)
	if plan["count"] != "1" || plan["apps"] != "notes" {
		t.Fatalf("plan outputs: %v", plan)
	}
	var matrix struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(plan["matrix"])), &matrix); err != nil {
		t.Fatal(err)
	}
	needs := map[string]any{"plan": map[string]any{"outputs": plan}}
	sim.ctx["needs"] = needs
	entry := matrix.Include[0]

	sim.runJob("build", entry)
	subjects := sim.runJob("subjects", nil)
	// Provenance: the SLSA generator's artifact, emulated with the subjects it would sign.
	writeFile(t, filepath.Join(sim.artifacts, "bundles.intoto.jsonl", "bundles.intoto.jsonl"), `{"payloadType":"application/vnd.in-toto+json","subjects":"`+toStr(subjects["hashes"])+`"}`)
	needs["build"] = map[string]any{"outputs": map[string]any{}}
	needs["provenance"] = map[string]any{"outputs": map[string]any{"provenance-name": "bundles.intoto.jsonl"}}
	sim.runJob("publish", entry)

	// The GitHub Release has every asset of the rule, and the notes carry the transaction.
	tag := "notes-v1.0.0-sealed.1"
	assets, _ := os.ReadDir(filepath.Join(f.state, "gh", tag, "assets"))
	var names []string
	for _, a := range assets {
		names = append(names, a.Name())
	}
	sort.Strings(names)
	want := []string{"notes-1.0.0-sealed.1.bundle.tar", "notes-1.0.0-sealed.1.bundle.tar.crt", "notes-1.0.0-sealed.1.bundle.tar.intoto.jsonl",
		"notes-1.0.0-sealed.1.bundle.tar.sig", "notes-1.0.0-sealed.1.bundle.tar.sigstore.json", "notes-1.0.0-sealed.1.release.json",
		"sbom.notes-web.spdx.json", "sbom.postgres.spdx.json", "scan.notes-web.json", "scan.postgres.json"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("release assets\n got %v\nwant %v", names, want)
	}
	if fileExists(filepath.Join(f.state, "gh", tag, "draft")) {
		t.Fatal("the release must be published")
	}
	var doc ReleaseDoc
	if err := readJSONFile(filepath.Join(f.state, "gh", tag, "assets", "notes-1.0.0-sealed.1.release.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Onchain == nil || !txHashRe.MatchString(doc.Onchain.TxHash) || doc.Onchain.ChainID != 31337 || doc.Rekor == nil || doc.Rekor.LogIndex != 424242 ||
		doc.Commit != commit || doc.SignerIdentity != "https://github.com/sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main" {
		t.Fatalf("release.json: %+v", doc)
	}
	notes := readFile(t, filepath.Join(f.state, "gh", tag, "notes"))
	mustContain(t, notes, "transaction [`"+doc.Onchain.TxHash+"`]")
	onchain := castOut(t, "call", c.registry, "releaseByVersion(bytes32,string)(bytes32)", composer.AppID("notes").Hex(), "1.0.0-sealed.1", "--rpc-url", c.rpc)
	if onchain != doc.ReleaseID {
		t.Fatalf("onchain release %s, release.json %s", onchain, doc.ReleaseID)
	}
	bundle := readFile(t, filepath.Join(f.state, "gh", tag, "assets", "notes-1.0.0-sealed.1.bundle.tar"))
	if composer.SHA256([]byte(bundle)).Hex() != doc.BundleHash {
		t.Fatal("the public bundle is the onchain bundleHash")
	}
	rel := castOut(t, "call", c.registry, "getRelease(bytes32)((bytes32,bytes32,bytes32,bytes32,uint8,uint64,string,string,string))", doc.ReleaseID, "--rpc-url", c.rpc)
	mustContain(t, rel, "https://github.com/sealedtempo/sealed/releases/download/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar.intoto.jsonl")
	mustContain(t, rel, "https://github.com/sealedtempo/sealed/releases/download/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar.sig")
	mustContain(t, f.calls(t), "cosign sign-blob --yes --bundle")

	// A re-run of publish (for example after a timeout) keeps the public release and the transaction.
	firstTx := doc.Onchain.TxHash
	sim.runJob("publish", entry)
	if err := readJSONFile(filepath.Join(f.state, "gh", tag, "assets", "notes-1.0.0-sealed.1.release.json"), &doc); err != nil || doc.Onchain.TxHash != firstTx || !doc.Onchain.AlreadyPublished {
		t.Fatalf("re-run: %+v %v", doc.Onchain, err)
	}
	if readFile(t, filepath.Join(f.state, "gh", tag, "assets", "notes-1.0.0-sealed.1.bundle.tar")) != bundle {
		t.Fatal("a re-run must not replace the public bundle")
	}

	// The next plan sees a complete release and plans nothing.
	plan = sim.runJob("plan", nil)
	if plan["count"] != "0" {
		t.Fatalf("second plan: %v", plan)
	}
}
