package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// The shape of ci.yml that the Linux CI portability review asked for (items L-1 to L-8): CI uses the
// toolchain the runtime images ship, pins docker compose wherever a suite checks compose output, gives go test
// an explicit timeout, runs the chain suites and the scraper's Firefox crawl, and prints the tool versions the
// review could not confirm on the runner.

type ciStep struct {
	Name             string         `yaml:"name"`
	Uses             string         `yaml:"uses"`
	Run              string         `yaml:"run"`
	With             map[string]any `yaml:"with"`
	WorkingDirectory string         `yaml:"working-directory"`
}

type ciJob struct {
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	Env            map[string]string `yaml:"env"`
	Steps          []ciStep          `yaml:"steps"`
}

type ciFile struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]ciJob  `yaml:"jobs"`
}

func loadCIWorkflow(t *testing.T) ciFile {
	t.Helper()
	var wf ciFile
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/ci.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("ci.yml has no jobs")
	}
	return wf
}

// ciStepIndex returns the index of the first step that matches, or -1.
func ciStepIndex(steps []ciStep, match func(ciStep) bool) int {
	for i, s := range steps {
		if match(s) {
			return i
		}
	}
	return -1
}

func ciUsesAction(name string) func(ciStep) bool {
	return func(s ciStep) bool { return strings.HasPrefix(s.Uses, name+"@") }
}

// ciRunsSuites matches the steps that run test suites (not the checks that merely contain the word test).
var ciRunsSuites = regexp.MustCompile(`go test |pnpm (-r )?test|node --test|-m unittest| test PYTHON=|make -C contracts test`)

// L-8: Go's default timeout is 10 minutes per package binary, too tight for runtime/composer's real-Docker
// stacks and catalog/tools/release on a 4 vCPU runner. The job timeout must be longer than -timeout, or a hung
// test can never be reported by Go with its stack before the job is cancelled.
func TestCIGoTestsHaveATimeout(t *testing.T) {
	wf := loadCIWorkflow(t)
	goTest := regexp.MustCompile(`\bgo test\b[^\n]*`)
	flag := regexp.MustCompile(`\s-timeout[ =](\S+)`)
	n := 0
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			for _, cmd := range goTest.FindAllString(s.Run, -1) {
				n++
				m := flag.FindStringSubmatch(cmd)
				if m == nil {
					t.Errorf("job %s: %q has no -timeout", name, cmd)
					continue
				}
				d, err := time.ParseDuration(m[1])
				if err != nil || d < 20*time.Minute {
					t.Errorf("job %s: %q: -timeout %s is not a duration of at least 20m", name, cmd, m[1])
					continue
				}
				if time.Duration(job.TimeoutMinutes)*time.Minute <= d {
					t.Errorf("job %s: timeout-minutes %d must be longer than go test -timeout %s", name, job.TimeoutMinutes, d)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("ci.yml runs no go test")
	}
}

// L-5: these jobs run suites whose assertions depend on the compose release (`config --format json` shape and
// escaping, `config --quiet` output, the read-only control's error text). Each one installs the pinned compose
// before its first suite and checks the plugin's digest and version.
func TestCIPinsCompose(t *testing.T) {
	wf := loadCIWorkflow(t)
	if v := wf.Env["COMPOSE_VERSION"]; !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(v) {
		t.Errorf("env COMPOSE_VERSION %q is not an exact version", v)
	}
	if s := wf.Env["COMPOSE_SHA256"]; !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s) {
		t.Errorf("env COMPOSE_SHA256 %q is not a sha256", s)
	}
	for _, name := range []string{"go", "ts", "catalog"} {
		job, ok := wf.Jobs[name]
		if !ok {
			t.Errorf("ci.yml has no %s job", name)
			continue
		}
		setup := ciStepIndex(job.Steps, ciUsesAction("docker/setup-compose-action"))
		if setup < 0 {
			t.Errorf("job %s: no docker/setup-compose-action step", name)
			continue
		}
		if v := fmt.Sprint(job.Steps[setup].With["version"]); v != "v${{ env.COMPOSE_VERSION }}" {
			t.Errorf("job %s: setup-compose-action version %q, want v${{ env.COMPOSE_VERSION }}", name, v)
		}
		if setup+1 >= len(job.Steps) {
			t.Errorf("job %s: no compose check after setup-compose-action", name)
			continue
		}
		check := job.Steps[setup+1].Run
		for _, want := range []string{`"$COMPOSE_SHA256  $HOME/.docker/cli-plugins/docker-compose" | sha256sum -c -`, `"$(docker compose version --short)" = "$COMPOSE_VERSION"`} {
			if !strings.Contains(check, want) {
				t.Errorf("job %s: the step after setup-compose-action does not run %s", name, want)
			}
		}
		first := ciStepIndex(job.Steps, func(s ciStep) bool { return ciRunsSuites.MatchString(s.Run) })
		if first < 0 || first < setup {
			t.Errorf("job %s: compose is pinned at step %d, after the first suite (step %d)", name, setup, first)
		}
	}
}

// L-7 and L-6.4: the ts job installs anvil and the contracts and sets SEALED_REQUIRE_CHAIN_TESTS=1, so the
// suites that gate on chainTestsEnabled() fail instead of skipping (TestCITSJobRequiresAnvil covers the ones that
// gate on anvilAvailable()), and it runs the scraper's Playwright Firefox crawl, which test/playwright.test.ts
// runs only with SCRAPER_PLAYWRIGHT_TESTS=1.
func TestCITSJobRunsChainTestsAndFirefoxCrawl(t *testing.T) {
	ts, ok := loadCIWorkflow(t).Jobs["ts"]
	if !ok {
		t.Fatal("ci.yml has no ts job")
	}
	if ts.Env["SEALED_REQUIRE_CHAIN_TESTS"] != "1" {
		t.Error(`ts job: env SEALED_REQUIRE_CHAIN_TESTS must be "1"`)
	}
	suite := ciStepIndex(ts.Steps, func(s ciStep) bool { return strings.TrimSpace(s.Run) == "pnpm -r test" })
	if suite < 0 {
		t.Fatal("ts job: no `pnpm -r test` step")
	}
	foundry := ciStepIndex(ts.Steps, ciUsesAction("foundry-rs/foundry-toolchain"))
	if foundry < 0 || foundry > suite {
		t.Error("ts job: foundry-rs/foundry-toolchain must run before pnpm -r test")
	} else if v := fmt.Sprint(ts.Steps[foundry].With["version"]); v != "${{ env.FOUNDRY_VERSION }}" {
		t.Errorf("ts job: Foundry version %q, want ${{ env.FOUNDRY_VERSION }}", v)
	}
	if deps := ciStepIndex(ts.Steps, func(s ciStep) bool { return strings.TrimSpace(s.Run) == "make -C contracts deps" }); deps < 0 || deps > suite {
		t.Error("ts job: make -C contracts deps must run before pnpm -r test (the chain suites build the contracts)")
	}
	crawl := ciStepIndex(ts.Steps, func(s ciStep) bool {
		return s.WorkingDirectory == "catalog/apps/scraper/runner" &&
			regexp.MustCompile(`pnpm exec playwright install (--with-deps )?firefox\n`).MatchString(s.Run) &&
			strings.Contains(s.Run, "pnpm test:playwright")
	})
	if crawl < 0 {
		t.Error("ts job: no step installs Playwright's Firefox and runs pnpm test:playwright in catalog/apps/scraper/runner")
	}
	pkg := readFile(t, filepath.Join(repoRoot(t), "catalog/apps/scraper/runner/package.json"))
	if !strings.Contains(pkg, `"test:playwright": "SCRAPER_PLAYWRIGHT_TESTS=1 vitest run test/playwright.test.ts"`) {
		t.Error("catalog/apps/scraper/runner/package.json: test:playwright no longer sets SCRAPER_PLAYWRIGHT_TESTS=1 for test/playwright.test.ts")
	}
}

// L-7: the relay and mpp-payer end-to-end suites gate on anvilAvailable() from runtime/relay/test/helpers/anvil.ts.
// It ignores SEALED_REQUIRE_CHAIN_TESTS and skips the suite when `anvil --version` does not exit 0, so the ts job's
// Require anvil step must fail the job in exactly that case, before pnpm -r test. The core and agent suites gate
// on chainTestsEnabled(), which throws under SEALED_REQUIRE_CHAIN_TESTS=1.
func TestCITSJobRequiresAnvil(t *testing.T) {
	root := repoRoot(t)
	ts, ok := loadCIWorkflow(t).Jobs["ts"]
	if !ok {
		t.Fatal("ci.yml has no ts job")
	}
	guard := ciStepIndex(ts.Steps, func(s ciStep) bool { return s.Name == "Require anvil" })
	suite := ciStepIndex(ts.Steps, func(s ciStep) bool { return strings.TrimSpace(s.Run) == "pnpm -r test" })
	if guard < 0 {
		t.Fatal("ts job: no Require anvil step")
	}
	if suite < 0 || guard > suite {
		t.Fatalf("ts job: Require anvil (step %d) must run before pnpm -r test (step %d)", guard, suite)
	}

	// The gates as they are today. A change to either one needs a matching change to the step or the comment.
	const helperPath = "runtime/relay/test/helpers/anvil.ts"
	body := regexp.MustCompile(`(?s)export function anvilAvailable\(\)[^{]*\{(.*?)\n\}`).FindStringSubmatch(readFile(t, filepath.Join(root, helperPath)))
	switch {
	case body == nil:
		t.Fatalf("%s: no anvilAvailable()", helperPath)
	case strings.Contains(body[1], "SEALED_REQUIRE_CHAIN_TESTS"):
		t.Log("anvilAvailable() reads SEALED_REQUIRE_CHAIN_TESTS itself; the Require anvil step is now a second check")
	case strings.Join(strings.Fields(body[1]), " ") != "const res = spawnSync('anvil', ['--version'], { stdio: 'ignore' }) return res.status === 0":
		t.Errorf("%s: anvilAvailable() is no longer just `anvil --version` exits 0; make the Require anvil step check the same, then update this test:\n%s", helperPath, body[1])
	}
	core := readFile(t, filepath.Join(root, "packages/core/src/testing/localTempo.ts"))
	if !regexp.MustCompile(`(?s)export function chainTestsEnabled\(\).*?process\.env\.SEALED_REQUIRE_CHAIN_TESTS === "1"\) \{\s*throw `).MatchString(core) {
		t.Error("chainTestsEnabled() no longer throws under SEALED_REQUIRE_CHAIN_TESTS=1, which ci.yml's ts job relies on")
	}

	// Every suite that gates on anvilAvailable() takes it from that helper, so the step covers it.
	importRe := regexp.MustCompile(`import \{[^}]*\banvilAvailable\b[^}]*\} from '([^']+)'`)
	var gated []string
	for _, top := range []string{"packages", "runtime", "catalog"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "dist", "dependencies":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".test.ts") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil || !strings.Contains(string(src), "anvilAvailable()") {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			gated = append(gated, rel)
			m := importRe.FindStringSubmatch(string(src))
			if m == nil {
				t.Errorf("%s: calls anvilAvailable() without importing it from %s", rel, helperPath)
				return nil
			}
			from, _ := filepath.Rel(root, filepath.Join(filepath.Dir(p), strings.TrimSuffix(m[1], ".js")+".ts"))
			if from != helperPath {
				t.Errorf("%s: anvilAvailable() comes from %s, not %s", rel, m[1], helperPath)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(gated) == 0 {
		t.Error("no suite gates on anvilAvailable() any more; drop the Require anvil step and this test")
	}
	t.Logf("suites that gate on anvilAvailable(): %v", gated)

	// Run the step as GitHub does (bash -e) with only the fake anvil on PATH.
	run := func(anvil string) (string, error) {
		bin := t.TempDir()
		if anvil != "" {
			writeFile(t, filepath.Join(bin, "anvil"), "#!/bin/sh\n"+anvil+"\n")
			if err := os.Chmod(filepath.Join(bin, "anvil"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-c", ts.Steps[guard].Run)
		cmd.Env = []string{"PATH=" + bin}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run("echo 'anvil Version: 1.8.6-v1.8.6'"); err != nil {
		t.Errorf("Require anvil failed with a working anvil: %v\n%s", err, out)
	}
	if out, err := run(""); err == nil || !strings.Contains(out, "::error::") {
		t.Errorf("Require anvil passed without anvil on PATH: %v\n%s", err, out)
	}
	if out, err := run("echo 'anvil: broken' >&2; exit 1"); err == nil || !strings.Contains(out, "::error::") {
		t.Errorf("Require anvil passed although anvil --version fails: %v\n%s", err, out)
	}
}

// The review could not confirm the runner's docker compose, shellcheck and dosfstools versions, so every job
// prints them, after its setup actions so the versions shown are the ones it uses.
func TestCIJobsPrintToolVersions(t *testing.T) {
	for name, job := range loadCIWorkflow(t).Jobs {
		i := ciStepIndex(job.Steps, func(s ciStep) bool { return s.Name == "Tool versions" })
		if i < 0 {
			t.Errorf("job %s: no Tool versions step", name)
			continue
		}
		for _, want := range []string{"docker compose version\n", "shellcheck --version", "dpkg-query -W dosfstools"} {
			if !strings.Contains(job.Steps[i].Run, want) {
				t.Errorf("job %s: Tool versions does not run %q", name, strings.TrimSpace(want))
			}
		}
		for j, s := range job.Steps[i+1:] {
			if s.Uses != "" {
				t.Errorf("job %s: %s (step %d) runs after Tool versions", name, s.Uses, i+1+j)
			}
		}
	}
}

// L-1 and L-2: CI tests with the Node and Python the shipped code runs on. Every Node image is pinned to one
// node:<version> tag, and the Python code that ships runs in the LiteLLM image's python3.<minor> venv.
func TestCIToolchainMatchesRuntimeImages(t *testing.T) {
	wf := loadCIWorkflow(t)
	root := repoRoot(t)
	nodeRe := regexp.MustCompile(`\bnode:(\d+\.\d+\.\d+)-`)
	pyRe := regexp.MustCompile(`\bpython(3\.\d+)/site-packages`)
	nodes, pythons := map[string][]string{}, map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dependencies", "tmp", "dist", "out":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "Dockerfile" && !strings.HasPrefix(d.Name(), "Dockerfile.") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for _, found := range []struct {
			re   *regexp.Regexp
			into map[string][]string
		}{{nodeRe, nodes}, {pyRe, pythons}} {
			seen := map[string]bool{}
			for _, m := range found.re.FindAllStringSubmatch(string(b), -1) {
				if !seen[m[1]] {
					seen[m[1]] = true
					found.into[m[1]] = append(found.into[m[1]], rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 || len(pythons) == 0 {
		t.Fatalf("found no node:<version> image (%v) or python3.<minor>/site-packages path (%v) in any Dockerfile", nodes, pythons)
	}
	for v, files := range nodes {
		if v != wf.Env["NODE_VERSION"] {
			t.Errorf("NODE_VERSION %q, but %v use node:%s", wf.Env["NODE_VERSION"], files, v)
		}
	}
	py := wf.Env["PYTHON_VERSION"]
	for v, files := range pythons {
		if py != v && !strings.HasPrefix(py, v+".") {
			t.Errorf("PYTHON_VERSION %q, but %v ship python%s", py, files, v)
		}
	}
}
