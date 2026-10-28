package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRealWorkflowsFollowThePolicy(t *testing.T) {
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	probs, err := CheckWorkflows(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Error(p)
	}
	// Every known action is used somewhere, so the list never holds stale pins.
	used := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		raw := readFile(t, filepath.Join(dir, e.Name()))
		for name := range KnownActions {
			if strings.Contains(raw, "uses: "+name+"@") || strings.Contains(raw, "uses: "+name+"/") {
				used[name] = true
			}
		}
	}
	for name := range KnownActions {
		if !used[name] {
			t.Errorf("%s is in KnownActions but no workflow uses it", name)
		}
	}
}

// The release pipeline's shape: the jobs exist, the mainnet key only reaches the publish job, provenance
// comes from the SLSA generator, and signing has id-token.
func TestReleaseWorkflowShape(t *testing.T) {
	raw := readFile(t, filepath.Join(repoRoot(t), ".github/workflows/release.yml"))
	var wf struct {
		Jobs map[string]struct {
			Uses        string            `yaml:"uses"`
			Environment string            `yaml:"environment"`
			Permissions map[string]string `yaml:"permissions"`
			Needs       any               `yaml:"needs"`
			Strategy    struct {
				MaxParallel int `yaml:"max-parallel"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		t.Fatal(err)
	}
	for _, j := range []string{"plan", "mirror", "build", "subjects", "slsa-pin", "provenance", "publish"} {
		if _, ok := wf.Jobs[j]; !ok {
			t.Errorf("release.yml has no %s job", j)
		}
	}
	if wf.Jobs["provenance"].Uses != SLSAGenerator {
		t.Errorf("provenance uses %q", wf.Jobs["provenance"].Uses)
	}
	if wf.Jobs["mirror"].Uses != "./.github/workflows/mirror.yml" {
		t.Errorf("mirror uses %q", wf.Jobs["mirror"].Uses)
	}
	if wf.Jobs["build"].Permissions["id-token"] != "write" {
		t.Error("build signs keyless and needs id-token: write")
	}
	pub := wf.Jobs["publish"]
	if pub.Environment != "mainnet" || pub.Strategy.MaxParallel != 1 || pub.Permissions["contents"] != "write" {
		t.Errorf("publish job: %+v", pub)
	}
	if strings.Count(raw, "secrets.OPS_PRIVATE_KEY") != 1 {
		t.Error("OPS_PRIVATE_KEY appears exactly once, in the publish step")
	}
	for _, f := range []string{"ci.yml", "catalog.yml", "images.yml", "mirror.yml", "release.yml"} {
		body := readFile(t, filepath.Join(repoRoot(t), ".github/workflows", f))
		if strings.ContainsAny(body, "—–") {
			t.Errorf("%s contains an em-dash or en-dash", f)
		}
		if f != "release.yml" && strings.Contains(body, "OPS_PRIVATE_KEY") {
			t.Errorf("%s must not reference OPS_PRIVATE_KEY", f)
		}
		if strings.Contains(body, "register-apps.sh") && !strings.Contains(body, "OWNER registers") {
			t.Errorf("%s runs register-apps.sh; it is OWNER-only", f)
		}
	}
}

func TestWorkflowPolicyViolations(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"tag pin": {`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
`, "pin by full commit SHA"},
		"unknown action": {`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: someone/action@0123456789012345678901234567890123456789 # v1.0.0
`, "not in the reviewed action list"},
		"wrong sha": {`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
`, "must be pinned to 3d3c42e5aac5ba805825da76410c181273ba90b1"},
		"missing version comment": {`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
`, "add the comment `# v7.0.1`"},
		"no permissions": {`on: push
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: true
`, "set top-level permissions"},
		"pull_request_target": {`on: [pull_request_target]
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: true
`, "pull_request_target runs untrusted code"},
		"secret in a PR workflow": {`on: pull_request
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "$X"
        env:
          X: ${{ secrets.TEMPO_RPC_URL }}
`, "secret TEMPO_RPC_URL in a workflow that pull requests trigger"},
		"OPS key outside mainnet": {`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: true
        env:
          K: ${{ secrets.OPS_PRIVATE_KEY }}
`, "only available to jobs with environment: mainnet"},
		"script injection": {`on: pull_request
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`, "untrusted event text expanded in a run script"},
		"docker action by tag": {`on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: docker://alpine:3
`, "docker actions must be pinned by digest"},
		"reusable workflow by other tag": {`on: push
permissions: {}
jobs:
  a:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
`, "pin by full commit SHA"},
	}
	for name, c := range cases {
		probs := checkWorkflow("x.yml", []byte(c.body))
		var all []string
		for _, p := range probs {
			all = append(all, p.String())
		}
		if !strings.Contains(strings.Join(all, "\n"), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, all)
		}
	}
	ok := `on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-24.04
    environment: mainnet
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: ./.github/actions/local
      - run: echo "$K"
        env:
          K: ${{ secrets.OPS_PRIVATE_KEY }}
  b:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
`
	if probs := checkWorkflow("ok.yml", []byte(ok)); len(probs) != 0 {
		t.Fatalf("clean workflow flagged: %v", probs)
	}
}
