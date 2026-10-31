package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Workflow shape helpers for the pre-publish review follow-ups (runtime-3, supply-7).

type wfStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type wfJob struct {
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []wfStep          `yaml:"steps"`
}

func loadWorkflowJobs(t *testing.T, name string) map[string]wfJob {
	t.Helper()
	var wf struct {
		Jobs map[string]wfJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows", name))), &wf); err != nil {
		t.Fatal(err)
	}
	return wf.Jobs
}

func stepIndex(t *testing.T, job wfJob, name string) int {
	t.Helper()
	for i, s := range job.Steps {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("no step %q", name)
	return -1
}

// runtime-3: the compose job extracts the Caddy that runtime-images.json pins and requires the real-Caddy
// test, which used to skip in CI because SEALED_CADDY_BIN was never set.
func TestCatalogComposeRunsThePinnedCaddy(t *testing.T) {
	requireJQ(t)
	compose := loadWorkflowJobs(t, "catalog.yml")["compose"]
	extract := stepIndex(t, compose, "Pinned Caddy binary")
	tests := stepIndex(t, compose, "Composer golden and compose tests")
	if extract > tests {
		t.Fatal("Caddy must be extracted before the tests")
	}
	st := compose.Steps[tests]
	if st.Env["SEALED_REQUIRE_CADDY"] != "1" || st.Env["SEALED_CADDY_BIN"] != "${{ runner.temp }}/caddy/caddy" ||
		!strings.Contains(st.Run, "./runtime/composer/...") {
		t.Fatalf("composer tests step: %+v", st)
	}

	var pins struct {
		Images map[string]struct{ Digest, Source string } `json:"images"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), RuntimeImagesFile))), &pins); err != nil {
		t.Fatal(err)
	}
	caddy := pins.Images["caddy"]
	repo, tag, err := splitSource(caddy.Source)
	if err != nil {
		t.Fatal(err)
	}
	version, _, _ := strings.Cut(tag, "-")

	var wf simWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/catalog.yml"))), &wf); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	logf := filepath.Join(t.TempDir(), "docker.log")
	writeFile(t, filepath.Join(bin, "docker"), `#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >>"$DOCKER_LOG"
case "$1" in
create) echo c0ffee ;;
cp) printf '#!/bin/sh\necho "%s"\n' "$FAKE_CADDY_VERSION" >"$3"; chmod +x "$3" ;;
rm) ;;
*) exit 2 ;;
esac
`)
	if err := os.Chmod(filepath.Join(bin, "docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(got string) error {
		writeFile(t, logf, "")
		sim := &simulator{t: t, wf: wf, workspace: repoRoot(t), temp: t.TempDir(), artifacts: t.TempDir(), path: bin + ":" + os.Getenv("PATH"),
			baseEnv: append(cleanEnv(), "DOCKER_LOG="+logf, "FAKE_CADDY_VERSION="+got),
			ctx:     map[string]any{"github": map[string]any{"event_name": "pull_request"}},
			skip:    map[string]bool{"Composer golden and compose tests": true, "Compose lint": true}}
		_, err := sim.runJobErr("compose", nil)
		return err
	}
	if err := run("v" + version + " h1:fake"); err != nil {
		t.Fatal(err)
	}
	log := readFile(t, logf)
	mustContain(t, log, "docker create --platform linux/amd64 "+repo+"@"+caddy.Digest+"\n")
	mustContain(t, log, "docker cp c0ffee:/usr/bin/caddy ")
	if err := run("v2.10.0 h1:fake"); err == nil || !strings.Contains(err.Error(), "is not Caddy v"+version) {
		t.Fatalf("another Caddy version must fail the job: %v", err)
	}
}
