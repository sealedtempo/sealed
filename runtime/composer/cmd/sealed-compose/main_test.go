package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/runtime/composer"
)

const apps = "../../testdata/apps"

func TestBundleCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "notes.tar")
	var stdout, stderr bytes.Buffer
	err := run([]string{"bundle", "--registry", "ghcr.io/sealed-dev", "--app-dir", filepath.Join(apps, "notes"), "--out", out}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	var infos []composer.ReleaseInfo
	if err := json.Unmarshal(stdout.Bytes(), &infos); err != nil || len(infos) != 1 {
		t.Fatalf("%v %s", err, stdout.String())
	}
	raw, _ := os.ReadFile(out)
	b, err := composer.LoadBundle(raw)
	if err != nil || b.Hash.Hex() != infos[0].BundleHash {
		t.Fatalf("written bundle: %v", err)
	}
}

func TestComposeCommand(t *testing.T) {
	dir := t.TempDir()
	args := []string{"compose", "--config", "../../testdata/config.json", "--defaults", "../../../../config/defaults.yaml",
		"--app-dir", filepath.Join(apps, "notes"), "--app-dir", filepath.Join(apps, "llm-gateway"), "--fill-release-ids", "--out", dir}
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	var sum map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	ac, _ := os.ReadFile(filepath.Join(dir, "app-compose.json"))
	if sum["stackHash"] != composer.SHA256(ac).Hex() {
		t.Fatalf("summary %v", sum)
	}
	for _, f := range []string{"docker-compose.json", "egress.json", "Caddyfile", "Caddyfile.payment-needed", "stack.json", "config.json", "pre-launch.sh"} {
		if st, err := os.Stat(filepath.Join(dir, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s not written", f)
		}
	}
	stdout.Reset()
	if err := run(append(args[:len(args)-2], "--print", "caddyfile"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "attest.34-1-2-3.sslip.io {") {
		t.Fatal("caddyfile not printed")
	}
	// Release flows refuse stacks with placeholder digests.
	err := run(append(append([]string{}, args[:len(args)-2]...), "--require-built"), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "unbuilt") {
		t.Fatalf("unbuilt stack passed --require-built: %v", err)
	}
	// Without --fill-release-ids the placeholder ids do not match.
	if err := run([]string{"compose", "--config", "../../testdata/config.json", "--registry", "ghcr.io/sealed-dev",
		"--app-dir", filepath.Join(apps, "notes"), "--app-dir", filepath.Join(apps, "llm-gateway")}, &stdout, &stderr); err == nil {
		t.Fatal("placeholder releaseIds accepted")
	}
}

func TestLintCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"lint", "--catalog", apps, "--require-sbom", "--json"}, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stdout.String())
	}
	tarPath := filepath.Join(t.TempDir(), "notes.tar")
	if err := run([]string{"bundle", "--registry", "ghcr.io/evil", "--app-dir", filepath.Join(apps, "notes"), "--out", tarPath}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run([]string{"lint", "--bundle", tarPath}, &stdout, &stderr); err == nil || !strings.Contains(stdout.String(), "[registry]") {
		t.Fatalf("foreign registry bundle passed lint: %v\n%s", err, stdout.String())
	}
	if err := run([]string{"lint"}, &stdout, &stderr); err == nil {
		t.Fatal("empty lint accepted")
	}
	if err := run([]string{"nope"}, &stdout, &stderr); err == nil {
		t.Fatal("unknown command accepted")
	}
}
