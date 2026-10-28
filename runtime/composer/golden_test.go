package composer

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden from the current composer output")

type goldenSummary struct {
	ComposerVersion string            `json:"composerVersion"`
	StackHash       string            `json:"stackHash"`
	ConfigHash      string            `json:"configHash"`
	DeploymentID    string            `json:"deploymentId"`
	Releases        []ReleaseInfo     `json:"releases"`
	Files           map[string]string `json:"files"`
}

// TestGoldenFixtureStack pins the composed output of the fixture stack.
// Any diff here changes every stackHash: bump Version (and the config's
// composerVersion) in the same commit, then run go test -run Golden -update.
// Other components (TS twin, verifier, simulator) can use these files as
// cross-implementation vectors.
func TestGoldenFixtureStack(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	files := map[string][]byte{
		"app-compose.json":         r.AppCompose,
		"config.json":              r.ConfigJSON,
		"egress.json":              r.EgressConfig,
		"Caddyfile":                r.Caddyfile,
		"Caddyfile.payment-needed": r.CaddyfilePaymentNeeded,
		"stack.json":               r.StackInfo,
		"pre-launch.sh":            []byte(r.PreLaunchScript),
	}
	sum := goldenSummary{
		ComposerVersion: Version,
		StackHash:       r.StackHash.Hex(),
		ConfigHash:      r.ConfigHash.Hex(),
		DeploymentID:    r.DeploymentID.Hex(),
		Files:           map[string]string{},
	}
	for _, b := range bundles {
		sum.Releases = append(sum.Releases, b.Info())
	}
	for name, b := range files {
		sum.Files[name] = SHA256(b).Hex()
	}
	summary, _ := json.MarshalIndent(sum, "", "  ")
	summary = append(summary, '\n')
	files["summary.json"] = summary

	dir := filepath.Join("testdata", "golden")
	if *update {
		if err := checkVersionBumped(dir, files); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for name, b := range files {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%v (run go test -run Golden -update)", err)
		}
		if !bytes.Equal(want, b) {
			t.Errorf("%s differs from testdata/golden (composer output changed: bump Version, then -update)", name)
		}
	}
}

// checkVersionBumped refuses -update when the output changed but Version did
// not: two builds of the same composer version must give the same stackHash
// for the same inputs, or the key broker and verifiers disagree.
func checkVersionBumped(dir string, files map[string][]byte) error {
	raw, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var old goldenSummary
	if err := json.Unmarshal(raw, &old); err != nil {
		return fmt.Errorf("testdata/golden/summary.json: %v", err)
	}
	if old.ComposerVersion != Version {
		return nil
	}
	for name, b := range files {
		if name == "summary.json" {
			continue
		}
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(want, b) {
			return fmt.Errorf("%s changed but composer Version is still %s: bump Version (and the configs' composerVersion) before -update", name, Version)
		}
	}
	return nil
}

func TestGoldenUpdateNeedsVersionBump(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app-compose.json", "old")
	write("summary.json", `{"composerVersion":"`+Version+`"}`)
	if err := checkVersionBumped(dir, map[string][]byte{"app-compose.json": []byte("old"), "summary.json": nil}); err != nil {
		t.Fatalf("unchanged output refused: %v", err)
	}
	if err := checkVersionBumped(dir, map[string][]byte{"app-compose.json": []byte("new")}); err == nil {
		t.Fatal("changed output without a version bump accepted")
	}
	if err := checkVersionBumped(dir, map[string][]byte{"stack.json": []byte("new file")}); err == nil {
		t.Fatal("new golden file without a version bump accepted")
	}
	write("summary.json", `{"composerVersion":"0.0.1"}`)
	if err := checkVersionBumped(dir, map[string][]byte{"app-compose.json": []byte("new")}); err != nil {
		t.Fatalf("bumped version refused: %v", err)
	}
}
