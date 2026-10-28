package composer

import (
	"bytes"
	"encoding/json"
	"flag"
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
