package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseShellTests runs every scripts/release/test/*.sh except the shared anvil-lib.sh: chain tests of the
// release and registration scripts on a local anvil --network tempo node (publish-release re-runs behind a capped
// eth_getLogs, register-apps with measurements files and with catalog.mainnet.json, RegisterCatalog without a key).
// Each script prints PASS on success and needs anvil, forge, cast, jq, python3 and contracts/dependencies;
// SEALED_REQUIRE_ANVIL=1 (CI) turns a missing tool into a failure. They run one after another, because each one
// compiles the contracts and starts its own node.
func TestReleaseShellTests(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	requireTools(t, "bash", "anvil", "forge", "cast", "jq", "python3")
	root := repoRoot(t)
	if !dirExists(filepath.Join(root, "contracts", "dependencies")) {
		skipOrFail(t, "contracts/dependencies is missing (run `make -C contracts deps`)")
	}
	scripts, err := filepath.Glob(filepath.Join(root, "scripts", "release", "test", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range scripts {
		if filepath.Base(s) != "anvil-lib.sh" {
			names = append(names, filepath.Base(s))
		}
	}
	for _, want := range []string{"publish-release-rerun.sh", "register-apps-images.sh", "register-apps-mainnet-catalog.sh",
		"register-catalog-owner-address.sh"} {
		if !strings.Contains(strings.Join(names, " "), want) {
			t.Errorf("scripts/release/test/%s is missing", want)
		}
	}
	bin := releaseBin(t)
	for _, name := range names {
		t.Run(strings.TrimSuffix(name, ".sh"), func(t *testing.T) {
			cmd := exec.Command("bash", filepath.Join(root, "scripts", "release", "test", name))
			cmd.Env = append(cleanEnv(), "SEALED_RELEASE_BIN="+bin, "TMPDIR="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", name, err, out)
			}
			if !strings.Contains("\n"+string(out), "\nPASS ") {
				t.Fatalf("%s printed no PASS line:\n%s", name, out)
			}
			for _, k := range []string{devOwner, devOps} {
				if strings.Contains(string(out), strings.TrimPrefix(k, "0x")) {
					t.Fatalf("%s printed a private key", name)
				}
			}
		})
	}
}
