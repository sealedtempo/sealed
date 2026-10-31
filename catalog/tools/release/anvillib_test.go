package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnvilLibStripsTrailingTmpdirSlash sources scripts/release/test/anvil-lib.sh with a TMPDIR
// that ends in a slash, the way macOS sets it by default, and checks that WORK holds no double
// slash. The release scripts canonicalize paths they log (register-apps.sh collapses "//" to "/"),
// so a double slash in WORK makes the chain tests' path-comparison assertions miss on a direct run.
// With the old anvil-lib.sh (WORK built straight from "${TMPDIR:-/tmp}") WORK carried the slash and
// this fails; the go chain wrapper hid it because it sets TMPDIR to t.TempDir(), which has none.
func TestAnvilLibStripsTrailingTmpdirSlash(t *testing.T) {
	requireTools(t, "bash")
	root := repoRoot(t)
	lib := filepath.Join(root, "scripts", "release", "test", "anvil-lib.sh")
	cmd := exec.Command("bash", "-c", `. "$1"; printf '%s' "$WORK"`, "bash", lib)
	// Appended last so it overrides the inherited TMPDIR; the trailing slash is the point.
	cmd.Env = append(cleanEnv(), "TMPDIR="+t.TempDir()+"/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sourcing anvil-lib.sh: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "//") {
		t.Fatalf("WORK has a double slash under a trailing-slash TMPDIR: %q", string(out))
	}
}
