package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D-057: a locally built sealed-verifierd binary next to its source never enters history. The rule in
// verifier/.gitignore once named the path from the repository root, which git reads relative to verifier/,
// so it ignored nothing.
func TestBuiltBinaryIsIgnored(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	if out, err := exec.Command(git, "rev-parse", "--is-inside-work-tree").Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Skip("not a git checkout")
	}
	bin, err := filepath.Abs("sealed-verifierd")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(git, "check-ignore", "--no-index", "-v", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("git does not ignore %s (D-057): %v %s", bin, err, out)
	}
	if !strings.Contains(string(out), "verifier/.gitignore") {
		t.Fatalf("ignored by an unexpected rule: %s", out)
	}
}
