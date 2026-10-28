package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfile covers docker-checks bug 4 for sealed-init: the build stage
// runs on the build machine and compiles for BuildKit's TARGETOS and
// TARGETARCH (no hard-coded GOARCH=amd64, no ARG defaults), and the copied
// sources cover every package of this module envexec imports.
func TestDockerfile(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	argDefault := regexp.MustCompile(`^ARG\s+(TARGETOS|TARGETARCH|TARGETPLATFORM|BUILDPLATFORM)\s*=`)
	hardcoded := regexp.MustCompile(`\bGO(ARCH|OS)=[a-z0-9]`)
	args := map[string]bool{}
	var copied []string
	sawFrom := false
	for _, l := range lines {
		f := strings.Fields(l)
		switch {
		case argDefault.MatchString(l):
			t.Errorf("%q sets a default for a BuildKit platform argument", l)
		case len(f) == 2 && f[0] == "ARG":
			args[f[1]] = true
		case f[0] == "RUN" && hardcoded.MatchString(l):
			t.Errorf("%q hard-codes the target platform", l)
		case f[0] == "FROM" && !sawFrom:
			sawFrom = true
			if !strings.Contains(l, "--platform=$BUILDPLATFORM") {
				t.Errorf("build stage %q does not run on $BUILDPLATFORM", l)
			}
		case len(f) == 3 && f[0] == "COPY" && strings.HasPrefix(f[1], "runtime/"):
			copied = append(copied, strings.TrimSuffix(f[1], "/")+"/")
		}
	}
	if !args["TARGETOS"] || !args["TARGETARCH"] {
		t.Errorf("build stage does not declare ARG TARGETOS and ARG TARGETARCH: %v", args)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if .Module}}{{if .Module.Main}}{{.Dir}}{{end}}{{end}}", "./runtime/envexec")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dir := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		rel, _ := filepath.Rel(root, dir)
		rel = filepath.ToSlash(rel) + "/"
		ok := false
		for _, c := range copied {
			ok = ok || strings.HasPrefix(rel, c)
		}
		if !ok {
			t.Errorf("envexec imports %s, which the Dockerfile does not copy (copies %v)", rel, copied)
		}
	}
}
