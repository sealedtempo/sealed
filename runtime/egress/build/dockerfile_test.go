package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfileCopiesEveryImportedPackage is docker-checks bug 3: the image
// build copies only some directories of this module, so every package of
// the module that sealed-egress imports must be among them, or the build
// fails with "cannot find module providing package".
func TestDockerfileCopiesEveryImportedPackage(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	df := readDockerfile(t, filepath.Join(root, "runtime", "egress", "Dockerfile"))
	var copied []string
	for _, l := range df {
		f := strings.Fields(l)
		if len(f) == 3 && f[0] == "COPY" && strings.HasPrefix(f[1], "runtime/") {
			copied = append(copied, strings.TrimSuffix(f[1], "/")+"/")
		}
	}
	cmd := exec.Command("go", "list", "-deps", "-tags", "smokescreen_no_prometheus",
		"-f", "{{if .Module}}{{if .Module.Main}}{{.Dir}}{{end}}{{end}}", "./runtime/egress/cmd/sealed-egress")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	n := 0
	for _, dir := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel) + "/"
		n++
		ok := false
		for _, c := range copied {
			if strings.HasPrefix(rel, c) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("sealed-egress imports %s, which the Dockerfile does not copy (copies %v)", rel, copied)
		}
	}
	if n == 0 {
		t.Fatal("go list found no packages of this module")
	}
}

// TestDockerfileBuildsForTheRequestedPlatform is docker-checks bug 4: a
// default on ARG TARGETOS or TARGETARCH overrides BuildKit's platform value,
// so a linux/arm64 image would carry an amd64 binary.
func TestDockerfileBuildsForTheRequestedPlatform(t *testing.T) {
	checkPlatformArgs(t, readDockerfile(t, filepath.Join("..", "Dockerfile")))
}

func checkPlatformArgs(t *testing.T, lines []string) {
	t.Helper()
	argDefault := regexp.MustCompile(`^ARG\s+(TARGETOS|TARGETARCH|TARGETPLATFORM|BUILDPLATFORM)\s*=`)
	hardcoded := regexp.MustCompile(`\bGO(ARCH|OS)=[a-z0-9]`)
	args := map[string]bool{}
	for i, l := range lines {
		if argDefault.MatchString(l) {
			t.Errorf("line %q sets a default for a BuildKit platform argument", l)
		}
		if f := strings.Fields(l); len(f) == 2 && f[0] == "ARG" {
			args[f[1]] = true
		}
		if strings.HasPrefix(l, "RUN ") && hardcoded.MatchString(l) {
			t.Errorf("line %q hard-codes the target platform", l)
		}
		if i == firstFrom(lines) && !strings.Contains(l, "--platform=$BUILDPLATFORM") {
			t.Errorf("build stage %q does not run on $BUILDPLATFORM", l)
		}
	}
	if !args["TARGETOS"] || !args["TARGETARCH"] {
		t.Errorf("build stage does not declare ARG TARGETOS and ARG TARGETARCH: %v", args)
	}
}

func firstFrom(lines []string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, "FROM ") {
			return i
		}
	}
	return -1
}

// readDockerfile returns the instruction lines, comments dropped.
func readDockerfile(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}
