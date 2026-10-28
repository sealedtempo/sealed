// Package build holds image build helpers for sealed-egress. The test
// checks that collect-licenses.sh covers every module actually linked into
// the linux/amd64 binary the Dockerfile builds.
package build

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectLicensesCoversEveryLinkedModule(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "sealed-egress")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-tags", "smokescreen_no_prometheus", "-o", bin, "./runtime/egress/cmd/sealed-egress")
	build.Dir, build.Env = root, env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out := filepath.Join(tmp, "licenses")
	collect := exec.Command("sh", "runtime/egress/build/collect-licenses.sh", out)
	collect.Dir, collect.Env = root, env
	if msg, err := collect.CombinedOutput(); err != nil {
		t.Fatalf("collect-licenses.sh: %v\n%s", err, msg)
	}
	version := exec.Command("go", "version", "-m", bin)
	info, err := version.Output()
	if err != nil {
		t.Fatal(err)
	}
	deps := 0
	sc := bufio.NewScanner(bytes.NewReader(info))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "dep" {
			continue
		}
		deps++
		entries, err := os.ReadDir(filepath.Join(out, filepath.FromSlash(fields[1])))
		if err != nil || len(entries) == 0 {
			t.Errorf("no license files collected for linked module %s", fields[1])
		}
	}
	if deps == 0 {
		t.Fatalf("no dependencies listed by go version -m:\n%s", info)
	}
	if _, err := os.Stat(filepath.Join(out, "go", "LICENSE")); err != nil {
		t.Error("Go distribution LICENSE missing")
	}
}
