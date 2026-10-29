package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseRunArgs(t *testing.T) {
	o, err := parseRunArgs([]string{"--app", "crm", "--secret", "APP_SECRET", "--optional-secret", "SMTP", "--", "/bin/app", "--flag"})
	if err != nil {
		t.Fatal(err)
	}
	if o.App != "crm" || len(o.Required) != 1 || len(o.Optional) != 1 || strings.Join(o.Command, " ") != "/bin/app --flag" {
		t.Fatalf("parsed %+v", o)
	}
	if o.SecretsDir != defaultSecretsDir || o.Ready != defaultReady {
		t.Fatalf("defaults %+v", o)
	}
	bad := [][]string{
		{"--app", "crm"},                                // no command
		{"--app", "../etc", "--", "x"},                  // traversal
		{"--app", "crm", "--secret", "../x", "--", "x"}, // bad secret name
		{"--app", "crm", "--secret", "A", "--secret", "A", "--", "x"},
		{"--app", "crm", "--bogus", "1", "--", "x"},
		{"--app"},
		{"--app", "crm", "--timeout", "-1s", "--", "x"},
	}
	for _, args := range bad {
		if _, err := parseRunArgs(args); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
}

func TestReadyGate(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	if isReady(ready) {
		t.Fatal("missing path must not be ready")
	}
	if err := os.Mkdir(ready, 0o755); err != nil {
		t.Fatal(err)
	}
	if isReady(ready) {
		t.Fatal("empty ready dir must not be ready")
	}
	if err := waitReady(ready, 50*time.Millisecond, &bytes.Buffer{}); err == nil {
		t.Fatal("expected timeout")
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(ready, readyMarker), nil, 0o644)
	}()
	var log bytes.Buffer
	if err := waitReady(ready, 5*time.Second, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "waiting for") {
		t.Fatalf("log %q", log.String())
	}
	file := filepath.Join(dir, "ready-file")
	_ = os.WriteFile(file, nil, 0o644)
	if !isReady(file) {
		t.Fatal("regular file gate must be ready")
	}
}

func TestLoadSecrets(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "crm")
	_ = os.MkdirAll(app, 0o755)
	_ = os.WriteFile(filepath.Join(app, "APP_SECRET"), []byte("s3cret\n"), 0o444)
	o := &runOptions{App: "crm", SecretsDir: dir, Required: []string{"APP_SECRET"}, Optional: []string{"SMTP"}}
	got, err := loadSecrets(o)
	if err != nil {
		t.Fatal(err)
	}
	if got["APP_SECRET"] != "s3cret\n" || len(got) != 1 {
		t.Fatalf("got %q", got)
	}
	o.Required = append(o.Required, "MISSING")
	if _, err := loadSecrets(o); err == nil {
		t.Fatal("missing required secret must fail")
	}
	_ = os.WriteFile(filepath.Join(app, "NUL"), []byte("a\x00b"), 0o444)
	if _, err := loadSecrets(&runOptions{App: "crm", SecretsDir: dir, Required: []string{"NUL"}}); err == nil {
		t.Fatal("NUL must fail")
	}
	_ = os.WriteFile(filepath.Join(app, "BIG"), bytes.Repeat([]byte("x"), maxSecretBytes+1), 0o444)
	if _, err := loadSecrets(&runOptions{App: "crm", SecretsDir: dir, Required: []string{"BIG"}}); err == nil {
		t.Fatal("oversized secret must fail")
	}
}

// TestEmptySecretFiles covers the per-file mounts (D-042): sealed-agent
// writes an empty file for an optional secret the customer did not set.
func TestEmptySecretFiles(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "crm")
	_ = os.MkdirAll(app, 0o755)
	_ = os.WriteFile(filepath.Join(app, "SMTP"), nil, 0o444)
	_ = os.WriteFile(filepath.Join(app, "APP_SECRET"), []byte("v"), 0o444)
	got, err := loadSecrets(&runOptions{App: "crm", SecretsDir: dir, Required: []string{"APP_SECRET"}, Optional: []string{"SMTP"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["SMTP"]; ok || got["APP_SECRET"] != "v" {
		t.Fatalf("empty optional secret exported: %q", got)
	}
	if _, err := loadSecrets(&runOptions{App: "crm", SecretsDir: dir, Required: []string{"SMTP"}}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty required secret accepted: %v", err)
	}
}

func TestBuildEnv(t *testing.T) {
	env := buildEnv([]string{"PATH=/bin", "APP_SECRET=old", "X=1"}, map[string]string{"APP_SECRET": "new", "B": "2"})
	want := "PATH=/bin X=1 APP_SECRET=new B=2"
	if strings.Join(env, " ") != want {
		t.Fatalf("got %v", env)
	}
}

func TestProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(503)
	}))
	defer ok.Close()
	if err := probe(ok.URL+"/healthz", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := probe(ok.URL+"/other", time.Second); err == nil {
		t.Fatal("503 must fail")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := probe("tcp://"+addr, time.Second); err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if err := probe("tcp://"+addr, 200*time.Millisecond); err == nil {
		t.Fatal("closed port must fail")
	}
	if err := probe("ftp://"+addr, time.Second); err == nil {
		t.Fatal("bad scheme must fail")
	}
}

func TestInstall(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	_ = os.WriteFile(src, []byte("binary"), 0o600)
	dst := filepath.Join(dir, "bin")
	if err := install(src, dst); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dst, "envexec"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("installed %v %v", st, err)
	}
	if err := install(src, dst); err != nil { // idempotent
		t.Fatal(err)
	}
}

// TestPrivateDir: the payer's state directory becomes 0700 for its owner,
// and envexec refuses anything that is not a directory this uid owns.
func TestPrivateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o755); err != nil { // as sealed-agent creates it
		t.Fatal(err)
	}
	euid := os.Geteuid()
	if err := privateDir(state, euid); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(state); st.Mode().Perm() != 0o700 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("mode %v, want 0700", st.Mode())
	}
	if err := privateDir(state, euid); err != nil { // idempotent
		t.Fatal(err)
	}
	// Special bits go too.
	if err := os.Chmod(state, 0o700|os.ModeSetgid); err == nil {
		if err := privateDir(state, euid); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(state); st.Mode()&os.ModeSetgid != 0 {
			t.Fatalf("setgid kept: %v", st.Mode())
		}
	}
	// Another uid's directory is refused and left alone.
	_ = os.Chmod(state, 0o755)
	if err := privateDir(state, euid+1); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("foreign owner: %v", err)
	}
	if st, _ := os.Stat(state); st.Mode().Perm() != 0o755 {
		t.Fatalf("foreign directory changed: %v", st.Mode())
	}
	// A symlink (even to a good directory), a file and a missing path are refused.
	link := filepath.Join(dir, "link")
	_ = os.Symlink(state, link)
	file := filepath.Join(dir, "file")
	_ = os.WriteFile(file, nil, 0o644)
	for _, p := range []string{link, file, filepath.Join(dir, "missing")} {
		if err := privateDir(p, euid); err == nil {
			t.Errorf("%s: accepted", p)
		}
	}
	if st, _ := os.Stat(state); st.Mode().Perm() != 0o755 {
		t.Fatalf("followed the symlink: %v", st.Mode())
	}
}

// TestBinaryExecs builds the real binary and checks it waits, exports only the
// declared secrets and execs the command with the container's environment.
func TestBinaryExecs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec semantics differ")
	}
	envBin, err := exec.LookPath("env")
	if err != nil {
		t.Skip("no env binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "envexec")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	secrets := filepath.Join(dir, "secrets", "crm")
	_ = os.MkdirAll(secrets, 0o755)
	_ = os.WriteFile(filepath.Join(secrets, "APP_SECRET"), []byte("v1"), 0o444)
	_ = os.WriteFile(filepath.Join(secrets, "OTHER"), []byte("not-exported"), 0o444)
	ready := filepath.Join(dir, "ready")
	_ = os.Mkdir(ready, 0o755)
	_ = os.WriteFile(filepath.Join(ready, "ok"), nil, 0o644)

	cmd := exec.Command(bin, "--app", "crm", "--secret", "APP_SECRET", "--secrets-dir", filepath.Join(dir, "secrets"),
		"--ready", ready, "--", envBin)
	cmd.Env = []string{"KEEP=1", "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "APP_SECRET=v1") || !strings.Contains(s, "KEEP=1") || strings.Contains(s, "not-exported") {
		t.Fatalf("env output:\n%s", s)
	}

	// Not ready: the timeout fires and the command never runs.
	_ = os.Remove(filepath.Join(ready, "ok"))
	cmd = exec.Command(bin, "--app", "crm", "--ready", ready, "--timeout", "300ms", "--", envBin)
	if out, err := cmd.CombinedOutput(); err == nil || strings.Contains(string(out), "KEEP") {
		t.Fatalf("expected failure before exec, got %v\n%s", err, out)
	}

	// private: the directory becomes 0700, then the command runs with the
	// container's environment unchanged (no secrets, no ready gate).
	state := filepath.Join(dir, "state")
	_ = os.Mkdir(state, 0o755)
	_ = os.Chmod(state, 0o755)
	cmd = exec.Command(bin, "private", state, "--", envBin)
	cmd.Env = []string{"KEEP=2", "PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "KEEP=2") {
		t.Fatalf("private: %v\n%s", err, out)
	}
	if st, _ := os.Stat(state); st.Mode().Perm() != 0o700 {
		t.Fatalf("private: mode %v", st.Mode())
	}
	// A refused directory stops the container before the command runs.
	_ = os.Symlink(state, filepath.Join(dir, "state-link"))
	cmd = exec.Command(bin, "private", filepath.Join(dir, "state-link"), "--", envBin)
	cmd.Env = []string{"KEEP=3"}
	if out, err := cmd.CombinedOutput(); err == nil || strings.Contains(string(out), "KEEP=3") {
		t.Fatalf("private through a symlink: %v\n%s", err, out)
	}
	for _, bad := range [][]string{{"private"}, {"private", state}, {"private", state, "--"}, {"private", state, envBin}} {
		if err := exec.Command(bin, bad...).Run(); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}

	// probe and install subcommands.
	if err := exec.Command(bin, "probe", "tcp://127.0.0.1:1").Run(); err == nil {
		t.Fatal("probe of a closed port must fail")
	}
	inst := filepath.Join(dir, "vol")
	if out, err := exec.Command(bin, "install", inst).CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	a, _ := os.ReadFile(bin)
	b, _ := os.ReadFile(filepath.Join(inst, "envexec"))
	if !bytes.Equal(a, b) {
		t.Fatal("installed binary differs")
	}
}
