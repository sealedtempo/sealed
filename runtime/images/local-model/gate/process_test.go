package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The binary is built once and run as a real process, so signal forwarding, the child
// environment and exit codes are tested the way the container runs them.
var gateBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ollama-gate")
	if err != nil {
		panic(err)
	}
	gateBinary = filepath.Join(dir, "sealed-ollama-gate")
	build := exec.Command("go", "build", "-o", gateBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("go build: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var servingLine = regexp.MustCompile(`serving (127\.0\.0\.1:\d+) `)

type gateProc struct {
	cmd    *exec.Cmd
	addr   string
	stderr *bytes.Buffer
}

func startGate(t *testing.T, env []string, args ...string) *gateProc {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	cmd := exec.Command(gateBinary, args...)
	cmd.Env = env
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &gateProc{cmd: cmd, stderr: &bytes.Buffer{}}
	found := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		sent := false
		for scanner.Scan() {
			line := scanner.Text()
			p.stderr.WriteString(line + "\n")
			if m := servingLine.FindStringSubmatch(line); m != nil && !sent {
				found <- m[1]
				sent = true
			}
		}
		if !sent {
			close(found)
		}
	}()
	select {
	case addr, ok := <-found:
		if !ok {
			t.Fatalf("gate exited before serving: %s", p.stderr.String())
		}
		p.addr = addr
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("gate did not start")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return p
}

func waitExit(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("gate did not exit")
	}
	return -1
}

func TestGateRunsOllamaAndForwardsSIGTERM(t *testing.T) {
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "Ollama is running")
	}))
	defer ollama.Close()
	upstream := strings.TrimPrefix(ollama.URL, "http://")
	envFile := filepath.Join(t.TempDir(), "env")
	// Install the TERM trap before writing ENV_FILE, which the test waits on as the readiness marker: otherwise a
	// SIGTERM arriving in the window after env is written but before the trap is set kills the child with the default
	// disposition (143) instead of the trap's exit 7 (flake).
	child := `trap 'exit 7' TERM; env > "$ENV_FILE"; while :; do sleep 0.05; done`
	env := []string{"PATH=" + os.Getenv("PATH"), "ENV_FILE=" + envFile, "OLLAMA_HOST=0.0.0.0:11434",
		"GATE_KEY=k-0123456789abcdef", "HTTP_PROXY=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9"}
	p := startGate(t, env, "-listen", "127.0.0.1:0", "-upstream", upstream, "-allow-peer", "llm-gateway-litellm",
		"-key-env", "GATE_KEY", "--", "/bin/sh", "-c", child)

	resp, err := http.Get("http://" + p.addr + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()
	if code := run([]string{"probe", "http://" + p.addr + "/healthz"}, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("probe exit %d", code)
	}

	deadline := time.Now().Add(5 * time.Second)
	var childEnv []byte
	for time.Now().Before(deadline) {
		if childEnv, _ = os.ReadFile(envFile); bytes.Contains(childEnv, []byte("PATH=")) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !bytes.Contains(childEnv, []byte("OLLAMA_HOST="+upstream+"\n")) {
		t.Fatalf("child OLLAMA_HOST not set to the loopback upstream:\n%s", childEnv)
	}
	if bytes.Contains(childEnv, []byte("GATE_KEY")) || bytes.Contains(childEnv, []byte("0.0.0.0:11434")) {
		t.Fatalf("child env leaks the key or the public address:\n%s", childEnv)
	}

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, p.cmd); code != 7 {
		t.Fatalf("exit %d, want the child's 7; stderr:\n%s", code, p.stderr.String())
	}
	if strings.Contains(p.stderr.String(), "k-0123456789abcdef") {
		t.Fatal("key printed")
	}
}

func TestGateExitsWithOllama(t *testing.T) {
	p := startGate(t, []string{"PATH=" + os.Getenv("PATH")}, "-listen", "127.0.0.1:0",
		"--", "/bin/sh", "-c", "sleep 0.3; exit 3")
	if code := waitExit(t, p.cmd); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
}

func TestServeArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-upstream", "10.0.0.5:11435", "--", "ollama"},
		{"-upstream", "localhost", "--", "ollama"},
		{"-listen", "127.0.0.1:0"},
		{"stray", "--", "ollama"},
		{"-allow-loopback=false", "--", "ollama"},
	} {
		if code := run(args, nil, io.Discard, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	var errOut bytes.Buffer
	if code := run([]string{"-listen", "127.0.0.1:0", "-key-env", "NOPE", "--", "true"}, []string{"NOPE=tiny-k"}, io.Discard, &errOut); code != 2 {
		t.Fatalf("short key: exit %d", code)
	}
	if strings.Contains(errOut.String(), "tiny-k") {
		t.Fatal("key value printed")
	}
}

func TestProbe(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9") // must be ignored
	if code := run([]string{"probe", srv.URL}, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	status = http.StatusServiceUnavailable
	if code := run([]string{"probe", srv.URL}, nil, io.Discard, io.Discard); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if code := run([]string{"probe"}, nil, io.Discard, io.Discard); code != 2 {
		t.Fatalf("usage exit %d", code)
	}
}

func TestChildEnv(t *testing.T) {
	got := childEnv([]string{"A=1", "OLLAMA_HOST=0.0.0.0:11434", "KEY=secret", "B=2"}, "127.0.0.1:11435", "KEY")
	want := []string{"A=1", "B=2", "OLLAMA_HOST=127.0.0.1:11435"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v", got)
	}
}
