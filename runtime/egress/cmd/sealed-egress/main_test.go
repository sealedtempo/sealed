package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/egress"
	"github.com/sealed-dev/sealed/runtime/egress/policy"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func clearProxyEnv(t *testing.T) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SEALED_EGRESS_CONFIG"} {
		t.Setenv(v, "")
	}
}

func writeConfig(t *testing.T, statsListen string) string {
	t.Helper()
	cfg := &policy.Config{
		Listen:              &policy.Listen{Proxy: "127.0.0.1:0", DNS: "127.0.0.1:0", Stats: statsListen},
		UpstreamDNS:         []string{"127.0.0.1:53"},
		Callers:             []policy.Caller{{Name: "sealed-agent", IP: "172.30.0.3", Allow: []string{"rpc.tempo.xyz:443"}}},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{"172.30.0.3"},
	}
	data, err := policy.EncodeCanonical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "egress.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheck(t *testing.T) {
	clearProxyEnv(t)
	path := writeConfig(t, "127.0.0.1:0")
	var out syncBuffer
	if code := run([]string{"-config", path, "-check"}, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "ok "+path+" sha256:") {
		t.Errorf("output %q", out.String())
	}

	// The env var is used when no flag is given.
	t.Setenv("SEALED_EGRESS_CONFIG", path)
	out = syncBuffer{}
	if code := run([]string{"-check"}, &out); code != 0 {
		t.Fatalf("env path: exit %d: %s", code, out.String())
	}
}

func TestInvalidConfigExits2(t *testing.T) {
	clearProxyEnv(t)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"listen": {}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	if code := run([]string{"-config", bad}, &out); code != 2 {
		t.Errorf("bad config exit %d", code)
	}
	if !strings.Contains(out.String(), "config rejected") {
		t.Errorf("output %q", out.String())
	}
	if code := run([]string{"-config", filepath.Join(t.TempDir(), "missing.json")}, &out); code != 2 {
		t.Errorf("missing config exit %d", code)
	}
	if code := run([]string{"-nope"}, &out); code != 2 {
		t.Errorf("bad flag exit %d", code)
	}
	if resolveConfigPath("") != DefaultConfigPath {
		t.Error("default config path not used")
	}
}

func TestHealthcheck(t *testing.T) {
	clearProxyEnv(t)
	cfg, _, err := policy.Load(writeConfig(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := egress.Start(cfg, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())

	path := writeConfig(t, svc.StatsAddr.String())
	var out syncBuffer
	if code := run([]string{"-config", path, "-healthcheck"}, &out); code != 0 {
		t.Fatalf("healthy service: exit %d %s", code, out.String())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := ln.Addr().String()
	ln.Close()
	if code := run([]string{"-config", writeConfig(t, free), "-healthcheck"}, &out); code != 1 {
		t.Errorf("nothing listening: exit %d", code)
	}
}

func TestRunShutsDownOnSIGTERM(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://203.0.113.1:3128") // must be dropped, not honored
	path := writeConfig(t, "127.0.0.1:0")
	var out syncBuffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"-config", path}, &out) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "sealed-egress started") {
		if time.Now().After(deadline) {
			t.Fatalf("not started: %s", out.String())
		}
		select {
		case code := <-done:
			t.Fatalf("exited early with %d: %s", code, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop after SIGTERM")
	}
	logs := out.String()
	for _, want := range []string{"ignoring proxy environment variable", "config_sha256", "shutting down", `"final":true`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q: %s", want, logs)
		}
	}
}
