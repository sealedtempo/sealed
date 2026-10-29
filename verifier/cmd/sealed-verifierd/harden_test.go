package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/verifier/httpapi"
)

// D-061 and review V-1: the in-VM sidecar (--stack-config) serves only its allowed clients and, by default, never
// fetches a caller's URL; D-060: the chain head age limit is configurable up to 5 minutes.
func TestLockdownFlags(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"schema":"sealed-config/v1","chainId":31337,"endpoints":{"tempoRpc":"http://127.0.0.1:8545"},`+
		`"contracts":{"platformRegistry":"0x00000000000000000000000000000000000000e1","appRegistry":"0x00000000000000000000000000000000000000e2",`+
		`"deploymentRegistry":"0x00000000000000000000000000000000000000e3","feeSplitter":"0x00000000000000000000000000000000000000e4"}}`), 0o644)
	stackEnv := map[string]string{"SEALED_CONFIG_FILE": cfgPath}

	// Defaults outside a stack: live fetch on, every client, 60 s head age.
	c, err := loadConfig(addrFlags, envMap(nil), io.Discard)
	if err != nil || !c.LiveFetch || len(c.AllowedClients) != 0 || c.MaxChainHeadAge != 60*time.Second {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	// In a stack, live fetch is off unless asked for.
	c, err = loadConfig(nil, envMap(stackEnv), io.Discard)
	if err != nil || c.LiveFetch {
		t.Fatalf("stack sidecar fetches URLs: %v %+v", err, c)
	}
	c, err = loadConfig([]string{"--live-fetch", "true"}, envMap(stackEnv), io.Discard)
	if err != nil || !c.LiveFetch {
		t.Fatalf("explicit live fetch in a stack: %v", err)
	}
	c, err = loadConfig(addrFlags, envMap(map[string]string{"SEALED_VERIFIERD_LIVE_FETCH": "0"}), io.Discard)
	if err != nil || c.LiveFetch {
		t.Fatalf("SEALED_VERIFIERD_LIVE_FETCH=0: %v", err)
	}
	// The composer passes the payer's address.
	c, err = loadConfig(nil, envMap(map[string]string{"SEALED_CONFIG_FILE": cfgPath, "SEALED_VERIFIERD_ALLOWED_CLIENTS": "172.30.0.5"}), io.Discard)
	if err != nil || !slices.Equal(c.AllowedClients, []netip.Prefix{netip.MustParsePrefix("172.30.0.5/32")}) {
		t.Fatalf("allowed clients: %v %v", err, c.AllowedClients)
	}
	c, err = loadConfig(append([]string{"--allowed-clients", "172.30.0.5,10.8.0.0/16", "--max-chain-head-age", "5m"}, addrFlags...), envMap(nil), io.Discard)
	if err != nil || len(c.AllowedClients) != 2 || c.MaxChainHeadAge != 5*time.Minute {
		t.Fatalf("flags: %v %+v", err, c)
	}
	c, err = loadConfig(addrFlags, envMap(map[string]string{"SEALED_VERIFIERD_MAX_CHAIN_HEAD_AGE": "30s"}), io.Discard)
	if err != nil || c.MaxChainHeadAge != 30*time.Second {
		t.Fatalf("head age from the environment: %v", err)
	}
	for _, bad := range [][]string{
		{"--allowed-clients", "payer"}, {"--allowed-clients", "172.30.0.5/33"}, {"--live-fetch", "maybe"},
		{"--max-chain-head-age", "6m"}, {"--max-chain-head-age", "0s"}, {"--max-chain-head-age", "-1s"}, {"--max-chain-head-age", "soon"},
	} {
		if _, err := loadConfig(append(bad, addrFlags...), envMap(nil), io.Discard); err == nil {
			t.Errorf("%v accepted", bad)
		} else if !strings.Contains(err.Error(), strings.TrimPrefix(bad[0], "--")) {
			t.Errorf("%v: error %v does not name the flag", bad, err)
		}
	}
}

// The lockdown settings reach the HTTP server, and a sidecar without an allowlist warns at startup.
func TestServerGetsLockdownSettings(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"schema":"sealed-config/v1","chainId":31337,"endpoints":{"tempoRpc":"http://127.0.0.1:1"},`+
		`"contracts":{"platformRegistry":"0x00000000000000000000000000000000000000e1","appRegistry":"0x00000000000000000000000000000000000000e2",`+
		`"deploymentRegistry":"0x00000000000000000000000000000000000000e3","feeSplitter":"0x00000000000000000000000000000000000000e4"}}`), 0o644)
	useComposer(t, nil)
	for _, tc := range []struct {
		args []string
		warn bool
	}{
		{args: []string{"--allowed-clients", "172.30.0.5", "--max-chain-head-age", "90s"}},
		{args: nil, warn: true},
	} {
		c, err := loadConfig(tc.args, envMap(map[string]string{"SEALED_CONFIG_FILE": cfgPath}), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		var logs bytes.Buffer
		srv, err := newServer(context.Background(), c, slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if !srv.DisableLiveFetch || !slices.Equal(srv.AllowedClients, c.AllowedClients) || srv.MaxChainHeadAge != c.MaxChainHeadAge {
			t.Fatalf("server %+v from config %+v", srv, c)
		}
		if got := strings.Contains(logs.String(), "without --allowed-clients"); got != tc.warn {
			t.Fatalf("warning %v, want %v:\n%s", got, tc.warn, logs.String())
		}
	}
}

// The help's example client is the payer's address on the verifier network the composer gives verifierd (composer
// 1.3.0, D-061), not its edge address 172.30.0.5, which verifierd never sees.
func TestAllowedClientsHelpNamesThePayersVerifierAddress(t *testing.T) {
	var help bytes.Buffer
	loadConfig([]string{"-h"}, envMap(nil), &help)
	if !strings.Contains(help.String(), composer.PayerVerifierIP) || strings.Contains(help.String(), composer.PayerIP+" ") {
		t.Fatalf("--allowed-clients help: %s", help.String())
	}
}

// /healthz tells the platform api which composerVersion new configs must name (the daemon's runtime/composer) and the
// body limit, so the api reads them instead of pinning its own copies (harden-api deferred item, merge-c-private).
func TestHealthzReportsComposerVersionAndBodyLimit(t *testing.T) {
	useComposer(t, newComposer)
	c, err := loadConfig(append([]string{"--tempo-rpc", "http://127.0.0.1:1", "--chain-id", "31337", "--dev-allow-simulated"}, addrFlags...),
		envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newServer(context.Background(), c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(srv.Handler())
	defer api.Close()
	resp, err := http.Get(api.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["composerVersion"] != composer.Version || body["maxBodyBytes"] != float64(httpapi.MaxBodyBytes) || body["composer"] != true {
		t.Fatalf("healthz %v, want composerVersion %s and maxBodyBytes %d", body, composer.Version, httpapi.MaxBodyBytes)
	}
}
