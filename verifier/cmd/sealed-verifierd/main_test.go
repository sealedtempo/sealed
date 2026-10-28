package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/anviltest"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var addrFlags = []string{
	"--platform-registry", "0x5FbDB2315678afecb367f032d93F642f64180aa3",
	"--app-registry", "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
	"--deployment-registry", "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
}

func TestDevFlagsNeedDevSimEnv(t *testing.T) {
	for _, flag := range []string{"--dev-allow-simulated", "--dev-insecure-live-tls"} {
		args := append([]string{flag}, addrFlags...)
		if _, err := loadConfig(args, envMap(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "SEALED_DEV_SIM=1") {
			t.Fatalf("%s accepted without SEALED_DEV_SIM=1: %v", flag, err)
		}
		if _, err := loadConfig(args, envMap(map[string]string{"SEALED_DEV_SIM": "true"}), io.Discard); err == nil {
			t.Fatalf("%s accepted with SEALED_DEV_SIM=true", flag)
		}
		c, err := loadConfig(args, envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if flag == "--dev-allow-simulated" && !c.AllowSimulated {
			t.Fatal("flag not applied")
		}
	}
	// SEALED_DEV_SIM alone never enables simulated quotes.
	c, err := loadConfig(addrFlags, envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
	if err != nil || c.AllowSimulated {
		t.Fatalf("AllowSimulated without the flag: %v", err)
	}
}

func TestConfigSources(t *testing.T) {
	c, err := loadConfig(addrFlags, envMap(map[string]string{"TEMPO_PUBLIC_RPC_URL": "https://rpc.example", "SEALED_VERIFIERD_LISTEN": ":9999"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.RPCURL != "https://rpc.example" || c.Listen != ":9999" || c.ChainID != 4217 || len(c.TCBPolicy.AllowedStatuses) != 2 {
		t.Fatalf("%+v", c)
	}
	if _, err := loadConfig(nil, envMap(nil), io.Discard); err == nil {
		t.Fatal("started without registry addresses")
	}

	dir := t.TempDir()
	dep := filepath.Join(dir, "local.json")
	os.WriteFile(dep, []byte(`{"chainId":31337,"contracts":{"PlatformRegistry":{"address":"0x5FbDB2315678afecb367f032d93F642f64180aa3"},"AppRegistry":{"address":"0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"},"DeploymentRegistry":{"address":"0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"}}}`), 0o644)
	if _, err := loadConfig([]string{"--deployments", dep}, envMap(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "chain 31337") {
		t.Fatalf("deployments for another chain accepted: %v", err)
	}
	c, err = loadConfig([]string{"--deployments", dep, "--chain-id", "31337", "--deployment-registry", "0x0000000000000000000000000000000000000abc"}, envMap(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addrs.AppRegistry != common.HexToAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512") || c.Addrs.DeploymentRegistry != common.HexToAddress("0xabc") {
		t.Fatalf("addresses %+v", c.Addrs)
	}

	defaults := filepath.Join(dir, "defaults.yaml")
	os.WriteFile(defaults, []byte("tcb_policy:\n  allowed_statuses: [UpToDate]\n"), 0o644)
	c, err = loadConfig(append([]string{"--defaults", defaults}, addrFlags...), envMap(nil), io.Discard)
	if err != nil || len(c.TCBPolicy.AllowedStatuses) != 1 {
		t.Fatalf("defaults file: %v %+v", err, c)
	}
	repoDefaults := filepath.Join("..", "..", "..", "config", "defaults.yaml")
	if _, err := loadConfig(append([]string{"--defaults", repoDefaults}, addrFlags...), envMap(nil), io.Discard); err != nil {
		t.Fatalf("repo defaults: %v", err)
	}
	for _, bad := range [][]string{{"--chain-id", "x"}, {"--collateral-ttl", "-1s"}, {"--platform-registry", "nope"}, {"extra"}} {
		args := append(append([]string{}, addrFlags...), bad...)
		if _, err := loadConfig(args, envMap(nil), io.Discard); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

// TestDaemonEndToEnd runs the daemon's wiring against a local Tempo node with the real contracts.
func TestDaemonEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	n := anviltest.Start(t)
	r := anviltest.DeployRegistries(t, n)
	m := anviltest.Measurements{}
	for i := range m.MRTD {
		m.MRTD[i], m.RTMR0[i], m.RTMR1[i], m.RTMR2[i] = 0x11, 0x22, 0x33, 0x44
	}
	imageID := r.AddImage(t, n, "sealed-sim", "1.0.0", m, false)
	addrs := chain.Addresses{PlatformRegistry: r.PlatformRegistry, AppRegistry: r.AppRegistry, DeploymentRegistry: r.DeploymentRegistry}
	w := fixture.NewWorld(n.ChainID.Uint64(), addrs, anviltest.Addr(anviltest.Customer), anviltest.Addr(anviltest.Enclave), imageID)
	for _, a := range w.Apps {
		r.PublishRelease(t, n, r.RegisterApp(t, n, a.Slug), a.Version, a.BundleHash)
	}
	r.ApproveStack(t, n, anviltest.Customer, w.Compose().StackHash, w.ReleaseIDs(), imageID)
	b := w.Bundle(n.Now(t))
	r.RegisterDeployment(t, n, anviltest.Record(fixture.Record(b)))

	args := []string{"--tempo-rpc", n.URL, "--chain-id", n.ChainID.String(), "--dev-allow-simulated",
		"--platform-registry", r.PlatformRegistry.Hex(), "--app-registry", r.AppRegistry.Hex(), "--deployment-registry", r.DeploymentRegistry.Hex(),
		"--collateral-cache-dir", t.TempDir()}
	c, err := loadConfig(args, envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	composerFactory = func(*config, verify.ChainReader) (verify.Composer, error) { return fixture.Composer{}, nil }
	t.Cleanup(func() { composerFactory = nil })
	srv, err := newServer(context.Background(), c, log)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(srv.Handler())
	defer api.Close()
	raw, _ := json.Marshal(b)
	resp, err := http.Post(api.URL+"/v1/verify/evidence?format=text", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(text), "Sealed verification (evidence): PASS") || !strings.Contains(string(text), "WARNING") {
		t.Fatalf("daemon report:\n%s", text)
	}

	// A wrong chain id is a startup error, not a silent mismatch.
	c.ChainID = 4217
	if _, err := newServer(context.Background(), c, log); err == nil || !strings.Contains(err.Error(), "expected 4217") {
		t.Fatalf("chain mismatch at startup: %v", err)
	}

	// Without the composer the daemon still starts and fails stack recomputation closed.
	composerFactory = nil
	c.ChainID = n.ChainID.Uint64()
	srv, err = newServer(context.Background(), c, log)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Deps.Composer != nil {
		t.Fatal("composer wired")
	}
}
