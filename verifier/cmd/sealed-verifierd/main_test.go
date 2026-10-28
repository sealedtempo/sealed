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

	"github.com/sealed-dev/sealed/runtime/composer"
	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/bundles"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/anviltest"
	"github.com/sealed-dev/sealed/verifier/internal/fixture"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// useComposer replaces composerFactory for one test.
func useComposer(t *testing.T, f func(*config, verify.ChainReader) (verify.Composer, error)) {
	t.Helper()
	old := composerFactory
	composerFactory = f
	t.Cleanup(func() { composerFactory = old })
}

var addrFlags = []string{
	"--platform-registry", "0x5FbDB2315678afecb367f032d93F642f64180aa3",
	"--app-registry", "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
	"--deployment-registry", "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
}

func TestDevFlagsNeedDevSimEnv(t *testing.T) {
	for _, flag := range []string{"--dev-allow-simulated", "--dev-insecure-live-tls", "--dev-live-allow-private"} {
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
	if c.RPCURL != "https://rpc.example" || c.Listen != ":9999" || c.ChainID != 4217 || len(c.TCBPolicy.AllowedStatuses) != 2 ||
		c.MaxInFlight != 8 || c.LiveHosts != nil || c.LivePrivate {
		t.Fatalf("%+v", c)
	}
	c, err = loadConfig(append([]string{"--live-allowed-hosts", " *.sslip.io, relay.example.com ,", "--max-in-flight", "3"}, addrFlags...), envMap(nil), io.Discard)
	if err != nil || len(c.LiveHosts) != 2 || c.LiveHosts[0] != "*.sslip.io" || c.LiveHosts[1] != "relay.example.com" || c.MaxInFlight != 3 {
		t.Fatalf("live hosts %v %v", c, err)
	}
	if c, err = loadConfig(addrFlags, envMap(map[string]string{"SEALED_VERIFIERD_LIVE_HOSTS": "*.sslip.io"}), io.Discard); err != nil || len(c.LiveHosts) != 1 {
		t.Fatalf("live hosts from env: %v", err)
	}
	// No address source on chain 4217: the embedded contracts/deployments/tempo-mainnet.json (brief item 19).
	c, err = loadConfig(nil, envMap(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, mainnet := chain.Mainnet(); c.Addrs != mainnet || c.ChainID != 4217 || c.RPCURL != "https://rpc.tempo.xyz" || !strings.Contains(c.AddrSource, "tempo-mainnet.json") {
		t.Fatalf("mainnet defaults: %+v (%s)", c.Addrs, c.AddrSource)
	}
	if c.Addrs.FeeSplitter != common.HexToAddress("0x3D288c0756c3F26Da0f41257D688bAB3dB3d94AD") {
		t.Fatalf("mainnet FeeSplitter %s", c.Addrs.FeeSplitter.Hex())
	}
	// Other chains have no embedded deployment.
	if _, err := loadConfig([]string{"--chain-id", "31337"}, envMap(nil), io.Discard); err == nil {
		t.Fatal("started on chain 31337 without registry addresses")
	}
	// A flag overrides one embedded address.
	c, err = loadConfig([]string{"--deployment-registry", "0x0000000000000000000000000000000000000abc"}, envMap(nil), io.Discard)
	if err != nil || c.Addrs.DeploymentRegistry != common.HexToAddress("0xabc") || c.Addrs.AppRegistry != common.HexToAddress("0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43") ||
		!strings.Contains(c.AddrSource, "flag overrides") {
		t.Fatalf("override: %v %+v %s", err, c, c.AddrSource)
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
	for _, bad := range [][]string{{"--chain-id", "x"}, {"--collateral-ttl", "-1s"}, {"--platform-registry", "nope"}, {"extra"},
		{"--max-in-flight", "0"}, {"--live-allowed-hosts", "https://x.sslip.io"}, {"--live-allowed-hosts", "a.*.io"},
		{"--release-asset-base", "http://127.0.0.1:1/releases"}, {"--release-asset-base", "https://u:p@github.com/x"},
		{"--release-asset-base", "https://github.com/x?y=1"}, {"--release-asset-base", ","}, {"--fee-splitter", "0x12"}} {
		args := append(append([]string{}, addrFlags...), bad...)
		if _, err := loadConfig(args, envMap(nil), io.Discard); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

// TestDaemonRedactsRPCURL: a provider key in TEMPO_RPC_URL never reaches reports, HTTP bodies or logs.
func TestDaemonRedactsRPCURL(t *testing.T) {
	const secret = "SECRET-API-KEY"
	args := append([]string{"--tempo-rpc", "http://127.0.0.1:1/v2/" + secret + "?token=abc", "--dev-allow-simulated"}, addrFlags...)
	c, err := loadConfig(args, envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	useComposer(t, func(*config, verify.ChainReader) (verify.Composer, error) { return fixture.Composer{}, nil })
	srv, err := newServer(context.Background(), c, log)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(srv.Handler())
	defer api.Close()
	w := fixture.NewWorld(4217, c.Addrs, common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906"), common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9"), fixture.SimImageID(false))
	bundle, _ := json.Marshal(w.Bundle(1_793_000_000))
	var bodies []string
	for _, req := range []struct{ path, body string }{
		{"/v1/verify/evidence", string(bundle)},
		{"/v1/verify/evidence?format=text", string(bundle)},
		{"/v1/compose", string(w.ConfigJSON())},
	} {
		resp, err := http.Post(api.URL+req.path, "application/json", strings.NewReader(req.body))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodies = append(bodies, string(raw))
	}
	for _, out := range append(bodies, logs.String()) {
		for _, leak := range []string{secret, "token=abc", "/v2/"} {
			if strings.Contains(out, leak) {
				t.Fatalf("RPC URL secret %q leaked:\n%s", leak, out)
			}
		}
	}
	if !strings.Contains(bodies[0], "127.0.0.1:1") || !strings.Contains(bodies[2], "127.0.0.1:1") {
		t.Fatalf("errors should still name the RPC host:\n%s\n%s", bodies[0], bodies[2])
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

	useComposer(t, func(*config, verify.ChainReader) (verify.Composer, error) { return fixture.Composer{}, nil })
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

// TestInVMConfig: the composer's sealed-verifierd sidecar sets only PORT and SEALED_CONFIG_FILE (the stack's public
// config), and the image sets SEALED_DEFAULTS_FILE. That is enough to listen, reach the RPC and read the
// stack's registries.
func TestInVMConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"schema":"sealed-config/v1","chainId":31337,"endpoints":{"tempoRpc":"http://127.0.0.1:8545"},`+
		`"contracts":{"platformRegistry":"0x00000000000000000000000000000000000000e1","appRegistry":"0x00000000000000000000000000000000000000e2",`+
		`"deploymentRegistry":"0x00000000000000000000000000000000000000e3","feeSplitter":"0x00000000000000000000000000000000000000e4"}}`), 0o644)
	repoDefaults := filepath.Join("..", "..", "..", "config", "defaults.yaml")
	c, err := loadConfig(nil, envMap(map[string]string{"PORT": "8088", "SEALED_CONFIG_FILE": cfgPath, "SEALED_DEFAULTS_FILE": repoDefaults}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := chain.Addresses{PlatformRegistry: common.HexToAddress("0xe1"), AppRegistry: common.HexToAddress("0xe2"),
		DeploymentRegistry: common.HexToAddress("0xe3"), FeeSplitter: common.HexToAddress("0xe4")}
	if c.Listen != ":8088" || c.ChainID != 31337 || c.RPCURL != "http://127.0.0.1:8545" || c.Addrs != want || c.AddrSource != cfgPath {
		t.Fatalf("in-VM config: %+v", c)
	}
	if len(c.ReleaseAssetBases) != 1 || c.ReleaseAssetBases[0] != bundles.DefaultReleaseAssetBase {
		t.Fatalf("release asset base from defaults.yaml: %v", c.ReleaseAssetBases)
	}
	// Explicit settings win over the stack config.
	c, err = loadConfig([]string{"--tempo-rpc", "https://rpc.example", "--listen", ":9000"}, envMap(map[string]string{"PORT": "8088", "SEALED_CONFIG_FILE": cfgPath}), io.Discard)
	if err != nil || c.RPCURL != "https://rpc.example" || c.Listen != ":9000" {
		t.Fatalf("explicit settings: %v %+v", err, c)
	}
	if _, err := loadConfig([]string{"--chain-id", "4217"}, envMap(map[string]string{"SEALED_CONFIG_FILE": cfgPath}), io.Discard); err == nil || !strings.Contains(err.Error(), "chain 31337") {
		t.Fatalf("stack config for another chain: %v", err)
	}
	os.WriteFile(cfgPath, []byte(`{"schema":"sealed-config/v1","chainId":31337,"contracts":{}}`), 0o644)
	if _, err := loadConfig(nil, envMap(map[string]string{"SEALED_CONFIG_FILE": cfgPath}), io.Discard); err == nil {
		t.Fatal("stack config without registries accepted")
	}
	os.WriteFile(cfgPath, []byte(`{"schema":"sealed-evidence/v1"}`), 0o644)
	if _, err := loadConfig(nil, envMap(map[string]string{"SEALED_CONFIG_FILE": cfgPath}), io.Discard); err == nil {
		t.Fatal("non-config accepted as stack config")
	}
}

// TestReleaseAssetBases: mirrors are a comma-separated list; plain http only under SEALED_DEV_SIM=1.
func TestReleaseAssetBases(t *testing.T) {
	c, err := loadConfig([]string{"--release-asset-base", " https://github.com/sealedtempo/sealed/releases/download/ , https://mirror.example/sealed"}, envMap(nil), io.Discard)
	if err != nil || len(c.ReleaseAssetBases) != 2 || c.ReleaseAssetBases[0] != bundles.DefaultReleaseAssetBase || c.ReleaseAssetBases[1] != "https://mirror.example/sealed" {
		t.Fatalf("bases %v %v", c, err)
	}
	if c, err = loadConfig(nil, envMap(nil), io.Discard); err != nil || len(c.ReleaseAssetBases) != 1 || c.ReleaseAssetBases[0] != bundles.DefaultReleaseAssetBase {
		t.Fatalf("default base %v %v", c, err)
	}
	if c, err = loadConfig([]string{"--release-asset-base", "http://127.0.0.1:9/r"}, envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard); err != nil || c.ReleaseAssetBases[0] != "http://127.0.0.1:9/r" {
		t.Fatalf("dev http base %v %v", c, err)
	}
	if c, err = loadConfig(nil, envMap(map[string]string{"SEALED_RELEASE_ASSET_BASE": "https://mirror.example/x", "SEALED_BUNDLE_CACHE_DIR": "/tmp/b"}), io.Discard); err != nil ||
		c.ReleaseAssetBases[0] != "https://mirror.example/x" || c.BundleCacheDir != "/tmp/b" {
		t.Fatalf("env %v %v", c, err)
	}
}

// TestDefaultBaseMatchesDefaults keeps bundles.DefaultReleaseAssetBase equal to config/defaults.yaml.
func TestDefaultBaseMatchesDefaults(t *testing.T) {
	d, err := composer.LoadDefaults(filepath.Join("..", "..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Catalog.ReleaseAssetBase != bundles.DefaultReleaseAssetBase {
		t.Fatalf("config/defaults.yaml release_asset_base %q, bundles.DefaultReleaseAssetBase %q", d.Catalog.ReleaseAssetBase, bundles.DefaultReleaseAssetBase)
	}
}
