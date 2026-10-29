package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestEmbeddedMainnet(t *testing.T) {
	s, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.ChainID != 4217 || s.RPCURL != "https://rpc.tempo.xyz" || s.Defaults.Catalog.Registry != "ghcr.io/sealedtempo" {
		t.Fatalf("%+v", s)
	}
	if strings.ToLower(s.Registries.DeploymentRegistry.Hex()) != "0x254efb9d1809a95ec6d233cc57b3a10849bd2c8e" || s.FeeSplitter.Hex() == "0x0000000000000000000000000000000000000000" {
		t.Fatalf("addresses %+v", s.Registries)
	}
	if s.SpendLimitPerDay() != "2000000" || s.ReleaseAssetBase() != "https://github.com/sealedtempo/sealed/releases/download" {
		t.Fatalf("spend %s base %s", s.SpendLimitPerDay(), s.ReleaseAssetBase())
	}
	if strings.ToLower(s.Defaults.Chain.FeeToken) != "0x20c000000000000000000000b9537d11c60e8b50" {
		t.Fatal("fee token is USDC.e (D-035)")
	}
}

func TestOverrides(t *testing.T) {
	dir := t.TempDir()
	dep := filepath.Join(dir, "d.json")
	os.WriteFile(dep, []byte(`{"chainId": 31337, "contracts": {}}`), 0o600)
	if _, err := Load(Options{DeploymentsFile: dep, RPCURL: "http://127.0.0.1:8545"}); err == nil || !strings.Contains(err.Error(), "address is not set") {
		t.Fatalf("deployments without registries accepted: %v", err)
	}
	os.WriteFile(dep, []byte(`{"chainId": 4217, "contracts": {"PlatformRegistry": {"address": "0x00000000000000000000000000000000000000e1"}}}`), 0o600)
	if _, err := Load(Options{DeploymentsFile: dep}); err == nil {
		t.Fatal("missing registries accepted")
	}
	env := map[string]string{"TEMPO_RPC_URL": "https://rpc.example.com/key"}
	o := Options{}.FromEnv(func(k string) string { return env[k] })
	s, err := Load(o)
	if err != nil || s.RPCURL != "https://rpc.example.com/key" {
		t.Fatalf("rpc override: %v", err)
	}
}

const testnetDeployments = `{"chainId": 42431, "network": "tempo-testnet",
  "config": {"feeToken": "0x20C0000000000000000000000000000000000001", "treasury": "0x00000000000000000000000000000000000000b7"},
  "contracts": {"PlatformRegistry": {"address": "0x00000000000000000000000000000000000000a1"},
    "AppRegistry": {"address": "0x00000000000000000000000000000000000000a2"},
    "DeploymentRegistry": {"address": "0x00000000000000000000000000000000000000a3"},
    "FeeSplitter": {"address": "0x00000000000000000000000000000000000000a4"}}}`

// TestDeploymentsFileForAnotherChain: a deployments file for another chain is enough without a defaults file. The
// chain id, network name and fee token come from it; mainnet's public RPC and explorer do not apply, so an RPC must
// be given; --chain-id and TEMPO_CHAIN_ID must agree with it.
func TestDeploymentsFileForAnotherChain(t *testing.T) {
	dir := t.TempDir()
	dep := filepath.Join(dir, "tempo-testnet.json")
	os.WriteFile(dep, []byte(testnetDeployments), 0o600)

	if _, err := Load(Options{DeploymentsFile: dep}); err == nil || !strings.Contains(err.Error(), "pass --rpc (or TEMPO_RPC_URL) with an RPC of chain 42431") {
		t.Fatalf("mainnet's public RPC used for chain 42431: %v", err)
	}
	s, err := Load(Options{DeploymentsFile: dep, RPCURL: "https://rpc.testnet.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Derived || s.ChainID != 42431 || s.Defaults.Chain.ChainID != 42431 || s.Defaults.Chain.Name != "tempo-testnet" ||
		s.Defaults.Chain.PublicRPCURL != "" || s.Defaults.Chain.ExplorerURL != "" || s.RPCURL != "https://rpc.testnet.example" {
		t.Fatalf("derived chain settings %+v", s)
	}
	if s.FeeToken != common.HexToAddress("0x20C0000000000000000000000000000000000001") || s.Defaults.Chain.FeeToken != "0x20c0000000000000000000000000000000000001" {
		t.Fatalf("fee token %s %s", s.FeeToken.Hex(), s.Defaults.Chain.FeeToken)
	}
	if s.Registries.FeeSplitter != s.FeeSplitter || s.FeeSplitter != common.HexToAddress("0xa4") || s.Treasury != common.HexToAddress("0xb7") {
		t.Fatalf("addresses %+v", s.Registries)
	}
	// Platform-wide defaults stay.
	if s.ReleaseAssetBase() != "https://github.com/sealedtempo/sealed/releases/download" || s.SpendLimitPerDay() != "2000000" {
		t.Fatalf("platform defaults changed: %s %s", s.ReleaseAssetBase(), s.SpendLimitPerDay())
	}

	// --chain-id and TEMPO_CHAIN_ID.
	if s, err := Load(Options{DeploymentsFile: dep, RPCURL: "https://rpc.testnet.example", ChainID: 42431}); err != nil || s.ChainID != 42431 {
		t.Fatalf("--chain-id 42431: %v", err)
	}
	if _, err := Load(Options{DeploymentsFile: dep, RPCURL: "https://rpc.testnet.example", ChainID: 4217}); err == nil || !strings.Contains(err.Error(), "deployments file is for chain 42431") {
		t.Fatalf("--chain-id 4217 with a 42431 file: %v", err)
	}
	env := map[string]string{"TEMPO_CHAIN_ID": "4217", "TEMPO_RPC_URL": "https://rpc.testnet.example", "SEALED_DEPLOYMENTS_FILE": dep}
	if _, err := Load(Options{}.FromEnv(func(k string) string { return env[k] })); err == nil || !strings.Contains(err.Error(), "TEMPO_CHAIN_ID") {
		t.Fatalf("TEMPO_CHAIN_ID 4217 with a 42431 file: %v", err)
	}
	env["TEMPO_CHAIN_ID"] = "forty"
	if _, err := Load(Options{}.FromEnv(func(k string) string { return env[k] })); err == nil || !strings.Contains(err.Error(), "not a chain id") {
		t.Fatalf("TEMPO_CHAIN_ID forty: %v", err)
	}
	// The flag wins over the environment.
	env["TEMPO_CHAIN_ID"] = "4217"
	if s, err := Load(Options{ChainID: 42431}.FromEnv(func(k string) string { return env[k] })); err != nil || s.ChainID != 42431 {
		t.Fatalf("--chain-id over TEMPO_CHAIN_ID: %v", err)
	}
	// A chain other than mainnet's needs that chain's deployments.
	if _, err := Load(Options{ChainID: 42431, RPCURL: "https://rpc.testnet.example"}); err == nil || !strings.Contains(err.Error(), "the embedded deployments are Tempo mainnet's") {
		t.Fatalf("--chain-id 42431 with the embedded mainnet deployments: %v", err)
	}
	if s, err := Load(Options{ChainID: 4217}); err != nil || s.Derived || s.ChainID != 4217 {
		t.Fatalf("--chain-id 4217: %v", err)
	}
	// A deployments file without chainId takes --chain-id.
	noID := filepath.Join(dir, "no-id.json")
	os.WriteFile(noID, []byte(strings.Replace(testnetDeployments, `"chainId": 42431, `, "", 1)), 0o600)
	if s, err := Load(Options{DeploymentsFile: noID, RPCURL: "http://127.0.0.1:8545", ChainID: 42431}); err != nil || s.ChainID != 42431 || !s.Derived {
		t.Fatalf("chain from --chain-id: %v %+v", err, s)
	}
	// An explicit defaults file is never overridden: its chain must match.
	defs, _ := os.ReadFile(filepath.Join("..", "..", "..", "config", "defaults.yaml"))
	df := filepath.Join(dir, "defaults.yaml")
	os.WriteFile(df, defs, 0o600)
	if _, err := Load(Options{DefaultsFile: df, DeploymentsFile: dep, RPCURL: "https://rpc.testnet.example"}); err == nil || !strings.Contains(err.Error(), "defaults name chain 4217") {
		t.Fatalf("a mainnet defaults file with testnet deployments: %v", err)
	}
	// Without config.feeToken the fee token is unknown on that chain (bootstrap and deploy then ask for it).
	noToken := filepath.Join(dir, "no-token.json")
	os.WriteFile(noToken, []byte(strings.Replace(testnetDeployments, `"feeToken": "0x20C0000000000000000000000000000000000001", `, "", 1)), 0o600)
	if s, err := Load(Options{DeploymentsFile: noToken, RPCURL: "https://rpc.testnet.example"}); err != nil || s.FeeToken != (common.Address{}) || s.Defaults.Chain.FeeToken != "" {
		t.Fatalf("no fee token: %v %+v", err, s)
	}
}
