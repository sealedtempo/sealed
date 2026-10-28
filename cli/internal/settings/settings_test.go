package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if _, err := Load(Options{DeploymentsFile: dep}); err == nil {
		t.Fatal("deployments for another chain accepted")
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
