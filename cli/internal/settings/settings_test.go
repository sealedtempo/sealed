package settings

import (
	"os"
	"path/filepath"
	"regexp"
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

// TestCloudDefaults: the cloud block of config/defaults.yaml is read (G30). The CLI deploys to Google Cloud with Intel
// TDX only, and every machine type with a registered image is in cloud.machine_family.
func TestCloudDefaults(t *testing.T) {
	repo, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	df := filepath.Join(dir, "defaults.yaml")
	os.WriteFile(df, repo, 0o600)
	for name, o := range map[string]Options{"embedded": {}, "config/defaults.yaml": {DefaultsFile: df}} {
		s, err := Load(o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c := s.Defaults.Cloud
		if c != (Cloud{Provider: "gcp", TEE: "intel-tdx", MachineFamily: "c3", Region: "us-central1"}) {
			t.Fatalf("%s: cloud %+v", name, c)
		}
		if got := c.MachineTypes(); len(got) != 1 || got[0] != "c3-standard-8" || s.Defaults.DefaultMachineType != "c3-standard-8" {
			t.Fatalf("%s: machine types %v, default %s (D-083: c3-standard-8 only)", name, got, s.Defaults.DefaultMachineType)
		}
		if ct, err := ConfidentialInstanceType(c.TEE); err != nil || ct != "TDX" {
			t.Fatalf("%s: tee %s maps to %q: %v", name, c.TEE, ct, err)
		}
		for _, mt := range RegisteredMachineTypes {
			if !strings.HasPrefix(mt, c.MachineFamily+"-") {
				t.Errorf("%s: registered machine type %s is not in machine_family %s", name, mt, c.MachineFamily)
			}
		}
	}

	const cloudLine = "cloud: {provider: gcp, tee: intel-tdx, machine_family: c3, region: us-central1}"
	const mtLine = "default_machine_type: c3-standard-8"
	if !strings.Contains(string(repo), cloudLine) || !strings.Contains(string(repo), mtLine) {
		t.Fatalf("config/defaults.yaml no longer has %q and %q; update this test", cloudLine, mtLine)
	}
	for name, c := range map[string]struct{ old, new, want string }{
		"another provider":       {cloudLine, "cloud: {provider: aws, tee: intel-tdx, machine_family: c3, region: us-central1}", `cloud.provider "aws"`},
		"no provider":            {cloudLine, "cloud: {tee: intel-tdx, machine_family: c3, region: us-central1}", `cloud.provider ""`},
		"another tee":            {cloudLine, "cloud: {provider: gcp, tee: amd-sev-snp, machine_family: n2d, region: us-central1}", `cloud.tee "amd-sev-snp"`},
		"no tee":                 {cloudLine, "cloud: {provider: gcp, machine_family: c3, region: us-central1}", `cloud.tee ""`},
		"tee case":               {cloudLine, "cloud: {provider: gcp, tee: Intel-TDX, machine_family: c3, region: us-central1}", `cloud.tee "Intel-TDX"`},
		"family without images":  {cloudLine, "cloud: {provider: gcp, tee: intel-tdx, machine_family: c4, region: us-central1}", `cloud.machine_family "c4"`},
		"no family":              {cloudLine, "cloud: {provider: gcp, tee: intel-tdx, region: us-central1}", `cloud.machine_family ""`},
		"unregistered default":   {mtLine, "default_machine_type: c3-standard-4", `default_machine_type "c3-standard-4"`},
		"default of another fam": {mtLine, "default_machine_type: c4-standard-8", `default_machine_type "c4-standard-8"`},
		"no default":             {mtLine, "", `default_machine_type ""`},
	} {
		os.WriteFile(df, []byte(strings.Replace(string(repo), c.old, c.new, 1)), 0o600)
		if _, err := Load(Options{DefaultsFile: df}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %s", name, err, c.want)
		}
	}
	if _, err := ConfidentialInstanceType("amd-sev-snp"); err == nil {
		t.Fatal("amd-sev-snp has no confidentialInstanceType the CLI deploys")
	}
}

// TestCloudRegionMatchesBootstrapModule: the bootstrap module's default region is cloud.region (G30). sealed bootstrap
// passes cloud.region when --region is not given; the default applies when the module is applied on its own.
func TestCloudRegionMatchesBootstrapModule(t *testing.T) {
	s, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`variable "region" \{[^}]*?\bdefault\s*=\s*"([^"]+)"`)
	for _, dir := range []string{filepath.Join("..", "..", "..", "infra", "terraform", "customer-bootstrap"), filepath.Join("..", "embedded", "tfmodule")} {
		b, err := os.ReadFile(filepath.Join(dir, "variables.tf"))
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if m := re.FindSubmatch(b); m != nil {
			got = string(m[1])
		}
		if got != s.Defaults.Cloud.Region {
			t.Errorf("%s/variables.tf: default region %q, want cloud.region %q", dir, got, s.Defaults.Cloud.Region)
		}
	}
}
