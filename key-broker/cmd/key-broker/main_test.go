package main

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"go.yaml.in/yaml/v3"

	"github.com/sealed-dev/sealed/key-broker/internal/anvil"
	"github.com/sealed-dev/sealed/key-broker/internal/kbtest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

const testKeyVersion = "projects/cust-proj-1/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb/cryptoKeyVersions/1"

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func prodEnv(extra map[string]string) map[string]string {
	m := map[string]string{
		"SEALED_CUSTOMER":    strings.ToLower(kbtest.Customer.Hex()),
		"SEALED_GCP_PROJECT": "cust-proj-1",
		"SEALED_KMS_KEY":     "projects/cust-proj-1/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(nil, envMap(prodEnv(map[string]string{"PORT": "9999"})), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9999" || c.ChainID != 4217 || c.RPCURL != defaultRPC || c.ReleaseBase != defaultReleaseAssetBase ||
		c.KMSKey != testKeyVersion || c.Customer != kbtest.Customer || c.MaxInFlight != 8 ||
		strings.Join(c.TCBPolicy.AllowedStatuses, ",") != "UpToDate,SWHardeningNeeded" {
		t.Fatalf("config %+v", c)
	}
	// Flags override the environment.
	c, err = loadConfig([]string{"--chain-id", "31337", "--kms-key-version", "3", "--tcb-allowed", "UpToDate"}, envMap(prodEnv(nil)), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.ChainID != 31337 || !strings.HasSuffix(c.KMSKey, "/cryptoKeyVersions/3") || len(c.TCBPolicy.AllowedStatuses) != 1 {
		t.Fatalf("config %+v", c)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"no customer":         {nil, map[string]string{"SEALED_CUSTOMER": ""}},
		"zero customer":       {[]string{"--customer", "0x0000000000000000000000000000000000000000"}, nil},
		"bad customer":        {[]string{"--customer", "alice"}, nil},
		"no project":          {nil, map[string]string{"SEALED_GCP_PROJECT": ""}},
		"no kms key":          {nil, map[string]string{"SEALED_KMS_KEY": ""}},
		"bad kms key":         {[]string{"--kms-key", "my-key"}, nil},
		"http catalog":        {[]string{"--release-asset-base", "http://example.com/releases"}, nil},
		"bad rpc":             {[]string{"--tempo-rpc", "ws://rpc"}, nil},
		"bad registry":        {[]string{"--app-registry", "0x12"}, nil},
		"unknown tcb status":  {[]string{"--tcb-allowed", "UpToDate,Whatever"}, nil},
		"empty tcb policy":    {[]string{"--tcb-allowed", ""}, nil},
		"zero chain id":       {[]string{"--chain-id", "0"}, nil},
		"stray argument":      {[]string{"serve"}, nil},
		"tiny nonce capacity": {[]string{"--nonce-capacity", "1"}, nil},
	} {
		if _, err := loadConfig(c.args, envMap(prodEnv(c.env)), io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestMainnetDefaults keeps the built-in defaults equal to the deployed contracts and config/defaults.yaml.
func TestMainnetDefaults(t *testing.T) {
	root, err := anvil.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	d, addrs, err := chain.LoadDeployments(filepath.Join(root, "contracts", "deployments", "tempo-mainnet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d.ChainID != defaultChainID || addrs.PlatformRegistry != common.HexToAddress(defaultPlatformRegistry) ||
		addrs.AppRegistry != common.HexToAddress(defaultAppRegistry) || addrs.DeploymentRegistry != common.HexToAddress(defaultDeploymentRegistry) {
		t.Fatalf("defaults differ from tempo-mainnet.json: %+v", addrs)
	}
	raw, err := os.ReadFile(filepath.Join(root, "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Cloud struct {
			Region string `yaml:"region"`
		} `yaml:"cloud"`
		Chain struct {
			ChainID      uint64 `yaml:"chain_id"`
			PublicRPCURL string `yaml:"public_rpc_url"`
		} `yaml:"chain"`
		Catalog struct {
			ReleaseAssetBase string `yaml:"release_asset_base"`
		} `yaml:"catalog"`
		TCBPolicy struct {
			AllowedStatuses []string `yaml:"allowed_statuses"`
		} `yaml:"tcb_policy"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	c, _ := loadConfig(nil, envMap(prodEnv(nil)), io.Discard)
	if cfg.Chain.ChainID != defaultChainID || cfg.Chain.PublicRPCURL != defaultRPC || cfg.Catalog.ReleaseAssetBase != defaultReleaseAssetBase ||
		cfg.Cloud.Region != defaultRegion || strings.Join(cfg.TCBPolicy.AllowedStatuses, ",") != strings.Join(c.TCBPolicy.AllowedStatuses, ",") {
		t.Fatalf("defaults differ from config/defaults.yaml: %+v", cfg)
	}
}

// TestDockerfileIsProduction: every base image is pinned by digest, the final stage is distroless static as
// nonroot, and the go build has no build tags (so no dev build can become the image).
func TestDockerfileIsProduction(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	df := string(raw)
	froms := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(df, -1)
	if len(froms) != 2 {
		t.Fatalf("%d FROM lines", len(froms))
	}
	for _, f := range froms {
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(f[1]) {
			t.Errorf("base image %s is not pinned by digest", f[1])
		}
	}
	if !strings.HasPrefix(froms[1][1], "gcr.io/distroless/static-debian13:nonroot@") || !strings.Contains(df, "USER nonroot:nonroot") {
		t.Fatal("the runtime stage must be distroless static, nonroot")
	}
	build := regexp.MustCompile(`(?s)go build .*?\./key-broker/cmd/key-broker`).FindString(df)
	if build == "" || strings.Contains(build, "-tags") {
		t.Fatalf("go build line %q must not set build tags", build)
	}
	if !strings.Contains(build, "CGO_ENABLED=0") && !strings.Contains(df, "CGO_ENABLED=0") {
		t.Fatal("the binary must be static")
	}
}
