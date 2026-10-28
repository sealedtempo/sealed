package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.yaml.in/yaml/v3"

	"github.com/sealed-dev/sealed/key-broker/internal/anvil"
	"github.com/sealed-dev/sealed/key-broker/internal/kbtest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

const testKeyVersion = "projects/cust-proj-1/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1"

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// prodEnv is what the bootstrap Terraform sets (key_broker.tf on ws/cli), plus extra.
func prodEnv(extra map[string]string) map[string]string {
	m := map[string]string{
		"SEALED_CUSTOMER_ADDRESS":    strings.ToLower(kbtest.Customer.Hex()),
		"SEALED_GCP_PROJECT":         "cust-proj-1",
		"SEALED_GCP_PROJECT_NUMBER":  "123456789012",
		"SEALED_SECRET_PREFIX":       "sealed-",
		"SEALED_KMS_KEY_VERSION":     testKeyVersion,
		"TEMPO_RPC_URL":              "https://rpc.tempo.xyz",
		"TEMPO_CHAIN_ID":             "4217",
		"SEALED_PLATFORM_REGISTRY":   strings.ToLower(defaultPlatformRegistry),
		"SEALED_APP_REGISTRY":        strings.ToLower(defaultAppRegistry),
		"SEALED_DEPLOYMENT_REGISTRY": strings.ToLower(defaultDeploymentRegistry),
		"SEALED_RELEASE_ASSET_BASE":  defaultReleaseAssetBase,
	}
	for k, v := range extra {
		if v == "" {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return m
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(nil, prodEnv(map[string]string{"PORT": "9999"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9999" || c.ChainID != 4217 || c.RPCURL != defaultRPC || c.ReleaseBase != defaultReleaseAssetBase ||
		c.KMSKey != testKeyVersion || c.Customer != kbtest.Customer || c.MaxInFlight != 8 || c.ProjectNumber != "123456789012" ||
		c.FeeSplitter != common.HexToAddress(defaultFeeSplitter) || c.FeeToken != common.HexToAddress(defaultFeeToken) ||
		c.MaxHeadAge != 60*time.Second || c.Region != "" ||
		strings.Join(c.TCBPolicy.AllowedStatuses, ",") != "UpToDate,SWHardeningNeeded" {
		t.Fatalf("config %+v", c)
	}
	// Flags override the environment.
	v3 := strings.Replace(testKeyVersion, "/1", "/3", 1)
	c, err = loadConfig([]string{"--kms-key-version", v3, "--tcb-allowed", "UpToDate", "--chain-max-head-age", "2m", "--max-in-flight", "3",
		"--allowed-images", "0x" + strings.Repeat("ab", 32)}, prodEnv(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.KMSKey != v3 || len(c.TCBPolicy.AllowedStatuses) != 1 || c.MaxHeadAge != 2*time.Minute || c.MaxInFlight != 3 || len(c.AllowedImages) != 1 {
		t.Fatalf("config %+v", c)
	}
	// The bootstrap's own RPC and chain are used, not the defaults (spec 5.7).
	c, err = loadConfig(nil, prodEnv(map[string]string{"TEMPO_RPC_URL": "https://tempo.customer-rpc.example/v1/KEY"}), io.Discard)
	if err != nil || c.RPCURL != "https://tempo.customer-rpc.example/v1/KEY" {
		t.Fatalf("rpc %v %+v", err, c)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"no customer":              {nil, map[string]string{"SEALED_CUSTOMER_ADDRESS": ""}},
		"zero customer":            {[]string{"--customer", "0x0000000000000000000000000000000000000000"}, nil},
		"bad customer":             {[]string{"--customer", "alice"}, nil},
		"no project":               {nil, map[string]string{"SEALED_GCP_PROJECT": ""}},
		"no kms key":               {nil, map[string]string{"SEALED_KMS_KEY_VERSION": ""}},
		"kms key without version":  {nil, map[string]string{"SEALED_KMS_KEY_VERSION": strings.TrimSuffix(testKeyVersion, "/cryptoKeyVersions/1")}},
		"kms version 0":            {nil, map[string]string{"SEALED_KMS_KEY_VERSION": strings.Replace(testKeyVersion, "/1", "/0", 1)}},
		"bad kms key":              {[]string{"--kms-key-version", "my-key"}, nil},
		"http catalog":             {[]string{"--release-asset-base", "http://example.com/releases"}, nil},
		"bad rpc":                  {[]string{"--tempo-rpc", "ws://rpc"}, nil},
		"plain http rpc":           {nil, map[string]string{"TEMPO_RPC_URL": "http://rpc.tempo.xyz"}},
		"rpc with credentials":     {nil, map[string]string{"TEMPO_RPC_URL": "https://u:p@rpc.tempo.xyz"}},
		"plain http secretmanager": {nil, map[string]string{"SEALED_SECRETMANAGER_ENDPOINT": "http://secretmanager.example"}},
		"plain http kms":           {nil, map[string]string{"SEALED_KMS_ENDPOINT": "http://10.0.0.8"}},
		"plain http logging":       {nil, map[string]string{"SEALED_LOGGING_ENDPOINT": "http://logging.example"}},
		"bad registry":             {[]string{"--app-registry", "0x12"}, nil},
		"bad fee splitter":         {nil, map[string]string{"SEALED_FEE_SPLITTER": "0x12"}},
		"zero fee token":           {[]string{"--fee-token", "0x0000000000000000000000000000000000000000"}, nil},
		"bad allowed image":        {[]string{"--allowed-images", "0x12"}, nil},
		"unknown tcb status":       {[]string{"--tcb-allowed", "UpToDate,Whatever"}, nil},
		"empty tcb policy":         {[]string{"--tcb-allowed", ""}, nil},
		"zero chain id":            {[]string{"--chain-id", "0"}, nil},
		"local chain outside dev":  {nil, map[string]string{"TEMPO_CHAIN_ID": "31337"}},
		"stray argument":           {[]string{"serve"}, nil},
		"tiny nonce capacity":      {[]string{"--nonce-capacity", "1"}, nil},
		"head age over 5 minutes":  {[]string{"--chain-max-head-age", "6m"}, nil},
		"other secret prefix":      {nil, map[string]string{"SEALED_SECRET_PREFIX": "acme-"}},
		"bad project number":       {nil, map[string]string{"SEALED_GCP_PROJECT_NUMBER": "proj-1"}},
		"old customer name":        {nil, map[string]string{"SEALED_CUSTOMER": strings.ToLower(kbtest.Customer.Hex())}},
		"old rpc name":             {nil, map[string]string{"SEALED_TEMPO_RPC": "https://other.example"}},
		"old chain name":           {nil, map[string]string{"SEALED_CHAIN_ID": "4217"}},
		"old kms name":             {nil, map[string]string{"SEALED_KMS_KEY": testKeyVersion}},
		"misspelled setting":       {nil, map[string]string{"SEALED_TEMPO_RPC_URL": "https://other.example"}},
		"unknown tempo setting":    {nil, map[string]string{"TEMPO_RPC": "https://other.example"}},
	} {
		if _, err := loadConfig(c.args, prodEnv(c.env), io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestLoopbackHTTPAllowed: plain http is fine to a loopback address (local nodes and fakes).
func TestLoopbackHTTPAllowed(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8545", "http://localhost:8545", "http://[::1]:8545"} {
		if err := checkEndpoint("x", u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"http://127.0.0.1.nip.io", "http://169.254.169.254", "ftp://127.0.0.1"} {
		if err := checkEndpoint("x", u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

// TestBootstrapEnvContract (F5): the environment the bootstrap Terraform renders for the broker is exactly the set
// the broker reads. It parses infra/terraform/customer-bootstrap/key_broker.tf (or $SEALED_KB_BOOTSTRAP_TF) and skips
// where that module is not in the tree.
func TestBootstrapEnvContract(t *testing.T) {
	path := os.Getenv("SEALED_KB_BOOTSTRAP_TF")
	if path == "" {
		root, err := anvil.RepoRoot()
		if err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(root, "infra", "terraform", "customer-bootstrap", "key_broker.tf")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not in this tree", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range regexp.MustCompile(`(?s)env\s*\{\s*name\s*=\s*"([A-Z0-9_]+)"`).FindAllStringSubmatch(string(raw), -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	want := append([]string(nil), bootstrapEnv...)
	sort.Strings(want)
	if !slices.Equal(names, want) {
		t.Fatalf("the bootstrap sets %v, the broker reads %v", names, want)
	}
	// Values as the module renders them (lower-cased addresses, the full key version name).
	c, err := loadConfig(nil, prodEnv(nil), io.Discard)
	if err != nil {
		t.Fatalf("the rendered environment is refused: %v", err)
	}
	if c.RPCURL != "https://rpc.tempo.xyz" || c.KMSKey != testKeyVersion {
		t.Fatalf("config %+v", c)
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
	var dep struct {
		Config struct {
			FeeToken string `json:"feeToken"`
		} `json:"config"`
		Contracts map[string]struct {
			Address string `json:"address"`
		} `json:"contracts"`
	}
	depRaw, _ := os.ReadFile(filepath.Join(root, "contracts", "deployments", "tempo-mainnet.json"))
	if err := json.Unmarshal(depRaw, &dep); err != nil {
		t.Fatal(err)
	}
	if common.HexToAddress(dep.Contracts["FeeSplitter"].Address) != common.HexToAddress(defaultFeeSplitter) ||
		common.HexToAddress(dep.Config.FeeToken) != common.HexToAddress(defaultFeeToken) {
		t.Fatalf("fee defaults differ from tempo-mainnet.json: %+v", dep)
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
	c, _ := loadConfig(nil, prodEnv(nil), io.Discard)
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
