package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.yaml.in/yaml/v3"

	"github.com/sealedtempo/sealed/runtime/composer"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/bundles"
	"github.com/sealedtempo/sealed/verifier/chain"
	"github.com/sealedtempo/sealed/verifier/httpapi"
)

// config is the daemon configuration from flags, with defaults from the environment.
type config struct {
	Listen          string
	RPCURL          string
	ChainID         uint64
	DeploymentsFile string
	StackConfigFile string
	Addrs           chain.Addresses
	AddrSource      string // where Addrs came from, for the startup log
	DefaultsFile    string
	TCBPolicy       attest.TCBPolicy
	CacheDir        string
	CacheTTL        time.Duration
	LiveTimeout     time.Duration
	LiveHosts       []string
	// LiveFetch lets POST /v1/verify/live fetch a caller's attest URL. Off by default in a stack (--stack-config),
	// where the payer submits what it fetched itself (review V-1).
	LiveFetch bool
	// AllowedClients are the only source addresses served when set (D-061: the payer's address in a stack).
	AllowedClients []netip.Prefix
	// MaxChainHeadAge bounds the age of the chain head of every verification (D-060).
	MaxChainHeadAge time.Duration
	MaxInFlight     int
	AllowSimulated  bool
	InsecureLiveTLS bool
	LivePrivate     bool
	// ReleaseAssetBases are the release asset bases bundles are fetched from (D-046), the catalog's first.
	ReleaseAssetBases []string
	// BundleCacheDir keeps verified bundles on disk by bundleHash; memory only when empty.
	BundleCacheDir string
}

// devSimEnv must be "1" for any dev flag to be accepted.
const devSimEnv = "SEALED_DEV_SIM"

func loadConfig(args []string, getenv func(string) string, stderr io.Writer) (*config, error) {
	env := func(keys ...string) string {
		for _, k := range keys {
			if v := getenv(k); v != "" {
				return v
			}
		}
		return ""
	}
	or := func(v, def string) string {
		if v == "" {
			return def
		}
		return v
	}
	fs := flag.NewFlagSet("sealed-verifierd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := &config{}
	var platform, apps, deployments, feeSplitter, chainID, ttl, liveHosts, maxInFlight, bases, liveFetch, clients, headAge string
	defaultListen := ":8088"
	if p := env("PORT"); p != "" {
		defaultListen = ":" + p // the composer's sealed-verifierd sidecar sets PORT
	}
	fs.StringVar(&c.Listen, "listen", or(env("SEALED_VERIFIERD_LISTEN"), defaultListen), "listen address (SEALED_VERIFIERD_LISTEN, else :$PORT)")
	fs.StringVar(&c.RPCURL, "tempo-rpc", env("TEMPO_RPC_URL", "TEMPO_PUBLIC_RPC_URL"), "Tempo JSON-RPC URL (TEMPO_RPC_URL, TEMPO_PUBLIC_RPC_URL); else the stack config's endpoints.tempoRpc, else https://rpc.tempo.xyz")
	fs.StringVar(&chainID, "chain-id", env("TEMPO_CHAIN_ID"), "expected chain id (TEMPO_CHAIN_ID); else the stack config's chainId, else 4217")
	fs.StringVar(&c.DeploymentsFile, "deployments", env("SEALED_DEPLOYMENTS_FILE"), "contracts/deployments/<network>.json with the registry addresses (SEALED_DEPLOYMENTS_FILE); the embedded tempo-mainnet.json is the default on chain 4217")
	fs.StringVar(&c.StackConfigFile, "stack-config", env("SEALED_CONFIG_FILE"), "public deployment config (sealed-config/v1) of the stack this daemon runs in, for chainId, endpoints.tempoRpc and contracts (SEALED_CONFIG_FILE, set by the composer)")
	fs.StringVar(&feeSplitter, "fee-splitter", env("SEALED_FEE_SPLITTER"), "FeeSplitter address configs must name (SEALED_FEE_SPLITTER); from the address source when unset")
	fs.StringVar(&bases, "release-asset-base", env("SEALED_RELEASE_ASSET_BASE"), "comma-separated release asset bases to fetch bundles from, the catalog's first, mirrors after (SEALED_RELEASE_ASSET_BASE); else catalog.release_asset_base of --defaults, else "+bundles.DefaultReleaseAssetBase)
	fs.StringVar(&c.BundleCacheDir, "bundle-cache-dir", env("SEALED_BUNDLE_CACHE_DIR"), "directory for verified release bundles by bundleHash; memory only when unset (SEALED_BUNDLE_CACHE_DIR)")
	fs.StringVar(&platform, "platform-registry", env("SEALED_PLATFORM_REGISTRY"), "PlatformRegistry address, overrides the deployments file (SEALED_PLATFORM_REGISTRY)")
	fs.StringVar(&apps, "app-registry", env("SEALED_APP_REGISTRY"), "AppRegistry address (SEALED_APP_REGISTRY)")
	fs.StringVar(&deployments, "deployment-registry", env("SEALED_DEPLOYMENT_REGISTRY"), "DeploymentRegistry address (SEALED_DEPLOYMENT_REGISTRY)")
	fs.StringVar(&c.DefaultsFile, "defaults", env("SEALED_DEFAULTS_FILE"), "config/defaults.yaml for tcb_policy (SEALED_DEFAULTS_FILE); built-in policy when unset")
	fs.StringVar(&c.CacheDir, "collateral-cache-dir", env("SEALED_COLLATERAL_CACHE_DIR"), "directory for cached Intel PCS collateral; memory only when unset (SEALED_COLLATERAL_CACHE_DIR)")
	fs.StringVar(&ttl, "collateral-ttl", or(env("SEALED_COLLATERAL_TTL"), attest.DefaultCollateralTTL.String()), "collateral cache TTL (SEALED_COLLATERAL_TTL)")
	fs.DurationVar(&c.LiveTimeout, "live-timeout", 30*time.Second, "timeout of a live /attest round trip")
	fs.StringVar(&liveHosts, "live-allowed-hosts", env("SEALED_VERIFIERD_LIVE_HOSTS"), "comma-separated attest hosts live verification may fetch, exact or *.domain (for example *.sslip.io,relay.example.com); any public host when empty (SEALED_VERIFIERD_LIVE_HOSTS)")
	fs.StringVar(&liveFetch, "live-fetch", env("SEALED_VERIFIERD_LIVE_FETCH"), "true to let POST /v1/verify/live fetch a caller's attest URL, false to verify only caller-fetched attestations (SEALED_VERIFIERD_LIVE_FETCH); default false with --stack-config (the in-VM sidecar), else true")
	fs.StringVar(&clients, "allowed-clients", env("SEALED_VERIFIERD_ALLOWED_CLIENTS"), "comma-separated source IP addresses or CIDR prefixes that may call the API, for example the payer's 172.30.250.5 on a stack's verifier network, which the composer sets (SEALED_VERIFIERD_ALLOWED_CLIENTS); every source when empty; loopback may always read /healthz")
	fs.StringVar(&headAge, "max-chain-head-age", or(env("SEALED_VERIFIERD_MAX_CHAIN_HEAD_AGE"), verify.DefaultMaxChainHeadAge.String()), "oldest chain head a verification accepts, at most 5m; a staler RPC fails the chain check (SEALED_VERIFIERD_MAX_CHAIN_HEAD_AGE)")
	fs.StringVar(&maxInFlight, "max-in-flight", or(env("SEALED_VERIFIERD_MAX_IN_FLIGHT"), strconv.Itoa(httpapi.DefaultMaxInFlight)), "concurrent verifications before answering 429 (SEALED_VERIFIERD_MAX_IN_FLIGHT)")
	fs.BoolVar(&c.AllowSimulated, "dev-allow-simulated", false, "DEV ONLY: accept dev simulator quotes and releases without release CI's signature; requires SEALED_DEV_SIM=1")
	fs.BoolVar(&c.InsecureLiveTLS, "dev-insecure-live-tls", false, "DEV ONLY: skip WebPKI checks of /attest certificates; requires SEALED_DEV_SIM=1")
	fs.BoolVar(&c.LivePrivate, "dev-live-allow-private", false, "DEV ONLY: let live verification fetch loopback and private addresses; requires SEALED_DEV_SIM=1")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	devSim := getenv(devSimEnv) == "1"
	if (c.AllowSimulated || c.InsecureLiveTLS || c.LivePrivate) && !devSim {
		return nil, fmt.Errorf("refusing to start: --dev-allow-simulated, --dev-insecure-live-tls and --dev-live-allow-private need %s=1 (never set in production)", devSimEnv)
	}
	for _, h := range strings.Split(liveHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			if strings.ContainsAny(h, "/:@ ") || strings.Count(h, "*") > 1 || (strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
				return nil, fmt.Errorf("--live-allowed-hosts: invalid host pattern %q", h)
			}
			c.LiveHosts = append(c.LiveHosts, h)
		}
	}
	var err error
	if c.AllowedClients, err = httpapi.ParseClients(clients); err != nil {
		return nil, fmt.Errorf("--allowed-clients: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(liveFetch)) {
	case "":
		c.LiveFetch = c.StackConfigFile == ""
	case "1", "true", "yes", "on":
		c.LiveFetch = true
	case "0", "false", "no", "off":
		c.LiveFetch = false
	default:
		return nil, fmt.Errorf("--live-fetch: %q is not true or false", liveFetch)
	}
	if c.MaxChainHeadAge, err = time.ParseDuration(headAge); err != nil || c.MaxChainHeadAge <= 0 || c.MaxChainHeadAge > verify.MaxChainHeadAgeLimit {
		return nil, fmt.Errorf("--max-chain-head-age: %q must be a duration above 0 and at most %s (D-060)", headAge, verify.MaxChainHeadAgeLimit)
	}
	var stack *stackConfig
	if c.StackConfigFile != "" {
		var err error
		if stack, err = loadStackConfig(c.StackConfigFile); err != nil {
			return nil, err
		}
		if chainID == "" {
			chainID = strconv.FormatUint(stack.ChainID, 10)
		}
		if c.RPCURL == "" {
			c.RPCURL = stack.Endpoints.TempoRPC
		}
	}
	if chainID == "" {
		chainID = strconv.Itoa(chain.MainnetChainID)
	}
	if c.RPCURL == "" {
		c.RPCURL = "https://rpc.tempo.xyz"
	}
	if c.ChainID, err = strconv.ParseUint(chainID, 10, 64); err != nil || c.ChainID == 0 {
		return nil, fmt.Errorf("invalid chain id %q", chainID)
	}
	if stack != nil && stack.ChainID != c.ChainID {
		return nil, fmt.Errorf("%s is for chain %d, expected %d", c.StackConfigFile, stack.ChainID, c.ChainID)
	}
	if c.CacheTTL, err = time.ParseDuration(ttl); err != nil || c.CacheTTL <= 0 {
		return nil, fmt.Errorf("invalid collateral TTL %q", ttl)
	}
	if c.MaxInFlight, err = strconv.Atoi(maxInFlight); err != nil || c.MaxInFlight <= 0 {
		return nil, fmt.Errorf("invalid --max-in-flight %q", maxInFlight)
	}

	// Address source, first match: --deployments, the stack config, the embedded deployment of the chain
	// (contracts/deployments/tempo-mainnet.json on 4217). The --*-registry flags override single addresses.
	switch {
	case c.DeploymentsFile != "":
		d, a, err := chain.LoadDeployments(c.DeploymentsFile)
		if err != nil {
			return nil, err
		}
		if d.ChainID != 0 && d.ChainID != c.ChainID {
			return nil, fmt.Errorf("%s is for chain %d, expected %d", c.DeploymentsFile, d.ChainID, c.ChainID)
		}
		c.Addrs, c.AddrSource = a, c.DeploymentsFile
	case stack != nil:
		if c.Addrs, err = stack.addresses(); err != nil {
			return nil, fmt.Errorf("%s: %w", c.StackConfigFile, err)
		}
		c.AddrSource = c.StackConfigFile
	default:
		if a, ok := chain.DefaultAddresses(c.ChainID); ok {
			c.Addrs, c.AddrSource = a, "embedded contracts/deployments/tempo-mainnet.json"
		}
	}
	overridden := false
	for _, o := range []struct {
		name string
		v    string
		dst  *common.Address
	}{
		{"platform-registry", platform, &c.Addrs.PlatformRegistry},
		{"app-registry", apps, &c.Addrs.AppRegistry},
		{"deployment-registry", deployments, &c.Addrs.DeploymentRegistry},
		{"fee-splitter", feeSplitter, &c.Addrs.FeeSplitter},
	} {
		if o.v == "" {
			continue
		}
		if !common.IsHexAddress(o.v) {
			return nil, fmt.Errorf("--%s: invalid address %q", o.name, o.v)
		}
		*o.dst = common.HexToAddress(o.v)
		overridden = true
	}
	if overridden {
		if c.AddrSource == "" {
			c.AddrSource = "flags"
		} else {
			c.AddrSource += " with flag overrides"
		}
	}
	if err := c.Addrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w (use --deployments, --stack-config or the --*-registry flags; only chain %d has embedded defaults)", err, chain.MainnetChainID)
	}

	c.TCBPolicy = attest.DefaultTCBPolicy()
	if c.DefaultsFile != "" {
		raw, err := os.ReadFile(c.DefaultsFile)
		if err != nil {
			return nil, err
		}
		if c.TCBPolicy, err = attest.TCBPolicyFromDefaults(raw); err != nil {
			return nil, err
		}
		if bases == "" {
			var d struct {
				Catalog struct {
					ReleaseAssetBase string `yaml:"release_asset_base"`
				} `yaml:"catalog"`
			}
			if err := yaml.Unmarshal(raw, &d); err != nil {
				return nil, fmt.Errorf("%s: %w", c.DefaultsFile, err)
			}
			bases = d.Catalog.ReleaseAssetBase
		}
	}
	if bases == "" {
		bases = bundles.DefaultReleaseAssetBase
	}
	// Bundles are checked against their onchain hash, so plain http changes nothing about what is composed; it is
	// still dev only, like the other loopback conveniences.
	if c.ReleaseAssetBases, err = bundles.ParseBases(bases, devSim); err != nil {
		return nil, fmt.Errorf("--release-asset-base: %w (plain http needs %s=1)", err, devSimEnv)
	}
	return c, nil
}

// stackConfig is the part of the public deployment config (sealed-config/v1) the daemon reads when it runs as the
// stack's sidecar.
type stackConfig struct {
	Schema    string `json:"schema"`
	ChainID   uint64 `json:"chainId"`
	Endpoints struct {
		TempoRPC string `json:"tempoRpc"`
	} `json:"endpoints"`
	Contracts struct {
		PlatformRegistry   string `json:"platformRegistry"`
		AppRegistry        string `json:"appRegistry"`
		DeploymentRegistry string `json:"deploymentRegistry"`
		FeeSplitter        string `json:"feeSplitter"`
	} `json:"contracts"`
}

func loadStackConfig(path string) (*stackConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sc stackConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sc.Schema != composer.ConfigSchema || sc.ChainID == 0 {
		return nil, fmt.Errorf("%s: not a %s document with a chainId", path, composer.ConfigSchema)
	}
	return &sc, nil
}

func (sc *stackConfig) addresses() (chain.Addresses, error) {
	var a chain.Addresses
	for _, f := range []struct {
		name string
		v    string
		dst  *common.Address
	}{
		{"contracts.platformRegistry", sc.Contracts.PlatformRegistry, &a.PlatformRegistry},
		{"contracts.appRegistry", sc.Contracts.AppRegistry, &a.AppRegistry},
		{"contracts.deploymentRegistry", sc.Contracts.DeploymentRegistry, &a.DeploymentRegistry},
		{"contracts.feeSplitter", sc.Contracts.FeeSplitter, &a.FeeSplitter},
	} {
		if f.v == "" {
			continue
		}
		if !common.IsHexAddress(f.v) {
			return a, fmt.Errorf("%s: invalid address %q", f.name, f.v)
		}
		*f.dst = common.HexToAddress(f.v)
	}
	return a, a.Validate()
}
