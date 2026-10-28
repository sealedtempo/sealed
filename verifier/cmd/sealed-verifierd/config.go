package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/httpapi"
)

// config is the daemon configuration from flags, with defaults from the environment.
type config struct {
	Listen          string
	RPCURL          string
	ChainID         uint64
	DeploymentsFile string
	Addrs           chain.Addresses
	DefaultsFile    string
	TCBPolicy       attest.TCBPolicy
	CacheDir        string
	CacheTTL        time.Duration
	LiveTimeout     time.Duration
	LiveHosts       []string
	MaxInFlight     int
	AllowSimulated  bool
	InsecureLiveTLS bool
	LivePrivate     bool
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
	var platform, apps, deployments, chainID, ttl, liveHosts, maxInFlight string
	fs.StringVar(&c.Listen, "listen", or(env("SEALED_VERIFIERD_LISTEN"), ":8088"), "listen address (SEALED_VERIFIERD_LISTEN)")
	fs.StringVar(&c.RPCURL, "tempo-rpc", or(env("TEMPO_RPC_URL", "TEMPO_PUBLIC_RPC_URL"), "https://rpc.tempo.xyz"), "Tempo JSON-RPC URL (TEMPO_RPC_URL, TEMPO_PUBLIC_RPC_URL)")
	fs.StringVar(&chainID, "chain-id", or(env("TEMPO_CHAIN_ID"), "4217"), "expected chain id (TEMPO_CHAIN_ID)")
	fs.StringVar(&c.DeploymentsFile, "deployments", env("SEALED_DEPLOYMENTS_FILE"), "contracts/deployments/<network>.json with the registry addresses (SEALED_DEPLOYMENTS_FILE)")
	fs.StringVar(&platform, "platform-registry", env("SEALED_PLATFORM_REGISTRY"), "PlatformRegistry address, overrides the deployments file (SEALED_PLATFORM_REGISTRY)")
	fs.StringVar(&apps, "app-registry", env("SEALED_APP_REGISTRY"), "AppRegistry address (SEALED_APP_REGISTRY)")
	fs.StringVar(&deployments, "deployment-registry", env("SEALED_DEPLOYMENT_REGISTRY"), "DeploymentRegistry address (SEALED_DEPLOYMENT_REGISTRY)")
	fs.StringVar(&c.DefaultsFile, "defaults", env("SEALED_DEFAULTS_FILE"), "config/defaults.yaml for tcb_policy (SEALED_DEFAULTS_FILE); built-in policy when unset")
	fs.StringVar(&c.CacheDir, "collateral-cache-dir", env("SEALED_COLLATERAL_CACHE_DIR"), "directory for cached Intel PCS collateral; memory only when unset (SEALED_COLLATERAL_CACHE_DIR)")
	fs.StringVar(&ttl, "collateral-ttl", or(env("SEALED_COLLATERAL_TTL"), attest.DefaultCollateralTTL.String()), "collateral cache TTL (SEALED_COLLATERAL_TTL)")
	fs.DurationVar(&c.LiveTimeout, "live-timeout", 30*time.Second, "timeout of a live /attest round trip")
	fs.StringVar(&liveHosts, "live-allowed-hosts", env("SEALED_VERIFIERD_LIVE_HOSTS"), "comma-separated attest hosts live verification may fetch, exact or *.domain (for example *.sslip.io,relay.example.com); any public host when empty (SEALED_VERIFIERD_LIVE_HOSTS)")
	fs.StringVar(&maxInFlight, "max-in-flight", or(env("SEALED_VERIFIERD_MAX_IN_FLIGHT"), strconv.Itoa(httpapi.DefaultMaxInFlight)), "concurrent verifications before answering 429 (SEALED_VERIFIERD_MAX_IN_FLIGHT)")
	fs.BoolVar(&c.AllowSimulated, "dev-allow-simulated", false, "DEV ONLY: accept dev simulator quotes; requires SEALED_DEV_SIM=1")
	fs.BoolVar(&c.InsecureLiveTLS, "dev-insecure-live-tls", false, "DEV ONLY: skip WebPKI checks of /attest certificates; requires SEALED_DEV_SIM=1")
	fs.BoolVar(&c.LivePrivate, "dev-live-allow-private", false, "DEV ONLY: let live verification fetch loopback and private addresses; requires SEALED_DEV_SIM=1")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	if (c.AllowSimulated || c.InsecureLiveTLS || c.LivePrivate) && getenv(devSimEnv) != "1" {
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
	if c.ChainID, err = strconv.ParseUint(chainID, 10, 64); err != nil || c.ChainID == 0 {
		return nil, fmt.Errorf("invalid chain id %q", chainID)
	}
	if c.CacheTTL, err = time.ParseDuration(ttl); err != nil || c.CacheTTL <= 0 {
		return nil, fmt.Errorf("invalid collateral TTL %q", ttl)
	}
	if c.MaxInFlight, err = strconv.Atoi(maxInFlight); err != nil || c.MaxInFlight <= 0 {
		return nil, fmt.Errorf("invalid --max-in-flight %q", maxInFlight)
	}

	if c.DeploymentsFile != "" {
		d, a, err := chain.LoadDeployments(c.DeploymentsFile)
		if err != nil {
			return nil, err
		}
		if d.ChainID != 0 && d.ChainID != c.ChainID {
			return nil, fmt.Errorf("%s is for chain %d, expected %d", c.DeploymentsFile, d.ChainID, c.ChainID)
		}
		c.Addrs = a
	}
	for _, o := range []struct {
		name string
		v    string
		dst  *common.Address
	}{
		{"platform-registry", platform, &c.Addrs.PlatformRegistry},
		{"app-registry", apps, &c.Addrs.AppRegistry},
		{"deployment-registry", deployments, &c.Addrs.DeploymentRegistry},
	} {
		if o.v == "" {
			continue
		}
		if !common.IsHexAddress(o.v) {
			return nil, fmt.Errorf("--%s: invalid address %q", o.name, o.v)
		}
		*o.dst = common.HexToAddress(o.v)
	}
	if err := c.Addrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w (use --deployments or the --*-registry flags)", err)
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
	}
	return c, nil
}
