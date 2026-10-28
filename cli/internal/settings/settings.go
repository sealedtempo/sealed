// Package settings loads the platform defaults (config/defaults.yaml) and the contract addresses
// (contracts/deployments/<network>.json) the CLI works with. The binary embeds both; --defaults and --deployments
// (or SEALED_DEFAULTS_FILE and SEALED_DEPLOYMENTS_FILE) replace them, and TEMPO_RPC_URL replaces the public RPC.
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"go.yaml.in/yaml/v3"

	"github.com/sealed-dev/sealed/cli/internal/embedded"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// Defaults is the part of config/defaults.yaml the CLI reads.
type Defaults struct {
	Cloud struct {
		Region string `yaml:"region"`
	} `yaml:"cloud"`
	SpendLimitPerDayUSD      float64 `yaml:"spend_limit_per_day_usd"`
	GracePeriodMinutes       int64   `yaml:"grace_period_minutes"`
	SettlementIntervalMinute int64   `yaml:"settlement_interval_minutes"`
	DefaultMachineType       string  `yaml:"default_machine_type"`
	DataDiskGB               int     `yaml:"data_disk_gb"`
	Chain                    struct {
		Name             string `yaml:"name"`
		ChainID          uint64 `yaml:"chain_id"`
		PublicRPCURL     string `yaml:"public_rpc_url"`
		ExplorerURL      string `yaml:"explorer_url"`
		FeeToken         string `yaml:"fee_token"`
		FeeTokenSymbol   string `yaml:"fee_token_symbol"`
		FeeTokenDecimals int    `yaml:"fee_token_decimals"`
	} `yaml:"chain"`
	Catalog struct {
		Registry         string `yaml:"registry"`
		ReleaseAssetBase string `yaml:"release_asset_base"`
	} `yaml:"catalog"`
}

// Settings is everything a command needs to reach the chain and the catalog.
type Settings struct {
	Defaults    Defaults
	DefaultsRaw []byte // for attest.TCBPolicyFromDefaults
	ChainID     uint64
	RPCURL      string
	Registries  chain.Addresses
	FeeSplitter common.Address
	Treasury    common.Address
	DeployBlock uint64
}

// Options select non-default sources. Empty fields use the embedded copies.
type Options struct {
	DefaultsFile    string
	DeploymentsFile string
	RPCURL          string
}

// FromEnv fills empty options from SEALED_DEFAULTS_FILE, SEALED_DEPLOYMENTS_FILE and TEMPO_RPC_URL.
func (o Options) FromEnv(getenv func(string) string) Options {
	if o.DefaultsFile == "" {
		o.DefaultsFile = getenv("SEALED_DEFAULTS_FILE")
	}
	if o.DeploymentsFile == "" {
		o.DeploymentsFile = getenv("SEALED_DEPLOYMENTS_FILE")
	}
	if o.RPCURL == "" {
		o.RPCURL = getenv("TEMPO_RPC_URL")
	}
	return o
}

type deploymentsFile struct {
	ChainID uint64 `json:"chainId"`
	Network string `json:"network"`
	Config  struct {
		Treasury common.Address `json:"treasury"`
	} `json:"config"`
	Contracts map[string]struct {
		Address common.Address `json:"address"`
	} `json:"contracts"`
	DeployBlock uint64 `json:"deployBlock"`
}

// Load reads the defaults and deployments.
func Load(o Options) (*Settings, error) {
	s := &Settings{DefaultsRaw: embedded.DefaultsYAML}
	if o.DefaultsFile != "" {
		b, err := os.ReadFile(o.DefaultsFile)
		if err != nil {
			return nil, err
		}
		s.DefaultsRaw = b
	}
	if err := yaml.Unmarshal(s.DefaultsRaw, &s.Defaults); err != nil {
		return nil, fmt.Errorf("defaults: %w", err)
	}
	if s.Defaults.Chain.ChainID == 0 || s.Defaults.Catalog.Registry == "" || s.Defaults.Catalog.ReleaseAssetBase == "" {
		return nil, fmt.Errorf("defaults: chain.chain_id, catalog.registry and catalog.release_asset_base are required")
	}
	raw := embedded.MainnetDeployments
	if o.DeploymentsFile != "" {
		b, err := os.ReadFile(o.DeploymentsFile)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var d deploymentsFile
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("deployments: %w", err)
	}
	s.ChainID = s.Defaults.Chain.ChainID
	if d.ChainID != 0 && d.ChainID != s.ChainID {
		return nil, fmt.Errorf("deployments are for chain %d, defaults name chain %d", d.ChainID, s.ChainID)
	}
	s.Registries = chain.Addresses{
		PlatformRegistry:   d.Contracts["PlatformRegistry"].Address,
		AppRegistry:        d.Contracts["AppRegistry"].Address,
		DeploymentRegistry: d.Contracts["DeploymentRegistry"].Address,
	}
	if err := s.Registries.Validate(); err != nil {
		return nil, fmt.Errorf("deployments: %w", err)
	}
	s.FeeSplitter = d.Contracts["FeeSplitter"].Address
	s.Treasury = d.Config.Treasury
	s.DeployBlock = d.DeployBlock
	s.RPCURL = s.Defaults.Chain.PublicRPCURL
	if o.RPCURL != "" {
		s.RPCURL = o.RPCURL
	}
	if s.RPCURL == "" {
		return nil, fmt.Errorf("no Tempo RPC URL (set chain.public_rpc_url, TEMPO_RPC_URL or --rpc)")
	}
	return s, nil
}

// ReleaseAssetBase is catalog.release_asset_base without a trailing slash.
func (s *Settings) ReleaseAssetBase() string {
	return strings.TrimRight(s.Defaults.Catalog.ReleaseAssetBase, "/")
}

// SpendLimitPerDay is spend_limit_per_day_usd in fee token base units.
func (s *Settings) SpendLimitPerDay() string {
	dec := s.Defaults.Chain.FeeTokenDecimals
	if dec == 0 {
		dec = 6
	}
	// Defaults hold whole or cent amounts; round to base units.
	scale := 1.0
	for i := 0; i < dec; i++ {
		scale *= 10
	}
	return fmt.Sprintf("%.0f", s.Defaults.SpendLimitPerDayUSD*scale)
}
