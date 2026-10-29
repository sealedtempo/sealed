// Package settings loads the platform defaults (config/defaults.yaml) and the contract addresses
// (contracts/deployments/<network>.json) the CLI works with. The binary embeds both; --defaults and --deployments
// (or SEALED_DEFAULTS_FILE and SEALED_DEPLOYMENTS_FILE) replace them, and TEMPO_RPC_URL replaces the public RPC.
//
// A deployments file for another chain (a testnet, a local node) is enough on its own: when no defaults file is
// given, the chain id, network name and fee token come from that file instead of the embedded mainnet defaults, and
// the mainnet public RPC no longer applies, so an RPC for that chain must be given (--rpc or TEMPO_RPC_URL).
// --chain-id (TEMPO_CHAIN_ID) states the expected chain; it must agree with the deployments file.
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"go.yaml.in/yaml/v3"

	"github.com/sealedtempo/sealed/cli/internal/embedded"
	"github.com/sealedtempo/sealed/verifier/chain"
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
	// Registries are the three registries, plus the FeeSplitter when the deployments file names one (the verifier
	// then requires it in config.contracts.feeSplitter).
	Registries  chain.Addresses
	FeeSplitter common.Address
	// FeeToken is chain.fee_token of the defaults, or the deployments file's config.feeToken on another chain.
	FeeToken    common.Address
	Treasury    common.Address
	DeployBlock uint64
	// Derived is true when the chain settings came from a deployments file for another chain than the embedded
	// defaults' (Tempo mainnet).
	Derived bool
}

// Options select non-default sources. Empty fields use the embedded copies.
type Options struct {
	DefaultsFile    string
	DeploymentsFile string
	RPCURL          string
	// ChainID is the chain the caller expects; 0 takes it from the deployments file, else the defaults.
	ChainID uint64
	// ChainIDText is ChainID as given in the environment (TEMPO_CHAIN_ID), parsed by Load.
	ChainIDText string
}

// FromEnv fills empty options from SEALED_DEFAULTS_FILE, SEALED_DEPLOYMENTS_FILE, TEMPO_RPC_URL and TEMPO_CHAIN_ID.
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
	if o.ChainID == 0 && o.ChainIDText == "" {
		o.ChainIDText = getenv("TEMPO_CHAIN_ID")
	}
	return o
}

type deploymentsFile struct {
	ChainID uint64 `json:"chainId"`
	Network string `json:"network"`
	Config  struct {
		Treasury common.Address `json:"treasury"`
		FeeToken common.Address `json:"feeToken"`
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
	want, err := o.chainID()
	if err != nil {
		return nil, err
	}
	switch {
	case want != 0 && d.ChainID != 0 && want != d.ChainID && o.DeploymentsFile == "":
		return nil, fmt.Errorf("--chain-id (TEMPO_CHAIN_ID) %d: the embedded deployments are Tempo mainnet's (%d); pass --deployments (SEALED_DEPLOYMENTS_FILE) with that chain's contracts/deployments/<network>.json",
			want, d.ChainID)
	case want != 0 && d.ChainID != 0 && want != d.ChainID:
		return nil, fmt.Errorf("--chain-id (TEMPO_CHAIN_ID) %d, but the deployments file is for chain %d", want, d.ChainID)
	case want == 0:
		want = d.ChainID
	}
	if want == 0 {
		want = s.Defaults.Chain.ChainID
	}
	if want != s.Defaults.Chain.ChainID {
		switch {
		case o.DefaultsFile != "":
			return nil, fmt.Errorf("deployments are for chain %d, defaults name chain %d", want, s.Defaults.Chain.ChainID)
		case o.DeploymentsFile == "":
			return nil, fmt.Errorf("chain %d: the embedded deployments are Tempo mainnet's (%d); pass --deployments (SEALED_DEPLOYMENTS_FILE) with that chain's contracts/deployments/<network>.json",
				want, s.Defaults.Chain.ChainID)
		}
		// The embedded defaults are mainnet's: their chain block does not describe this chain. Everything else
		// (catalog, release asset base, TCB policy, settlement) is platform-wide and stays.
		s.Derived = true
		name := d.Network
		if name == "" {
			name = fmt.Sprintf("chain-%d", want)
		}
		s.Defaults.Chain.Name = name
		s.Defaults.Chain.ChainID = want
		s.Defaults.Chain.PublicRPCURL = ""
		s.Defaults.Chain.ExplorerURL = ""
		s.Defaults.Chain.FeeToken = ""
		if d.Config.FeeToken != (common.Address{}) {
			s.Defaults.Chain.FeeToken = strings.ToLower(d.Config.FeeToken.Hex())
		}
	}
	s.ChainID = want
	s.Registries = chain.Addresses{
		PlatformRegistry:   d.Contracts["PlatformRegistry"].Address,
		AppRegistry:        d.Contracts["AppRegistry"].Address,
		DeploymentRegistry: d.Contracts["DeploymentRegistry"].Address,
		FeeSplitter:        d.Contracts["FeeSplitter"].Address,
	}
	if err := s.Registries.Validate(); err != nil {
		return nil, fmt.Errorf("deployments: %w", err)
	}
	s.FeeSplitter = d.Contracts["FeeSplitter"].Address
	if s.Defaults.Chain.FeeToken != "" {
		if !common.IsHexAddress(s.Defaults.Chain.FeeToken) {
			return nil, fmt.Errorf("defaults: chain.fee_token %q is not an address", s.Defaults.Chain.FeeToken)
		}
		s.FeeToken = common.HexToAddress(s.Defaults.Chain.FeeToken)
	}
	s.Treasury = d.Config.Treasury
	s.DeployBlock = d.DeployBlock
	s.RPCURL = s.Defaults.Chain.PublicRPCURL
	if o.RPCURL != "" {
		s.RPCURL = o.RPCURL
	}
	if s.RPCURL == "" {
		if s.Derived {
			return nil, fmt.Errorf("the deployments file is for chain %d, and chain.public_rpc_url serves Tempo mainnet: pass --rpc (or TEMPO_RPC_URL) with an RPC of chain %d", s.ChainID, s.ChainID)
		}
		return nil, fmt.Errorf("no Tempo RPC URL (set chain.public_rpc_url, TEMPO_RPC_URL or --rpc)")
	}
	return s, nil
}

func (o Options) chainID() (uint64, error) {
	if o.ChainID != 0 || o.ChainIDText == "" {
		return o.ChainID, nil
	}
	id, err := strconv.ParseUint(strings.TrimSpace(o.ChainIDText), 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("TEMPO_CHAIN_ID %q is not a chain id", o.ChainIDText)
	}
	return id, nil
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
