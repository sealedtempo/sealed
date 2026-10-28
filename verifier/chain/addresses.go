package chain

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
)

// Addresses are the registry contracts the verifier reads.
type Addresses struct {
	PlatformRegistry   common.Address `json:"platformRegistry"`
	AppRegistry        common.Address `json:"appRegistry"`
	DeploymentRegistry common.Address `json:"deploymentRegistry"`
	// FeeSplitter is optional: the verifier never reads it, but when it is known the config's
	// contracts.feeSplitter must equal it.
	FeeSplitter common.Address `json:"feeSplitter,omitempty"`
}

// Validate requires the three registry addresses to be set.
func (a Addresses) Validate() error {
	for name, v := range map[string]common.Address{
		"platformRegistry":   a.PlatformRegistry,
		"appRegistry":        a.AppRegistry,
		"deploymentRegistry": a.DeploymentRegistry,
	} {
		if v == (common.Address{}) {
			return fmt.Errorf("chain: %s address is not set", name)
		}
	}
	return nil
}

// Deployments is the part of contracts/deployments/<network>.json the verifier needs.
type Deployments struct {
	ChainID   uint64 `json:"chainId"`
	Network   string `json:"network"`
	Contracts map[string]struct {
		Address common.Address `json:"address"`
	} `json:"contracts"`
}

// LoadDeployments reads contracts/deployments/<network>.json (written by the contracts deploy script).
func LoadDeployments(path string) (Deployments, Addresses, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Deployments{}, Addresses{}, err
	}
	return ParseDeployments(path, raw)
}

// ParseDeployments decodes a deployments file; name is used in errors.
func ParseDeployments(name string, raw []byte) (Deployments, Addresses, error) {
	var d Deployments
	if err := json.Unmarshal(raw, &d); err != nil {
		return Deployments{}, Addresses{}, fmt.Errorf("parse %s: %w", name, err)
	}
	a := Addresses{
		PlatformRegistry:   d.Contracts["PlatformRegistry"].Address,
		AppRegistry:        d.Contracts["AppRegistry"].Address,
		DeploymentRegistry: d.Contracts["DeploymentRegistry"].Address,
		FeeSplitter:        d.Contracts["FeeSplitter"].Address,
	}
	if err := a.Validate(); err != nil {
		return d, a, fmt.Errorf("%s: %w", name, err)
	}
	return d, a, nil
}

// MainnetChainID is Tempo mainnet.
const MainnetChainID = 4217

//go:embed deployments/tempo-mainnet.json
var mainnetDeployments []byte

// Mainnet returns the Tempo mainnet deployment embedded from contracts/deployments/tempo-mainnet.json (refreshed by
// `make -C verifier abi`; TestEmbeddedMainnetDeployments fails when the copy drifts). It is the default address
// source of sealed-verifierd and every library user on chain 4217.
func Mainnet() (Deployments, Addresses) {
	d, a, err := ParseDeployments("embedded tempo-mainnet.json", mainnetDeployments)
	if err != nil || d.ChainID != MainnetChainID {
		panic(fmt.Sprintf("chain: embedded tempo-mainnet.json: chain %d, %v", d.ChainID, err)) // checked by tests
	}
	return d, a
}

// DefaultAddresses returns the embedded deployment for chainID, and false when none is embedded (only Tempo
// mainnet is).
func DefaultAddresses(chainID uint64) (Addresses, bool) {
	if chainID != MainnetChainID {
		return Addresses{}, false
	}
	_, a := Mainnet()
	return a, true
}
