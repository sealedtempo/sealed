package chain

import (
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
}

// Validate requires every address to be set.
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
	var d Deployments
	if err := json.Unmarshal(raw, &d); err != nil {
		return Deployments{}, Addresses{}, fmt.Errorf("parse %s: %w", path, err)
	}
	a := Addresses{
		PlatformRegistry:   d.Contracts["PlatformRegistry"].Address,
		AppRegistry:        d.Contracts["AppRegistry"].Address,
		DeploymentRegistry: d.Contracts["DeploymentRegistry"].Address,
	}
	if err := a.Validate(); err != nil {
		return d, a, fmt.Errorf("%s: %w", path, err)
	}
	return d, a, nil
}
