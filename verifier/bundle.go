package verify

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// Schemas this package understands.
const (
	EvidenceSchema = "sealed-evidence/v1"
	ConfigSchema   = "sealed-config/v1"
	RuntimeDstack  = "dstack"
)

// Bundle is an evidence bundle (INTERFACES.md section 8). Config and EventLog stay raw so their hashes are
// computed over exactly what was sent.
type Bundle struct {
	Schema        string          `json:"schema"`
	ChainID       uint64          `json:"chainId"`
	Contracts     BundleContracts `json:"contracts"`
	DeploymentID  string          `json:"deploymentId"`
	Customer      string          `json:"customer"`
	ImageID       string          `json:"imageId"`
	ReleaseIDs    []string        `json:"releaseIds"`
	Config        json.RawMessage `json:"config"`
	ConfigHash    string          `json:"configHash"`
	AppCompose    string          `json:"appCompose"`
	StackHash     string          `json:"stackHash"`
	EnclaveSigner string          `json:"enclaveSigner"`
	Nonce2        string          `json:"nonce2"`
	AttestedAt    uint64          `json:"attestedAt"`
	Quote         string          `json:"quote"`
	QuoteHash     string          `json:"quoteHash"`
	EventLog      json.RawMessage `json:"eventLog"`
	EventLogHash  string          `json:"eventLogHash"`
	Runtime       string          `json:"runtime"`
	// Record is added by the platform after registration and is not covered by any hash.
	Record *BundleRecord `json:"record,omitempty"`
}

// BundleContracts are the registry addresses a bundle claims. The verifier always reads its own configured
// addresses and only checks that these agree.
type BundleContracts struct {
	PlatformRegistry   string `json:"platformRegistry"`
	AppRegistry        string `json:"appRegistry"`
	DeploymentRegistry string `json:"deploymentRegistry"`
}

// BundleRecord points at the registration transaction.
type BundleRecord struct {
	TxHash string `json:"txHash"`
	Method int    `json:"method"`
}

// ParseBundle decodes an evidence bundle.
func ParseBundle(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("evidence bundle: %w", err)
	}
	return &b, nil
}

// Config is the part of the public deployment config (sealed-config/v1, INTERFACES.md section 5) the verifier
// reads. The full document is validated by the composer.
type Config struct {
	Schema    string      `json:"schema"`
	ChainID   uint64      `json:"chainId"`
	Customer  string      `json:"customer"`
	Salt      string      `json:"salt"`
	ImageID   string      `json:"imageId"`
	Apps      []ConfigApp `json:"apps"`
	Contracts struct {
		PlatformRegistry   string `json:"platformRegistry"`
		AppRegistry        string `json:"appRegistry"`
		DeploymentRegistry string `json:"deploymentRegistry"`
	} `json:"contracts"`
}

// ConfigApp is one entry of config.apps.
type ConfigApp struct {
	ID        string `json:"id"`
	ReleaseID string `json:"releaseId"`
}

// parsedConfig is a Config with its byte fields decoded.
type parsedConfig struct {
	Config
	customer   common.Address
	salt       [32]byte
	imageID    [32]byte
	releaseIDs [][32]byte
}

func parseConfig(raw json.RawMessage) (*parsedConfig, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("config missing")
	}
	var c parsedConfig
	if err := json.Unmarshal(raw, &c.Config); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Schema != ConfigSchema {
		return nil, fmt.Errorf("config schema %q, want %q", c.Schema, ConfigSchema)
	}
	var err error
	if c.customer, err = parseAddress(c.Customer); err != nil {
		return nil, fmt.Errorf("config.customer: %w", err)
	}
	if c.salt, err = hexb.Decode32(c.Salt); err != nil {
		return nil, fmt.Errorf("config.salt: %w", err)
	}
	if c.imageID, err = hexb.Decode32(c.ImageID); err != nil {
		return nil, fmt.Errorf("config.imageId: %w", err)
	}
	if len(c.Apps) == 0 {
		return nil, fmt.Errorf("config.apps is empty")
	}
	for i, a := range c.Apps {
		id, err := hexb.Decode32(a.ReleaseID)
		if err != nil {
			return nil, fmt.Errorf("config.apps[%d].releaseId: %w", i, err)
		}
		c.releaseIDs = append(c.releaseIDs, id)
	}
	return &c, nil
}

func parseAddress(s string) (common.Address, error) {
	b, err := hexb.Decode20(s)
	if err != nil {
		return common.Address{}, err
	}
	return common.Address(b), nil
}

func parseIDs(ss []string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(ss))
	for i, s := range ss {
		id, err := hexb.Decode32(s)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, id)
	}
	return out, nil
}
