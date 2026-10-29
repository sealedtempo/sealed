package verify

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/verifier/chain"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
	"github.com/sealedtempo/sealed/verifier/internal/strictjson"
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

// ParseBundle decodes an evidence bundle. Keys are case-sensitive and unique (internal/strictjson).
func ParseBundle(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := strictjson.Unmarshal(raw, &b); err != nil {
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
		FeeSplitter        string `json:"feeSplitter"`
	} `json:"contracts"`
	Endpoints        ConfigEndpoints     `json:"endpoints"`
	Debug            bool                `json:"debug"`
	EgressAdditions  map[string][]string `json:"egressAdditions"`
	AllowedVpcRanges []string            `json:"allowedVpcRanges"`
	RelayOwner       string              `json:"relayOwner"`
}

// ConfigEndpoints are config.endpoints: the services the stack trusts.
type ConfigEndpoints struct {
	KeyBroker   string `json:"keyBroker,omitempty"`
	PlatformAPI string `json:"platformApi,omitempty"`
	TempoRPC    string `json:"tempoRpc,omitempty"`
	Relay       string `json:"relay,omitempty"`
	RelayAttest string `json:"relayAttest,omitempty"`
}

// ConfigSummary is what the customer approved in the public config beyond its hash, for `sealed verify` and the
// console to show: whether containers keep logs (debug), the endpoints the stack trusts (the key broker releases
// its disk key and secrets), the egress hosts added per app and the VPC ranges the stack may reach.
type ConfigSummary struct {
	Debug            bool                `json:"debug"`
	Endpoints        ConfigEndpoints     `json:"endpoints"`
	EgressAdditions  map[string][]string `json:"egressAdditions,omitempty"`
	AllowedVpcRanges []string            `json:"allowedVpcRanges,omitempty"`
	RelayOwner       string              `json:"relayOwner,omitempty"`
}

// summary returns the ConfigSummary. URLs lose userinfo, query and fragment; the Tempo RPC keeps only scheme and
// host, since RPC providers put API keys in the path.
func (c *Config) summary() *ConfigSummary {
	sum := &ConfigSummary{
		Debug: c.Debug,
		Endpoints: ConfigEndpoints{
			KeyBroker: shownURL(c.Endpoints.KeyBroker), PlatformAPI: shownURL(c.Endpoints.PlatformAPI),
			TempoRPC: chainRedact(c.Endpoints.TempoRPC), Relay: shownURL(c.Endpoints.Relay), RelayAttest: shownURL(c.Endpoints.RelayAttest),
		},
		AllowedVpcRanges: c.AllowedVpcRanges,
		RelayOwner:       c.RelayOwner,
	}
	for app, hosts := range c.EgressAdditions {
		if len(hosts) == 0 {
			continue
		}
		if sum.EgressAdditions == nil {
			sum.EgressAdditions = map[string][]string{}
		}
		sum.EgressAdditions[app] = hosts
	}
	return sum
}

func shownURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid url>"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

func chainRedact(raw string) string {
	if raw == "" {
		return ""
	}
	return chain.RedactURL(raw)
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
	if err := strictjson.Unmarshal(raw, &c.Config); err != nil {
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
