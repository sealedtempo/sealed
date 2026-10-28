package composer

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Fixed in-VM network layout (INTERFACES section 6 and 14). These are part of
// the composer version; TestNetworkMatchesDefaults keeps config/defaults.yaml
// in step.
const (
	AppsSubnet   = "172.30.0.0/24"
	EdgeSubnet   = "172.31.0.0/24"
	EgressAppsIP = "172.30.0.2"
	AgentIP      = "172.30.0.3"
	CaddyIP      = "172.30.0.4"
	PayerIP      = "172.30.0.5"
	VerifierdIP  = "172.30.0.6"
	EgressEdgeIP = "172.31.0.2"
	CaddyEdgeIP  = "172.31.0.4"
	DNSIP        = EgressAppsIP
	firstAppHost = 16
	lastAppHost  = 254
)

// Defaults is the subset of config/defaults.yaml the composer and the bundle
// builder read.
type Defaults struct {
	Catalog struct {
		Registry         string `yaml:"registry"`
		ReleaseAssetBase string `yaml:"release_asset_base"`
	} `yaml:"catalog"`
	Network struct {
		AppsSubnet   string `yaml:"apps_subnet"`
		EdgeSubnet   string `yaml:"edge_subnet"`
		EgressAppsIP string `yaml:"egress_apps_ip"`
		EgressEdgeIP string `yaml:"egress_edge_ip"`
		DNSIP        string `yaml:"dns_ip"`
		AllowedPorts []int  `yaml:"allowed_ports"`
	} `yaml:"network"`
}

// LoadDefaults reads config/defaults.yaml.
func LoadDefaults(path string) (*Defaults, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Defaults
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if d.Catalog.Registry == "" {
		return nil, fmt.Errorf("%s: catalog.registry is required", path)
	}
	return &d, nil
}
