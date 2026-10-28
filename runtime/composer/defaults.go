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

// Per-app internal networks (D-041). App number n (1..MaxConfigApps, in the
// config's sorted app order) gets network app-<appId>, subnet 172.30.<n>.0/24,
// gateway .1. sealed-egress is .2 and sealed-agent .3 on every app network;
// the app's services get .16 upwards (primary first, then name order). Only
// the primary service also joins the shared apps network.
const (
	AppNetworkPrefix = "app-"
	appNetEgressHost = 2
	appNetAgentHost  = 3
)

// AppSubnet is the subnet of app number n (1-based).
func AppSubnet(n int) string { return fmt.Sprintf("172.30.%d.0/24", n) }

// appNetIP is host h on app network n.
func appNetIP(n, h int) string { return fmt.Sprintf("172.30.%d.%d", n, h) }

// AppNetwork is the compose network name of an app.
func AppNetwork(appID string) string { return AppNetworkPrefix + appID }

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
