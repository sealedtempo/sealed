// Package embedded holds copies of the repository files the sealed binary needs at run time: the platform defaults,
// the mainnet deployment addresses, the registry ABIs and the customer bootstrap Terraform module. The copies keep
// the CLI a single binary that works outside a checkout; drift_test.go fails when a copy differs from its source
// (run `go generate ./cli/internal/embedded`).
package embedded

import (
	"embed"
	"io/fs"
)

//go:generate ./sync.sh

// DefaultsYAML is config/defaults.yaml.
//
//go:embed defaults.yaml
var DefaultsYAML []byte

// MainnetDeployments is contracts/deployments/tempo-mainnet.json.
//
//go:embed tempo-mainnet.json
var MainnetDeployments []byte

//go:embed abi/*.json
var abiFiles embed.FS

//go:embed all:tfmodule
var tfModule embed.FS

// ABI returns contracts/abi/<name>.json (PlatformRegistry, AppRegistry or DeploymentRegistry).
func ABI(name string) ([]byte, error) { return abiFiles.ReadFile("abi/" + name + ".json") }

// BootstrapModule is infra/terraform/customer-bootstrap rooted at the module directory.
func BootstrapModule() fs.FS {
	sub, err := fs.Sub(tfModule, "tfmodule")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}
