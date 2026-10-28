package chain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/verifier/internal/anviltest"
)

// abiSignatures lists every function (with its outputs), event and error of an ABI, sorted.
func abiSignatures(t *testing.T, raw []byte) []string {
	t.Helper()
	a, err := abi.JSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range a.Methods {
		var outs []string
		for _, o := range m.Outputs {
			outs = append(outs, o.Type.String())
		}
		out = append(out, "function "+m.Sig+" returns ("+strings.Join(outs, ",")+")")
	}
	for _, e := range a.Events {
		out = append(out, "event "+e.Sig)
	}
	for _, e := range a.Errors {
		out = append(out, "error "+e.Sig)
	}
	slices.Sort(out)
	return out
}

// TestEmbeddedABIsMatchContracts fails when verifier/chain/abi drifts from the contracts' committed ABIs (refresh with
// `make -C verifier abi`). It needs the contracts tree; set SEALED_REQUIRE_ANVIL=1 to fail instead of skipping
// when it is missing.
func TestEmbeddedABIsMatchContracts(t *testing.T) {
	dir, err := anviltest.ContractsDir()
	if err != nil {
		anviltest.SkipOrFail(t, err.Error())
	}
	for _, name := range []string{"PlatformRegistry", "AppRegistry", "DeploymentRegistry"} {
		t.Run(name, func(t *testing.T) {
			upstream, err := os.ReadFile(filepath.Join(dir, "abi", name+".json"))
			if err != nil {
				anviltest.SkipOrFail(t, "contracts ABI not generated: "+err.Error())
			}
			ours, err := abiFiles.ReadFile("abi/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(upstream, ours) {
				t.Errorf("abi/%s.json is not a byte copy of contracts/abi/%s.json (make -C verifier abi)", name, name)
			}
			want, got := abiSignatures(t, upstream), abiSignatures(t, ours)
			for _, s := range want {
				if !slices.Contains(got, s) {
					t.Errorf("embedded ABI lacks %s", s)
				}
			}
			for _, s := range got {
				if !slices.Contains(want, s) {
					t.Errorf("embedded ABI has %s, which the contracts no longer have", s)
				}
			}
		})
	}
}

// TestEmbeddedMainnetDeployments: the default address source is a byte copy of
// contracts/deployments/tempo-mainnet.json, and its registry addresses are the deployed ones (D-035).
func TestEmbeddedMainnetDeployments(t *testing.T) {
	d, a := Mainnet()
	want := Addresses{
		PlatformRegistry:   common.HexToAddress("0x18AB956ea44757587896dfD25632FB3e89F7002d"),
		AppRegistry:        common.HexToAddress("0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43"),
		DeploymentRegistry: common.HexToAddress("0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E"),
		FeeSplitter:        common.HexToAddress("0x3D288c0756c3F26Da0f41257D688bAB3dB3d94AD"),
	}
	if a != want || d.ChainID != 4217 || d.Network != "tempo-mainnet" {
		t.Fatalf("embedded mainnet deployment: chain %d %q %+v", d.ChainID, d.Network, a)
	}
	// DeploymentRegistry was constructed with (owner, PlatformRegistry, AppRegistry): the file is self-consistent.
	var ctor struct {
		Contracts map[string]struct {
			ConstructorArgs string `json:"constructorArgs"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(mainnetDeployments, &ctor); err != nil {
		t.Fatal(err)
	}
	args := common.FromHex(ctor.Contracts["DeploymentRegistry"].ConstructorArgs)
	if len(args) != 96 || common.BytesToAddress(args[44:64]) != a.PlatformRegistry || common.BytesToAddress(args[76:96]) != a.AppRegistry {
		t.Fatalf("DeploymentRegistry constructor args do not name the embedded registries: %x", args)
	}
	if got, ok := DefaultAddresses(4217); !ok || got != a {
		t.Fatal("DefaultAddresses(4217)")
	}
	if _, ok := DefaultAddresses(31337); ok {
		t.Fatal("a default deployment for a chain without one")
	}

	dir, err := anviltest.ContractsDir()
	if err != nil {
		anviltest.SkipOrFail(t, err.Error())
	}
	upstream, err := os.ReadFile(filepath.Join(dir, "deployments", "tempo-mainnet.json"))
	if err != nil {
		anviltest.SkipOrFail(t, "contracts deployments file: "+err.Error())
	}
	if !bytes.Equal(upstream, mainnetDeployments) {
		t.Fatal("deployments/tempo-mainnet.json is not a byte copy of contracts/deployments/tempo-mainnet.json (make -C verifier abi)")
	}
}
