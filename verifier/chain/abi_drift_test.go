package chain

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"

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
