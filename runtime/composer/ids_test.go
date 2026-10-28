package composer

import (
	"bytes"
	"strings"
	"testing"
)

func h(s string) Hash {
	v, err := ParseHash(s)
	if err != nil {
		panic(err)
	}
	return v
}

func rep(b string, n int) string { return "0x" + strings.Repeat(b, n) }

// Golden values computed with Foundry cast 1.7.1 (cast keccak / cast abi-encode).
func TestIDsMatchSolidityABI(t *testing.T) {
	if got := AppID("llm-gateway").Hex(); got != "0x75628f63cb267b5e13ef7a1e5091b3377e14d68e3d4e2d8a0cbfbe92de419ef9" {
		t.Errorf("appId %s", got)
	}
	if got := ReleaseID(h(rep("11", 32)), "1.2.3", h(rep("22", 32))).Hex(); got != "0x3e30a27672ffdfe343c733823bb78c6778a45350031af5eb96d030e582ca716b" {
		t.Errorf("releaseId %s", got)
	}
	long := "a-much-longer-version-string-that-spans-more-than-32-bytes+build.7"
	if got := ReleaseID(h(rep("11", 32)), long, h(rep("22", 32))).Hex(); got != "0xe4ea53dd89cfc65ff3c0466007161be72d9de61c9c85ac34178763f420c8833d" {
		t.Errorf("releaseId long %s", got)
	}
	cust, _ := ParseAddress("0x00000000000000000000000000000000000000aa")
	if got := DeploymentID(cust, h(rep("33", 32)), h(rep("44", 32))).Hex(); got != "0x265a552a1a094cccfa07292f1bfed013cc01ec3b5e287e797010113c8d831501" {
		t.Errorf("deploymentId %s", got)
	}
	if got := ImageID("sealed-sim", "0.6.1", h(rep("55", 32))).Hex(); got != "0x536fa84b29b9c0bc866d5dcdf69de93caf02eed551642a70850b3b3c6d866e6a" {
		t.Errorf("imageId %s", got)
	}
	mh, err := MeasurementsHash(bytes.Repeat([]byte{0x11}, 48), bytes.Repeat([]byte{0x22}, 48), bytes.Repeat([]byte{0x33}, 48), bytes.Repeat([]byte{0x44}, 48))
	if err != nil || mh.Hex() != "0xea88d19f83c91226f30db083cc8c6b4c6e15feb4f9217fbe5775724c0c9cfbfe" {
		t.Errorf("measurementsHash %s %v", mh.Hex(), err)
	}
	if _, err := MeasurementsHash([]byte{1}, nil, nil, nil); err == nil {
		t.Error("short measurement must fail")
	}
}

func TestParseHexValues(t *testing.T) {
	for _, bad := range []string{"", "0x", "0X" + strings.Repeat("a", 64), "0x" + strings.Repeat("A", 64), "0x" + strings.Repeat("a", 63)} {
		if _, err := ParseHash(bad); err == nil {
			t.Errorf("ParseHash(%q) should fail", bad)
		}
	}
	if _, err := ParseAddress("0x00000000000000000000000000000000000000AA"); err == nil {
		t.Error("checksummed address must be rejected")
	}
	var hh Hash
	if err := hh.UnmarshalText([]byte(rep("ab", 32))); err != nil || hh.Hex() != rep("ab", 32) {
		t.Fatal(err)
	}
}
