package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func b32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	copy(out[:], b)
	return out
}

func TestReportDataVectors(t *testing.T) {
	v := loadVectors(t).ReportData
	var signer [20]byte
	sb, _ := hex.DecodeString(v["enclaveSigner"])
	copy(signer[:], sb)

	cases := map[string]ReportData{
		"keyRelease": KeyReleaseReportData(b32(t, v["nonce"]), b32(t, v["ephemeralPub"])),
		"evidence":   EvidenceReportData(b32(t, v["stackHash"]), b32(t, v["configHash"]), signer, b32(t, v["nonce2"])),
		"liveAttest": LiveAttestReportData(b32(t, v["nonce"]), b32(t, v["tlsPubKeyHash"]), signer),
	}
	for name, got := range cases {
		if hex.EncodeToString(got[:]) != v[name] {
			t.Errorf("%s = %x, want %s", name, got, v[name])
		}
		for _, b := range got[32:] {
			if b != 0 {
				t.Errorf("%s: upper 32 bytes not zero", name)
			}
		}
	}
}

func TestReportDataDomainSeparation(t *testing.T) {
	var a, b [32]byte
	var s [20]byte
	kr := KeyReleaseReportData(a, b)
	la := LiveAttestReportData(a, b, s)
	ev := EvidenceReportData(a, b, s, a)
	if kr == la || kr == ev || la == ev {
		t.Fatal("constructions collide")
	}
	// Spot check the first construction by hand.
	want := sha256.Sum256(append([]byte(TagKeyRelease), make([]byte, 64)...))
	if [32]byte(kr[:32]) != want {
		t.Fatal("key release construction")
	}
}
