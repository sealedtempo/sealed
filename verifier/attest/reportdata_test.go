package attest

import (
	"crypto/sha256"
	"encoding/binary"
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
	raw := loadVectors(t).ReportData
	v := map[string]string{}
	for k, x := range raw {
		if s, ok := x.(string); ok {
			v[k] = s
		}
	}
	attestedAt, ok := raw["attestedAt"].(float64)
	if !ok || attestedAt != 1793000000 {
		t.Fatalf("vectors: attestedAt %v", raw["attestedAt"])
	}
	var signer [20]byte
	sb, _ := hex.DecodeString(v["enclaveSigner"])
	copy(signer[:], sb)

	cases := map[string]ReportData{
		"keyRelease": KeyReleaseReportData(b32(t, v["nonce"]), b32(t, v["ephemeralPub"])),
		"evidence":   EvidenceReportData(b32(t, v["stackHash"]), b32(t, v["configHash"]), signer, b32(t, v["nonce2"]), uint64(attestedAt)),
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
	ev := EvidenceReportData(a, b, s, a, 0)
	if kr == la || kr == ev || la == ev {
		t.Fatal("constructions collide")
	}
	// Spot check the first construction by hand.
	want := sha256.Sum256(append([]byte(TagKeyRelease), make([]byte, 64)...))
	if [32]byte(kr[:32]) != want {
		t.Fatal("key release construction")
	}
}

// TestEvidenceReportDataBindsAttestedAt (D-047): the evidence construction ends with uint64be(attestedAt), so the
// same quote cannot be presented with another attestedAt.
func TestEvidenceReportDataBindsAttestedAt(t *testing.T) {
	stack, cfg, nonce2 := [32]byte{0xaa}, [32]byte{0xbb}, [32]byte{0xdd}
	signer := [20]byte{0xcc}
	const at = uint64(1793000000)
	got := EvidenceReportData(stack, cfg, signer, nonce2, at)
	msg := []byte(TagEvidence)
	for _, f := range [][]byte{stack[:], cfg[:], signer[:], nonce2[:], binary.BigEndian.AppendUint64(nil, at)} {
		msg = append(msg, f...)
	}
	if want := sha256.Sum256(msg); [32]byte(got[:32]) != want || len(msg) != len(TagEvidence)+32+32+20+32+8 {
		t.Fatal("evidence construction is not tag || stackHash || configHash || enclaveSigner || nonce2 || uint64be(attestedAt)")
	}
	for _, other := range []uint64{0, at - 1, at + 1, at << 8} {
		if EvidenceReportData(stack, cfg, signer, nonce2, other) == got {
			t.Fatalf("attestedAt %d gives the same report_data as %d", other, at)
		}
	}
}
