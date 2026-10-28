package attest

import "crypto/sha256"

// Domain-separation tags of the three report_data constructions (INTERFACES.md section 3, D-010).
const (
	TagKeyRelease = "sealed/kb-release/v1"
	TagEvidence   = "sealed/evidence/v1"
	TagLiveAttest = "sealed/attest/v1"
)

// ReportData is the 64-byte TDX report_data field.
type ReportData [ReportDataSize]byte

func tagged(tag string, fields ...[]byte) ReportData {
	h := sha256.New()
	h.Write([]byte(tag))
	for _, f := range fields {
		h.Write(f)
	}
	var rd ReportData
	copy(rd[:32], h.Sum(nil)) // the last 32 bytes stay zero
	return rd
}

// KeyReleaseReportData is sha256("sealed/kb-release/v1" || nonce || ephemeralPub) || 32 zero bytes.
func KeyReleaseReportData(nonce, ephemeralPub [32]byte) ReportData {
	return tagged(TagKeyRelease, nonce[:], ephemeralPub[:])
}

// EvidenceReportData is sha256("sealed/evidence/v1" || stackHash || configHash || enclaveSigner || nonce2) ||
// 32 zero bytes.
func EvidenceReportData(stackHash, configHash [32]byte, enclaveSigner [20]byte, nonce2 [32]byte) ReportData {
	return tagged(TagEvidence, stackHash[:], configHash[:], enclaveSigner[:], nonce2[:])
}

// LiveAttestReportData is sha256("sealed/attest/v1" || nonce || tlsPubKeyHash || enclaveSigner) || 32 zero
// bytes, where tlsPubKeyHash = sha256(DER SubjectPublicKeyInfo of the serving TLS certificate).
func LiveAttestReportData(nonce, tlsPubKeyHash [32]byte, enclaveSigner [20]byte) ReportData {
	return tagged(TagLiveAttest, nonce[:], tlsPubKeyHash[:], enclaveSigner[:])
}
