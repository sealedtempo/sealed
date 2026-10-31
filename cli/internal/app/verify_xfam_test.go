package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/cli/internal/embedded"
	"github.com/sealedtempo/sealed/verifier/attest"
)

// TestVerifyXFAMFromDefaults (D-077): sealed verify takes the XFAM allowlist from the defaults it runs with (the
// embedded copy of config/defaults.yaml, or --defaults), and a defaults file without tdx.allowed_xfam is refused
// rather than verified without the check.
func TestVerifyXFAMFromDefaults(t *testing.T) {
	v, err := newQuoteVerifier(embedded.DefaultsYAML, false, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.AllowedXFAM(), attest.DefaultAllowedXFAM()) {
		t.Fatalf("embedded defaults give %v", v.AllowedXFAM())
	}
	own := []byte("tcb_policy:\n  allowed_statuses: [UpToDate]\ntdx:\n  allowed_xfam: [\"0x600e7\"]\n")
	if v, err = newQuoteVerifier(own, false, t.TempDir()); err != nil || !slices.Equal(v.AllowedXFAM(), []uint64{0x600e7}) {
		t.Fatalf("--defaults list: %v %v", v, err)
	}
	none := []byte("tcb_policy:\n  allowed_statuses: [UpToDate]\n")
	if _, err := newQuoteVerifier(none, false, t.TempDir()); err == nil || !strings.Contains(err.Error(), "tdx.allowed_xfam") {
		t.Fatalf("defaults without tdx.allowed_xfam: %v", err)
	}
}
