package keybroker_test

import (
	"context"
	"encoding/binary"
	"net/http"
	"slices"
	"strings"
	"testing"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/kbtest"
	"github.com/sealedtempo/sealed/verifier/attest"
)

// hostXFAMVerifier stands in for Intel: it accepts the attempt's simulated quote and answers with a hardware quote
// (Intel's v5 sample, with the XFAM this test chooses) that carries the attempt's measurements, RTMR3 and
// report_data. That is a quote Intel would sign for a TD the host launched with other CPU features: only XFAM differs
// from a quote the broker releases to.
type hostXFAMVerifier struct {
	t    testing.TB
	xfam uint64
}

func (v hostXFAMVerifier) VerifyQuote(_ context.Context, raw []byte) (*attest.QuoteResult, error) {
	sim, err := attest.ParseQuote(raw, attest.ParseOptions{AllowSimulated: true})
	if err != nil {
		return nil, err
	}
	hw, err := attest.TrimQuote(readTDXQuote(v.t, "v5_sample"))
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(hw[48+6+16+48+48+8+8:], v.xfam) // v5: header, body descriptor, then XFAM at 128
	q, err := attest.ParseQuote(hw, attest.ParseOptions{})
	if err != nil {
		return nil, err
	}
	if q.XFAMValue() != v.xfam {
		v.t.Fatalf("XFAM offset: decoded 0x%x", q.XFAMValue())
	}
	q.MRTD, q.RTMR, q.ReportData = sim.MRTD, sim.RTMR, sim.ReportData
	return &attest.QuoteResult{Quote: q, TCBStatus: "UpToDate", PlatformTCBStatus: "UpToDate", QETCBStatus: "UpToDate"}, nil
}

// TestReleaseRefusesXFAMOutsideAllowlist (kb-3, D-077): a hardware quote whose XFAM is not in tdx.allowed_xfam gets
// measurements_mismatch at the image check, the captured C3 value 0x602e7 is released to, and a broker configured with
// its own list applies that list.
func TestReleaseRefusesXFAMOutsideAllowlist(t *testing.T) {
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	s := w.Compose(t, kbtest.StackOptions{})
	w.Approve(t, s)

	for _, x := range []uint64{0x600e7, 0x602e7 | 1<<8 | 1<<15, 0x602e7 &^ (0x3 << 17), 0x3} {
		h := newHarness(t, w, harnessOpts{quotes: hostXFAMVerifier{t, x}, disallowSim: true})
		out := h.release(t, h.attempt(t, s))
		d := expectDenied(t, out, http.StatusForbidden, keybroker.ReasonMeasurementsMismatch)
		if !strings.Contains(d.Detail, "tdx.allowed_xfam [0x602e7]") || out.Decision.Simulated {
			t.Fatalf("XFAM 0x%x: %s (simulated %v)", x, d.Detail, out.Decision.Simulated)
		}
		last := out.Decision.Checks[len(out.Decision.Checks)-1]
		if last.Name != keybroker.CheckImage {
			t.Fatalf("XFAM 0x%x refused by %s, want %s", x, last.Name, keybroker.CheckImage)
		}
	}

	h := newHarness(t, w, harnessOpts{quotes: hostXFAMVerifier{t, 0x602e7}, disallowSim: true})
	if got := h.b.Config().AllowedXFAM; !slices.Equal(got, attest.DefaultAllowedXFAM()) {
		t.Fatalf("default AllowedXFAM %v", got)
	}
	a := h.attempt(t, s)
	expectAllowed(t, h.release(t, a), a)

	own := func(c *keybroker.Config) { c.AllowedXFAM = []uint64{0x600e7} }
	h = newHarness(t, w, harnessOpts{quotes: hostXFAMVerifier{t, 0x602e7}, disallowSim: true, edit: own})
	expectDenied(t, h.release(t, h.attempt(t, s)), http.StatusForbidden, keybroker.ReasonMeasurementsMismatch)
	h = newHarness(t, w, harnessOpts{quotes: hostXFAMVerifier{t, 0x600e7}, disallowSim: true, edit: own})
	a = h.attempt(t, s)
	expectAllowed(t, h.release(t, a), a)
}
