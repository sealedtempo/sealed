package verify_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
)

// gcpQuoteXFAMOffset is XFAM in the real v4 quote: header (48), TEE_TCB_SVN, MRSEAM, MRSIGNERSEAM, SEAMATTRIBUTES and
// TDATTRIBUTES.
const gcpQuoteXFAMOffset = 48 + 16 + 48 + 48 + 8 + 8

// recordedGCPVerifier verifies the runtime spike's real quote (dstack on c3-standard-4) offline, against the Intel
// collateral recorded with it, at the recording time.
func recordedGCPVerifier(t *testing.T, allowed []uint64) *attest.Verifier {
	t.Helper()
	dir := filepath.Join("attest", "testdata", "gcp", "pcs")
	raw, err := os.ReadFile(filepath.Join(dir, "recorded.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		RecordedAt int64 `json:"recordedAt"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(meta.RecordedAt, 0)
	now := func() time.Time { return at }
	g, err := attest.NewCachingGetter(attest.CacheOptions{Dir: dir, TTL: 100 * 365 * 24 * time.Hour, Inner: offline{}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewVerifier(attest.VerifierOptions{Getter: g, Now: now, AllowedXFAM: allowed})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func gcpQuote(t *testing.T, xfam *uint64) []byte {
	t.Helper()
	q, err := os.ReadFile(filepath.Join("attest", "testdata", "gcp", "quote.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(q[gcpQuoteXFAMOffset:]); got != 0x602e7 {
		t.Fatalf("quote.dat XFAM 0x%x at offset %d, want the captured 0x602e7", got, gcpQuoteXFAMOffset)
	}
	if xfam != nil {
		q = bytes.Clone(q)
		binary.LittleEndian.PutUint64(q[gcpQuoteXFAMOffset:], *xfam)
	}
	return q
}

// TestTDAttributesPinsXFAM (kb-3, D-077): the verifier's td_attributes check refuses a quote whose XFAM is not in
// tdx.allowed_xfam, even when the quote itself verifies, and passes the real C3 capture.
func TestTDAttributesPinsXFAM(t *testing.T) {
	run := func(t *testing.T, v *attest.Verifier, quote []byte) *verify.Report {
		t.Helper()
		e := newEnv(t, false)
		e.deps.Quotes = v
		e.opts.AcceptSimulated = false
		e.b.Quote = hexb.Enc(quote)
		return e.run(t)
	}
	tdCheck := func(t *testing.T, rep *verify.Report) verify.Check {
		t.Helper()
		c := rep.Check(verify.CheckTDAttributes)
		if c == nil {
			t.Fatal("no td_attributes check in the report")
		}
		return *c
	}

	t.Run("captured C3 XFAM passes", func(t *testing.T) {
		rep := run(t, recordedGCPVerifier(t, nil), gcpQuote(t, nil))
		if q := rep.Check(verify.CheckQuote); q == nil || !q.OK {
			t.Fatalf("real quote does not verify: %+v", q)
		}
		c := tdCheck(t, rep)
		if !c.OK || c.Data["xfam"] != "0xe702060000000000" || !slices.Equal(c.Data["allowedXfam"].([]string), []string{"0x602e7"}) {
			t.Fatalf("td_attributes %+v", c)
		}
	})
	t.Run("a verified quote with an XFAM outside the list is refused", func(t *testing.T) {
		rep := run(t, recordedGCPVerifier(t, []uint64{0x600e7}), gcpQuote(t, nil))
		if q := rep.Check(verify.CheckQuote); q == nil || !q.OK {
			t.Fatalf("real quote does not verify: %+v", q)
		}
		if c := tdCheck(t, rep); c.OK || !strings.Contains(c.Detail, "XFAM 0x602e7, which is not in tdx.allowed_xfam [0x600e7]") || rep.OK {
			t.Fatalf("td_attributes %+v, report ok %v", c, rep.OK)
		}
	})
	for _, x := range []uint64{0x600e7, 0x602e7 | 1<<8 | 1<<15, 0x602e7 &^ (0x3 << 17), 0x3} {
		t.Run(fmt.Sprintf("byte flip to 0x%x", x), func(t *testing.T) {
			rep := run(t, recordedGCPVerifier(t, nil), gcpQuote(t, &x))
			if c := tdCheck(t, rep); c.OK || !strings.Contains(c.Detail, "xfam_not_allowed") || !strings.Contains(c.Detail, "tdx.allowed_xfam [0x602e7]") {
				t.Fatalf("XFAM 0x%x: td_attributes %+v", x, c)
			}
			if q := rep.Check(verify.CheckQuote); q == nil || q.OK {
				t.Fatalf("XFAM 0x%x: the modified quote verified", x)
			}
		})
	}
	t.Run("simulated quote", func(t *testing.T) {
		e := newEnv(t, false)
		rep := e.run(t)
		if c := tdCheck(t, rep); !c.OK || !rep.OK {
			t.Fatalf("simulated dev evidence: td_attributes %+v, ok %v", c, rep.OK)
		}
	})
}
