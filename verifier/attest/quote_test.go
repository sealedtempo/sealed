package attest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

func readQuote(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "quotes", name+".dat"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Offset of TD_ATTRIBUTES in a v4 quote: header(48) + tee_tcb_svn(16) + mrseam(48) + mrsignerseam(48) +
// seam_attributes(8).
const v4TDAttributesOffset = 48 + 16 + 48 + 48 + 8

func TestParseRealQuotes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint32
	}{
		{"v4_spr_e4", 4},
		{"v5_sample", 5},
		{"v4_gce_cos113", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readQuote(t, tc.name)
			q, err := ParseQuote(raw, ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if q.Version != tc.version || q.Simulated {
				t.Fatalf("version %d simulated %v", q.Version, q.Simulated)
			}
			// Cross-check our extractor against go-tdx-guest's own proto fields.
			p, err := abi.QuoteToProto(raw)
			if err != nil {
				t.Fatal(err)
			}
			var mrtd, rd, attrs []byte
			var rtmrs [][]byte
			switch v := p.(type) {
			case *pb.QuoteV4:
				b := v.GetTdQuoteBody()
				mrtd, rd, attrs, rtmrs = b.GetMrTd(), b.GetReportData(), b.GetTdAttributes(), b.GetRtmrs()
			case *pb.QuoteV5:
				b := v.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
				mrtd, rd, attrs, rtmrs = b.GetMrTd(), b.GetReportData(), b.GetTdAttributes(), b.GetRtmrs()
			}
			if !bytes.Equal(q.MRTD[:], mrtd) || !bytes.Equal(q.ReportData[:], rd) || !bytes.Equal(q.TDAttributes[:], attrs) {
				t.Fatal("extracted fields differ from go-tdx-guest")
			}
			for i := range rtmrs {
				if !bytes.Equal(q.RTMR[i][:], rtmrs[i]) {
					t.Fatalf("rtmr%d differs", i)
				}
			}
			want := crypto.Keccak256(q.MRTD[:], q.RTMR[0][:], q.RTMR[1][:], q.RTMR[2][:])
			if got := q.MeasurementsHash(); !bytes.Equal(got[:], want) {
				t.Fatal("measurementsHash mismatch")
			}
			if q.Debug() {
				t.Fatal("fixture quote unexpectedly has DEBUG set")
			}
			if err := q.CheckProductionAttributes(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	raw := readQuote(t, "v4_spr_e4")
	badVersion := bytes.Clone(raw)
	binary.LittleEndian.PutUint16(badVersion[0:2], 3)
	badTee := bytes.Clone(raw)
	binary.LittleEndian.PutUint32(badTee[4:8], 0) // SGX
	for name, in := range map[string][]byte{
		"empty":       nil,
		"short":       raw[:20],
		"truncated":   raw[:len(raw)/2],
		"version 3":   badVersion,
		"tee not TDX": badTee,
		"garbage":     bytes.Repeat([]byte{0xab}, 1200),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseQuote(in, ParseOptions{AllowSimulated: true}); !errors.Is(err, ErrQuoteInvalid) {
				t.Fatalf("err = %v, want ErrQuoteInvalid", err)
			}
		})
	}
}

func TestDebugAttribute(t *testing.T) {
	raw := bytes.Clone(readQuote(t, "v4_spr_e4"))
	raw[v4TDAttributesOffset] |= 0x01
	q, err := ParseQuote(raw, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Debug() {
		t.Fatal("Debug() = false")
	}
	if err := q.CheckProductionAttributes(); !errors.Is(err, ErrTDAttributes) {
		t.Fatalf("err = %v", err)
	}
	raw[v4TDAttributesOffset] &^= 0x01
	raw[v4TDAttributesOffset+3] |= 0x20 // bit 29: MIGRATABLE
	q, err = ParseQuote(raw, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Migratable() || q.CheckProductionAttributes() == nil {
		t.Fatal("migratable TD accepted")
	}
}

func TestMeasurementsHashVector(t *testing.T) {
	// Same value contracts/script/local-e2e.sh computes with cast for 0x11/0x22/0x33/0x44 measurements.
	got := SimMeasurementsHash(false)
	want := crypto.Keccak256(bytes.Repeat([]byte{0x11}, 48), bytes.Repeat([]byte{0x22}, 48),
		bytes.Repeat([]byte{0x33}, 48), bytes.Repeat([]byte{0x44}, 48))
	if !bytes.Equal(got[:], want) {
		t.Fatalf("got %x want %x", got, want)
	}
	if SimMeasurementsHash(true) == got {
		t.Fatal("debug image must have a different measurementsHash")
	}
}
