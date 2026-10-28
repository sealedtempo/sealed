package attest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// signedQuote returns fixture `name` cut to its signed length (some fixtures carry unsigned trailing bytes).
func signedQuote(t *testing.T, name string) []byte {
	t.Helper()
	raw := readQuote(t, name)
	p, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw[:len(raw)-len(extraBytes(p))]
}

// gceQuote is the real GCE C3 quote without the zero padding of its 8000-byte buffer.
func gceQuote(t *testing.T) []byte {
	t.Helper()
	q, err := TrimQuote(readQuote(t, "v4_gce_cos113"))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// Offset of TD_ATTRIBUTES in a v4 quote: header(48) + tee_tcb_svn(16) + mrseam(48) + mrsignerseam(48) +
// seam_attributes(8).
const v4TDAttributesOffset = 48 + 16 + 48 + 48 + 8

func TestParseRealQuotes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    uint32
		production bool // TD_ATTRIBUTES of a production Linux TD
	}{
		{"v4_spr_e4", 4, false}, // PKS without SEPT_VE_DISABLE
		{"v5_sample", 5, true},
		{"v4_gce_cos113", 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := signedQuote(t, tc.name)
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
			var mrtd, rd, attrs, xfam []byte
			var rtmrs [][]byte
			switch v := p.(type) {
			case *pb.QuoteV4:
				b := v.GetTdQuoteBody()
				mrtd, rd, attrs, xfam, rtmrs = b.GetMrTd(), b.GetReportData(), b.GetTdAttributes(), b.GetXfam(), b.GetRtmrs()
			case *pb.QuoteV5:
				b := v.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
				mrtd, rd, attrs, xfam, rtmrs = b.GetMrTd(), b.GetReportData(), b.GetTdAttributes(), b.GetXfam(), b.GetRtmrs()
			}
			if !bytes.Equal(q.MRTD[:], mrtd) || !bytes.Equal(q.ReportData[:], rd) || !bytes.Equal(q.TDAttributes[:], attrs) || !bytes.Equal(q.XFAM[:], xfam) {
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
			if err := q.CheckProductionAttributes(); (err == nil) != tc.production {
				t.Fatalf("CheckProductionAttributes = %v, want production=%v", err, tc.production)
			}
		})
	}
}

func TestParseRejectsTrailingBytes(t *testing.T) {
	// The fixtures as captured: v4_spr_e4 carries 39 non-zero unsigned bytes, the GCE quote 3065 bytes of zeros.
	for _, name := range []string{"v4_spr_e4", "v4_gce_cos113"} {
		if _, err := ParseQuote(readQuote(t, name), ParseOptions{}); !errors.Is(err, ErrQuoteInvalid) || !strings.Contains(err.Error(), "unsigned bytes") {
			t.Fatalf("%s with trailing bytes: %v", name, err)
		}
	}
	signed := signedQuote(t, "v5_sample")
	for name, tail := range map[string][]byte{
		"junk":         []byte("appended bytes change the sha256"),
		"zero padding": make([]byte, 64),
		"one byte":     {0},
	} {
		t.Run(name, func(t *testing.T) {
			raw := append(bytes.Clone(signed), tail...)
			if _, err := ParseQuote(raw, ParseOptions{}); !errors.Is(err, ErrQuoteInvalid) {
				t.Fatalf("quote with %d trailing bytes accepted: %v", len(tail), err)
			}
			trimmed, err := TrimQuote(raw)
			if allZero(tail) {
				if err != nil || !bytes.Equal(trimmed, signed) {
					t.Fatalf("TrimQuote: %v", err)
				}
			} else if !errors.Is(err, ErrQuoteInvalid) {
				t.Fatalf("TrimQuote removed non-zero bytes: %v", err)
			}
		})
	}
	if out, err := TrimQuote(signed); err != nil || !bytes.Equal(out, signed) {
		t.Fatalf("TrimQuote of a signed quote: %v", err)
	}
	if _, err := TrimQuote([]byte("short")); !errors.Is(err, ErrQuoteInvalid) {
		t.Fatalf("TrimQuote of garbage: %v", err)
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

func TestTDAttributes(t *testing.T) {
	base := gceQuote(t) // 0x10000000: SEPT_VE_DISABLE only
	for _, tc := range []struct {
		name  string
		attrs uint64
		ok    bool
	}{
		{"gce production", tdAttrSeptVEDisable, true},
		{"with optional features", tdAttrSeptVEDisable | tdAttrPKS | tdAttrKL | tdAttrLASS | tdAttrPerfmon, true},
		{"debug", tdAttrSeptVEDisable | tdAttrDebug, false},
		{"reserved TUD bit", tdAttrSeptVEDisable | 1<<3, false},
		{"migratable", tdAttrSeptVEDisable | tdAttrMigratable, false},
		{"SEPT_VE_DISABLE cleared", 0, false},
		{"reserved SEC bit", tdAttrSeptVEDisable | 1<<12, false},
		{"reserved OTHER bit", tdAttrSeptVEDisable | 1<<40, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Clone(base)
			binary.LittleEndian.PutUint64(raw[v4TDAttributesOffset:], tc.attrs)
			q, err := ParseQuote(raw, ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if q.TDAttributesValue() != tc.attrs || q.Debug() != (tc.attrs&tdAttrDebug != 0) || q.Migratable() != (tc.attrs&tdAttrMigratable != 0) {
				t.Fatalf("decoded 0x%x", q.TDAttributesValue())
			}
			err = q.CheckProductionAttributes()
			if (err == nil) != tc.ok {
				t.Fatalf("CheckProductionAttributes(0x%x) = %v, want ok=%v", tc.attrs, err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrTDAttributes) {
				t.Fatalf("error %v does not wrap ErrTDAttributes", err)
			}
		})
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
