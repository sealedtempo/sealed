package attest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Offset of XFAM in a v4 quote: right after TD_ATTRIBUTES.
const v4XFAMOffset = v4TDAttributesOffset + 8

// repoXFAM is tdx.allowed_xfam of config/defaults.yaml, equal to DefaultAllowedXFAM (TestXFAMAllowlistFromRepoDefaults).
func repoXFAM(t *testing.T) []uint64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := XFAMAllowlistFromDefaults(raw)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestXFAMAllowlistFromRepoDefaults (D-077): the built-in list, which the key broker uses, is the one in
// config/defaults.yaml, and it is exactly what C3 produced on every real capture (TestRealGCPGolden and
// TestRealGCPMachineTypes check each capture against it).
func TestXFAMAllowlistFromRepoDefaults(t *testing.T) {
	if got := repoXFAM(t); !slices.Equal(got, DefaultAllowedXFAM()) {
		t.Fatalf("defaults.yaml tdx.allowed_xfam %v differs from DefaultAllowedXFAM %v", got, DefaultAllowedXFAM())
	}
	if !slices.Equal(DefaultAllowedXFAM(), []uint64{0x602e7}) {
		t.Fatalf("DefaultAllowedXFAM %v: only values measured on registered C3 shapes belong here", DefaultAllowedXFAM())
	}
	v, err := NewVerifier(VerifierOptions{Getter: offlineGetter{}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.AllowedXFAM(), DefaultAllowedXFAM()) {
		t.Fatalf("a verifier without AllowedXFAM uses %v", v.AllowedXFAM())
	}
}

func TestXFAMAllowlistFromDefaultsRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"no tdx section":  "tcb_policy:\n  allowed_statuses: [UpToDate]\n",
		"empty list":      "tdx:\n  allowed_xfam: []\n",
		"no list":         "tdx: {}\n",
		"no 0x prefix":    "tdx:\n  allowed_xfam: [\"602e7\"]\n",
		"bare 0x":         "tdx:\n  allowed_xfam: [\"0x\"]\n",
		"not hex":         "tdx:\n  allowed_xfam: [\"0x60z\"]\n",
		"over 64 bits":    "tdx:\n  allowed_xfam: [\"0x10000000000000000\"]\n",
		"not yaml":        "tdx: [\n",
		"decimal integer": "tdx:\n  allowed_xfam: [393959]\n",
	} {
		if l, err := XFAMAllowlistFromDefaults([]byte(doc)); err == nil {
			t.Errorf("%s: accepted as %v", name, l)
		}
	}
	l, err := XFAMAllowlistFromDefaults([]byte("tdx:\n  allowed_xfam: [\"0x602e7\", \"0x600e7\"]\n"))
	if err != nil || !slices.Equal(l, []uint64{0x602e7, 0x600e7}) {
		t.Fatalf("two entries: %v %v", l, err)
	}
}

// TestCheckXFAM is the kb-3 repro inverted: on the real GCP quote (dstack on c3-standard-4), every XFAM outside
// tdx.allowed_xfam is refused, including 0x600e7 from Google's COS 113 C3 quote, and the captured 0x602e7 passes.
func TestCheckXFAM(t *testing.T) {
	allowed := repoXFAM(t)
	signed := readGCPFile(t, "quote.dat")
	if got := binary.LittleEndian.Uint64(signed[v4XFAMOffset:]); got != 0x602e7 {
		t.Fatalf("offset %d holds 0x%x, not the capture's XFAM", v4XFAMOffset, got)
	}
	cos, err := ParseQuote(gceQuote(t), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		xfam uint64
		ok   bool
	}{
		{"captured C3 value", 0x602e7, true},
		{"COS 113 C3 quote (no PKRU)", cos.XFAMValue(), false},
		{"extra features (bits 8 and 15)", 0x602e7 | 1<<8 | 1<<15, false},
		{"AMX removed", 0x602e7 &^ (0x3 << 17), false},
		{"x87 and SSE only", 0x3, false},
		{"zero", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Clone(signed)
			binary.LittleEndian.PutUint64(raw[v4XFAMOffset:], tc.xfam)
			q, err := ParseQuote(raw, ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if q.XFAMValue() != tc.xfam {
				t.Fatalf("decoded 0x%x", q.XFAMValue())
			}
			err = CheckXFAM(q.XFAM[:], allowed)
			if (err == nil) != tc.ok {
				t.Fatalf("CheckXFAM(0x%x) = %v, want ok=%v", tc.xfam, err, tc.ok)
			}
			if err != nil && (!errors.Is(err, ErrXFAM) || !strings.Contains(err.Error(), "tdx.allowed_xfam [0x602e7]")) {
				t.Fatalf("error %v", err)
			}
		})
	}
	if cos.XFAMValue() != 0x600e7 {
		t.Fatalf("COS 113 fixture XFAM 0x%x, want 0x600e7", cos.XFAMValue())
	}
	if err := CheckXFAM(signed[v4XFAMOffset:v4XFAMOffset+7], allowed); !errors.Is(err, ErrXFAM) {
		t.Fatalf("7-byte XFAM: %v", err)
	}
	if err := CheckXFAM(signed[v4XFAMOffset:v4XFAMOffset+8], nil); !errors.Is(err, ErrXFAM) {
		t.Fatalf("empty allowlist accepted: %v", err)
	}

	// A verifier applies its own list.
	q, err := ParseQuote(signed, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewVerifier(VerifierOptions{Getter: offlineGetter{}, AllowedXFAM: []uint64{0x600e7}})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.CheckXFAM(q); !errors.Is(err, ErrXFAM) {
		t.Fatalf("a verifier allowing only 0x600e7 accepted 0x602e7: %v", err)
	}
	if err := other.CheckXFAM(cos); err != nil {
		t.Fatal(err)
	}
	def, _ := NewVerifier(VerifierOptions{Getter: offlineGetter{}})
	if err := def.CheckXFAM(q); err != nil {
		t.Fatal(err)
	}
}
