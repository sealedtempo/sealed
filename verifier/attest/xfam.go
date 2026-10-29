package attest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ErrXFAM is returned when a quote's XFAM is not in the allowlist (D-077). The key broker answers
// measurements_mismatch for it, as for a non-zero MRCONFIGID: the TD was launched with a setting the registered
// machine shapes were never measured with.
var ErrXFAM = errors.New("xfam_not_allowed")

// DefaultAllowedXFAM matches tdx.allowed_xfam in config/defaults.yaml (D-077): the XFAM values measured on the
// registered machine shapes. 0x602e7 is what every C3 quote captured so far carries (testdata/gcp: c3-standard-4 and
// c3-standard-8): x87, SSE, AVX, AVX-512 (3 bits), PKRU and AMX TILECFG and TILEDATA.
func DefaultAllowedXFAM() []uint64 { return []uint64{0x602e7} }

// XFAMAllowlistFromDefaults reads tdx.allowed_xfam from the contents of config/defaults.yaml. Each entry is a
// 0x-prefixed hex string (the little-endian u64 value, as in DefaultAllowedXFAM). A missing or empty list is an
// error, so a defaults file can never turn the check off.
func XFAMAllowlistFromDefaults(defaultsYAML []byte) ([]uint64, error) {
	var doc struct {
		TDX *struct {
			AllowedXFAM []string `yaml:"allowed_xfam"`
		} `yaml:"tdx"`
	}
	if err := yaml.Unmarshal(defaultsYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse defaults: %w", err)
	}
	if doc.TDX == nil || len(doc.TDX.AllowedXFAM) == 0 {
		return nil, errors.New("defaults: tdx.allowed_xfam missing or empty")
	}
	out := make([]uint64, 0, len(doc.TDX.AllowedXFAM))
	for _, s := range doc.TDX.AllowedXFAM {
		h, ok := strings.CutPrefix(s, "0x")
		if !ok || h == "" {
			return nil, fmt.Errorf("defaults: tdx.allowed_xfam entry %q is not a 0x hex value", s)
		}
		v, err := strconv.ParseUint(h, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("defaults: tdx.allowed_xfam entry %q: %v", s, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// CheckXFAM refuses an XFAM (the 8 quote bytes, little-endian) that is not in allowed. XFAM is the set of extended
// CPU features the host enabled for the TD; the host chooses it at launch and no register measures it, so it is
// pinned by allowlist (D-077). An empty allowlist refuses every value.
func CheckXFAM(xfam []byte, allowed []uint64) error {
	if len(xfam) != xfamLen {
		return fmt.Errorf("%w: XFAM is %d bytes, want %d", ErrXFAM, len(xfam), xfamLen)
	}
	v := binary.LittleEndian.Uint64(xfam)
	if !slices.Contains(allowed, v) {
		return fmt.Errorf("%w: the TD was launched with XFAM %s, which is not in tdx.allowed_xfam %s (D-077)", ErrXFAM, fmtXFAM(v), fmtXFAMList(allowed))
	}
	return nil
}

// XFAMValue is XFAM as a little-endian integer.
func (q *Quote) XFAMValue() uint64 { return binary.LittleEndian.Uint64(q.XFAM[:]) }

// CheckXFAM refuses the quote's XFAM when it is not in this verifier's allowlist (VerifierOptions.AllowedXFAM).
func (v *Verifier) CheckXFAM(q *Quote) error { return CheckXFAM(q.XFAM[:], v.opts.AllowedXFAM) }

// AllowedXFAM returns a copy of this verifier's XFAM allowlist.
func (v *Verifier) AllowedXFAM() []uint64 { return slices.Clone(v.opts.AllowedXFAM) }

func fmtXFAM(v uint64) string { return "0x" + strconv.FormatUint(v, 16) }

func fmtXFAMList(vs []uint64) string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = fmtXFAM(v)
	}
	return "[" + strings.Join(s, ", ") + "]"
}
