// Package attest parses and verifies Intel TDX quotes, replays the dstack RTMR3 event log and builds the Sealed
// report_data constructions (INTERFACES.md sections 3, 6 and 15).
package attest

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Sizes of the TD report fields we extract.
const (
	MeasurementSize = 48
	ReportDataSize  = 64
	tdAttributesLen = 8
	xfamLen         = 8
	teeTcbSvnLen    = 16
)

// TD_ATTRIBUTES bits (little-endian uint64, Intel TDX module ABI).
const (
	tdAttrDebug         = uint64(1) << 0
	tdAttrTUD           = uint64(0xff) // TD under debug: DEBUG and bits 1-7, reserved for future debug features
	tdAttrLASS          = uint64(1) << 27
	tdAttrSeptVEDisable = uint64(1) << 28
	tdAttrMigratable    = uint64(1) << 29
	tdAttrPKS           = uint64(1) << 30
	tdAttrKL            = uint64(1) << 31
	tdAttrPerfmon       = uint64(1) << 63
	// tdAttrOptional are feature bits a production TD may have; every other bit outside TUD is reserved.
	tdAttrOptional = tdAttrLASS | tdAttrPKS | tdAttrKL | tdAttrPerfmon
)

// Errors that callers map to reason codes (INTERFACES.md section 9). Every error returned by this package wraps
// exactly one of them.
var (
	ErrQuoteInvalid        = errors.New("quote_invalid")
	ErrTCBStatus           = errors.New("tcb_status")
	ErrSimulatedNotAllowed = fmt.Errorf("%w: simulated quote not allowed", ErrQuoteInvalid)
	ErrRTMR3Replay         = errors.New("rtmr3_replay")
)

// Measurement is one 48-byte TDX measurement register.
type Measurement [MeasurementSize]byte

// Quote is a parsed TDX quote (v4 or v5) or a dev simulator quote.
type Quote struct {
	Raw          []byte
	Version      uint32 // 4 or 5; 0 for simulated quotes
	Simulated    bool
	MRTD         Measurement
	RTMR         [4]Measurement
	ReportData   ReportData
	TDAttributes [tdAttributesLen]byte
	// XFAM is the extended features the host enabled for the TD; like TD_ATTRIBUTES it is not in MRTD or RTMR0-2.
	XFAM      [xfamLen]byte
	TeeTcbSvn [teeTcbSvnLen]byte

	proto any // *pb.QuoteV4 or *pb.QuoteV5; nil when simulated
}

// ParseOptions control which quote formats ParseQuote accepts.
type ParseOptions struct {
	// AllowSimulated accepts the dev simulator format (INTERFACES.md section 15). Production builds never set it.
	AllowSimulated bool
}

// ParseQuote parses raw quote bytes. Simulated quotes are rejected unless opts.AllowSimulated is set.
//
// raw must be exactly the signed quote: header, body and signature data. Bytes after the signature data are covered
// by no signature, so accepting them would let anyone derive new quoteHash values from one real quote; producers
// strip padding with TrimQuote. For the same reason the PCK certificate chain must be in canonical PEM form
// (checkCertChainEncoding). What stays malleable is ECDSA itself: the quote signature and the QE report signature
// each also verify as (r, n-s), so one attestation has up to four encodings and quoteHash does not name it uniquely.
// Freshness rests on report_data (nonces, attestedAt), never on quoteHash.
func ParseQuote(raw []byte, opts ParseOptions) (*Quote, error) {
	if IsSimulatedQuote(raw) {
		if !opts.AllowSimulated {
			return nil, ErrSimulatedNotAllowed
		}
		return parseSimQuote(raw)
	}
	p, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	if err := abi.CheckQuote(p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	if extra := extraBytes(p); len(extra) > 0 {
		kind := "non-zero"
		if allZero(extra) {
			kind = "zero padding"
		}
		return nil, fmt.Errorf("%w: %d unsigned bytes (%s) after the signature data; send exactly the signed quote", ErrQuoteInvalid, len(extra), kind)
	}
	if err := checkCertChainEncoding(p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	q := &Quote{Raw: bytes.Clone(raw), proto: p}
	if err := q.extract(p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	return q, nil
}

// checkCertChainEncoding requires the PCK certificate chain of the signature data to be exactly the PEM encoding
// pem.Encode gives its certificates (64-column base64, LF line ends, no headers), optionally followed by the one NUL
// byte some quote generation libraries write. Only the decoded certificates are authenticated, through the chain to
// the Intel SGX Root CA: PEM decoding skips spaces, tabs and CRs in the base64 and ignores padding bits, so without
// this check anyone could rewrite one real quote into many byte strings that verify (fuzz finding, FuzzVerifyQuote).
// Every captured quote (GCE C3 on three machine shapes, the Intel and go-tdx-guest samples) is canonical.
func checkCertChainEncoding(p any) error {
	s, ok := p.(interface {
		GetSignedData() *pb.Ecdsa256BitQuoteV4AuthData
	})
	if !ok {
		return fmt.Errorf("unsupported quote type %T", p)
	}
	chain := s.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
	var canon []byte
	rest := chain
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		canon = append(canon, pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: blk.Bytes})...)
		rest = r
	}
	if len(canon) == 0 {
		return errors.New("the signature data carries no PEM PCK certificate chain")
	}
	if len(rest) == 1 && rest[0] == 0 {
		canon = append(canon, 0)
	}
	if !bytes.Equal(canon, chain) {
		return errors.New("the PCK certificate chain is not in canonical PEM form; send the quote exactly as it was generated")
	}
	return nil
}

func extraBytes(p any) []byte {
	if v, ok := p.(interface{ GetExtraBytes() []byte }); ok {
		return v.GetExtraBytes()
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// TrimQuote returns raw without the zero padding some quote generation interfaces append after the signature data
// (a fixed-size buffer). It refuses non-zero trailing bytes. Simulated quotes are returned unchanged.
func TrimQuote(raw []byte) ([]byte, error) {
	if IsSimulatedQuote(raw) {
		return raw, nil
	}
	p, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	extra := extraBytes(p)
	if !allZero(extra) {
		return nil, fmt.Errorf("%w: %d trailing bytes after the signature data are not zero padding", ErrQuoteInvalid, len(extra))
	}
	return raw[:len(raw)-len(extra)], nil
}

// tdBody is the subset of the v4 and v5 TD quote bodies we read. go-tdx-guest's rtmr helpers only accept v4,
// so we extract the fields ourselves.
type tdBody interface {
	GetMrTd() []byte
	GetRtmrs() [][]byte
	GetReportData() []byte
	GetTdAttributes() []byte
	GetXfam() []byte
	GetTeeTcbSvn() []byte
}

func (q *Quote) extract(p any) error {
	var body tdBody
	switch v := p.(type) {
	case *pb.QuoteV4:
		q.Version = abi.QuoteVersionV4
		body = v.GetTdQuoteBody()
	case *pb.QuoteV5:
		q.Version = abi.QuoteVersionV5
		body = v.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
	default:
		return fmt.Errorf("unsupported quote type %T", p)
	}
	if v, ok := p.(interface{ GetHeader() *pb.Header }); ok && v.GetHeader().GetTeeType() != abi.TeeTDX {
		return fmt.Errorf("not a TDX quote (tee type 0x%x)", v.GetHeader().GetTeeType())
	}
	if err := copyExact(q.MRTD[:], body.GetMrTd(), "mrtd"); err != nil {
		return err
	}
	rtmrs := body.GetRtmrs()
	if len(rtmrs) != len(q.RTMR) {
		return fmt.Errorf("want 4 rtmrs, got %d", len(rtmrs))
	}
	for i, r := range rtmrs {
		if err := copyExact(q.RTMR[i][:], r, fmt.Sprintf("rtmr%d", i)); err != nil {
			return err
		}
	}
	if err := copyExact(q.ReportData[:], body.GetReportData(), "report_data"); err != nil {
		return err
	}
	if err := copyExact(q.TDAttributes[:], body.GetTdAttributes(), "td_attributes"); err != nil {
		return err
	}
	if err := copyExact(q.XFAM[:], body.GetXfam(), "xfam"); err != nil {
		return err
	}
	return copyExact(q.TeeTcbSvn[:], body.GetTeeTcbSvn(), "tee_tcb_svn")
}

func copyExact(dst, src []byte, name string) error {
	if len(src) != len(dst) {
		return fmt.Errorf("%s: want %d bytes, got %d", name, len(dst), len(src))
	}
	copy(dst, src)
	return nil
}

func (q *Quote) tdAttributes() uint64 { return binary.LittleEndian.Uint64(q.TDAttributes[:]) }

// TDAttributesValue is TD_ATTRIBUTES as a little-endian integer.
func (q *Quote) TDAttributesValue() uint64 { return q.tdAttributes() }

// Debug reports TD_ATTRIBUTES.DEBUG (bit 0). A debug TD can be inspected by the host.
func (q *Quote) Debug() bool { return q.tdAttributes()&tdAttrDebug != 0 }

// Migratable reports TD_ATTRIBUTES.MIGRATABLE (bit 29).
func (q *Quote) Migratable() bool { return q.tdAttributes()&tdAttrMigratable != 0 }

// MeasurementsHash is keccak256(mrtd || rtmr0 || rtmr1 || rtmr2), as stored in PlatformRegistry.
func (q *Quote) MeasurementsHash() [32]byte {
	return MeasurementsHash(q.MRTD, q.RTMR[0], q.RTMR[1], q.RTMR[2])
}

// MeasurementsHash is keccak256(mrtd || rtmr0 || rtmr1 || rtmr2), each exactly 48 bytes (INTERFACES.md section 2).
func MeasurementsHash(mrtd, rtmr0, rtmr1, rtmr2 Measurement) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(mrtd[:], rtmr0[:], rtmr1[:], rtmr2[:]))
	return out
}
