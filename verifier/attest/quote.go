// Package attest parses and verifies Intel TDX quotes, replays the dstack RTMR3 event log and builds the Sealed
// report_data constructions (INTERFACES.md sections 3, 6 and 15).
package attest

import (
	"bytes"
	"encoding/binary"
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
	teeTcbSvnLen    = 16
)

// TD_ATTRIBUTES bits (little-endian uint64).
const (
	tdAttrDebug      = uint64(1) << 0
	tdAttrMigratable = uint64(1) << 29
)

// Errors that callers map to reason codes (INTERFACES.md section 9). Every error returned by this package wraps
// exactly one of them.
var (
	ErrQuoteInvalid        = errors.New("quote_invalid")
	ErrTCBStatus           = errors.New("tcb_status")
	ErrSimulatedNotAllowed = errors.New("quote_invalid: simulated quote not allowed")
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
	TeeTcbSvn    [teeTcbSvnLen]byte

	proto any // *pb.QuoteV4 or *pb.QuoteV5; nil when simulated
}

// ParseOptions control which quote formats ParseQuote accepts.
type ParseOptions struct {
	// AllowSimulated accepts the dev simulator format (INTERFACES.md section 15). Production builds never set it.
	AllowSimulated bool
}

// ParseQuote parses raw quote bytes. Simulated quotes are rejected unless opts.AllowSimulated is set.
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
	q := &Quote{Raw: bytes.Clone(raw), proto: p}
	if err := q.extract(p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	return q, nil
}

// tdBody is the subset of the v4 and v5 TD quote bodies we read. go-tdx-guest's rtmr helpers only accept v4,
// so we extract the fields ourselves.
type tdBody interface {
	GetMrTd() []byte
	GetRtmrs() [][]byte
	GetReportData() []byte
	GetTdAttributes() []byte
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
