package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify/trust"
)

// TCBEvaluation is the TCB status of a verified quote, matched the way Intel's Quote Verification Library does.
type TCBEvaluation struct {
	// Platform is the first TCB level whose SGX components and PCESVN are at most the PCK certificate's and whose
	// TDX components are at most the quote's TEE_TCB_SVN (from index 2 when the TDX module major version is set).
	Platform pcs.TcbLevel
	// Module is the matched TDX module identity level. It is nil when TEE_TCB_SVN[1] is zero (no module identity).
	Module *pcs.TcbLevel
	// QE is the quoting enclave identity level matched by the QE report's ISVSVN.
	QE pcs.TcbLevel
	// Status converges Platform and Module: an OutOfDate (or Revoked) module dominates, otherwise the platform wins.
	Status pcs.TcbComponentStatus
	// AdvisoryIDs is the sorted union of the platform and module advisories.
	AdvisoryIDs []string
}

// collateralSource returns the PCS response body a verification used for url.
type collateralSource interface {
	body(url string) ([]byte, bool)
}

// recordingGetter wraps a getter for one verification and keeps the bodies it returned, so the TCB evaluation reads
// exactly the collateral go-tdx-guest verified (no second fetch, no cache expiry in between).
type recordingGetter struct {
	inner trust.HTTPSGetter

	mu     sync.Mutex
	bodies map[string][]byte
}

func newRecordingGetter(inner trust.HTTPSGetter) *recordingGetter {
	return &recordingGetter{inner: inner, bodies: map[string][]byte{}}
}

func (g *recordingGetter) Get(url string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), url)
}

func (g *recordingGetter) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	h, b, err := trust.GetWith(ctx, g.inner, url)
	if err == nil {
		g.mu.Lock()
		g.bodies[url] = bytes.Clone(b)
		g.mu.Unlock()
	}
	return h, b, err
}

func (g *recordingGetter) body(url string) ([]byte, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.bodies[url]
	return b, ok
}

// evaluateTCB matches the platform, TDX module and QE TCB levels of q against the TCB info and QE identity in src.
// The caller must already have verified q and the signatures of that collateral.
func evaluateTCB(q *Quote, ext *pcs.PckExtensions, src collateralSource) (*TCBEvaluation, error) {
	info, err := signedTcbInfo(src, ext.FMSPC)
	if err != nil {
		return nil, err
	}
	qeID, err := signedQeIdentity(src)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(info.Fmspc, ext.FMSPC) || info.ID != "TDX" {
		return nil, fmt.Errorf("%w: TCB info is for %s fmspc %s, quote has fmspc %s", ErrQuoteInvalid, info.ID, info.Fmspc, ext.FMSPC)
	}
	if qeID.ID != "TD_QE" {
		return nil, fmt.Errorf("%w: QE identity id %q, want TD_QE", ErrQuoteInvalid, qeID.ID)
	}
	seam, err := seamIdentity(q)
	if err != nil {
		return nil, err
	}

	ev := &TCBEvaluation{}
	tee := q.TeeTcbSvn[:]
	platform, ok := matchPlatformLevel(info.TcbLevels, tee, ext.TCB.CPUSvnComponents, ext.TCB.PCESvn)
	if !ok {
		return nil, fmt.Errorf("%w: no TCB level matches the platform (CPUSVN %x, PCESVN %d, TEE_TCB_SVN %x)", ErrTCBStatus, ext.TCB.CPUSvnComponents, ext.TCB.PCESvn, tee)
	}
	ev.Platform = platform
	if tee[1] > 0 {
		id, err := matchModuleIdentity(info.TdxModuleIdentities, tee[1], seam)
		if err != nil {
			return nil, err
		}
		lvl, ok := matchModuleLevel(id, tee[0])
		if !ok {
			return nil, fmt.Errorf("%w: no %s TCB level matches TDX module ISVSVN %d", ErrTCBStatus, id.ID, tee[0])
		}
		ev.Module = &lvl
	}
	isvsvn, err := qeIsvSvn(q)
	if err != nil {
		return nil, err
	}
	ev.QE, ok = matchQELevel(qeID.TcbLevels, isvsvn)
	if !ok {
		return nil, fmt.Errorf("%w: no QE identity TCB level matches QE ISVSVN %d", ErrTCBStatus, isvsvn)
	}
	ev.Status = convergeTCBStatus(ev.Platform.TcbStatus, ev.Module)
	ev.AdvisoryIDs = unionAdvisories(ev.Platform, ev.Module)
	return ev, nil
}

// signedField returns the raw value of key in a PCS JSON body: the exact bytes Intel's signature covers.
func signedField(body []byte, key string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%q missing", key)
	}
	return v, nil
}

func signedTcbInfo(src collateralSource, fmspc string) (*pcs.TcbInfo, error) {
	body, ok := src.body(pcs.TcbInfoURL(fmspc))
	if !ok {
		return nil, fmt.Errorf("%w: TCB info for fmspc %s was not fetched", ErrQuoteInvalid, fmspc)
	}
	raw, err := signedField(body, "tcbInfo")
	if err != nil {
		return nil, fmt.Errorf("%w: TCB info: %v", ErrQuoteInvalid, err)
	}
	var info pcs.TcbInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("%w: TCB info: %v", ErrQuoteInvalid, err)
	}
	return &info, nil
}

func signedQeIdentity(src collateralSource) (*pcs.EnclaveIdentity, error) {
	body, ok := src.body(pcs.QeIdentityURL())
	if !ok {
		return nil, fmt.Errorf("%w: QE identity was not fetched", ErrQuoteInvalid)
	}
	raw, err := signedField(body, "enclaveIdentity")
	if err != nil {
		return nil, fmt.Errorf("%w: QE identity: %v", ErrQuoteInvalid, err)
	}
	var id pcs.EnclaveIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("%w: QE identity: %v", ErrQuoteInvalid, err)
	}
	return &id, nil
}

// svnsAtLeast reports whether have[i] >= want[i].Svn for every i >= start. Lengths must match.
func svnsAtLeast(have []byte, want []pcs.TcbComponent, start int) bool {
	if len(have) != len(want) {
		return false
	}
	for i := start; i < len(have); i++ {
		if have[i] < want[i].Svn {
			return false
		}
	}
	return true
}

// matchPlatformLevel returns the first (highest) TCB level the platform satisfies. Levels are sorted descending by
// Intel. With a TDX module major version set, TEE_TCB_SVN[0:2] identify the module and are matched separately.
func matchPlatformLevel(levels []pcs.TcbLevel, teeTcbSvn, cpuSvn []byte, pceSvn uint16) (pcs.TcbLevel, bool) {
	start := 0
	if teeTcbSvn[1] > 0 {
		start = 2
	}
	for _, l := range levels {
		if svnsAtLeast(cpuSvn, l.Tcb.SgxTcbcomponents, 0) && pceSvn >= l.Tcb.Pcesvn && svnsAtLeast(teeTcbSvn, l.Tcb.TdxTcbcomponents, start) {
			return l, true
		}
	}
	return pcs.TcbLevel{}, false
}

// seam is the TDX module identity a quote reports.
type seam struct {
	mrSigner   []byte
	attributes []byte
}

func seamIdentity(q *Quote) (seam, error) {
	var b interface {
		GetMrSignerSeam() []byte
		GetSeamAttributes() []byte
	}
	switch v := q.proto.(type) {
	case *pb.QuoteV4:
		b = v.GetTdQuoteBody()
	case *pb.QuoteV5:
		b = v.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
	default:
		return seam{}, fmt.Errorf("%w: unsupported quote type %T", ErrQuoteInvalid, q.proto)
	}
	return seam{mrSigner: b.GetMrSignerSeam(), attributes: b.GetSeamAttributes()}, nil
}

// matchModuleIdentity finds TDX_<major> and checks the module's MRSIGNER and masked attributes against it, as QVL does.
func matchModuleIdentity(ids []pcs.TdxModuleIdentity, major byte, s seam) (*pcs.TdxModuleIdentity, error) {
	want := fmt.Sprintf("TDX_%02x", major)
	for i := range ids {
		id := &ids[i]
		if !strings.EqualFold(id.ID, want) {
			continue
		}
		if !bytes.Equal(id.Mrsigner.Bytes, s.mrSigner) {
			return nil, fmt.Errorf("%w: MRSIGNERSEAM %x is not %s's %x", ErrQuoteInvalid, s.mrSigner, id.ID, id.Mrsigner.Bytes)
		}
		if len(id.AttributesMask.Bytes) != len(s.attributes) || !bytes.Equal(applyMask(id.AttributesMask.Bytes, s.attributes), id.Attributes.Bytes) {
			return nil, fmt.Errorf("%w: SEAMATTRIBUTES %x do not match %s", ErrQuoteInvalid, s.attributes, id.ID)
		}
		return id, nil
	}
	return nil, fmt.Errorf("%w: TCB info has no module identity %s", ErrTCBStatus, want)
}

func applyMask(mask, v []byte) []byte {
	out := make([]byte, len(v))
	for i := range v {
		out[i] = mask[i] & v[i]
	}
	return out
}

// matchModuleLevel returns the first module TCB level whose ISVSVN is at most the module's (TEE_TCB_SVN[0]).
func matchModuleLevel(id *pcs.TdxModuleIdentity, isvsvn byte) (pcs.TcbLevel, bool) {
	for _, l := range id.TcbLevels {
		if uint32(isvsvn) >= l.Tcb.Isvsvn {
			return l, true
		}
	}
	return pcs.TcbLevel{}, false
}

func qeIsvSvn(q *Quote) (uint32, error) {
	var sd *pb.Ecdsa256BitQuoteV4AuthData
	switch v := q.proto.(type) {
	case *pb.QuoteV4:
		sd = v.GetSignedData()
	case *pb.QuoteV5:
		sd = v.GetSignedData()
	default:
		return 0, fmt.Errorf("%w: unsupported quote type %T", ErrQuoteInvalid, q.proto)
	}
	r := sd.GetCertificationData().GetQeReportCertificationData().GetQeReport()
	if r == nil {
		return 0, fmt.Errorf("%w: quote has no QE report", ErrQuoteInvalid)
	}
	return r.GetIsvSvn(), nil
}

func matchQELevel(levels []pcs.TcbLevel, isvsvn uint32) (pcs.TcbLevel, bool) {
	for _, l := range levels {
		if l.Tcb.Isvsvn <= isvsvn {
			return l, true
		}
	}
	return pcs.TcbLevel{}, false
}

// statusRank orders statuses from best to worst for combinations Intel's QVL does not define.
var statusRank = map[pcs.TcbComponentStatus]int{
	pcs.TcbComponentStatusUpToDate:                          0,
	pcs.TcbComponentStatusSwHardeningNeeded:                 1,
	pcs.TcbComponentStatusConfigurationNeeded:               2,
	pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded: 3,
	pcs.TcbComponentStatusOutOfDate:                         4,
	pcs.TcbComponentStatusOutOfDateConfigurationNeeded:      5,
	pcs.TcbComponentStatusRevoked:                           6,
}

func isConfigurationNeeded(s pcs.TcbComponentStatus) bool {
	return s == pcs.TcbComponentStatusConfigurationNeeded || s == pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded ||
		s == pcs.TcbComponentStatusOutOfDateConfigurationNeeded
}

// convergeTCBStatus combines the platform status with the TDX module status (QVL convergeTcbStatusWithTdxModuleStatus):
// an OutOfDate module makes the result OutOfDate (OutOfDateConfigurationNeeded when the platform needs
// configuration), a Revoked module makes it Revoked, an UpToDate module leaves the platform status. Combinations
// QVL leaves undefined take the worse of the two.
func convergeTCBStatus(platform pcs.TcbComponentStatus, module *pcs.TcbLevel) pcs.TcbComponentStatus {
	if module == nil || module.TcbStatus == pcs.TcbComponentStatusUpToDate {
		return platform
	}
	switch module.TcbStatus {
	case pcs.TcbComponentStatusOutOfDate:
		switch {
		case platform == pcs.TcbComponentStatusRevoked:
			return platform
		case isConfigurationNeeded(platform):
			return pcs.TcbComponentStatusOutOfDateConfigurationNeeded
		default:
			return pcs.TcbComponentStatusOutOfDate
		}
	case pcs.TcbComponentStatusRevoked:
		return pcs.TcbComponentStatusRevoked
	}
	pr, pok := statusRank[platform]
	mr, mok := statusRank[module.TcbStatus]
	if !pok || (mok && mr > pr) {
		return module.TcbStatus
	}
	return platform
}

func unionAdvisories(platform pcs.TcbLevel, module *pcs.TcbLevel) []string {
	out := slices.Clone(platform.AdvisoryIDs)
	if module != nil {
		out = append(out, module.AdvisoryIDs...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
