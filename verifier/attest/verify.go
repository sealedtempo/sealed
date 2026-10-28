package attest

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// ErrTDAttributes is returned when TD_ATTRIBUTES allow host inspection (debug) or live migration.
var ErrTDAttributes = errors.New("image_debug")

// VerifierOptions configure a Verifier.
type VerifierOptions struct {
	// AllowSimulated accepts dev simulator quotes. Only dev builds behind SEALED_DEV_SIM=1 may set it.
	AllowSimulated bool
	// Getter fetches Intel PCS collateral. Nil means an in-memory CachingGetter over HTTPS.
	Getter trust.HTTPSGetter
	// TCBPolicy decides which TCB statuses pass. A zero policy is replaced by DefaultTCBPolicy.
	TCBPolicy TCBPolicy
	// Now is the time certificates, CRLs and collateral are checked against; nil means time.Now.
	Now func() time.Time
	// TrustedRoots replaces the embedded Intel SGX Root CA (tests only).
	TrustedRoots *x509.CertPool
}

// Verifier verifies TDX quotes against Intel collateral and a TCB policy. It is safe for concurrent use.
type Verifier struct {
	opts VerifierOptions
}

// QuoteResult is the outcome of a successful VerifyQuote.
type QuoteResult struct {
	Quote     *Quote
	Simulated bool
	// TCBStatus is the converged TDX status (platform and TDX module); the policy was applied to it.
	TCBStatus string
	// PlatformTCBStatus is the status of the matched platform TCB level (CPU SVN, PCE SVN, TDX components).
	PlatformTCBStatus string
	// ModuleTCBStatus is the status of the matched TDX module identity level; empty when the quote has none.
	ModuleTCBStatus string
	QETCBStatus     string
	// TCBDate is the platform level's tcbDate; ModuleTCBDate the module level's.
	TCBDate       string
	ModuleTCBDate string
	// AdvisoryIDs is the union of the platform and module advisories.
	AdvisoryIDs []string
	FMSPC       string
}

// NewVerifier validates the options and returns a Verifier.
func NewVerifier(o VerifierOptions) (*Verifier, error) {
	if len(o.TCBPolicy.AllowedStatuses) == 0 {
		o.TCBPolicy = DefaultTCBPolicy()
	}
	if err := o.TCBPolicy.Validate(); err != nil {
		return nil, err
	}
	if o.Getter == nil {
		g, err := NewCachingGetter(CacheOptions{})
		if err != nil {
			return nil, err
		}
		o.Getter = g
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Verifier{opts: o}, nil
}

// AllowsSimulated reports whether this verifier accepts dev simulator quotes.
func (v *Verifier) AllowsSimulated() bool { return v.opts.AllowSimulated }

// ParseQuote parses raw with this verifier's simulator setting, without verifying it.
func (v *Verifier) ParseQuote(raw []byte) (*Quote, error) {
	return ParseQuote(raw, ParseOptions{AllowSimulated: v.opts.AllowSimulated})
}

// VerifyQuote parses raw, verifies its signature, PCK chain, QE report, collateral signatures and expiry and
// revocation lists, then applies the TCB policy. Any failure is an error: there is no partial success.
// Simulated quotes are only parsed (and only when allowed); the result is flagged Simulated.
func (v *Verifier) VerifyQuote(ctx context.Context, raw []byte) (*QuoteResult, error) {
	q, err := v.ParseQuote(raw)
	if err != nil {
		return nil, err
	}
	if q.Simulated {
		return &QuoteResult{Quote: q, Simulated: true, TCBStatus: "Simulated", QETCBStatus: "Simulated"}, nil
	}

	now := v.opts.Now()
	rec := newRecordingGetter(v.opts.Getter)
	// verify.Options is mutated by the library (collateral, chain); build one per call.
	vopts := &verify.Options{
		GetCollateral:    true,
		CheckRevocations: true,
		Getter:           rec,
		// The library's own status check is all-or-nothing (UpToDate only); evaluateTCB and the policy replace it.
		DisableTcbStatusCheck: true,
		TrustedRoots:          v.opts.TrustedRoots,
		Now:                   &verify.TimeSet{PckCertChain: now, TcbInfo: now, QeIdentity: now, PckCrl: now, RootCaCrl: now},
	}
	if err := verify.TdxQuoteContext(ctx, q.proto, vopts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	chain, err := verify.ExtractChainFromQuote(q.proto)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, fmt.Errorf("%w: PCK certificate extensions: %v", ErrQuoteInvalid, err)
	}
	return v.applyTCB(q, ext, rec)
}

// applyTCB evaluates and applies the TCB policy to an already verified quote and the collateral it was verified with.
func (v *Verifier) applyTCB(q *Quote, ext *pcs.PckExtensions, src collateralSource) (*QuoteResult, error) {
	ev, err := evaluateTCB(q, ext, src)
	if err != nil {
		return nil, err
	}
	if err := v.opts.TCBPolicy.Check(ev); err != nil {
		return nil, err
	}
	res := &QuoteResult{
		Quote:             q,
		TCBStatus:         string(ev.Status),
		PlatformTCBStatus: string(ev.Platform.TcbStatus),
		QETCBStatus:       string(ev.QE.TcbStatus),
		TCBDate:           ev.Platform.TcbDate,
		AdvisoryIDs:       ev.AdvisoryIDs,
		FMSPC:             ext.FMSPC,
	}
	if ev.Module != nil {
		res.ModuleTCBStatus = string(ev.Module.TcbStatus)
		res.ModuleTCBDate = ev.Module.TcbDate
	}
	return res, nil
}

// CheckProductionAttributes rejects TD_ATTRIBUTES a production TD must not have. TD_ATTRIBUTES are chosen by the host
// at launch and are not part of MRTD or RTMR0-2, so they are checked here: no TUD bit (DEBUG and the reserved debug
// bits), not MIGRATABLE, SEPT_VE_DISABLE set (Intel's recommendation for Linux guests), and no reserved bit.
// LASS, PKS, KL and PERFMON are allowed.
func (q *Quote) CheckProductionAttributes() error {
	a := q.tdAttributes()
	if q.Debug() {
		return fmt.Errorf("%w: TD_ATTRIBUTES.DEBUG is set", ErrTDAttributes)
	}
	if a&tdAttrTUD != 0 {
		return fmt.Errorf("%w: TD_ATTRIBUTES 0x%016x has reserved TUD (debug) bits set", ErrTDAttributes, a)
	}
	if a&tdAttrMigratable != 0 {
		return fmt.Errorf("%w: TD_ATTRIBUTES.MIGRATABLE is set", ErrTDAttributes)
	}
	if a&tdAttrSeptVEDisable == 0 {
		return fmt.Errorf("%w: TD_ATTRIBUTES.SEPT_VE_DISABLE is not set (0x%016x)", ErrTDAttributes, a)
	}
	if extra := a &^ (tdAttrSeptVEDisable | tdAttrOptional); extra != 0 {
		return fmt.Errorf("%w: TD_ATTRIBUTES 0x%016x has reserved or unknown bits 0x%016x set", ErrTDAttributes, a, extra)
	}
	return nil
}
