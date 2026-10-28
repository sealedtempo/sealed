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
	Quote       *Quote
	Simulated   bool
	TCBStatus   string
	QETCBStatus string
	TCBDate     string
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
	// verify.Options is mutated by the library (collateral, chain); build one per call.
	vopts := &verify.Options{
		GetCollateral:         true,
		CheckRevocations:      true,
		Getter:                v.opts.Getter,
		DisableTcbStatusCheck: true, // replaced by our policy below
		TrustedRoots:          v.opts.TrustedRoots,
		Now:                   &verify.TimeSet{PckCertChain: now, TcbInfo: now, QeIdentity: now, PckCrl: now, RootCaCrl: now},
	}
	if err := verify.TdxQuoteContext(ctx, q.proto, vopts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuoteInvalid, err)
	}
	tdx, qe, err := verify.SupportedTcbLevelsFromCollateral(q.proto, vopts)
	if err != nil {
		return nil, fmt.Errorf("%w: no supported TCB level: %v", ErrTCBStatus, err)
	}
	if err := v.opts.TCBPolicy.Check(tdx, qe); err != nil {
		return nil, err
	}
	res := &QuoteResult{
		Quote:       q,
		TCBStatus:   string(tdx.TcbStatus),
		QETCBStatus: string(qe.TcbStatus),
		TCBDate:     tdx.TcbDate,
		AdvisoryIDs: tdx.AdvisoryIDs,
	}
	if chain, err := verify.ExtractChainFromQuote(q.proto); err == nil {
		if ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate); err == nil {
			res.FMSPC = ext.FMSPC
		}
	}
	return res, nil
}

// CheckProductionAttributes rejects TDs with the DEBUG or MIGRATABLE attribute set.
func (q *Quote) CheckProductionAttributes() error {
	if q.Debug() {
		return fmt.Errorf("%w: TD_ATTRIBUTES.DEBUG is set", ErrTDAttributes)
	}
	if q.Migratable() {
		return fmt.Errorf("%w: TD_ATTRIBUTES.MIGRATABLE is set", ErrTDAttributes)
	}
	return nil
}
