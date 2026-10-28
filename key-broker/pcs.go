package keybroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/sealed-dev/sealed/verifier/attest"
)

// intelRootFingerprint is the SHA-256 of the Intel SGX Root CA's DER encoding.
const intelRootFingerprint = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

// IntelRootPool returns a pool holding only the Intel SGX Root CA.
func IntelRootPool() (*x509.CertPool, error) {
	blk, _ := pem.Decode([]byte(intelRootPEM))
	if blk == nil {
		return nil, errors.New("embedded Intel SGX Root CA is not PEM")
	}
	if fp := sha256.Sum256(blk.Bytes); hex.EncodeToString(fp[:]) != intelRootFingerprint {
		return nil, errors.New("embedded Intel SGX Root CA has the wrong fingerprint")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	p.AddCert(c)
	return p, nil
}

// PCKGate verifies the PCK certificate chain a quote carries against the Intel SGX Root CA before the inner
// verifier runs. go-tdx-guest fetches collateral from Intel PCS for the quote's FMSPC before it checks that chain,
// so without the gate an unauthenticated caller could make the broker fetch (and retry, for tens of seconds,
// holding a release slot) PCS URLs for made-up platforms. Simulated quotes pass through to the inner verifier,
// which refuses them unless it allows them.
type PCKGate struct {
	Inner QuoteVerifier
	Roots *x509.CertPool
	// Now is the clock for certificate validity; nil means time.Now.
	Now func() time.Time
}

// NewPCKGate wraps inner with the embedded Intel SGX Root CA.
func NewPCKGate(inner QuoteVerifier) (*PCKGate, error) {
	roots, err := IntelRootPool()
	if err != nil {
		return nil, err
	}
	return &PCKGate{Inner: inner, Roots: roots}, nil
}

// VerifyQuote implements QuoteVerifier.
func (g *PCKGate) VerifyQuote(ctx context.Context, raw []byte) (*attest.QuoteResult, error) {
	if !attest.IsSimulatedQuote(raw) {
		if err := g.checkChain(raw); err != nil {
			return nil, fmt.Errorf("%w: %v", attest.ErrQuoteInvalid, err)
		}
	}
	return g.Inner.VerifyQuote(ctx, raw)
}

func (g *PCKGate) checkChain(raw []byte) error {
	p, err := abi.QuoteToProto(raw)
	if err != nil {
		return err
	}
	ch, err := verify.ExtractChainFromQuote(p)
	if err != nil {
		return fmt.Errorf("PCK certificate chain: %v", err)
	}
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	inter := x509.NewCertPool()
	inter.AddCert(ch.IntermediateCertificate)
	if _, err := ch.PCKCertificate.Verify(x509.VerifyOptions{Roots: g.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("the PCK certificate chain does not verify to the Intel SGX Root CA: %v", err)
	}
	return nil
}

// CollateralProbe wraps the collateral getter the quote verifier uses and records, per release, that a collateral
// fetch failed (Intel PCS down or its answer unusable). The broker then answers 503 so the agent retries, instead of
// a 403 quote_invalid that reads like an attack in the customer's log (F6).
type CollateralProbe struct {
	Inner trust.HTTPSGetter
}

// Get implements trust.HTTPSGetter.
func (p CollateralProbe) Get(url string) (map[string][]string, []byte, error) {
	return p.GetContext(context.Background(), url)
}

// GetContext implements trust.ContextHTTPSGetter.
func (p CollateralProbe) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	h, b, err := trust.GetWith(ctx, p.Inner, url)
	if err != nil && ctx.Err() == nil {
		if m, ok := ctx.Value(probeKey{}).(*probeMark); ok {
			m.hit.Store(true)
		}
	}
	return h, b, err
}

type probeKey struct{}

type probeMark struct{ hit atomic.Bool }

func (m *probeMark) failed() bool { return m.hit.Load() }

func withCollateralProbe(ctx context.Context) (context.Context, *probeMark) {
	m := &probeMark{}
	return context.WithValue(ctx, probeKey{}, m), m
}

// tdConfig are TD fields the host chooses at launch that MRTD and RTMR0 to RTMR2 do not cover (F7).
type tdConfig struct {
	XFAM          []byte
	MrConfigID    []byte
	MrOwner       []byte
	MrOwnerConfig []byte
}

func readTDConfig(raw []byte) (*tdConfig, error) {
	p, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("quote body: %v", err)
	}
	type body interface {
		GetXfam() []byte
		GetMrConfigId() []byte
		GetMrOwner() []byte
		GetMrOwnerConfig() []byte
	}
	var b body
	switch v := p.(type) {
	case *pb.QuoteV4:
		b = v.GetTdQuoteBody()
	case *pb.QuoteV5:
		b = v.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
	default:
		return nil, fmt.Errorf("unsupported quote type %T", p)
	}
	return &tdConfig{XFAM: b.GetXfam(), MrConfigID: b.GetMrConfigId(), MrOwner: b.GetMrOwner(), MrOwnerConfig: b.GetMrOwnerConfig()}, nil
}

// check requires MRCONFIGID and MROWNERCONFIG to be zero: dstack on GCP leaves both zero and consumes neither, so a
// value there means a TD launched with a configuration the approved image was never measured with. MROWNER is set by
// Google (stable across reboots) and XFAM by the host; both are recorded in the decision, not pinned (deferred).
func (td *tdConfig) check() error {
	for _, f := range []struct {
		name string
		v    []byte
	}{{"MRCONFIGID", td.MrConfigID}, {"MROWNERCONFIG", td.MrOwnerConfig}} {
		if len(f.v) != 48 {
			return fmt.Errorf("%s is %d bytes, want 48", f.name, len(f.v))
		}
		if !bytes.Equal(f.v, make([]byte, 48)) {
			return fmt.Errorf("the TD was launched with %s 0x%x; Sealed images require it to be zero", f.name, f.v)
		}
	}
	return nil
}
