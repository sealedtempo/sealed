// Package releasesig checks that release CI built and signed a release bundle (supply-2). It implements
// verify.ReleaseSignatures with sigstore-go, offline: no Sigstore service is called, the Sigstore public-good trusted
// root is embedded (trusted_root.json), and the assets come from the same release asset bases as the bundles (D-046).
//
// A release passes when both assets next to its bundle verify for the onchain bundleHash:
//
//   - <bundle>.sigstore.json, the cosign sign-blob bundle of release.yml's build job (onchain signatureURI, G13): a
//     message signature over sha256(bundle.tar) = bundleHash, whose Fulcio certificate names
//     ReleaseWorkflow on GitHubOIDCIssuer, with an embedded SCT and a transparency log entry;
//   - <bundle>.intoto.jsonl, the Sigstore bundle of slsa-github-generator v2.1.0 (onchain provenanceURI): a DSSE
//     in-toto statement signed by SLSABuilder for ReleaseWorkflow (certificate Build Config URI), with the SLSA v0.2
//     predicate of that builder and a subject whose sha256 is bundleHash.
//
// The identities are fixed here, not read from release.json or the chain, so neither the OPS key nor whoever can
// edit a GitHub Release can choose them.
package releasesig

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/sealedtempo/sealed/runtime/composer"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/bundles"
)

// The identities release CI signs with (.github/workflows/release.yml, scripts/release/sign-bundle.sh).
const (
	// GitHubOIDCIssuer is the issuer of GitHub Actions identity tokens.
	GitHubOIDCIssuer = "https://token.actions.githubusercontent.com"
	// SourceRepository is the public repository whose release workflow signs releases.
	SourceRepository = "https://github.com/sealedtempo/sealed"
	// SourceRef is the only branch release.yml publishes from.
	SourceRef = "refs/heads/main"
	// ReleaseWorkflow is the certificate identity of release.yml on main: the subject of the bundle signature and the
	// Build Config URI of the provenance.
	ReleaseWorkflow = SourceRepository + "/.github/workflows/release.yml@" + SourceRef
	// SLSABuilder is the reusable workflow that signs the provenance, by the tag release.yml calls (its slsa-pin job
	// checks the tag still names commit f7dd8c54c2067bafc12ca7a55595d5ee9b75204a). Moving release.yml to another
	// generator version means accepting that version here too, while keeping v2.1.0 for older releases.
	SLSABuilder = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
	// SLSAPredicateType is the predicate the generic generator v2.1.0 writes.
	SLSAPredicateType = "https://slsa.dev/provenance/v0.2"
)

// Asset names next to <bundle> (composer.ReleaseAssets.Bundle).
const (
	SignatureSuffix  = ".sigstore.json"
	ProvenanceSuffix = ".intoto.jsonl"
	// MaxAssetBytes bounds one download; a Sigstore bundle is a few KiB, the provenance of a release run lists one
	// subject per bundle.
	MaxAssetBytes = 1 << 20
)

// trustedRootJSON is the Sigstore public-good trusted root: the TUF target trusted_root.json of
// https://tuf-repo-cdn.sigstore.dev (targets version 14, sha256
// 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66), checked against the TUF root embedded in
// sigstore-go v1.3.0 on 2026-10-29. It holds the Fulcio CAs, the Rekor v1 log and the log2025-1 Rekor v2 shard, the
// CT logs and the timestamp authority. A signature from a key Sigstore adds later fails until this file is updated
// from TUF (TestEmbeddedTrustedRoot pins its hash, so an update is deliberate).
//
//go:embed trusted_root.json
var trustedRootJSON []byte

var (
	publicGoodOnce sync.Once
	publicGood     *root.TrustedRoot
	publicGoodErr  error
)

// PublicGoodTrustedRoot returns the embedded Sigstore public-good trusted root.
func PublicGoodTrustedRoot() (*root.TrustedRoot, error) {
	publicGoodOnce.Do(func() {
		publicGood, publicGoodErr = root.NewTrustedRootFromJSON(trustedRootJSON)
	})
	return publicGood, publicGoodErr
}

// Options configure a Verifier.
type Options struct {
	// Bases are the release asset bases, the catalog's first and mirrors after (bundles.ParseBases). Each base is
	// tried in order until one serves both assets and they verify.
	Bases []string
	// AllowHTTP accepts http:// bases (local devnets and tests); otherwise every base must be https.
	AllowHTTP bool
	// Fetcher downloads the assets; nil means bundles.HTTPFetcher with HTTP, MaxAssetBytes and the default
	// redirect rule.
	Fetcher bundles.Fetcher
	// HTTP is the client of the default fetcher; nil uses one with bundles.DefaultFetchTimeout.
	HTTP *http.Client
}

// Verifier implements verify.ReleaseSignatures. Verified releases are cached by app, version and bundleHash.
type Verifier struct {
	bases   []string
	fetcher bundles.Fetcher
	sig     *sgverify.Verifier
	signer  sgverify.CertificateIdentity // the bundle signature
	builder sgverify.CertificateIdentity // the provenance

	mu    sync.Mutex
	cache map[cacheKey]verify.ReleaseSignature
}

var _ verify.ReleaseSignatures = (*Verifier)(nil)

type cacheKey struct {
	app, version string
	hash         [32]byte
}

// New returns a Verifier with the production policy: the embedded public-good trusted root, an SCT in every
// certificate, a transparency log entry and an observer timestamp for every signature, and the fixed identities.
func New(o Options) (*Verifier, error) {
	tr, err := PublicGoodTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("sigstore trusted root: %w", err)
	}
	return newVerifier(o, tr, true)
}

func newVerifier(o Options, trusted root.TrustedMaterial, requireSCT bool) (*Verifier, error) {
	if len(o.Bases) == 0 {
		return nil, errors.New("releasesig: no release asset base")
	}
	for _, b := range o.Bases {
		u, err := url.Parse(b)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(o.AllowHTTP && u.Scheme == "http")) {
			return nil, fmt.Errorf("releasesig: release asset base %q must be an https URL", b)
		}
	}
	opts := []sgverify.VerifierOption{sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1)}
	if requireSCT {
		opts = append(opts, sgverify.WithSignedCertificateTimestamps(1))
	}
	sv, err := sgverify.NewVerifier(trusted, opts...)
	if err != nil {
		return nil, err
	}
	signer, err := identity(ReleaseWorkflow, certificate.Extensions{
		SourceRepositoryURI: SourceRepository, SourceRepositoryRef: SourceRef, BuildConfigURI: ReleaseWorkflow,
	})
	if err != nil {
		return nil, err
	}
	builder, err := identity(SLSABuilder, certificate.Extensions{
		SourceRepositoryURI: SourceRepository, SourceRepositoryRef: SourceRef, BuildConfigURI: ReleaseWorkflow,
	})
	if err != nil {
		return nil, err
	}
	f := o.Fetcher
	if f == nil {
		f = bundles.HTTPFetcher{Client: o.HTTP, MaxBytes: MaxAssetBytes, UserAgent: "sealed-verifier"}
	}
	return &Verifier{bases: o.Bases, fetcher: f, sig: sv, signer: signer, builder: builder, cache: map[cacheKey]verify.ReleaseSignature{}}, nil
}

// identity is an exact SAN on the GitHub OIDC issuer with the given certificate extensions.
func identity(san string, ext certificate.Extensions) (sgverify.CertificateIdentity, error) {
	sanMatcher, err := sgverify.NewSANMatcher(san, "")
	if err != nil {
		return sgverify.CertificateIdentity{}, err
	}
	issuer, err := sgverify.NewIssuerMatcher(GitHubOIDCIssuer, "")
	if err != nil {
		return sgverify.CertificateIdentity{}, err
	}
	return sgverify.NewCertificateIdentity(sanMatcher, issuer, ext)
}

// VerifyReleaseSignature implements verify.ReleaseSignatures.
func (v *Verifier) VerifyReleaseSignature(ctx context.Context, rel verify.ComposeRelease) (*verify.ReleaseSignature, error) {
	key := cacheKey{rel.App, rel.Version, rel.BundleHash}
	v.mu.Lock()
	if got, ok := v.cache[key]; ok {
		v.mu.Unlock()
		return &got, nil
	}
	v.mu.Unlock()
	var errs []error
	for _, base := range v.bases {
		a, err := composer.NewReleaseAssets(base, rel.App, rel.Version)
		if err != nil {
			return nil, fmt.Errorf("release asset URL: %w", err)
		}
		got, err := v.fromBundleURL(ctx, a.Bundle, rel.BundleHash)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		v.mu.Lock()
		v.cache[key] = *got
		v.mu.Unlock()
		return got, nil
	}
	return nil, errors.Join(errs...)
}

func (v *Verifier) fromBundleURL(ctx context.Context, bundleURL string, hash [32]byte) (*verify.ReleaseSignature, error) {
	sigURL, provURL := bundleURL+SignatureSuffix, bundleURL+ProvenanceSuffix
	raw, err := v.fetcher.Fetch(ctx, sigURL)
	if err != nil {
		return nil, err
	}
	sig, err := v.VerifySignature(raw, hash)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sigURL, err)
	}
	raw, err = v.fetcher.Fetch(ctx, provURL)
	if err != nil {
		return nil, err
	}
	prov, err := v.VerifyProvenance(raw, hash)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", provURL, err)
	}
	sig.SignatureURL, sig.ProvenanceURL = sigURL, provURL
	sig.Builder, sig.BuildConfig = prov.Builder, prov.BuildConfig
	return sig, nil
}

// VerifySignature checks a .sigstore.json: a message signature over exactly hash (sha256 of the bundle), by
// ReleaseWorkflow.
func (v *Verifier) VerifySignature(raw []byte, hash [32]byte) (*verify.ReleaseSignature, error) {
	b, err := parseBundle(raw)
	if err != nil {
		return nil, err
	}
	if sc, err := b.SignatureContent(); err != nil || sc.MessageSignatureContent() == nil {
		return nil, errors.New("not a blob signature (no message signature)")
	}
	res, err := v.sig.Verify(b, sgverify.NewPolicy(sgverify.WithArtifactDigest("sha256", hash[:]), sgverify.WithCertificateIdentity(v.signer)))
	if err != nil {
		return nil, fmt.Errorf("not signed by %s for bundleHash 0x%x: %w", ReleaseWorkflow, hash, err)
	}
	out := &verify.ReleaseSignature{}
	if c := res.Signature.Certificate; c != nil {
		out.Signer, out.Issuer = c.SubjectAlternativeName, c.Extensions.Issuer
	}
	for _, ts := range res.VerifiedTimestamps {
		if t := ts.Timestamp.Unix(); out.SignedAt == 0 || t < out.SignedAt {
			out.SignedAt = t
		}
	}
	if entries, err := b.TlogEntries(); err == nil && len(entries) > 0 {
		out.LogIndex = entries[0].LogIndex()
	}
	return out, nil
}

// Provenance is what a verified provenance shows.
type Provenance struct {
	Builder     string // certificate SAN, SLSABuilder
	BuildConfig string // certificate Build Config URI, ReleaseWorkflow
	Subject     string // name of the subject whose sha256 is the bundleHash
}

// VerifyProvenance checks an .intoto.jsonl: a Sigstore bundle with a DSSE in-toto statement signed by SLSABuilder for
// ReleaseWorkflow, with the SLSA v0.2 predicate of SLSABuilder and a subject whose sha256 is hash. The file holds one
// bundle; one per line is accepted too.
func (v *Verifier) VerifyProvenance(raw []byte, hash [32]byte) (*Provenance, error) {
	candidates := [][]byte{bytes.TrimSpace(raw)}
	if lines := bytes.Split(candidates[0], []byte("\n")); len(lines) > 1 {
		candidates = append(candidates, lines...)
	}
	var errs []error
	for _, c := range candidates {
		if len(bytes.TrimSpace(c)) == 0 {
			continue
		}
		p, err := v.verifyProvenanceBundle(c, hash)
		if err == nil {
			return p, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, errors.New("empty provenance")
	}
	return nil, errs[0]
}

func (v *Verifier) verifyProvenanceBundle(raw []byte, hash [32]byte) (*Provenance, error) {
	b, err := parseBundle(raw)
	if err != nil {
		return nil, err
	}
	if sc, err := b.SignatureContent(); err != nil || sc.EnvelopeContent() == nil {
		return nil, errors.New("not an attestation (no DSSE envelope)")
	}
	res, err := v.sig.Verify(b, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), sgverify.WithCertificateIdentity(v.builder)))
	if err != nil {
		return nil, fmt.Errorf("not signed by %s for %s: %w", SLSABuilder, ReleaseWorkflow, err)
	}
	st := res.Statement
	if st == nil {
		return nil, errors.New("no in-toto statement")
	}
	if st.GetPredicateType() != SLSAPredicateType {
		return nil, fmt.Errorf("predicate type %q, want %q", st.GetPredicateType(), SLSAPredicateType)
	}
	if id := st.GetPredicate().GetFields()["builder"].GetStructValue().GetFields()["id"].GetStringValue(); id != SLSABuilder {
		return nil, fmt.Errorf("provenance builder %q, want %q", id, SLSABuilder)
	}
	want := hex.EncodeToString(hash[:])
	for _, s := range st.GetSubject() {
		if strings.EqualFold(s.GetDigest()["sha256"], want) {
			p := &Provenance{Subject: s.GetName()}
			if c := res.Signature.Certificate; c != nil {
				p.Builder, p.BuildConfig = c.SubjectAlternativeName, c.Extensions.BuildConfigURI
			}
			return p, nil
		}
	}
	return nil, fmt.Errorf("no provenance subject has sha256 %s (the onchain bundleHash)", want)
}

func parseBundle(raw []byte) (*bundle.Bundle, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("not a Sigstore bundle: %w", err)
	}
	return &b, nil
}
