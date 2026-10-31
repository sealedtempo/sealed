// Package sigstoretest is a Fulcio and a Rekor of our own, generated for one test, for checking release signatures
// without calling any Sigstore service. It issues certificates with the Fulcio extensions GitHub Actions identities
// carry and writes Sigstore bundles in the shape release CI publishes: bundle v0.3 with one certificate and a Rekor v1
// entry with inclusion proof and signed entry timestamp. Its certificates carry no SCT, so only a verifier built with
// its TrustedRoot and without the SCT requirement accepts them; the production verifier (the public-good root)
// refuses them, which is what a release looks like that release CI did not sign.
//
// Only tests import this package.
package sigstoretest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
)

// GitHubOIDCIssuer is the issuer of GitHub Actions identity tokens.
const GitHubOIDCIssuer = "https://token.actions.githubusercontent.com"

// Sigstore is one local Fulcio CA and Rekor log.
type Sigstore struct {
	t      testing.TB
	inter  *x509.Certificate
	interK *ecdsa.PrivateKey
	// Log signs the transparency log entries; another Sigstore's log can be shared to test a foreign CA in a
	// trusted log.
	Log     *ca.VirtualSigstore
	trusted *root.TrustedRoot
}

// New generates a CA and a log valid for the next hour.
func New(t testing.TB) *Sigstore {
	t.Helper()
	rootCert, rootKey, err := ca.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	inter, interKey, err := ca.GenerateFulcioIntermediate(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	fulcio := &root.FulcioCertificateAuthority{Root: rootCert, Intermediates: []*x509.Certificate{inter},
		ValidityPeriodStart: time.Now().Add(-time.Hour), ValidityPeriodEnd: time.Now().Add(time.Hour), URI: "https://fulcio.test"}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio}, map[string]*root.TransparencyLog{}, nil, vs.RekorLogs())
	if err != nil {
		t.Fatal(err)
	}
	return &Sigstore{t: t, inter: inter, interK: interKey, Log: vs, trusted: tr}
}

// TrustedRoot trusts this CA and log.
func (s *Sigstore) TrustedRoot() *root.TrustedRoot { return s.trusted }

// Identity is what a certificate names.
type Identity struct {
	SAN, Issuer string
	Ext         certificate.Extensions
}

// GitHubActions is the identity Fulcio gives a job of workflow san (job_workflow_ref) in repo at ref, started by
// buildConfig (workflow_ref; san itself unless san is a reusable workflow).
func GitHubActions(san, repo, ref, buildConfig string) Identity {
	return Identity{SAN: san, Issuer: GitHubOIDCIssuer, Ext: certificate.Extensions{
		SourceRepositoryURI: repo, SourceRepositoryRef: ref, BuildConfigURI: buildConfig, BuildSignerURI: san,
		RunnerEnvironment: "github-hosted",
	}}
}

func (s *Sigstore) derUTF8(v string) []byte {
	b, err := asn1.MarshalWithParams(v, "utf8")
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// leaf issues a ten-minute code signing certificate for id, as Fulcio does for an identity token.
func (s *Sigstore) leaf(id Identity) (*x509.Certificate, *ecdsa.PrivateKey) {
	t := s.t
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(id.SAN)
	if err != nil {
		t.Fatal(err)
	}
	exts := []pkix.Extension{{Id: certificate.OIDIssuerV2, Value: s.derUTF8(id.Issuer)}}
	for _, e := range []struct {
		oid asn1.ObjectIdentifier
		v   string
	}{
		{certificate.OIDSourceRepositoryURI, id.Ext.SourceRepositoryURI},
		{certificate.OIDSourceRepositoryRef, id.Ext.SourceRepositoryRef},
		{certificate.OIDBuildConfigURI, id.Ext.BuildConfigURI},
		{certificate.OIDBuildSignerURI, id.Ext.BuildSignerURI},
		{certificate.OIDRunnerEnvironment, id.Ext.RunnerEnvironment},
	} {
		if e.v != "" {
			exts = append(exts, pkix.Extension{Id: e.oid, Value: s.derUTF8(e.v)})
		}
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.inter, &key.PublicKey, s.interK)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// logEntry puts body in the log at integrated time now, with an inclusion proof and a signed entry timestamp.
func (s *Sigstore) logEntry(kind string, body []byte) *protorekor.TransparencyLogEntry {
	t := s.t
	t.Helper()
	logID, err := s.Log.RekorLogID()
	if err != nil {
		t.Fatal(err)
	}
	rawID, err := hex.DecodeString(logID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	set, err := s.Log.RekorSignPayload(tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: now, LogIndex: 0, LogID: logID})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.Log.GetInclusionProof(body)
	if err != nil {
		t.Fatal(err)
	}
	rootHash, err := hex.DecodeString(*proof.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	return &protorekor.TransparencyLogEntry{
		LogIndex: 0, LogId: &protocommon.LogId{KeyId: rawID}, KindVersion: &protorekor.KindVersion{Kind: kind, Version: "0.0.1"},
		IntegratedTime: now, InclusionPromise: &protorekor.InclusionPromise{SignedEntryTimestamp: set},
		InclusionProof: &protorekor.InclusionProof{LogIndex: 0, RootHash: rootHash, TreeSize: *proof.TreeSize,
			Checkpoint: &protorekor.Checkpoint{Envelope: *proof.Checkpoint}},
		CanonicalizedBody: body,
	}
}

func (s *Sigstore) marshal(pb *protobundle.Bundle) []byte {
	s.t.Helper()
	b, err := bundle.NewBundle(pb)
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := b.MarshalJSON()
	if err != nil {
		s.t.Fatal(err)
	}
	return raw
}

func material(cert *x509.Certificate, tle *protorekor.TransparencyLogEntry) *protobundle.VerificationMaterial {
	return &protobundle.VerificationMaterial{
		Content:     &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw}},
		TlogEntries: []*protorekor.TransparencyLogEntry{tle},
	}
}

// SignBlob is `cosign sign-blob --bundle` by id of a file whose sha256 is digest: the .sigstore.json.
func (s *Sigstore) SignBlob(id Identity, digest [32]byte) []byte {
	t := s.t
	t.Helper()
	cert, key := s.leaf(id)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": map[string]any{
		"data":      map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(digest[:])}},
		"signature": map[string]any{"content": sig, "publicKey": map[string]any{"content": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return s.marshal(&protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: material(cert, s.logEntry("hashedrekord", body)),
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: digest[:]}, Signature: sig,
		}},
	})
}

// Attest signs an in-toto statement as a DSSE envelope by id, the way slsa-github-generator v2.1.0 writes its
// .intoto.jsonl (one Sigstore bundle).
func (s *Sigstore) Attest(id Identity, statement []byte) []byte {
	t := s.t
	t.Helper()
	cert, key := s.leaf(id)
	const payloadType = "application/vnd.in-toto+json"
	h := sha256.Sum256(dsse.PAE(payloadType, statement))
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	env := &dsse.Envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(statement),
		Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}}}
	entry, err := s.Log.GenerateTlogEntry(cert, env, sig, time.Now().Unix(), true)
	if err != nil {
		t.Fatal(err)
	}
	return s.marshal(&protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: material(cert, s.logEntry("dsse", entry.TransparencyLogEntry().GetCanonicalizedBody())),
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: statement, PayloadType: payloadType, Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
	})
}

// Provenance is the in-toto statement the generic generator writes for a run: an SLSA predicate of builder with one
// subject (sha256) per artifact, built from repo at ref by entryPoint.
func Provenance(t testing.TB, builder, predicateType, repo, ref, entryPoint string, subjects map[string][32]byte) []byte {
	t.Helper()
	var subj []map[string]any
	for name, h := range subjects {
		subj = append(subj, map[string]any{"name": name, "digest": map[string]string{"sha256": hex.EncodeToString(h[:])}})
	}
	b, err := json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": predicateType, "subject": subj,
		"predicate": map[string]any{
			"builder":    map[string]any{"id": builder},
			"buildType":  "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
			"invocation": map[string]any{"configSource": map[string]any{"uri": "git+" + repo + "@" + ref, "entryPoint": entryPoint}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ReleaseAssets signs an artifact the way release CI does: the .sigstore.json is a blob signature by signer, the
// .intoto.jsonl the provenance by builder (whose predicate names builder.SAN as the builder id) with the artifact as
// one of two subjects of the run.
func (s *Sigstore) ReleaseAssets(signer, builder Identity, predicateType, name string, hash [32]byte) (sig, prov []byte) {
	s.t.Helper()
	other := sha256.Sum256([]byte("another bundle of the same run"))
	st := Provenance(s.t, builder.SAN, predicateType, builder.Ext.SourceRepositoryURI, builder.Ext.SourceRepositoryRef,
		".github/workflows/release.yml", map[string][32]byte{name: hash, "other-1.0.0.bundle.tar": other})
	return s.SignBlob(signer, hash), append(s.Attest(builder, st), '\n')
}
