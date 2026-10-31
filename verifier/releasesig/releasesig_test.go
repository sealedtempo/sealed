package releasesig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/sealedtempo/sealed/internal/sigstoretest"
	"github.com/sealedtempo/sealed/runtime/composer"
	verify "github.com/sealedtempo/sealed/verifier"
)

// assetServer serves release assets by URL path and counts requests. No test reaches a Sigstore service: every
// bundle is verified offline.
type assetServer struct {
	*httptest.Server
	base   string
	mu     sync.Mutex
	assets map[string][]byte
	hits   map[string]int
}

func newAssetServer(t *testing.T) *assetServer {
	t.Helper()
	s := &assetServer{assets: map[string][]byte{}, hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		body, ok := s.assets[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	s.base = s.URL + "/sealedtempo/sealed/releases/download"
	return s
}

// put serves body at <bundle URL of rel><suffix>.
func (s *assetServer) put(t *testing.T, rel verify.ComposeRelease, suffix string, body []byte) {
	t.Helper()
	a, err := composer.NewReleaseAssets(s.base, rel.App, rel.Version)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(a.Bundle, s.URL) + suffix
	if body == nil {
		delete(s.assets, path)
		return
	}
	s.assets[path] = body
}

func (s *assetServer) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hits {
		n += h
	}
	return n
}

// releaseCI is the identity of release.yml's build job on main.
func releaseCI() sigstoretest.Identity {
	return sigstoretest.GitHubActions(ReleaseWorkflow, SourceRepository, SourceRef, ReleaseWorkflow)
}

// slsaGenerator is the identity of slsa-github-generator v2.1.0 called by release.yml on main.
func slsaGenerator() sigstoretest.Identity {
	return sigstoretest.GitHubActions(SLSABuilder, SourceRepository, SourceRef, ReleaseWorkflow)
}

func statement(t *testing.T, builder, predicateType string, subjects map[string][32]byte) []byte {
	return sigstoretest.Provenance(t, builder, predicateType, SourceRepository, SourceRef, ".github/workflows/release.yml", subjects)
}

func release(app, version string) verify.ComposeRelease {
	return verify.ComposeRelease{App: app, Version: version, BundleHash: sha256.Sum256([]byte("bundle " + app + " " + version))}
}

// releaseWorld is one release as release CI publishes it: the bundle's .sigstore.json by release.yml on main, and the
// run's provenance (this bundle and another one of the same run) by slsa-github-generator v2.1.0 for release.yml.
type releaseWorld struct {
	ls  *sigstoretest.Sigstore
	srv *assetServer
	rel verify.ComposeRelease
}

func newReleaseWorld(t *testing.T) *releaseWorld {
	t.Helper()
	w := &releaseWorld{ls: sigstoretest.New(t), srv: newAssetServer(t), rel: release("notes", "1.0.0-sealed.1")}
	w.srv.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(releaseCI(), w.rel.BundleHash))
	w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, slsaGenerator(), SLSABuilder, SLSAPredicateType, w.rel.BundleHash))
	return w
}

func (w *releaseWorld) provenance(t *testing.T, id sigstoretest.Identity, builder, predicateType string, hash [32]byte) []byte {
	t.Helper()
	other := sha256.Sum256([]byte("another bundle of the run"))
	return append(w.ls.Attest(id, statement(t, builder, predicateType, map[string][32]byte{
		"notes-1.0.0-sealed.1.bundle.tar": hash, "crm-2.0.0.bundle.tar": other,
	})), '\n')
}

// verifier checks against the local Sigstore with the production policy except the SCT requirement.
func (w *releaseWorld) verifier(t *testing.T, bases ...string) *Verifier {
	t.Helper()
	if len(bases) == 0 {
		bases = []string{w.srv.base}
	}
	v, err := newVerifier(Options{Bases: bases, AllowHTTP: true}, w.ls.TrustedRoot(), false)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestReleaseSignedByReleaseCI is the expected shape: both assets verify, and the result names release.yml on main,
// the pinned builder and the asset URLs. A second verification of the same release is served from the cache.
func TestReleaseSignedByReleaseCI(t *testing.T) {
	w := newReleaseWorld(t)
	v := w.verifier(t)
	got, err := v.VerifyReleaseSignature(context.Background(), w.rel)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := composer.NewReleaseAssets(w.srv.base, w.rel.App, w.rel.Version)
	if got.Signer != ReleaseWorkflow || got.Issuer != GitHubOIDCIssuer || got.Builder != SLSABuilder || got.BuildConfig != ReleaseWorkflow ||
		got.SignatureURL != a.Bundle+".sigstore.json" || got.ProvenanceURL != a.Bundle+".intoto.jsonl" || got.SignedAt == 0 {
		t.Fatalf("result %+v", got)
	}
	hits := w.srv.total()
	if _, err := v.VerifyReleaseSignature(context.Background(), w.rel); err != nil || w.srv.total() != hits {
		t.Fatalf("second verification: %v, %d new requests", err, w.srv.total()-hits)
	}
}

// TestReleaseNotSignedByReleaseCIFails: every way a release can lack release CI's signature fails, with a reason.
func TestReleaseNotSignedByReleaseCIFails(t *testing.T) {
	attacker := releaseCI()
	attacker.SAN = "https://github.com/attacker/sealed/.github/workflows/release.yml@refs/heads/main"
	attacker.Ext.SourceRepositoryURI = "https://github.com/attacker/sealed"
	attacker.Ext.BuildConfigURI = attacker.SAN
	branch := releaseCI()
	branch.SAN = SourceRepository + "/.github/workflows/release.yml@refs/heads/dev"
	branch.Ext.SourceRepositoryRef = "refs/heads/dev"
	branch.Ext.BuildConfigURI = branch.SAN
	otherIssuer := releaseCI()
	otherIssuer.Issuer = "https://accounts.google.com"
	sameSANOtherRef := releaseCI()
	sameSANOtherRef.Ext.SourceRepositoryRef = "refs/heads/dev"
	otherCaller := slsaGenerator()
	otherCaller.Ext.BuildConfigURI = SourceRepository + "/.github/workflows/ci.yml@refs/heads/main"
	oldBuilder := slsaGenerator()
	oldBuilder.SAN = strings.Replace(SLSABuilder, "v2.1.0", "v2.0.0", 1)
	other := sha256.Sum256([]byte("a bundle CI never built"))
	h := release("notes", "1.0.0-sealed.1").BundleHash
	notesHash := hex.EncodeToString(h[:])

	cases := []struct {
		name  string
		setup func(t *testing.T, w *releaseWorld)
		want  string
	}{
		{"signature by a test identity of another repository", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(attacker, w.rel.BundleHash))
		}, "not signed by " + ReleaseWorkflow},
		{"signature by release.yml on another branch", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(branch, w.rel.BundleHash))
		}, `expected SAN value "` + ReleaseWorkflow + `", got "` + branch.SAN + `"`},
		{"signature by release.yml with another OIDC issuer", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(otherIssuer, w.rel.BundleHash))
		}, "issuer"},
		{"signature whose certificate names another ref", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(sameSANOtherRef, w.rel.BundleHash))
		}, "SourceRepositoryRef"},
		{"signature over another bundle", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(releaseCI(), other))
		}, "for bundleHash 0x" + notesHash},
		{"signature that is an attestation, not a blob signature", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, w.ls.Attest(releaseCI(), statement(t, SLSABuilder, SLSAPredicateType, map[string][32]byte{"x": w.rel.BundleHash})))
		}, "not a blob signature"},
		{"no signature", func(t *testing.T, w *releaseWorld) { w.srv.put(t, w.rel, SignatureSuffix, nil) }, "HTTP 404"},
		{"signature that is not a Sigstore bundle", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, SignatureSuffix, []byte(`{"base64Signature":"MEUCIQ==","cert":"x"}`))
		}, "not a Sigstore bundle"},
		{"no provenance", func(t *testing.T, w *releaseWorld) { w.srv.put(t, w.rel, ProvenanceSuffix, nil) }, "HTTP 404"},
		{"provenance signed by release.yml itself, not the builder", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, releaseCI(), SLSABuilder, SLSAPredicateType, w.rel.BundleHash))
		}, "not signed by " + SLSABuilder},
		{"provenance of the builder called by another workflow", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, otherCaller, SLSABuilder, SLSAPredicateType, w.rel.BundleHash))
		}, "BuildConfigURI"},
		{"provenance of another builder version", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, oldBuilder, SLSABuilder, SLSAPredicateType, w.rel.BundleHash))
		}, `got "` + oldBuilder.SAN + `"`},
		{"provenance without the bundleHash as a subject", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, slsaGenerator(), SLSABuilder, SLSAPredicateType, other))
		}, "no provenance subject has sha256 " + notesHash},
		{"provenance naming another builder", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, slsaGenerator(), "https://example.com/builder", SLSAPredicateType, w.rel.BundleHash))
		}, "provenance builder"},
		{"provenance with another predicate type", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.provenance(t, slsaGenerator(), SLSABuilder, "https://slsa.dev/provenance/v1", w.rel.BundleHash))
		}, "predicate type"},
		{"provenance that is a blob signature", func(t *testing.T, w *releaseWorld) {
			w.srv.put(t, w.rel, ProvenanceSuffix, w.ls.SignBlob(slsaGenerator(), w.rel.BundleHash))
		}, "not an attestation"},
		{"assets signed by another Sigstore", func(t *testing.T, w *releaseWorld) {
			rogue := sigstoretest.New(t)
			w.srv.put(t, w.rel, SignatureSuffix, rogue.SignBlob(releaseCI(), w.rel.BundleHash))
		}, "transparency log"},
		{"certificate from another CA, logged in the trusted log", func(t *testing.T, w *releaseWorld) {
			rogue := sigstoretest.New(t)
			rogue.Log = w.ls.Log
			w.srv.put(t, w.rel, SignatureSuffix, rogue.SignBlob(releaseCI(), w.rel.BundleHash))
		}, "leaf certificate verification failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newReleaseWorld(t)
			tc.setup(t, w)
			_, err := w.verifier(t).VerifyReleaseSignature(context.Background(), w.rel)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestProductionPolicyRefusesLocallySignedRelease: bundles generated locally, even with release.yml's exact identity
// and the right digest, fail the production verifier, whose only CA is Sigstore's public-good Fulcio. This is what a
// release published with the OPS key but without release CI looks like.
func TestProductionPolicyRefusesLocallySignedRelease(t *testing.T) {
	w := newReleaseWorld(t)
	if _, err := w.verifier(t).VerifyReleaseSignature(context.Background(), w.rel); err != nil {
		t.Fatalf("the local Sigstore's own verifier must accept its release: %v", err)
	}
	prod, err := New(Options{Bases: []string{w.srv.base}, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = prod.VerifyReleaseSignature(context.Background(), w.rel)
	if err == nil || !strings.Contains(err.Error(), "not signed by "+ReleaseWorkflow) {
		t.Fatalf("production verifier: %v", err)
	}
	t.Log(err)
}

// TestPublicGoodBundleOfAnotherRepository uses a real public-good bundle (testdata, from sigstore-go): GitHub Actions
// provenance of sigstore/sigstore-js, signed by its release.yml on main. The production verifier, offline with the
// embedded trusted root, accepts its certificate chain, SCT, transparency log entry and timestamps, and refuses it
// because the identity is not ours.
func TestPublicGoodBundleOfAnotherRepository(t *testing.T) {
	raw, err := os.ReadFile("testdata/sigstore-js-2.0.0-provenance.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	prod, err := New(Options{Bases: []string{"https://github.com/sealedtempo/sealed/releases/download"}})
	if err != nil {
		t.Fatal(err)
	}
	// Everything but the identity verifies with the production options and the embedded root.
	b, err := parseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := prod.sig.Verify(b, sgverify.NewPolicy(sgverify.WithoutArtifactUnsafe(), sgverify.WithoutIdentitiesUnsafe()))
	if err != nil {
		t.Fatalf("the embedded trusted root does not verify a public-good bundle: %v", err)
	}
	if c := res.Signature.Certificate; c.SubjectAlternativeName != "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main" ||
		c.Extensions.Issuer != GitHubOIDCIssuer || c.Extensions.SourceRepositoryURI != "https://github.com/sigstore/sigstore-js" ||
		c.Extensions.SourceRepositoryRef != SourceRef || c.Extensions.BuildConfigURI != c.SubjectAlternativeName {
		t.Fatalf("certificate %+v", c)
	}
	// As a release signature or as provenance, it is refused for its identity.
	if _, err := prod.VerifyProvenance(raw, [32]byte{}); err == nil || !strings.Contains(err.Error(), `got "https://github.com/sigstore/sigstore-js/`) {
		t.Fatalf("provenance: %v", err)
	}
	if _, err := prod.VerifySignature(raw, [32]byte{}); err == nil || !strings.Contains(err.Error(), "not a blob signature") {
		t.Fatalf("signature: %v", err)
	}
}

// TestMirrors: a mirror is tried when the first base fails, and a base serving a bad signature does not stop the next.
func TestMirrors(t *testing.T) {
	w := newReleaseWorld(t)
	bad := newAssetServer(t)
	bad.put(t, w.rel, SignatureSuffix, w.ls.SignBlob(releaseCI(), sha256.Sum256([]byte("other"))))
	empty := newAssetServer(t)
	got, err := w.verifier(t, empty.base, bad.base, w.srv.base).VerifyReleaseSignature(context.Background(), w.rel)
	if err != nil || !strings.HasPrefix(got.SignatureURL, w.srv.base) {
		t.Fatalf("%+v %v", got, err)
	}
	_, err = w.verifier(t, empty.base, bad.base).VerifyReleaseSignature(context.Background(), w.rel)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "for bundleHash") {
		t.Fatalf("both failures are reported: %v", err)
	}
}

func TestBasesMustBeHTTPS(t *testing.T) {
	if _, err := New(Options{Bases: []string{"http://assets.example/releases"}}); err == nil {
		t.Fatal("plain http base accepted")
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("no base accepted")
	}
	if _, err := New(Options{Bases: []string{"http://127.0.0.1:1/releases"}, AllowHTTP: true}); err != nil {
		t.Fatal(err)
	}
}

// TestEmbeddedTrustedRoot pins the embedded public-good trusted root, so replacing it is a reviewed change, and checks
// it holds what the production policy needs.
func TestEmbeddedTrustedRoot(t *testing.T) {
	if got := sha256.Sum256(trustedRootJSON); hex.EncodeToString(got[:]) != "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66" {
		t.Fatalf("trusted_root.json sha256 %x: update the comment in releasesig.go with its TUF version and check", got)
	}
	tr, err := PublicGoodTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	var logs []string
	for _, l := range tr.RekorLogs() {
		logs = append(logs, l.BaseURL)
	}
	joined := strings.Join(logs, " ")
	if !strings.Contains(joined, "https://rekor.sigstore.dev") || !strings.Contains(joined, "https://log2025-1.rekor.sigstore.dev") ||
		len(tr.FulcioCertificateAuthorities()) == 0 || len(tr.CTLogs()) == 0 || len(tr.TimestampingAuthorities()) == 0 {
		t.Fatalf("trusted root: logs %v, %d CAs, %d CT logs, %d TSAs", logs, len(tr.FulcioCertificateAuthorities()), len(tr.CTLogs()), len(tr.TimestampingAuthorities()))
	}
}

// TestIdentitiesMatchTheWorkflow keeps the hard-coded identities equal to what .github/workflows/release.yml signs
// with: the generator it calls, by tag, and the repository config/defaults.yaml names.
func TestIdentitiesMatchTheWorkflow(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	gen := strings.TrimPrefix(SLSABuilder, "https://github.com/")
	gen = strings.Replace(gen, "@refs/tags/", "@", 1)
	if !strings.Contains(string(wf), "uses: "+gen+"\n") {
		t.Fatalf("release.yml does not call %s", gen)
	}
	if !strings.Contains(string(wf), "branches: [main]") {
		t.Fatal("release.yml no longer runs on main only")
	}
	defaults, err := os.ReadFile("../../config/defaults.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(defaults), SourceRepository) {
		t.Fatalf("config/defaults.yaml does not name %s", SourceRepository)
	}
}

// The provenance file may hold one bundle per line; a line that verifies is enough.
func TestProvenanceLines(t *testing.T) {
	w := newReleaseWorld(t)
	good := w.provenance(t, slsaGenerator(), SLSABuilder, SLSAPredicateType, w.rel.BundleHash)
	other := w.provenance(t, slsaGenerator(), SLSABuilder, SLSAPredicateType, sha256.Sum256([]byte("x")))
	v := w.verifier(t)
	if _, err := v.VerifyProvenance(append(other, good...), w.rel.BundleHash); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyProvenance([]byte("\n\n"), w.rel.BundleHash); err == nil {
		t.Fatal("empty provenance accepted")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(good); err != nil {
		t.Fatalf("a provenance line is one Sigstore bundle: %v", err)
	}
}
