package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// SLSAGenerator is the provenance generator reference used by release.yml. It must be a vX.Y.Z tag (the
// generator rejects SHA references); release.yml checks the tag still resolves to SLSAGeneratorCommit.
const (
	SLSAGenerator       = "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
	SLSAGeneratorCommit = "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"
	OIDCIssuer          = "https://token.actions.githubusercontent.com"
)

// ReleaseDoc is the machine-readable release summary uploaded as <appId>-<version>.release.json
// (schema sealed-release/v1) and rendered into the release notes.
type ReleaseDoc struct {
	Schema           string         `json:"schema"`
	App              string         `json:"app"`
	AppID            string         `json:"appId"`
	Version          string         `json:"version"`
	Tag              string         `json:"tag"`
	ReleaseID        string         `json:"releaseId"`
	BundleHash       string         `json:"bundleHash"`
	EgressPolicyHash string         `json:"egressPolicyHash"`
	SBOMHash         string         `json:"sbomHash"`
	BundleSize       int            `json:"bundleSize"`
	Repository       string         `json:"repository"`
	Commit           string         `json:"commit"`
	WorkflowRun      string         `json:"workflowRun,omitempty"`
	SignerIdentity   string         `json:"signerIdentity"`
	OIDCIssuer       string         `json:"oidcIssuer"`
	ProvenanceBy     string         `json:"provenanceBuilder"`
	Assets           AssetNames     `json:"assets"`
	Images           []ReleaseImage `json:"images"`
	Rekor            *RekorEntry    `json:"rekor,omitempty"`
	Onchain          *OnchainRecord `json:"onchain,omitempty"`
}

// ReleaseImage is one image of the release.
type ReleaseImage struct {
	Name    string       `json:"name"`
	Ref     string       `json:"ref"`
	Source  string       `json:"source"`
	License string       `json:"license"`
	Scan    *ScanSummary `json:"scan,omitempty"`
}

// RekorEntry locates the bundle signature in the Rekor transparency log.
type RekorEntry struct {
	LogIndex       int64  `json:"logIndex"`
	IntegratedTime int64  `json:"integratedTime,omitempty"`
	URL            string `json:"url"`
}

// OnchainRecord is the publishRelease transaction (written by scripts/release/publish-release.sh).
type OnchainRecord struct {
	ChainID          uint64 `json:"chainId"`
	AppRegistry      string `json:"appRegistry"`
	TxHash           string `json:"txHash"`
	BlockNumber      uint64 `json:"blockNumber"`
	From             string `json:"from"`
	ReleaseID        string `json:"releaseId"`
	FeeUnits         string `json:"feeUnits,omitempty"` // fee token base units (6 decimals)
	FeeUSD           string `json:"feeUsd,omitempty"`
	Explorer         string `json:"explorer,omitempty"`
	AlreadyPublished bool   `json:"alreadyPublished,omitempty"`
}

// sigstoreBundle is the part of a Sigstore bundle (cosign sign-blob --bundle) the release reads.
type sigstoreBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		TlogEntries []struct {
			LogIndex       json.RawMessage `json:"logIndex"`
			IntegratedTime json.RawMessage `json:"integratedTime"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"messageDigest"`
		Signature string `json:"signature"`
	} `json:"messageSignature"`
}

// SigstoreParts is what a Sigstore bundle yields for the .sig and .crt assets.
type SigstoreParts struct {
	SignatureB64   string // base64 signature, as cosign --output-signature wrote it
	CertificatePEM []byte
	Rekor          *RekorEntry
}

// ParseSigstoreBundle extracts the signature, certificate and Rekor entry of a blob signature and checks
// that it signs the blob with the given sha256 digest. cosign 3 writes only the bundle, so .sig and .crt
// are derived from it.
func ParseSigstoreBundle(raw []byte, blobSHA256 [32]byte) (*SigstoreParts, error) {
	var sb sigstoreBundle
	if err := json.Unmarshal(raw, &sb); err != nil {
		return nil, fmt.Errorf("sigstore bundle: %w", err)
	}
	if !strings.HasPrefix(sb.MediaType, "application/vnd.dev.sigstore.bundle") {
		return nil, fmt.Errorf("sigstore bundle: unexpected mediaType %q", sb.MediaType)
	}
	if sb.MessageSignature == nil || sb.MessageSignature.Signature == "" {
		return nil, fmt.Errorf("sigstore bundle: no message signature (not a blob signature)")
	}
	if sb.MessageSignature.MessageDigest.Algorithm != "SHA2_256" {
		return nil, fmt.Errorf("sigstore bundle: digest algorithm %q, want SHA2_256", sb.MessageSignature.MessageDigest.Algorithm)
	}
	d, err := base64.StdEncoding.DecodeString(sb.MessageSignature.MessageDigest.Digest)
	if err != nil || !bytes.Equal(d, blobSHA256[:]) {
		return nil, fmt.Errorf("sigstore bundle: signs a different blob (digest mismatch)")
	}
	if _, err := base64.StdEncoding.DecodeString(sb.MessageSignature.Signature); err != nil {
		return nil, fmt.Errorf("sigstore bundle: signature is not base64")
	}
	var certB64 string
	switch {
	case sb.VerificationMaterial.Certificate != nil:
		certB64 = sb.VerificationMaterial.Certificate.RawBytes
	case sb.VerificationMaterial.X509CertificateChain != nil && len(sb.VerificationMaterial.X509CertificateChain.Certificates) > 0:
		certB64 = sb.VerificationMaterial.X509CertificateChain.Certificates[0].RawBytes
	default:
		return nil, fmt.Errorf("sigstore bundle: no signing certificate (keyless signing expected)")
	}
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil || len(der) == 0 {
		return nil, fmt.Errorf("sigstore bundle: certificate is not base64 DER")
	}
	parts := &SigstoreParts{SignatureB64: sb.MessageSignature.Signature,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	if len(sb.VerificationMaterial.TlogEntries) == 0 {
		return nil, fmt.Errorf("sigstore bundle: no Rekor entry (the signature must be in the transparency log)")
	}
	e := sb.VerificationMaterial.TlogEntries[0]
	idx, err := jsonInt(e.LogIndex)
	if err != nil {
		return nil, fmt.Errorf("sigstore bundle: logIndex: %w", err)
	}
	it, _ := jsonInt(e.IntegratedTime)
	parts.Rekor = &RekorEntry{LogIndex: idx, IntegratedTime: it, URL: "https://search.sigstore.dev/?logIndex=" + strconv.FormatInt(idx, 10)}
	return parts, nil
}

// jsonInt reads an int64 written as a JSON number or a decimal string (protobuf JSON uses strings).
func jsonInt(raw json.RawMessage) (int64, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0, fmt.Errorf("missing")
	}
	return strconv.ParseInt(s, 10, 64)
}

// ReleaseInputs are the files the release job collects for one app.
type ReleaseInputs struct {
	Bundle         string // bundle tar
	ScanDir        string // <image>.summary.json files written by `waivers check --summary`
	SigstoreBundle string // optional until signing ran
	Commit         string
	RunURL         string
	Identity       string // certificate identity (workflow ref)
	Onchain        string // optional publish-release.sh result
}

// BuildReleaseDoc assembles the release summary from the bundle and the job's outputs.
func BuildReleaseDoc(d Defaults, in ReleaseInputs) (*ReleaseDoc, error) {
	raw, err := os.ReadFile(in.Bundle)
	if err != nil {
		return nil, err
	}
	b, err := composer.LoadBundle(raw)
	if err != nil {
		return nil, err
	}
	var images []string
	for _, img := range b.Manifest.Images {
		images = append(images, img.Name)
	}
	assets, err := Assets(d, b.Manifest.ID, b.Version(), images)
	if err != nil {
		return nil, err
	}
	doc := &ReleaseDoc{Schema: "sealed-release/v1", App: b.Manifest.ID, AppID: b.AppID.Hex(), Version: b.Version(),
		Tag: assets.Tag, ReleaseID: b.ReleaseID.Hex(), BundleHash: b.Hash.Hex(), EgressPolicyHash: b.EgressPolicyHash.Hex(),
		SBOMHash: b.SBOMHash.Hex(), BundleSize: len(raw), Repository: d.RepoURL(), Commit: in.Commit, WorkflowRun: in.RunURL,
		SignerIdentity: in.Identity, OIDCIssuer: OIDCIssuer, ProvenanceBy: SLSAGenerator, Assets: assets}
	if doc.SignerIdentity == "" {
		doc.SignerIdentity = d.RepoURL() + "/.github/workflows/release.yml@refs/heads/main"
	}
	for _, img := range b.Manifest.Images {
		ri := ReleaseImage{Name: img.Name, Ref: img.Ref, Source: img.Source, License: img.LicenseSPDX}
		if in.ScanDir != "" {
			p := filepath.Join(in.ScanDir, img.Name+".summary.json")
			var s ScanSummary
			if err := readJSONFile(p, &s); err != nil {
				return nil, fmt.Errorf("scan summary of %s: %w", img.Name, err)
			}
			if s.Image != img.Name {
				return nil, fmt.Errorf("%s is the summary of %q", p, s.Image)
			}
			ri.Scan = &s
		}
		doc.Images = append(doc.Images, ri)
	}
	if in.SigstoreBundle != "" {
		sraw, err := os.ReadFile(in.SigstoreBundle)
		if err != nil {
			return nil, err
		}
		parts, err := ParseSigstoreBundle(sraw, sha256.Sum256(raw))
		if err != nil {
			return nil, err
		}
		doc.Rekor = parts.Rekor
	}
	if in.Onchain != "" {
		var rec OnchainRecord
		if err := readJSONFile(in.Onchain, &rec); err != nil {
			return nil, err
		}
		if !strings.EqualFold(rec.ReleaseID, doc.ReleaseID) {
			return nil, fmt.Errorf("onchain record is for release %s, not %s", rec.ReleaseID, doc.ReleaseID)
		}
		doc.Onchain = &rec
	}
	return doc, nil
}

// Notes renders the GitHub Release notes. Plain words, no em-dashes (operating rule 12).
func (doc *ReleaseDoc) Notes(d Defaults) string {
	var b strings.Builder
	a := doc.Assets
	fmt.Fprintf(&b, "Release `%s` of the catalog app `%s`, built and signed by the release workflow", doc.Version, doc.App)
	if doc.Commit != "" {
		fmt.Fprintf(&b, " from commit [`%s`](%s/commit/%s)", short(doc.Commit, 12), doc.Repository, doc.Commit)
	}
	b.WriteString(".\n\n")

	b.WriteString("## Onchain\n\n")
	if doc.Onchain != nil {
		fmt.Fprintf(&b, "Published on Tempo (chain %d) with `AppRegistry.publishRelease` at `%s`: transaction [`%s`](%s), block %d.\n\n",
			doc.Onchain.ChainID, doc.Onchain.AppRegistry, doc.Onchain.TxHash, explorerTx(d, doc.Onchain), doc.Onchain.BlockNumber)
	} else {
		b.WriteString("Pending: the `AppRegistry.publishRelease` transaction has not been sent yet. Until it is, this release is not active and no stack can approve it.\n\n")
	}

	b.WriteString("## Hashes\n\n| field | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| appId | `%s` |\n| version | `%s` |\n| releaseId | `%s` |\n", doc.AppID, doc.Version, doc.ReleaseID)
	fmt.Fprintf(&b, "| bundleHash | `%s` (sha256 of `%s`, %d bytes) |\n", doc.BundleHash, a.Bundle, doc.BundleSize)
	fmt.Fprintf(&b, "| egressPolicyHash | `%s` |\n| sbomHash | `%s` |\n\n", doc.EgressPolicyHash, doc.SBOMHash)

	b.WriteString("## Images\n\n| image | reference | license | critical | high | medium | low | waived |\n|---|---|---|---|---|---|---|---|\n")
	for _, img := range doc.Images {
		if img.Scan == nil {
			fmt.Fprintf(&b, "| %s | `%s` | %s | | | | | |\n", img.Name, img.Ref, img.License)
			continue
		}
		c := img.Scan.Counts
		fmt.Fprintf(&b, "| %s | `%s` | %s | %d | %d | %d | %d | %d |\n", img.Name, img.Ref, img.License,
			c["critical"], c["high"], c["medium"], c["low"], len(img.Scan.Accepted))
	}
	var accepted []string
	for _, img := range doc.Images {
		if img.Scan == nil {
			continue
		}
		for _, f := range img.Scan.Accepted {
			accepted = append(accepted, fmt.Sprintf("- %s: %s %s in %s %s, waived until %s. %s", img.Name, f.Severity, f.ID, f.Package, f.Version, f.Expires, f.Note))
		}
	}
	if len(accepted) > 0 {
		b.WriteString("\nAccepted findings (waivers.yaml):\n\n" + strings.Join(accepted, "\n") + "\n")
	}
	b.WriteString("\nSBOMs (Syft, SPDX JSON) and Grype reports are attached per image and are also inside the bundle at `sbom/<image>.spdx.json` and `scan/<image>.json`.\n\n")

	b.WriteString("## Signature and provenance\n\n")
	fmt.Fprintf(&b, "- Signed with cosign keyless signing through GitHub OIDC (identity `%s`, issuer `%s`).\n", doc.SignerIdentity, doc.OIDCIssuer)
	if doc.Rekor != nil {
		fmt.Fprintf(&b, "- Rekor transparency log entry %d: %s\n", doc.Rekor.LogIndex, doc.Rekor.URL)
	}
	fmt.Fprintf(&b, "- SLSA build provenance from `%s`: `%s`.\n", doc.ProvenanceBy, a.Provenance)
	fmt.Fprintf(&b, "- `%s` and `%s` hold the signature and certificate; `%s` holds both plus the Rekor inclusion proof.\n\n", a.Signature, a.Certificate, a.SigstoreBundle)

	b.WriteString("## Verify\n\n```sh\n")
	fmt.Fprintf(&b, "gh release download %s --repo %s --dir %s\ncd %s\n", doc.Tag, d.RepoSlug(), doc.Tag, doc.Tag)
	fmt.Fprintf(&b, "sha256sum %s   # %s\n", a.Bundle, strings.TrimPrefix(doc.BundleHash, "0x"))
	fmt.Fprintf(&b, "cosign verify-blob --bundle %s \\\n  --certificate-identity %s \\\n  --certificate-oidc-issuer %s %s\n", a.SigstoreBundle, doc.SignerIdentity, doc.OIDCIssuer, a.Bundle)
	fmt.Fprintf(&b, "slsa-verifier verify-artifact %s --provenance-path %s --source-uri %s\n", a.Bundle, a.Provenance, strings.TrimPrefix(doc.Repository, "https://"))
	b.WriteString("# Rebuild the bundle from the source tree at the release commit with the attached SBOMs and scans:\n")
	b.WriteString("mkdir -p sbom scan\n")
	for _, img := range doc.Images {
		fmt.Fprintf(&b, "cp %s sbom/%s.spdx.json && cp %s scan/%s.json\n", a.SBOM[img.Name], img.Name, a.Scan[img.Name], img.Name)
	}
	fmt.Fprintf(&b, "sealed release build %s --sbom-dir sbom --scan-dir scan --out rebuilt.tar && cmp rebuilt.tar %s\n```\n", doc.App, a.Bundle)
	return b.String()
}

func explorerTx(d Defaults, rec *OnchainRecord) string {
	if rec.Explorer != "" {
		return rec.Explorer
	}
	return d.ExplorerURL + "/tx/" + rec.TxHash
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// AddOnchain reads an existing release.json and adds the onchain record, which must be for its release.
func AddOnchain(basePath, onchainPath string) (*ReleaseDoc, error) {
	var doc ReleaseDoc
	if err := readJSONFile(basePath, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != "sealed-release/v1" {
		return nil, fmt.Errorf("%s: schema %q, want sealed-release/v1", basePath, doc.Schema)
	}
	if onchainPath == "" {
		return nil, fmt.Errorf("--base needs --onchain")
	}
	var rec OnchainRecord
	if err := readJSONFile(onchainPath, &rec); err != nil {
		return nil, err
	}
	if !strings.EqualFold(rec.ReleaseID, doc.ReleaseID) {
		return nil, fmt.Errorf("onchain record is for release %s, not %s", rec.ReleaseID, doc.ReleaseID)
	}
	doc.Onchain = &rec
	return &doc, nil
}
