package composer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Release asset URL rule (D-046, integration brief item 18). A release of
// app <appId> (the slug, for example crm) at version <v> (the manifest's
// release_version, else upstream.version: the version hashed into
// releaseId) is the GitHub Release tagged <appId>-v<t> under
// catalog.release_asset_base, where <t> is <v> without a leading "v" or
// "V" before a digit (TagVersion: v1.58.2 is tagged coding-agent-v1.58.2,
// never coding-agent-vv1.58.2; 10.0.11 is tagged crm-v10.0.11). The asset
// names keep <v> exactly. The release holds:
//
//	<appId>-<v>.bundle.tar             the bundle; sha256 is the onchain bundleHash
//	<appId>-<v>.bundle.tar.sig         cosign signature
//	<appId>-<v>.bundle.tar.crt         cosign (Fulcio) certificate
//	<appId>-<v>.bundle.tar.intoto.jsonl SLSA provenance
//	sbom.<image>.spdx.json             the SBOM of each image (the bundle's sbom/<image>.spdx.json)
//
// The key broker, sealed-verifierd and the CLI fetch bundles by this URL and
// accept them only when sha256 equals the onchain bundleHash.

// MaxReleaseBundleBytes bounds a fetched bundle (the bundle loader's limit).
const MaxReleaseBundleBytes = maxBundleBytes

var (
	releaseSlugRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	releaseVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`)
	sbomImageRe      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// CheckReleaseVersion reports whether a version can name release assets.
// GitHub renames asset names that contain characters other than letters,
// digits, ".", "_" and "-" (a "+" build suffix included), so such a version
// would publish a bundle at a different URL than the one verifiers fetch.
// A version may start with "v" or "V" only before a digit (v1.58.2, whose
// tag drops that letter); any other leading v would give a <appId>-vv... or
// <appId>-vV... tag.
func CheckReleaseVersion(version string) error {
	if !releaseVersionRe.MatchString(version) {
		return fmt.Errorf("release version %q must match %s to name release assets (set release_version without +)", version, releaseVersionRe)
	}
	if (version[0] == 'v' || version[0] == 'V') && TagVersion(version) == version {
		return fmt.Errorf("release version %q starts with %q but not before a digit, so its tag would read <appId>-v%s; set release_version", version, version[:1], version)
	}
	return nil
}

// TagVersion is a release version as its tag names it: without one leading
// "v" or "V" when a digit follows, so the tag's own "v" is never doubled.
// Versions are compared and hashed (releaseId) as they are; only the tag
// changes. Two versions that differ only by that letter (1.2.3 and v1.2.3)
// share a tag, so an app can release only one of them.
func TagVersion(version string) string {
	if len(version) > 1 && (version[0] == 'v' || version[0] == 'V') && version[1] >= '0' && version[1] <= '9' {
		return version[1:]
	}
	return version
}

// ReleaseTag is the GitHub Release tag of an app version:
// <appId>-v<TagVersion(version)>.
func ReleaseTag(slug, version string) string { return slug + "-v" + TagVersion(version) }

// BundleAssetName is the bundle's asset name: <appId>-<version>.bundle.tar.
func BundleAssetName(slug, version string) string { return slug + "-" + version + ".bundle.tar" }

// SBOMPath is an image SBOM's path inside the bundle.
func SBOMPath(image string) string { return sbomDir + image + sbomSuffix }

// SBOMAssetName is an image SBOM's release asset name. GitHub asset names
// cannot contain "/", so the bundle path sbom/<image>.spdx.json is published
// as sbom.<image>.spdx.json.
func SBOMAssetName(image string) string { return "sbom." + image + sbomSuffix }

// ReleaseAssets holds the URLs of one release's assets.
type ReleaseAssets struct {
	Base        string // catalog.release_asset_base, no trailing slash
	Slug        string
	Version     string
	Tag         string
	Bundle      string
	Signature   string
	Certificate string
	Provenance  string
}

// NewReleaseAssets applies the asset URL rule. base is
// catalog.release_asset_base from config/defaults.yaml, for example
// https://github.com/sealedtempo/sealed/releases/download.
func NewReleaseAssets(base, slug, version string) (ReleaseAssets, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ReleaseAssets{}, fmt.Errorf("release asset base %q must be an http(s) URL without credentials, query or fragment", base)
	}
	base = strings.TrimRight(base, "/")
	if !releaseSlugRe.MatchString(slug) {
		return ReleaseAssets{}, fmt.Errorf("app id %q is not a catalog slug", slug)
	}
	if err := CheckReleaseVersion(version); err != nil {
		return ReleaseAssets{}, err
	}
	tag := ReleaseTag(slug, version)
	bundle := base + "/" + tag + "/" + BundleAssetName(slug, version)
	return ReleaseAssets{
		Base: base, Slug: slug, Version: version, Tag: tag,
		Bundle:      bundle,
		Signature:   bundle + ".sig",
		Certificate: bundle + ".crt",
		Provenance:  bundle + ".intoto.jsonl",
	}, nil
}

// SBOM is the URL of an image's SBOM in the same release.
func (a ReleaseAssets) SBOM(image string) (string, error) {
	if !sbomImageRe.MatchString(image) {
		return "", fmt.Errorf("image name %q is not a manifest image name", image)
	}
	return a.Base + "/" + a.Tag + "/" + SBOMAssetName(image), nil
}

// Assets returns the release asset URLs of a loaded bundle.
func (b *Bundle) Assets(base string) (ReleaseAssets, error) {
	return NewReleaseAssets(base, b.Manifest.ID, b.Version())
}

// BundleCache stores bundles by bundleHash (content addressed).
type BundleCache interface {
	// Get returns the bundle bytes for a hash, or false. Implementations
	// must return only bytes whose sha256 is the hash.
	Get(h Hash) ([]byte, bool)
	Put(h Hash, tar []byte) error
}

// DirCache is a BundleCache in a directory: <dir>/<hex bundleHash>.bundle.tar.
// Entries are re-hashed on every read, so a corrupted or swapped file is a
// miss, never a wrong bundle.
type DirCache struct{ Dir string }

func (c DirCache) path(h Hash) string {
	return filepath.Join(c.Dir, hex.EncodeToString(h[:])+".bundle.tar")
}

// Get implements BundleCache.
func (c DirCache) Get(h Hash) ([]byte, bool) {
	b, err := os.ReadFile(c.path(h))
	if err != nil || len(b) > MaxReleaseBundleBytes || SHA256(b) != h {
		return nil, false
	}
	return b, true
}

// Put implements BundleCache, writing through a temp file and a rename.
func (c DirCache) Put(h Hash, tar []byte) error {
	if SHA256(tar) != h {
		return errors.New("bundle cache: bytes do not match the hash")
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".bundle-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(tar); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path(h))
}

// BundleHashMismatchError is returned when fetched bytes do not hash to the
// onchain bundleHash (key broker reason bundle_hash_mismatch).
type BundleHashMismatchError struct {
	URL       string
	Want, Got Hash
}

func (e *BundleHashMismatchError) Error() string {
	return fmt.Sprintf("bundle %s: sha256 %s does not match the onchain bundleHash %s", e.URL, e.Got.Hex(), e.Want.Hex())
}

// FetchBundle returns the bundle with the given onchain bundleHash, from the
// cache or else downloaded from url (normally ReleaseAssets.Bundle). The
// bytes are accepted only when their sha256 equals bundleHash, then loaded
// with LoadBundle (canonical form only). client nil means
// http.DefaultClient; cache may be nil.
func FetchBundle(ctx context.Context, client *http.Client, url string, bundleHash Hash, cache BundleCache) (*Bundle, error) {
	if cache != nil {
		if b, ok := cache.Get(bundleHash); ok {
			return LoadBundle(b)
		}
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle %s: HTTP %d", url, resp.StatusCode)
	}
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(resp.Body, MaxReleaseBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", url, err)
	}
	if n > MaxReleaseBundleBytes {
		return nil, fmt.Errorf("bundle %s: larger than %d bytes", url, MaxReleaseBundleBytes)
	}
	tar := buf.Bytes()
	if got := SHA256(tar); got != bundleHash {
		return nil, &BundleHashMismatchError{URL: url, Want: bundleHash, Got: got}
	}
	b, err := LoadBundle(tar)
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", url, err)
	}
	if cache != nil {
		_ = cache.Put(bundleHash, tar) // a cache failure never fails the fetch
	}
	return b, nil
}
