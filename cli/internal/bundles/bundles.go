// Package bundles fetches release bundles by the release asset URL rule (D-046, brief item 18), checks each one
// against its onchain bundleHash, caches them by content hash, and recomputes stacks with runtime/composer for
// the verifier library (verify.Composer).
package bundles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sealedtempo/sealed/runtime/composer"
	verify "github.com/sealedtempo/sealed/verifier"
)

// MaxBundleSize bounds a download. Bundles hold manifests, SBOMs and scans, a few MiB at most.
const MaxBundleSize = 64 << 20

// AssetURL is <base>/<appId>-v<version>/<appId>-<version>.bundle.tar (D-046), from runtime/composer's
// NewReleaseAssets, the implementation the key broker, verifierd and release CI share.
func AssetURL(base, app, version string) (string, error) {
	a, err := composer.NewReleaseAssets(base, app, version)
	if err != nil {
		return "", err
	}
	return a.Bundle, nil
}

// Fetcher downloads bundles.
type Fetcher struct {
	Base     string       // catalog.release_asset_base
	HTTP     *http.Client // default: 2 minute timeout, https redirects only
	CacheDir string       // content-addressed cache (<sha256>.tar); empty disables it
	// AllowHTTP permits http:// bases (tests only).
	AllowHTTP bool
}

// ErrHashMismatch means the downloaded bytes are not the onchain bundle.
var ErrHashMismatch = errors.New("bundle_hash_mismatch")

func (f *Fetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && !f.AllowHTTP {
				return fmt.Errorf("redirect to non-https %s", req.URL.Host)
			}
			return nil
		},
	}
}

func (f *Fetcher) cachePath(want [32]byte) string {
	return filepath.Join(f.CacheDir, hex.EncodeToString(want[:])+".tar")
}

// Fetch returns the bytes of app's release bundle whose sha256 must equal want.
func (f *Fetcher) Fetch(ctx context.Context, app, version string, want [32]byte) ([]byte, error) {
	if f.CacheDir != "" {
		if b, err := os.ReadFile(f.cachePath(want)); err == nil && sha256.Sum256(b) == want {
			return b, nil
		}
	}
	u, err := AssetURL(f.Base, app, version)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u, "https://") && !f.AllowHTTP {
		return nil, fmt.Errorf("release asset base must be https: %s", f.Base)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	if len(b) > MaxBundleSize {
		return nil, fmt.Errorf("fetch %s: bundle larger than %d bytes", u, MaxBundleSize)
	}
	if got := sha256.Sum256(b); got != want {
		return nil, fmt.Errorf("%w: %s has sha256 0x%x, the onchain bundleHash is 0x%x", ErrHashMismatch, u, got, want)
	}
	if f.CacheDir != "" {
		_ = writeAtomic(f.cachePath(want), b)
	}
	return b, nil
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bundle-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Release identifies one onchain release.
type Release struct {
	App        string // slug
	ReleaseID  [32]byte
	AppID      [32]byte
	Version    string
	BundleHash [32]byte
}

// Load fetches and loads a release bundle, and checks that it is the release: same app, version, appId and
// releaseId.
func (f *Fetcher) Load(ctx context.Context, r Release) (*composer.Bundle, error) {
	raw, err := f.Fetch(ctx, r.App, r.Version, r.BundleHash)
	if err != nil {
		return nil, err
	}
	b, err := composer.LoadBundle(raw)
	if err != nil {
		return nil, fmt.Errorf("release %s %s: %w", r.App, r.Version, err)
	}
	switch {
	case b.Manifest.ID != r.App:
		return nil, fmt.Errorf("release %s %s: bundle is for app %q", r.App, r.Version, b.Manifest.ID)
	case b.Version() != r.Version:
		return nil, fmt.Errorf("release %s %s: bundle has version %q", r.App, r.Version, b.Version())
	case [32]byte(b.AppID) != r.AppID && r.AppID != [32]byte{}:
		return nil, fmt.Errorf("release %s %s: appId mismatch", r.App, r.Version)
	case [32]byte(b.ReleaseID) != r.ReleaseID && r.ReleaseID != [32]byte{}:
		return nil, fmt.Errorf("release %s %s: releaseId 0x%x, the chain says 0x%x", r.App, r.Version, b.ReleaseID, r.ReleaseID)
	}
	return b, nil
}

// Composer recomputes stacks for the verifier (verify.Composer) from bundles fetched by onchain bundleHash.
type Composer struct {
	Fetcher *Fetcher
}

// Compose implements verify.Composer.
func (c *Composer) Compose(ctx context.Context, in verify.ComposeInput) (*verify.ComposeOutput, error) {
	cfg, err := composer.ParseConfig(in.Config)
	if err != nil {
		return nil, err
	}
	var bs []*composer.Bundle
	for _, r := range in.Releases {
		b, err := c.Fetcher.Load(ctx, Release{App: r.App, ReleaseID: r.ReleaseID, AppID: r.AppID, Version: r.Version, BundleHash: r.BundleHash})
		if err != nil {
			return nil, err
		}
		bs = append(bs, b)
	}
	// Recompute against the sidecar set the customer approved in the config
	// (config.runtimeImages, part of configHash), not an embedded copy (D-097).
	ri, err := composer.RuntimeImagesFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	res, err := composer.ComposeWith(cfg, bs, ri)
	if err != nil {
		return nil, err
	}
	return &verify.ComposeOutput{AppCompose: res.AppCompose, StackHash: res.StackHash, ConfigHash: res.ConfigHash, DeploymentID: res.DeploymentID}, nil
}
