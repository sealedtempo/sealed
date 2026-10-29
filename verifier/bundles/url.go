// Package bundles gets release bundles for stack recomputation: it maps a release to its asset URL (D-046),
// fetches the bundle.tar, accepts it only when sha256 equals the onchain bundleHash, and keeps it in a
// content-addressed cache. Composer runs runtime/composer on the verified bundles and implements
// verify.Composer, so sealed-verifierd, `sealed verify` and the key broker recompute stacks the same way (D-006,
// D-012).
package bundles

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sealedtempo/sealed/runtime/composer"
)

// DefaultReleaseAssetBase is catalog.release_asset_base of config/defaults.yaml (TestDefaultBaseMatchesDefaults
// keeps them equal).
const DefaultReleaseAssetBase = "https://github.com/sealedtempo/sealed/releases/download"

// URLRule maps a release (app slug and release version, as AppRegistry records them) to the URL of its bundle.tar.
type URLRule interface {
	BundleURL(app, version string) (string, error)
}

// AssetRule is the release asset URL rule of D-046 (brief item 18):
//
//	<release_asset_base>/<appId>-v<release_version>/<appId>-<release_version>.bundle.tar
//
// where appId is the app slug. It delegates to runtime/composer's NewReleaseAssets, the one implementation the
// key broker, the CLI and release CI share, so every fetcher computes the URL release CI publishes.
type AssetRule struct {
	// Base is release_asset_base without a trailing slash, for example
	// https://github.com/sealedtempo/sealed/releases/download.
	Base string
}

// ErrNoAssetURL is returned for an app slug or version the URL rule cannot express (path characters, empty,
// characters GitHub renames in asset names such as "+").
var ErrNoAssetURL = errors.New("no release asset URL")

// BundleURL implements URLRule.
func (r AssetRule) BundleURL(app, version string) (string, error) {
	if r.Base == "" {
		return "", fmt.Errorf("%w: release asset base not set", ErrNoAssetURL)
	}
	a, err := composer.NewReleaseAssets(r.Base, app, version)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoAssetURL, err)
	}
	return a.Bundle, nil
}

// ParseBases splits a comma-separated list of release asset bases (the first is the catalog's, later ones are
// mirrors; every bundle is checked against its onchain hash, so a mirror cannot change what is composed). Each base
// must be an absolute https URL without query, fragment or userinfo; plain http is accepted only with
// allowInsecure (local tests and the dev simulator).
func ParseBases(list string, allowInsecure bool) ([]string, error) {
	var out []string
	for _, b := range strings.Split(list, ",") {
		b = strings.TrimRight(strings.TrimSpace(b), "/")
		if b == "" {
			continue
		}
		u, err := url.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("release asset base %q: %v", b, err)
		}
		switch {
		case u.Scheme != "https" && !(allowInsecure && u.Scheme == "http"):
			return nil, fmt.Errorf("release asset base %q: must be https", b)
		case u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
			return nil, fmt.Errorf("release asset base %q: want scheme://host/path only", b)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, errors.New("no release asset base")
	}
	return out, nil
}

// Rules returns one AssetRule per base, in order.
func Rules(bases []string) []URLRule {
	out := make([]URLRule, len(bases))
	for i, b := range bases {
		out[i] = AssetRule{Base: b}
	}
	return out
}
