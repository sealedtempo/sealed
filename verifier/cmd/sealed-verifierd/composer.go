package main

import (
	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/bundles"
)

// newComposer wires runtime/composer (brief item 19): bundles are fetched by the release asset URL rule (D-046)
// from the configured bases, accepted only when sha256 equals the onchain bundleHash, and cached by that hash in
// memory and, with --bundle-cache-dir, on disk. The releases themselves are read from AppRegistry by the verifier
// (pinned to the verification's block), so the chain decides which bytes are composed.
func newComposer(c *config, _ verify.ChainReader) (verify.Composer, error) {
	src, err := bundles.NewSource(c.ReleaseAssetBases, c.BundleCacheDir)
	if err != nil {
		return nil, err
	}
	return &bundles.Composer{Source: src}, nil
}
