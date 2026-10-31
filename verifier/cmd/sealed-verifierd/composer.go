package main

import (
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/bundles"
	"github.com/sealedtempo/sealed/verifier/releasesig"
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

// newSignatures checks release CI's signature and SLSA provenance of every release (supply-2) with the assets next
// to its bundle, from the same bases. loadConfig already refused plain http bases outside SEALED_DEV_SIM=1.
func newSignatures(c *config) (verify.ReleaseSignatures, error) {
	v, err := releasesig.New(releasesig.Options{Bases: c.ReleaseAssetBases, AllowHTTP: true})
	if err != nil {
		return nil, err
	}
	return v, nil
}
