package composer

import (
	_ "embed"
	"testing"
)

// The production composer package does not embed runtime-images.json (D-097);
// the authoritative copy lives in the rimembed subpackage. In-package tests
// embed it here for two distinct purposes. Neither _test.go embed ever links
// into any production binary (sealed-verifierd included).

// testRuntimeImagesJSON is the real production set (rimembed). Tests that
// validate the shipped set (TestRuntimeImages, the bad-digest parse test) use it,
// so a re-pin is still checked.
//
//go:embed rimembed/runtime-images.json
var testRuntimeImagesJSON []byte

// goldenRuntimeImagesJSON is a FROZEN fixture set that the golden and parity
// vectors pin, deliberately decoupled from rimembed (D-098). The golden tests
// the composer transform, which is digest-agnostic, so its sidecar digests are
// opaque fixed bytes. Keeping them out of rimembed means re-pinning a sidecar
// (production data) does not change the golden, so it needs no composer Version
// bump, which in turn keeps the sidecars that embed composer.Version (verifierd,
// key broker, agent) from an unreachable re-pin/bump/rebuild loop.
//
//go:embed testdata/golden-runtime-images.json
var goldenRuntimeImagesJSON []byte

func loadTestRuntimeImages(t *testing.T) *RuntimeImages {
	t.Helper()
	ri, err := ParseRuntimeImages(testRuntimeImagesJSON)
	if err != nil {
		t.Fatal(err)
	}
	return ri
}

// mustTestRuntimeImages returns the frozen fixture set for testConfig/the golden
// (no *testing.T in scope).
func mustTestRuntimeImages() *RuntimeImages {
	ri, err := ParseRuntimeImages(goldenRuntimeImagesJSON)
	if err != nil {
		panic(err)
	}
	return ri
}

// composeEmbedded stands in for the removed embed-backed Compose in the
// package's own tests: it composes with the frozen fixture set (matching
// testConfig's cfg.RuntimeImages), with the exact signature the old Compose had.
func composeEmbedded(cfg *Config, bundles []*Bundle) (*Result, error) {
	ri, err := ParseRuntimeImages(goldenRuntimeImagesJSON)
	if err != nil {
		return nil, err
	}
	return ComposeWith(cfg, bundles, ri)
}
