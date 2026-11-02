package composer

import (
	_ "embed"
	"testing"
)

// The production composer package does not embed runtime-images.json (D-097);
// the authoritative copy lives in the rimembed subpackage. In-package tests
// still exercise the real set, so they embed that same file here. This _test.go
// embed never links into any production binary (sealed-verifierd included).

//go:embed rimembed/runtime-images.json
var testRuntimeImagesJSON []byte

func loadTestRuntimeImages(t *testing.T) *RuntimeImages {
	t.Helper()
	ri, err := ParseRuntimeImages(testRuntimeImagesJSON)
	if err != nil {
		t.Fatal(err)
	}
	return ri
}

// mustTestRuntimeImages is loadTestRuntimeImages for helpers that build a config
// without a *testing.T in scope (testConfig).
func mustTestRuntimeImages() *RuntimeImages {
	ri, err := ParseRuntimeImages(testRuntimeImagesJSON)
	if err != nil {
		panic(err)
	}
	return ri
}

// composeEmbedded stands in for the removed embed-backed Compose in the
// package's own tests: it composes with the embedded runtime image set, with
// the exact signature the old Compose had.
func composeEmbedded(cfg *Config, bundles []*Bundle) (*Result, error) {
	ri, err := ParseRuntimeImages(testRuntimeImagesJSON)
	if err != nil {
		return nil, err
	}
	return ComposeWith(cfg, bundles, ri)
}
