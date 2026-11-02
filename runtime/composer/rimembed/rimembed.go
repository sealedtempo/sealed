// Package rimembed holds the embedded runtime-images.json: the runtime sidecar
// image set (digests) that composer pins into app-compose.json.
//
// It is imported ONLY by authoring tools (the sealed CLI, sealed-compose, the
// release pin tool) and by the key broker, whose image is listed in
// extra-images.json rather than runtime-images.json and so can embed the set
// without a self-reference. It is deliberately NOT imported by sealed-verifierd:
// runtime-images.json names verifierd's own image digest, and verifierd links
// the composer package to recompute app-compose.json, so embedding the set in
// verifierd would make its image digest depend on itself (D-097). Verifierd
// receives the set as an explicit argument to composer.ComposeWith instead.
//
// The file lives in this package's directory because //go:embed cannot reach a
// parent directory; the release pin tool writes it through its RuntimeImagesFile
// path constant.
package rimembed

import (
	_ "embed"

	"github.com/sealedtempo/sealed/runtime/composer"
)

//go:embed runtime-images.json
var raw []byte

// Raw returns the embedded runtime-images.json document.
func Raw() []byte { return append([]byte(nil), raw...) }

// Load parses and validates the embedded runtime image set.
func Load() (*composer.RuntimeImages, error) { return composer.ParseRuntimeImages(raw) }

// Compose composes a stack with the embedded runtime image set. It is the
// authoring-side convenience that the embed-free composer.Compose used to be;
// recompute consumers call composer.ComposeWith with the set from the config
// (composer.RuntimeImagesFromConfig) instead.
//
// For authoring it also stamps the embedded set into cfg.RuntimeImages when the
// caller has not set it, so the composed config carries the sidecar digests it
// is hashed with (config.runtimeImages, part of configHash). Callers that hash
// the config before composing (the deploy builder) must set cfg.RuntimeImages
// themselves; this stamp only covers callers that compose first.
func Compose(cfg *composer.Config, bundles []*composer.Bundle) (*composer.Result, error) {
	ri, err := Load()
	if err != nil {
		return nil, err
	}
	if cfg.RuntimeImages == nil {
		cfg.RuntimeImages = ri
	}
	return composer.ComposeWith(cfg, bundles, ri)
}
