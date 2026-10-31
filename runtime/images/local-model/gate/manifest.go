package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Ollama manifest media types. The layer media type decides what a blob is used for (weights,
// chat template, license, default parameters), so checking only blob hashes is not enough: a
// manifest that swaps roles among pinned blobs would still pass a hash-only check.
const (
	mediaModel    = "application/vnd.ollama.image.model"
	mediaTemplate = "application/vnd.ollama.image.template"
	mediaLicense  = "application/vnd.ollama.image.license"
	mediaParams   = "application/vnd.ollama.image.params"
	// Ollama 0.40.x stores the upstream registry manifest as a final layer of this media type.
	mediaNested = "application/vnd.docker.distribution.manifest.v2+json"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ollamaManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

// manifestPins are the expected blob digests (64 hex chars, no prefix) per role, plus an
// optional sha256 of the manifest file itself.
type manifestPins struct {
	Config, Model, Template, License, Params, Nested string
	ManifestSHA256                                   string
}

// verifyManifest checks the pulled manifest file against the pins and returns its sha256.
func verifyManifest(path string, pins manifestPins) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if pins.ManifestSHA256 != "" && pins.ManifestSHA256 != digest {
		return digest, fmt.Errorf("manifest sha256 %s, want %s", digest, pins.ManifestSHA256)
	}
	want := map[string]string{
		mediaModel: pins.Model, mediaTemplate: pins.Template, mediaLicense: pins.License, mediaParams: pins.Params, mediaNested: pins.Nested,
	}
	for role, pin := range want {
		if !hex64.MatchString(pin) {
			return digest, fmt.Errorf("pin for %s is not 64 hex characters", role)
		}
	}
	if !hex64.MatchString(pins.Config) {
		return digest, fmt.Errorf("config pin is not 64 hex characters")
	}
	var m ollamaManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return digest, fmt.Errorf("manifest is not JSON: %w", err)
	}
	if m.SchemaVersion != 2 {
		return digest, fmt.Errorf("schemaVersion %d, want 2", m.SchemaVersion)
	}
	if m.Config.Digest != "sha256:"+pins.Config {
		return digest, fmt.Errorf("config digest %s, want sha256:%s", m.Config.Digest, pins.Config)
	}
	if len(m.Layers) != len(want) {
		return digest, fmt.Errorf("%d layers, want exactly %d (model, template, license, params, nested manifest)", len(m.Layers), len(want))
	}
	seen := map[string]bool{}
	for _, layer := range m.Layers {
		pin, known := want[layer.MediaType]
		if !known {
			return digest, fmt.Errorf("unexpected layer media type %q", layer.MediaType)
		}
		if seen[layer.MediaType] {
			return digest, fmt.Errorf("media type %q appears twice", layer.MediaType)
		}
		seen[layer.MediaType] = true
		if layer.Digest != "sha256:"+pin {
			return digest, fmt.Errorf("%s layer is %s, want sha256:%s", layer.MediaType, layer.Digest, pin)
		}
	}
	return digest, nil
}
