package composer

import (
	_ "embed"
	"fmt"
	"sort"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

// Version is the composer version. It must equal config.composerVersion.
// Any change to composed output (this code, runtime-images.json, the Caddy
// templates or the host rules) requires a new version.
const Version = "1.0.0"

//go:embed runtime-images.json
var runtimeImagesJSON []byte

// RuntimeImage is one sidecar image from runtime-images.json.
type RuntimeImage struct {
	Name        string `json:"-"`
	Digest      string `json:"digest"`
	Source      string `json:"source"`
	LicenseSPDX string `json:"license_spdx"`
	Unbuilt     bool   `json:"unbuilt,omitempty"`
	Notes       string `json:"notes,omitempty"`
	Ref         string `json:"-"`
}

// RuntimeImages is the parsed runtime-images.json.
type RuntimeImages struct {
	Schema   string                   `json:"schema"`
	Registry string                   `json:"registry"`
	Images   map[string]*RuntimeImage `json:"images"`
}

// Sidecar image names.
const (
	imgCaddy     = "caddy"
	imgAgent     = "sealed-agent"
	imgEgress    = "sealed-egress"
	imgInit      = "sealed-init"
	imgPayer     = "sealed-mpp-payer"
	imgVerifierd = "sealed-verifierd"
)

// LoadRuntimeImages returns the embedded runtime image set.
func LoadRuntimeImages() (*RuntimeImages, error) {
	return parseRuntimeImages(runtimeImagesJSON)
}

func parseRuntimeImages(raw []byte) (*RuntimeImages, error) {
	var ri RuntimeImages
	if err := strictDecodeJSON(raw, &ri); err != nil {
		return nil, fmt.Errorf("runtime-images.json: %v", err)
	}
	if ri.Schema != "sealed-runtime-images/v1" {
		return nil, fmt.Errorf("runtime-images.json: unknown schema %q", ri.Schema)
	}
	for _, name := range []string{imgCaddy, imgAgent, imgEgress, imgInit, imgPayer, imgVerifierd} {
		img, ok := ri.Images[name]
		if !ok {
			return nil, fmt.Errorf("runtime-images.json: missing %s", name)
		}
		if !digestRe.MatchString(img.Digest) {
			return nil, fmt.Errorf("runtime-images.json: %s: invalid digest", name)
		}
		if (img.Digest == zeroDigest) != img.Unbuilt {
			return nil, fmt.Errorf("runtime-images.json: %s: unbuilt must be true exactly when the digest is all zeros", name)
		}
	}
	for name, img := range ri.Images {
		img.Name = name
		img.Ref = ri.Registry + "/" + name + "@" + img.Digest
		if !digestRefRe.MatchString(img.Ref) {
			return nil, fmt.Errorf("runtime-images.json: %s: invalid reference %q", name, img.Ref)
		}
	}
	return &ri, nil
}

// Unbuilt lists sidecar images whose digest is still the zero placeholder.
func (ri *RuntimeImages) Unbuilt() []string {
	var out []string
	for name, img := range ri.Images {
		if img.Unbuilt {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// strictDecodeJSON parses JSON with the canonical-JSON rules (no floats or
// duplicate keys) and decodes it into a typed struct without unknown fields.
func strictDecodeJSON(raw []byte, out any) error {
	v, err := cjson.Parse(raw)
	if err != nil {
		return err
	}
	return strictDecode(v, out)
}
