package composer

import (
	"fmt"
	"sort"

	"github.com/sealedtempo/sealed/runtime/composer/cjson"
)

// Version is the composer version. It must equal config.composerVersion.
// Any change to composed output (this code, runtime-images.json, the Caddy
// templates or the host rules) requires a new version.
const Version = "1.7.0"

// The runtime image set (runtime-images.json) is NOT embedded in this package.
// It names sealed-verifierd's own image digest, and sealed-verifierd links this
// package to recompute app-compose.json; embedding it here would make the
// verifierd image digest depend on itself (an unreachable fixpoint, D-097).
// Authoring tools load it from the rimembed subpackage; recompute consumers
// receive it as an explicit argument to ComposeWith (D-097).

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

// ParseRuntimeImages parses and validates a runtime-images.json document. It is
// the one entry point for the runtime sidecar set: rimembed.Load decodes the
// embedded file with it (authoring), and the recompute paths decode the set
// they are handed with it before calling ComposeWith (D-097).
func ParseRuntimeImages(raw []byte) (*RuntimeImages, error) {
	var ri RuntimeImages
	if err := strictDecodeJSON(raw, &ri); err != nil {
		return nil, fmt.Errorf("runtime-images.json: %v", err)
	}
	if err := finalizeRuntimeImages(&ri); err != nil {
		return nil, err
	}
	return &ri, nil
}

// finalizeRuntimeImages validates a decoded runtime image set and fills each
// image's derived Name and Ref. It is shared by ParseRuntimeImages (which
// decodes runtime-images.json) and RuntimeImagesFromConfig (which takes the set
// already decoded from config.runtimeImages).
func finalizeRuntimeImages(ri *RuntimeImages) error {
	if ri.Schema != "sealed-runtime-images/v1" {
		return fmt.Errorf("runtime-images.json: unknown schema %q", ri.Schema)
	}
	for _, name := range []string{imgCaddy, imgAgent, imgEgress, imgInit, imgPayer, imgVerifierd} {
		img, ok := ri.Images[name]
		if !ok {
			return fmt.Errorf("runtime-images.json: missing %s", name)
		}
		if !digestRe.MatchString(img.Digest) {
			return fmt.Errorf("runtime-images.json: %s: invalid digest", name)
		}
		if (img.Digest == zeroDigest) != img.Unbuilt {
			return fmt.Errorf("runtime-images.json: %s: unbuilt must be true exactly when the digest is all zeros", name)
		}
	}
	for name, img := range ri.Images {
		img.Name = name
		img.Ref = ri.Registry + "/" + name + "@" + img.Digest
		if !digestRefRe.MatchString(img.Ref) {
			return fmt.Errorf("runtime-images.json: %s: invalid reference %q", name, img.Ref)
		}
	}
	return nil
}

// RuntimeImagesFromConfig validates config.runtimeImages and returns it as the
// composer's runtime image set. The set travels in the customer-approved config
// (part of configHash), so sealed-verifierd and the key broker recompute against
// exactly the sidecars the customer approved without embedding the set that
// names verifierd's own image digest (D-097). The authoring tools populate the
// field from the rimembed embed before the stack is composed and approved.
func RuntimeImagesFromConfig(cfg *Config) (*RuntimeImages, error) {
	if cfg.RuntimeImages == nil || len(cfg.RuntimeImages.Images) == 0 {
		return nil, fmt.Errorf("config: runtimeImages is required")
	}
	ri := cfg.RuntimeImages.clone()
	if err := finalizeRuntimeImages(ri); err != nil {
		return nil, fmt.Errorf("config: runtimeImages: %w", err)
	}
	return ri, nil
}

// clone returns a deep copy so finalize's derived fields never mutate the config.
func (ri *RuntimeImages) clone() *RuntimeImages {
	out := &RuntimeImages{Schema: ri.Schema, Registry: ri.Registry, Images: make(map[string]*RuntimeImage, len(ri.Images))}
	for name, img := range ri.Images {
		cp := *img
		out.Images[name] = &cp
	}
	return out
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
