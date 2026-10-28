package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// BundleInfo is the publishRelease input of one bundle plus the derived ids.
type BundleInfo struct {
	composer.ReleaseInfo
	BundleSize int    `json:"bundleSize"`
	File       string `json:"file,omitempty"`
}

// BuildBundleFile builds a release bundle with the composer (the same code `sealed release build` uses),
// writes it to out, and returns its info. SBOMs and scans are required for every image.
func BuildBundleFile(appDir, sbomDir, scanDir, registry, out string) (*BundleInfo, error) {
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: appDir, SBOMDir: sbomDir, ScanDir: scanDir, Registry: registry})
	if err != nil {
		return nil, err
	}
	for _, img := range b.Manifest.Images {
		if img.Unbuilt() {
			return nil, fmt.Errorf("image %q still has the all-zero placeholder digest", img.Name)
		}
		if _, ok := b.Files["scan/"+img.Name+".json"]; !ok {
			return nil, fmt.Errorf("image %q has no scan report (scan/%s.json)", img.Name, img.Name)
		}
	}
	if out != "" {
		if err := os.WriteFile(out, b.Tar, 0o644); err != nil {
			return nil, err
		}
	}
	return &BundleInfo{ReleaseInfo: b.Info(), BundleSize: len(b.Tar), File: out}, nil
}

// BundleFileInfo loads a bundle tar (canonical form only) and returns its info.
func BundleFileInfo(path string) (*BundleInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := composer.LoadBundle(raw)
	if err != nil {
		return nil, err
	}
	return &BundleInfo{ReleaseInfo: b.Info(), BundleSize: len(raw), File: path}, nil
}

func readJSONFile(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
