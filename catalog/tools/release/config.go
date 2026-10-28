package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Defaults is the part of config/defaults.yaml the release tooling reads.
type Defaults struct {
	ChainID          uint64 // chain.chain_id
	ExplorerURL      string // chain.explorer_url
	PublicRPC        string // chain.public_rpc_url
	FeeToken         string // chain.fee_token
	Registry         string // catalog.registry
	ReleaseAssetBase string // catalog.release_asset_base, no trailing slash
}

// RepoURL is the public repository URL derived from the release asset base
// (https://github.com/<owner>/<repo>/releases/download -> https://github.com/<owner>/<repo>).
func (d Defaults) RepoURL() string {
	return strings.TrimSuffix(d.ReleaseAssetBase, "/releases/download")
}

// RepoSlug is <owner>/<repo>.
func (d Defaults) RepoSlug() string {
	return strings.TrimPrefix(d.RepoURL(), "https://github.com/")
}

var assetBaseRe = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/releases/download$`)

// LoadDefaults reads <root>/config/defaults.yaml.
func LoadDefaults(root string) (Defaults, error) {
	raw, err := os.ReadFile(filepath.Join(root, "config", "defaults.yaml"))
	if err != nil {
		return Defaults{}, err
	}
	var doc struct {
		Chain struct {
			ChainID     uint64 `yaml:"chain_id"`
			ExplorerURL string `yaml:"explorer_url"`
			PublicRPC   string `yaml:"public_rpc_url"`
			FeeToken    string `yaml:"fee_token"`
		} `yaml:"chain"`
		Catalog struct {
			Registry         string `yaml:"registry"`
			ReleaseAssetBase string `yaml:"release_asset_base"`
		} `yaml:"catalog"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Defaults{}, fmt.Errorf("config/defaults.yaml: %w", err)
	}
	d := Defaults{
		ChainID:          doc.Chain.ChainID,
		ExplorerURL:      strings.TrimRight(doc.Chain.ExplorerURL, "/"),
		PublicRPC:        doc.Chain.PublicRPC,
		FeeToken:         strings.ToLower(doc.Chain.FeeToken),
		Registry:         doc.Catalog.Registry,
		ReleaseAssetBase: strings.TrimRight(doc.Catalog.ReleaseAssetBase, "/"),
	}
	switch {
	case d.ChainID == 0:
		return Defaults{}, errors.New("config/defaults.yaml: chain.chain_id is missing")
	case d.Registry == "":
		return Defaults{}, errors.New("config/defaults.yaml: catalog.registry is missing")
	case !assetBaseRe.MatchString(d.ReleaseAssetBase):
		return Defaults{}, fmt.Errorf("config/defaults.yaml: catalog.release_asset_base %q is not https://github.com/<owner>/<repo>/releases/download", d.ReleaseAssetBase)
	}
	return d, nil
}

// FindRoot walks up from dir to the directory holding go.mod and config/defaults.yaml.
func FindRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if fileExists(filepath.Join(d, "go.mod")) && fileExists(filepath.Join(d, "config", "defaults.yaml")) {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("no repository root (go.mod and config/defaults.yaml) above %s", abs)
		}
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
