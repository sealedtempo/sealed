package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// AssetNames are the GitHub Release tag and asset file names of one app release (D-046, brief item 18):
//
//	<base>/<appId>-v<version>/<appId>-<version>.bundle.tar
//
// plus .sig, .crt and .intoto.jsonl next to the bundle. GitHub release assets cannot contain "/", so the
// SBOM that the rule places at sbom/<image>.spdx.json is the asset sbom.<image>.spdx.json (GitHub itself
// would rename a "/" to "."), and Grype reports are scan.<image>.json. The same files sit inside the
// bundle at sbom/<image>.spdx.json and scan/<image>.json.
type AssetNames struct {
	Tag            string            `json:"tag"`
	BaseURL        string            `json:"baseUrl"` // <release_asset_base>/<tag>
	Bundle         string            `json:"bundle"`
	Signature      string            `json:"signature"`      // base64 signature extracted from the Sigstore bundle
	Certificate    string            `json:"certificate"`    // PEM Fulcio certificate
	SigstoreBundle string            `json:"sigstoreBundle"` // cosign --bundle output (signature, certificate, Rekor proof)
	Provenance     string            `json:"provenance"`     // SLSA provenance (in-toto, slsa-github-generator)
	ReleaseJSON    string            `json:"releaseJson"`    // machine-readable summary (sealed-release/v1)
	SBOM           map[string]string `json:"sbom"`           // image -> asset
	Scan           map[string]string `json:"scan"`           // image -> asset
}

// URL returns the download URL of an asset of this release.
func (a AssetNames) URL(asset string) string { return a.BaseURL + "/" + asset }

// All lists every asset name, sorted.
func (a AssetNames) All() []string {
	out := []string{a.Bundle, a.Signature, a.Certificate, a.SigstoreBundle, a.Provenance, a.ReleaseJSON}
	for _, v := range a.SBOM {
		out = append(out, v)
	}
	for _, v := range a.Scan {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// CheckReleaseVersion rejects versions that cannot be released under the asset URL rule
// (composer.CheckReleaseVersion: GitHub renames asset names with other characters than letters, digits, ".",
// "-" and "_", "+" included, and a leading "v" or "V" must be followed by a digit). A version such as v1.58.2
// is released: its tag drops the leading v (composer.ReleaseTag, coding-agent-v1.58.2, never
// coding-agent-vv1.58.2), and the asset names and releaseId keep the version as it is.
func CheckReleaseVersion(version string) error { return composer.CheckReleaseVersion(version) }

// Assets computes the release names for an app version.
func Assets(d Defaults, app, version string, images []string) (AssetNames, error) {
	if err := CheckReleaseVersion(version); err != nil {
		return AssetNames{}, err
	}
	// The names the key broker, verifierd and the CLI fetch come from runtime/composer (one rule, D-046).
	bundle := composer.BundleAssetName(app, version)
	a := AssetNames{
		Tag:            composer.ReleaseTag(app, version),
		Bundle:         bundle,
		SBOM:           map[string]string{},
		Scan:           map[string]string{},
		ReleaseJSON:    app + "-" + version + ".release.json",
		Signature:      bundle + ".sig",
		Certificate:    bundle + ".crt",
		SigstoreBundle: bundle + ".sigstore.json",
		Provenance:     bundle + ".intoto.jsonl",
	}
	a.BaseURL = d.ReleaseAssetBase + "/" + a.Tag
	for _, img := range images {
		a.SBOM[img] = composer.SBOMAssetName(img)
		a.Scan[img] = "scan." + img + ".json"
	}
	return a, nil
}

// PlannedRelease is one app the release job releases.
type PlannedRelease struct {
	App       string     `json:"app"`
	Dir       string     `json:"dir"`
	Version   string     `json:"version"`
	AppID     string     `json:"appId"`
	Tag       string     `json:"tag"`
	Images    []string   `json:"images"`
	ImageRefs []ImageRef `json:"imageRefs"` // what the bundle pins and VMs pull: <registry>/<name>@<digest>
	Unbuilt   []string   `json:"unbuilt"`
	Assets    AssetNames `json:"assets"`
	Problem   string     `json:"problem,omitempty"` // set when the app cannot be released as is
}

// ImageRef is one image of a planned release.
type ImageRef struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
}

// Plan lists the releases for the given app ids (all top-level apps when ids is empty and all is set).
// An app whose version cannot be released gets Problem set instead of failing the whole plan, so the
// caller can report every problem at once.
func Plan(d Defaults, apps []App, ids []string, all bool) ([]PlannedRelease, error) {
	if all {
		ids = nil
		for _, a := range apps {
			if !a.Nested {
				ids = append(ids, a.ID)
			}
		}
	}
	sort.Strings(ids)
	var out []PlannedRelease
	seen := map[string]bool{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		a, ok := FindApp(apps, id)
		if !ok {
			return nil, fmt.Errorf("no app %q under %s", id, CatalogDir)
		}
		p := PlannedRelease{App: a.ID, Dir: a.Dir, Version: a.Version(), AppID: composer.AppID(a.ID).Hex(),
			Images: []string{}, ImageRefs: []ImageRef{}, Unbuilt: []string{}}
		for _, img := range a.Manifest.Images {
			p.Images = append(p.Images, img.Name)
			p.ImageRefs = append(p.ImageRefs, ImageRef{Name: img.Name, Ref: d.Registry + "/" + img.Name + "@" + img.Digest})
			if img.Unbuilt() {
				p.Unbuilt = append(p.Unbuilt, img.Name)
			}
		}
		assets, err := Assets(d, a.ID, p.Version, p.Images)
		if err != nil {
			p.Problem = err.Error()
		} else {
			p.Assets, p.Tag = assets, assets.Tag
		}
		if p.Problem == "" && len(p.Unbuilt) > 0 {
			p.Problem = fmt.Sprintf("images %s still have the all-zero placeholder digest (run the runtime image workflow and merge its pin PR)", strings.Join(p.Unbuilt, ", "))
		}
		out = append(out, p)
	}
	return out, nil
}
