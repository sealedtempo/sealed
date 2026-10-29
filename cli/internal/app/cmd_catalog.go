package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"text/tabwriter"

	"go.yaml.in/yaml/v3"

	"github.com/sealedtempo/sealed/cli/internal/bundles"
	"github.com/sealedtempo/sealed/cli/internal/registry"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// ReleaseView is one release as the catalog commands show it.
type ReleaseView struct {
	ReleaseID        string `json:"releaseId"`
	Version          string `json:"version"`
	Status           string `json:"status"`
	BundleHash       string `json:"bundleHash"`
	EgressPolicyHash string `json:"egressPolicyHash"`
	SBOMHash         string `json:"sbomHash"`
	PublishedAt      uint64 `json:"publishedAt"`
	ProvenanceURI    string `json:"provenanceUri,omitempty"`
	SignatureURI     string `json:"signatureUri,omitempty"`
	BundleURL        string `json:"bundleUrl,omitempty"`
}

// AppView is one catalog app.
type AppView struct {
	ID                 string        `json:"id"`
	AppID              string        `json:"appId"`
	Name               string        `json:"name"`
	License            string        `json:"license"`
	Maintainer         string        `json:"maintainer"`
	MaintainerShareBps uint16        `json:"maintainerShareBps"`
	MetadataURI        string        `json:"metadataUri,omitempty"`
	Latest             *ReleaseView  `json:"latest,omitempty"`
	Releases           []ReleaseView `json:"releases,omitempty"`
	Manifest           *ManifestView `json:"manifest,omitempty"`
}

// ManifestView summarizes the latest release's manifest (read from its bundle, checked against bundleHash).
type ManifestView struct {
	Description string             `json:"description"`
	Upstream    composer.Upstream  `json:"upstream"`
	Resources   composer.Resources `json:"resources"`
	Routes      []string           `json:"routes"`
	Secrets     []string           `json:"secrets"`
	Egress      []string           `json:"egressDefaultAllow"`
	Images      []string           `json:"images"`
	Metering    string             `json:"metering"`
}

func statusName(s uint8) string {
	switch s {
	case chain.ReleaseActive:
		return "active"
	case chain.ReleaseDeprecated:
		return "deprecated"
	case chain.ReleaseRevoked:
		return "revoked"
	}
	return "unknown"
}

func hx(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }

func releaseView(base, slug string, id [32]byte, r *chain.Release) ReleaseView {
	v := ReleaseView{
		ReleaseID: hx(id), Version: r.Version, Status: statusName(r.Status), BundleHash: hx(r.BundleHash),
		EgressPolicyHash: hx(r.EgressPolicyHash), SBOMHash: hx(r.SbomHash), PublishedAt: r.PublishedAt,
		ProvenanceURI: r.ProvenanceURI, SignatureURI: r.SignatureURI,
	}
	if u, err := bundles.AssetURL(base, slug, r.Version); err == nil {
		v.BundleURL = u
	}
	return v
}

func appView(ctx context.Context, r registry.Reader, base string, appID [32]byte, allReleases bool) (*AppView, error) {
	a, err := r.GetApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	v := &AppView{ID: a.Slug, AppID: hx(appID), Name: a.Name, License: a.LicenseSpdx, Maintainer: strings.ToLower(a.Maintainer.Hex()), MaintainerShareBps: a.MaintainerShareBps, MetadataURI: a.MetadataURI}
	latest, err := r.LatestRelease(ctx, appID)
	if err != nil {
		return nil, err
	}
	if latest != ([32]byte{}) {
		rel, err := r.GetRelease(ctx, latest)
		if err != nil {
			return nil, err
		}
		lv := releaseView(base, a.Slug, latest, rel)
		v.Latest = &lv
	}
	if allReleases {
		n, err := r.ReleaseCount(ctx, appID)
		if err != nil {
			return nil, err
		}
		for i := n; i > 0; i-- { // newest first
			id, err := r.ReleaseAt(ctx, appID, i-1)
			if err != nil {
				return nil, err
			}
			rel, err := r.GetRelease(ctx, id)
			if err != nil {
				return nil, err
			}
			v.Releases = append(v.Releases, releaseView(base, a.Slug, id, rel))
		}
	}
	return v, nil
}

const catalogUsage = `Usage:
  sealed catalog list [--json]
  sealed catalog show <app> [--no-manifest] [--json]

The catalog is read from AppRegistry on Tempo. show also downloads the latest release bundle and checks it
against the onchain bundleHash before it prints the manifest.
`

func runCatalog(ctx context.Context, args []string, e *Env) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(e.Stderr, catalogUsage)
		if len(args) == 0 {
			return usagef("sealed catalog needs list or show")
		}
		return nil
	}
	sub := args[0]
	fs := newFlags("sealed catalog "+sub, e)
	var c commonFlags
	c.register(fs)
	var noManifest bool
	if sub == "show" {
		fs.BoolVar(&noManifest, "no-manifest", false, "do not download the latest bundle")
	}
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	s, err := c.settings(e)
	if err != nil {
		return err
	}
	base := c.assetBase
	if base == "" {
		base = s.ReleaseAssetBase()
	}
	reader, err := e.chain(ctx, s)
	if err != nil {
		return err
	}
	switch sub {
	case "list", "ls":
		if len(pos) > 0 {
			return usagef("sealed catalog list takes no arguments")
		}
		n, err := reader.AppCount(ctx)
		if err != nil {
			return err
		}
		var apps []*AppView
		for i := uint64(0); i < n; i++ {
			id, err := reader.AppAt(ctx, i)
			if err != nil {
				return err
			}
			v, err := appView(ctx, reader, base, id, false)
			if err != nil {
				return err
			}
			apps = append(apps, v)
		}
		if c.json {
			if apps == nil {
				apps = []*AppView{}
			}
			return writeJSON(e.Stdout, apps)
		}
		tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "APP\tNAME\tLICENSE\tLATEST\tBUNDLE HASH")
		for _, a := range apps {
			ver, hash := "none", ""
			if a.Latest != nil {
				ver, hash = a.Latest.Version, a.Latest.BundleHash
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.License, ver, hash)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if len(apps) == 0 {
			e.printf("no apps registered on chain %d\n", s.ChainID)
		}
		return nil
	case "show":
		if len(pos) != 1 {
			return usagef("usage: sealed catalog show <app>")
		}
		appID := composer.AppID(pos[0])
		v, err := appView(ctx, reader, base, appID, true)
		if err != nil {
			return fmt.Errorf("app %s: %w", pos[0], err)
		}
		if !noManifest && v.Latest != nil {
			id, _ := registry.ParseHash32(v.Latest.ReleaseID)
			bh, _ := registry.ParseHash32(v.Latest.BundleHash)
			b, err := c.fetcher(e, s).Load(ctx, bundles.Release{App: v.ID, ReleaseID: id, AppID: appID, Version: v.Latest.Version, BundleHash: bh})
			if err != nil {
				return err
			}
			v.Manifest = manifestView(b)
		}
		if c.json {
			return writeJSON(e.Stdout, v)
		}
		printApp(e, v)
		return nil
	}
	return usagef("unknown catalog command %q\n\n%s", sub, catalogUsage)
}

func manifestView(b *composer.Bundle) *ManifestView {
	m := b.Manifest
	mv := &ManifestView{Description: m.Description, Upstream: m.Upstream, Resources: m.Resources, Metering: m.Metering.Unit + " (" + m.Metering.Source + ")"}
	for _, r := range m.Routes {
		mv.Routes = append(mv.Routes, fmt.Sprintf("%s %s -> %s:%d (%s)", r.Name, r.PathOrHost, r.Service, r.InternalPort, r.Auth))
	}
	// The secrets list is read loosely so same_as entries show too.
	var doc struct {
		Secrets []struct {
			Name     string `yaml:"name"`
			Generate string `yaml:"generate"`
			Optional bool   `yaml:"optional"`
			SameAs   string `yaml:"same_as"`
		} `yaml:"secrets"`
	}
	_ = yaml.Unmarshal(b.Files[composer.ManifestFile], &doc)
	for _, s := range doc.Secrets {
		line := s.Name + " (" + s.Generate
		if s.Optional {
			line += ", optional"
		}
		if s.SameAs != "" {
			line += ", same as " + s.SameAs
		}
		mv.Secrets = append(mv.Secrets, line+")")
	}
	for _, h := range b.Egress.DefaultAllow {
		mv.Egress = append(mv.Egress, h)
	}
	for _, img := range m.Images {
		ref := img.Ref
		if ref == "" {
			ref = img.Name + "@" + img.Digest
		}
		mv.Images = append(mv.Images, ref+" ("+img.LicenseSPDX+")")
	}
	return mv
}

func printApp(e *Env, v *AppView) {
	e.printf("%s (%s)\n  appId        %s\n  license      %s\n  maintainer   %s (%d bps of fees)\n", v.Name, v.ID, v.AppID, v.License, v.Maintainer, v.MaintainerShareBps)
	if m := v.Manifest; m != nil {
		e.printf("  description  %s\n  upstream     %s %s (%s)\n", oneLine(m.Description), m.Upstream.Repo, m.Upstream.Version, m.Upstream.LicenseSPDX)
		e.printf("  resources    %d CPU, %d GB memory, %d GB disk\n  metering     %s\n", m.Resources.CPU, m.Resources.MemoryGB, m.Resources.DiskGB, m.Metering)
		section := func(title string, items []string) {
			e.printf("  %s\n", title)
			if len(items) == 0 {
				e.printf("    none\n")
			}
			for _, it := range items {
				e.printf("    %s\n", it)
			}
		}
		section("images", m.Images)
		section("routes", m.Routes)
		section("default egress", m.Egress)
		section("secrets", m.Secrets)
	}
	e.printf("  releases\n")
	if len(v.Releases) == 0 {
		e.printf("    none\n")
	}
	for _, r := range v.Releases {
		e.printf("    %-24s %-10s releaseId %s\n      bundleHash %s\n      bundle     %s\n", r.Version, r.Status, r.ReleaseID, r.BundleHash, r.BundleURL)
		if r.ProvenanceURI != "" {
			e.printf("      provenance %s\n", r.ProvenanceURI)
		}
		if r.SignatureURI != "" {
			e.printf("      signature  %s\n", r.SignatureURI)
		}
	}
}
