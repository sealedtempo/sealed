package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	// RuntimeImagesFile is the composer's sidecar image list.
	RuntimeImagesFile = "runtime/composer/rimembed/runtime-images.json"
	// BuildsFile holds the build context of every image the catalog builds and the mirror policy.
	BuildsFile = "catalog/tools/release/images.yaml"
	// ExtraImagesFile pins built images that nothing else references (the key broker).
	ExtraImagesFile = "catalog/tools/release/extra-images.json"
	// RuntimeWaiversFile holds Grype waivers for sidecar and extra images.
	RuntimeWaiversFile = "catalog/tools/release/runtime-waivers.yaml"

	zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	digestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	tagCharRe   = regexp.MustCompile(`[^A-Za-z0-9_.-]`)
)

// BuildSettings is images.yaml.
type BuildSettings struct {
	Version     int                   `yaml:"version"`
	Builds      map[string]BuildEntry `yaml:"builds"`
	Extra       []ExtraEntry          `yaml:"extra"`
	NeverMirror []NeverMirror         `yaml:"never_mirror"`
}

// NeverMirror is an upstream repository whose license forbids redistribution.
type NeverMirror struct {
	Repository string `yaml:"repository"`
	Decision   string `yaml:"decision"`
	Reason     string `yaml:"reason"`
}

// BuildEntry is the build setting for one image directory.
type BuildEntry struct {
	Context         string `yaml:"context"`
	Nonreproducible string `yaml:"nonreproducible"`
}

// ExtraEntry is a built image that no manifest or runtime-images.json references.
type ExtraEntry struct {
	Name            string `yaml:"name"`
	Dir             string `yaml:"dir"`
	Context         string `yaml:"context"`
	Optional        bool   `yaml:"optional"`
	Nonreproducible string `yaml:"nonreproducible"`
}

// PinTarget is one place where a built image's digest is pinned.
type PinTarget struct {
	Kind  string `json:"kind"` // manifest, runtime or extra
	File  string `json:"file"` // repo-relative
	App   string `json:"app,omitempty"`
	Image string `json:"image"` // image name inside that file
}

// BuildImage is an image the runtime image workflow builds.
type BuildImage struct {
	Name            string      `json:"name"`
	Dir             string      `json:"dir"`        // repo-relative image directory (symlinks resolved)
	Context         string      `json:"context"`    // repo-relative build context ("." is the repository root)
	Dockerfile      string      `json:"dockerfile"` // repo-relative
	Repository      string      `json:"repository"` // <registry>/<name>
	CurrentDigest   string      `json:"currentDigest"`
	Nonreproducible string      `json:"nonreproducible,omitempty"`
	Pins            []PinTarget `json:"pins"`
	Waivers         []string    `json:"waivers"` // waivers.yaml files whose entries apply to this image
}

// Unbuilt reports whether no real digest is pinned yet.
func (b BuildImage) Unbuilt() bool { return b.CurrentDigest == zeroDigest }

// MirrorImage is an upstream image copied digest-identical to the catalog registry.
type MirrorImage struct {
	Name   string   `json:"name"`
	Source string   `json:"source"` // upstream reference as written in the manifest (with tag)
	Digest string   `json:"digest"`
	From   string   `json:"from"`   // <upstream repository>@<digest>
	To     string   `json:"to"`     // <registry>/<name>:<tag>, the tag that keeps the digest visible
	Target string   `json:"target"` // <registry>/<name>@<digest>, the reference stacks pull
	Users  []string `json:"users"`  // repo-relative files that pin it
	// Blocked names the decision that forbids mirroring this repository (images.yaml never_mirror).
	Blocked string `json:"blocked,omitempty"`
}

// ImageSet is every image the catalog ships.
type ImageSet struct {
	Registry string        `json:"registry"`
	Build    []BuildImage  `json:"build"`
	Mirror   []MirrorImage `json:"mirror"`
	// Blocked are upstream images a manifest names but whose license forbids copying them (never_mirror).
	Blocked []MirrorImage `json:"blocked"`
}

type runtimeImagesDoc struct {
	Registry string `json:"registry"`
	Images   map[string]struct {
		Digest string `json:"digest"`
		Source string `json:"source"`
	} `json:"images"`
}

// LoadBuildSettings reads images.yaml.
func LoadBuildSettings(root string) (*BuildSettings, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(BuildsFile)))
	if err != nil {
		return nil, err
	}
	var s BuildSettings
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", BuildsFile, err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("%s: version must be 1", BuildsFile)
	}
	for dir, e := range s.Builds {
		if e.Context != "dir" && e.Context != "root" {
			return nil, fmt.Errorf("%s: %s: context must be dir or root", BuildsFile, dir)
		}
	}
	for _, e := range s.Extra {
		if !imageNameRe.MatchString(e.Name) || e.Dir == "" || (e.Context != "dir" && e.Context != "root") {
			return nil, fmt.Errorf("%s: extra entry %q needs a name, dir and context dir or root", BuildsFile, e.Name)
		}
	}
	for _, n := range s.NeverMirror {
		if n.Repository == "" || !strings.HasPrefix(n.Decision, "D-") || n.Reason == "" {
			return nil, fmt.Errorf("%s: never_mirror entries need repository, decision (D-xxx) and reason", BuildsFile)
		}
	}
	return &s, nil
}

// resolveDir turns a path relative to base (repo-relative, slash separated) into a repo-relative path with
// symlinks resolved, and checks it stays inside the repository.
func resolveDir(root, base, rel string) (string, error) {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("invalid build directory %q", rel)
	}
	joined := filepath.Join(root, filepath.FromSlash(base), filepath.FromSlash(rel))
	real, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", fmt.Errorf("build directory %s/%s: %w", base, rel, err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	out, err := filepath.Rel(realRoot, real)
	if err != nil || out == ".." || strings.HasPrefix(out, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("build directory %s/%s leaves the repository", base, rel)
	}
	return filepath.ToSlash(out), nil
}

// splitSource splits an upstream image reference into repository and tag ("" when there is none).
func splitSource(src string) (repo, tag string, err error) {
	ref := src
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		repo, tag = ref[:colon], ref[colon+1:]
	} else {
		repo = ref
	}
	if repo == "" || slash < 0 {
		return "", "", fmt.Errorf("image source %q must name a registry host (for example docker.io/library/postgres:16)", src)
	}
	return repo, tag, nil
}

// mirrorTag is the tag the mirror pushes: the upstream tag plus 12 hex digits of the digest, so two digests
// published under one upstream tag never overwrite each other.
func mirrorTag(upstreamTag, digest string) string {
	short := strings.TrimPrefix(digest, "sha256:")[:12]
	t := tagCharRe.ReplaceAllString(upstreamTag, "-")
	t = strings.TrimLeft(t, ".-")
	if t == "" {
		return "sha256-" + short
	}
	if len(t) > 100 {
		t = t[:100]
	}
	return t + "-" + short
}

// LoadImages collects every built and mirrored image of the catalog and the runtime.
func LoadImages(root string) (*ImageSet, error) {
	d, err := LoadDefaults(root)
	if err != nil {
		return nil, err
	}
	settings, err := LoadBuildSettings(root)
	if err != nil {
		return nil, err
	}
	apps, err := LoadApps(root, true)
	if err != nil {
		return nil, err
	}
	set := &ImageSet{Registry: d.Registry}
	builds := map[string]*BuildImage{} // by dir
	byName := map[string]string{}      // build image name -> dir
	mirrors := map[string]*MirrorImage{}
	var errs []string

	addBuild := func(name, dir string, pin PinTarget, digest, waivers string) {
		entry, ok := settings.Builds[dir]
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: image %q builds from %s, which has no entry in %s", pin.File, name, dir, BuildsFile))
			return
		}
		if other, ok := byName[name]; ok && other != dir {
			errs = append(errs, fmt.Sprintf("built image name %q is used for %s and %s", name, other, dir))
			return
		}
		byName[name] = dir
		b := builds[dir]
		if b == nil {
			ctx := dir
			if entry.Context == "root" {
				ctx = "."
			}
			b = &BuildImage{Name: name, Dir: dir, Context: ctx, Dockerfile: dir + "/Dockerfile",
				Repository: d.Registry + "/" + name, CurrentDigest: digest, Nonreproducible: entry.Nonreproducible}
			builds[dir] = b
		}
		if b.Name != name {
			errs = append(errs, fmt.Sprintf("%s is built under two names, %q and %q", dir, b.Name, name))
			return
		}
		if b.CurrentDigest != digest {
			errs = append(errs, fmt.Sprintf("image %q is pinned to different digests (%s in %s)", name, digest, pin.File))
		}
		b.Pins = append(b.Pins, pin)
		if waivers != "" && !contains(b.Waivers, waivers) {
			b.Waivers = append(b.Waivers, waivers)
		}
	}

	for _, a := range apps {
		for _, img := range a.Manifest.Images {
			pin := PinTarget{Kind: "manifest", File: a.ManifestFile(), App: a.ID, Image: img.Name}
			waivers := a.Dir + "/waivers.yaml"
			if a.Nested {
				// A variant shares its app's waivers unless it has its own.
				if !fileExists(filepath.Join(root, filepath.FromSlash(waivers))) {
					waivers = path.Join(CatalogDir, a.ID, "waivers.yaml")
				}
			}
			if rel, ok := strings.CutPrefix(img.Source, "build:"); ok {
				dir, err := resolveDir(root, a.Dir, rel)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", a.ManifestFile(), err))
					continue
				}
				addBuild(img.Name, dir, pin, img.Digest, waivers)
				continue
			}
			addMirror(mirrors, d.Registry, img.Name, img.Source, img.Digest, a.ManifestFile(), &errs)
		}
	}

	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RuntimeImagesFile)))
	if err != nil {
		return nil, err
	}
	var ri runtimeImagesDoc
	if err := json.Unmarshal(raw, &ri); err != nil {
		return nil, fmt.Errorf("%s: %w", RuntimeImagesFile, err)
	}
	if ri.Registry != d.Registry {
		errs = append(errs, fmt.Sprintf("%s registry %q differs from config/defaults.yaml catalog.registry %q", RuntimeImagesFile, ri.Registry, d.Registry))
	}
	for _, name := range sortedKeys(ri.Images) {
		img := ri.Images[name]
		pin := PinTarget{Kind: "runtime", File: RuntimeImagesFile, Image: name}
		if rel, ok := strings.CutPrefix(img.Source, "build:"); ok {
			dir, err := resolveDir(root, ".", rel)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", RuntimeImagesFile, err))
				continue
			}
			addBuild(name, dir, pin, img.Digest, RuntimeWaiversFile)
			continue
		}
		addMirror(mirrors, d.Registry, name, img.Source, img.Digest, RuntimeImagesFile, &errs)
	}

	extra, err := loadExtraImages(root)
	if err != nil {
		return nil, err
	}
	for _, e := range settings.Extra {
		if !fileExists(filepath.Join(root, filepath.FromSlash(e.Dir), "Dockerfile")) {
			if e.Optional {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: extra image %q: %s/Dockerfile does not exist", BuildsFile, e.Name, e.Dir))
			continue
		}
		digest := zeroDigest
		if x, ok := extra.Images[e.Name]; ok {
			digest = x.Digest
		}
		if _, ok := settings.Builds[e.Dir]; !ok {
			settings.Builds[e.Dir] = BuildEntry{Context: e.Context, Nonreproducible: e.Nonreproducible}
		}
		addBuild(e.Name, e.Dir, PinTarget{Kind: "extra", File: ExtraImagesFile, Image: e.Name}, digest, RuntimeWaiversFile)
	}

	for _, name := range sortedKeys(mirrors) {
		if _, clash := byName[mirrors[name].Name]; clash {
			errs = append(errs, fmt.Sprintf("image name %q is both built and mirrored; give one of them another name", mirrors[name].Name))
		}
	}
	for dir := range settings.Builds {
		if _, used := builds[dir]; !used {
			errs = append(errs, fmt.Sprintf("%s: %s is not referenced by any manifest or runtime image; remove it", BuildsFile, dir))
		}
	}
	for _, b := range builds {
		if !fileExists(filepath.Join(root, filepath.FromSlash(b.Dockerfile))) {
			errs = append(errs, fmt.Sprintf("%s does not exist", b.Dockerfile))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New(strings.Join(errs, "\n"))
	}
	for _, dir := range sortedKeys(builds) {
		set.Build = append(set.Build, *builds[dir])
	}
	sort.Slice(set.Build, func(i, j int) bool { return set.Build[i].Name < set.Build[j].Name })
	set.Mirror, set.Blocked = []MirrorImage{}, []MirrorImage{}
	for _, k := range sortedKeys(mirrors) {
		m := *mirrors[k]
		repo := strings.TrimSuffix(m.From, "@"+m.Digest)
		for _, n := range settings.NeverMirror {
			if strings.EqualFold(repo, n.Repository) {
				m.Blocked = n.Decision + ": " + n.Reason
			}
		}
		if m.Blocked != "" {
			set.Blocked = append(set.Blocked, m)
		} else {
			set.Mirror = append(set.Mirror, m)
		}
	}
	return set, nil
}

func addMirror(mirrors map[string]*MirrorImage, registry, name, source, digest, file string, errs *[]string) {
	if !digestRe.MatchString(digest) || digest == zeroDigest {
		*errs = append(*errs, fmt.Sprintf("%s: upstream image %q needs a real digest", file, name))
		return
	}
	repo, tag, err := splitSource(source)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s: %v", file, err))
		return
	}
	key := name + "@" + digest
	m := mirrors[key]
	if m == nil {
		m = &MirrorImage{Name: name, Source: source, Digest: digest, From: repo + "@" + digest,
			To: registry + "/" + name + ":" + mirrorTag(tag, digest), Target: registry + "/" + name + "@" + digest}
		mirrors[key] = m
	}
	if !contains(m.Users, file) {
		m.Users = append(m.Users, file)
		sort.Strings(m.Users)
	}
}

// SelectBuilds returns the builds to run: every unbuilt image, every image whose directory holds a changed
// file, and every repository-root image when a file outside catalog/apps and docs changed (its Dockerfile
// may copy it). With all set every image is selected; names limits the result to those images.
func SelectBuilds(set *ImageSet, changed []string, all bool, names []string) []BuildImage {
	var out []BuildImage
	for _, b := range set.Build {
		if len(names) > 0 && !contains(names, b.Name) {
			continue
		}
		if all || len(names) > 0 || b.Unbuilt() || buildChanged(b, changed) {
			out = append(out, b)
		}
	}
	return out
}

// ChangedBuilds returns the builds whose inputs a changed file touches, by the rules of SelectBuilds but
// without the unbuilt images it adds. The pull request check (images-pr.yml) builds these.
func ChangedBuilds(set *ImageSet, changed []string) []BuildImage {
	var out []BuildImage
	for _, b := range set.Build {
		if buildChanged(b, changed) {
			out = append(out, b)
		}
	}
	return out
}

func buildChanged(b BuildImage, changed []string) bool {
	for _, f := range changed {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.HasPrefix(f, b.Dir+"/") || f == BuildsFile {
			return true
		}
		if b.Context == "." && !strings.HasPrefix(f, CatalogDir+"/") && !strings.HasPrefix(f, "docs/") &&
			!strings.HasPrefix(f, ".github/") {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ScanApp is one app of the scan matrix: the images to scan and the waivers that apply to them.
type ScanApp struct {
	App     string      `json:"app"`
	Dir     string      `json:"dir"`
	Waivers string      `json:"waivers"`
	Images  []ScanImage `json:"images"`
}

// ScanImage is one image to scan. Mirrored images are scanned at their upstream source by digest (the
// same bytes the mirror serves); built images at the catalog registry, after the scan checks images.yml's
// signature on them (Built, supply-3). Unbuilt images have no digest yet.
type ScanImage struct {
	Name    string `json:"name"`
	Ref     string `json:"ref,omitempty"`
	Built   bool   `json:"built,omitempty"`
	Unbuilt bool   `json:"unbuilt,omitempty"`
	Blocked string `json:"blocked,omitempty"`
}

// ScanMatrix lists the top-level apps (all when apps is empty) with their images, then the runtime images
// as the RuntimeScanApp entry when apps is empty or names it.
func ScanMatrix(set *ImageSet, root string, apps []string) []ScanApp {
	list, err := LoadApps(root, false)
	if err != nil {
		return nil
	}
	upstream := map[string]MirrorImage{}
	for _, m := range append(append([]MirrorImage{}, set.Mirror...), set.Blocked...) {
		upstream[m.Name+"@"+m.Digest] = m
	}
	out := []ScanApp{}
	for _, a := range list {
		if len(apps) > 0 && !contains(apps, a.ID) {
			continue
		}
		sa := ScanApp{App: a.ID, Dir: a.Dir, Waivers: a.Dir + "/waivers.yaml", Images: []ScanImage{}}
		for _, img := range a.Manifest.Images {
			si := ScanImage{Name: img.Name}
			switch {
			case img.Unbuilt():
				si.Unbuilt = true
			case strings.HasPrefix(img.Source, "build:"):
				si.Ref, si.Built = set.Registry+"/"+img.Name+"@"+img.Digest, true
			default:
				m := upstream[img.Name+"@"+img.Digest]
				si.Ref, si.Blocked = m.From, m.Blocked
			}
			sa.Images = append(sa.Images, si)
		}
		out = append(out, sa)
	}
	if len(apps) == 0 || contains(apps, RuntimeScanApp) {
		out = append(out, runtimeScanApp(set, upstream))
	}
	return out
}

// RuntimeScanApp is the scan matrix entry for the images every stack runs but no app manifest names: Caddy
// and the sidecars (runtime-images.json) and the key broker (extra-images.json). App ids starting with
// "sealed-" are reserved, so no catalog app can take this name. It has no app directory, so the scan job
// skips the catalog lint for it, and runtime-waivers.yaml applies (supply-5).
const RuntimeScanApp = "sealed-runtime"

func runtimeScanApp(set *ImageSet, upstream map[string]MirrorImage) ScanApp {
	sa := ScanApp{App: RuntimeScanApp, Waivers: RuntimeWaiversFile, Images: []ScanImage{}}
	for _, b := range set.Build {
		for _, p := range b.Pins {
			if p.Kind != "runtime" && p.Kind != "extra" {
				continue
			}
			si := ScanImage{Name: b.Name}
			if b.Unbuilt() {
				si.Unbuilt = true
			} else {
				si.Ref = b.Repository + "@" + b.CurrentDigest
			}
			sa.Images = append(sa.Images, si)
			break
		}
	}
	for _, m := range upstream {
		if contains(m.Users, RuntimeImagesFile) {
			sa.Images = append(sa.Images, ScanImage{Name: m.Name, Ref: m.From, Blocked: m.Blocked})
		}
	}
	sort.Slice(sa.Images, func(i, j int) bool {
		a, b := sa.Images[i], sa.Images[j]
		return a.Name < b.Name || (a.Name == b.Name && a.Ref < b.Ref)
	})
	return sa
}
