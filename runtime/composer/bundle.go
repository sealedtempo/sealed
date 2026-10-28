package composer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
	"go.yaml.in/yaml/v3"
)

// Fixed bundle file names (INTERFACES section 7, D-028).
const (
	ManifestFile = "manifest.yaml"
	FragmentFile = "compose.fragment.yaml"
	EgressFile   = "egress.yaml"
	licensesDir  = "LICENSES/"
	sbomDir      = "sbom/"
	scanDir      = "scan/"
	sbomSuffix   = ".spdx.json"
)

// Bundle is a loaded, validated release bundle.
type Bundle struct {
	Hash             Hash              // bundleHash = sha256(bundle.tar)
	Tar              []byte            // the canonical tar bytes
	Files            map[string][]byte // every regular file in the tar
	Manifest         *Manifest
	Fragment         *Fragment
	Egress           *EgressPolicy
	EgressPolicyHash Hash
	SBOMHash         Hash
	AppID            Hash
	ReleaseID        Hash
}

// Version is the release version hashed into the releaseId.
func (b *Bundle) Version() string { return b.Manifest.Version() }

// BuildInput describes where the bundle builder reads its files.
type BuildInput struct {
	// AppDir is catalog/apps/<id>. It must hold manifest.yaml,
	// compose.fragment.yaml and egress.yaml; LICENSE-NOTICE and every file
	// under LICENSES/ go into the bundle's LICENSES/ directory.
	AppDir string
	// SBOMDir holds <image>.spdx.json for every manifest image. Defaults to
	// AppDir/sbom when it exists.
	SBOMDir string
	// ScanDir holds <image>.json scan reports. Defaults to AppDir/scan when it exists.
	ScanDir string
	// Registry is catalog.registry from config/defaults.yaml. Every
	// images[].ref in the bundled manifest becomes <Registry>/<name>@<digest>.
	Registry string
	// AllowMissingSBOM permits images without an SBOM (local development only;
	// catalog lint and the release job reject such bundles).
	AllowMissingSBOM bool
}

// BuildBundle reads an app directory and returns the loaded bundle. The tar
// bytes are in Bundle.Tar; the same inputs always give the same bytes.
func BuildBundle(in BuildInput) (*Bundle, error) {
	files, err := CollectBundleFiles(in)
	if err != nil {
		return nil, err
	}
	tarBytes, err := WriteTar(files)
	if err != nil {
		return nil, err
	}
	return LoadBundle(tarBytes)
}

// CollectBundleFiles gathers and normalizes the files of a bundle.
func CollectBundleFiles(in BuildInput) (map[string][]byte, error) {
	if !digestRefRe.MatchString(in.Registry + "/x@" + zeroDigest) {
		return nil, fmt.Errorf("bundle: invalid registry %q", in.Registry)
	}
	files := map[string][]byte{}
	for _, name := range []string{ManifestFile, FragmentFile, EgressFile} {
		b, err := os.ReadFile(filepath.Join(in.AppDir, name))
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		files[name] = NormalizeText(b)
	}
	m, err := ParseManifest(files[ManifestFile])
	if err != nil {
		return nil, err
	}
	manifestBytes, err := withImageRefs(files[ManifestFile], m, in.Registry)
	if err != nil {
		return nil, err
	}
	files[ManifestFile] = manifestBytes

	if b, err := os.ReadFile(filepath.Join(in.AppDir, "LICENSE-NOTICE")); err == nil {
		files[licensesDir+"LICENSE-NOTICE"] = NormalizeText(b)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if err := addTree(files, filepath.Join(in.AppDir, "LICENSES"), licensesDir, ""); err != nil {
		return nil, err
	}

	sbomSrc := defaultDir(in.SBOMDir, filepath.Join(in.AppDir, "sbom"))
	scanSrc := defaultDir(in.ScanDir, filepath.Join(in.AppDir, "scan"))
	images := map[string]bool{}
	for _, img := range m.Images {
		images[img.Name] = true
	}
	for _, spec := range []struct{ dir, prefix, suffix string }{{sbomSrc, sbomDir, sbomSuffix}, {scanSrc, scanDir, ".json"}} {
		if spec.dir == "" {
			continue
		}
		if err := addTree(files, spec.dir, spec.prefix, spec.suffix); err != nil {
			return nil, err
		}
	}
	for name := range files {
		for _, spec := range []struct{ prefix, suffix string }{{sbomDir, sbomSuffix}, {scanDir, ".json"}} {
			if rest, ok := strings.CutPrefix(name, spec.prefix); ok {
				img, ok := strings.CutSuffix(rest, spec.suffix)
				if !ok || !images[img] {
					return nil, fmt.Errorf("bundle: %s does not belong to a manifest image", name)
				}
			}
		}
	}
	if !in.AllowMissingSBOM {
		for _, img := range m.Images {
			if _, ok := files[sbomDir+img.Name+sbomSuffix]; !ok {
				return nil, fmt.Errorf("bundle: image %q has no SBOM (%s%s%s)", img.Name, sbomDir, img.Name, sbomSuffix)
			}
		}
	}
	return files, nil
}

func defaultDir(explicit, fallback string) string {
	if explicit != "" {
		return explicit
	}
	if st, err := os.Stat(fallback); err == nil && st.IsDir() {
		return fallback
	}
	return ""
}

// addTree copies every regular file under dir into files with the given
// prefix. A non-empty suffix restricts the copy to files with that suffix,
// flat in dir.
func addTree(files map[string][]byte, dir, prefix, suffix string) error {
	st, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("bundle: %s is not a directory", dir)
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && suffix != "" {
				return fmt.Errorf("bundle: unexpected directory %s", p)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("bundle: %s is not a regular file", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(path.Base(rel), ".") {
			return nil // editor and OS droppings such as .DS_Store
		}
		if suffix != "" && !strings.HasSuffix(rel, suffix) {
			return fmt.Errorf("bundle: %s: expected a %s file", p, suffix)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[prefix+rel] = NormalizeText(b)
		return nil
	})
}

// withImageRefs sets images[i].ref = <registry>/<name>@<digest> in the
// manifest YAML, editing the node tree so comments and key order survive.
func withImageRefs(src []byte, m *Manifest, registry string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("manifest.yaml: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("manifest.yaml: top level must be a mapping")
	}
	images := mappingValue(doc.Content[0], "images")
	if images == nil || images.Kind != yaml.SequenceNode || len(images.Content) != len(m.Images) {
		return nil, fmt.Errorf("manifest.yaml: images must be a block list")
	}
	for i, item := range images.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("manifest.yaml: images[%d] must be a mapping", i)
		}
		ref := registry + "/" + m.Images[i].Name + "@" + m.Images[i].Digest
		if v := mappingValue(item, "ref"); v != nil {
			v.Value, v.Tag, v.Style = ref, "!!str", 0
			continue
		}
		item.Content = append(item.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ref"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ref})
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("manifest.yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// LoadBundle parses and validates a bundle tar: canonical tar form, LF
// endings, layout, manifest (schema and semantics), fragment rules, egress
// policy and resolved image references. It computes every release hash.
func LoadBundle(tarBytes []byte) (*Bundle, error) {
	files, err := ReadTar(tarBytes)
	if err != nil {
		return nil, err
	}
	for name, b := range files {
		if err := checkLayout(name); err != nil {
			return nil, err
		}
		if !bytes.Equal(NormalizeText(b), b) {
			return nil, fmt.Errorf("bundle: %s is not LF-normalized", name)
		}
	}
	for _, name := range []string{ManifestFile, FragmentFile, EgressFile} {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("bundle: %s is missing", name)
		}
	}
	m, err := ParseManifest(files[ManifestFile])
	if err != nil {
		return nil, err
	}
	for i, img := range m.Images {
		if img.Ref == "" {
			return nil, &ManifestError{App: m.ID, Field: fmt.Sprintf("images[%d].ref", i), Msg: "missing; bundles carry resolved image references"}
		}
		if !digestRefRe.MatchString(img.Ref) {
			return nil, &ManifestError{App: m.ID, Field: fmt.Sprintf("images[%d].ref", i), Msg: fmt.Sprintf("%q is not a digest reference", img.Ref)}
		}
	}
	frag, err := ParseFragment(m, files[FragmentFile])
	if err != nil {
		return nil, err
	}
	egress, egressHash, err := ParseEgressPolicy(files[EgressFile])
	if err != nil {
		return nil, fmt.Errorf("app %q: %w", m.ID, err)
	}
	sbomHash, err := computeSBOMHash(files)
	if err != nil {
		return nil, err
	}
	b := &Bundle{
		Hash:             SHA256(tarBytes),
		Tar:              tarBytes,
		Files:            files,
		Manifest:         m,
		Fragment:         frag,
		Egress:           egress,
		EgressPolicyHash: egressHash,
		SBOMHash:         sbomHash,
		AppID:            AppID(m.ID),
	}
	b.ReleaseID = ReleaseID(b.AppID, m.Version(), b.Hash)
	return b, nil
}

func checkLayout(name string) error {
	switch name {
	case ManifestFile, FragmentFile, EgressFile:
		return nil
	}
	if strings.HasPrefix(name, licensesDir) {
		return nil
	}
	for _, spec := range []struct{ prefix, suffix string }{{sbomDir, sbomSuffix}, {scanDir, ".json"}} {
		if rest, ok := strings.CutPrefix(name, spec.prefix); ok && strings.HasSuffix(rest, spec.suffix) && !strings.Contains(rest, "/") {
			return nil
		}
	}
	return fmt.Errorf("bundle: unexpected file %q", name)
}

// computeSBOMHash is sha256(CJSON({"<image>": "0x<sha256 of sbom file>"})).
func computeSBOMHash(files map[string][]byte) (Hash, error) {
	set := map[string]any{}
	names := make([]string, 0)
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rest, ok := strings.CutPrefix(name, sbomDir)
		if !ok {
			continue
		}
		img := strings.TrimSuffix(rest, sbomSuffix)
		sum := SHA256(files[name])
		set[img] = "0x" + hex.EncodeToString(sum[:])
	}
	canon, err := cjson.Encode(set)
	if err != nil {
		return Hash{}, err
	}
	return SHA256(canon), nil
}

// ReleaseInfo is what the release job publishes onchain for a bundle.
type ReleaseInfo struct {
	AppID            string `json:"appId"`
	Slug             string `json:"slug"`
	Version          string `json:"version"`
	BundleHash       string `json:"bundleHash"`
	EgressPolicyHash string `json:"egressPolicyHash"`
	SBOMHash         string `json:"sbomHash"`
	ReleaseID        string `json:"releaseId"`
}

// Info returns the publishRelease arguments and the derived releaseId.
func (b *Bundle) Info() ReleaseInfo {
	return ReleaseInfo{
		AppID:            b.AppID.Hex(),
		Slug:             b.Manifest.ID,
		Version:          b.Version(),
		BundleHash:       b.Hash.Hex(),
		EgressPolicyHash: b.EgressPolicyHash.Hex(),
		SBOMHash:         b.SBOMHash.Hex(),
		ReleaseID:        b.ReleaseID.Hex(),
	}
}
