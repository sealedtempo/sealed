package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/sealedtempo/sealed/runtime/composer"
)

// BuildResult is what one runtime image workflow build reports (one JSON file per image).
type BuildResult struct {
	Name          string       `json:"name"`
	Dir           string       `json:"dir"`
	Repository    string       `json:"repository"`
	Tag           string       `json:"tag"`
	Digest        string       `json:"digest"`
	Commit        string       `json:"commit"`
	Reproducible  *bool        `json:"reproducible,omitempty"` // nil when the rebuild check did not run
	RebuildDigest string       `json:"rebuildDigest,omitempty"`
	Scan          *ScanSummary `json:"scan,omitempty"`
}

// PinChange is one digest written by Pin.
type PinChange struct {
	File  string `json:"file"`
	Image string `json:"image"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// Pin scopes: the catalog PR changes manifests; the runtime PR changes runtime-images.json and
// extra-images.json, which needs a composer version bump (composed bytes change).
const (
	ScopeCatalog = "catalog"
	ScopeRuntime = "runtime"
	ScopeAll     = "all"
)

func scopeIncludes(scope, kind string) bool {
	switch scope {
	case ScopeAll:
		return true
	case ScopeCatalog:
		return kind == "manifest"
	case ScopeRuntime:
		return kind == "runtime" || kind == "extra"
	}
	return false
}

// LoadBuildResults reads every *.json file in dir.
func LoadBuildResults(dir string) ([]BuildResult, error) {
	var out []BuildResult
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r BuildResult
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, r)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// Pin writes the digests of results into every pin target within scope. Results for images the set does
// not know, or whose directory differs, are errors: the PR must never pin an image built from elsewhere.
func Pin(root string, set *ImageSet, results []BuildResult, scope string) ([]PinChange, error) {
	if scope != ScopeCatalog && scope != ScopeRuntime && scope != ScopeAll {
		return nil, fmt.Errorf("unknown scope %q (want catalog, runtime or all)", scope)
	}
	byName := map[string]BuildImage{}
	for _, b := range set.Build {
		byName[b.Name] = b
	}
	type edit struct {
		target PinTarget
		digest string
	}
	perFile := map[string][]edit{}
	seen := map[string]bool{}
	for _, r := range results {
		b, ok := byName[r.Name]
		if !ok {
			return nil, fmt.Errorf("result for unknown image %q", r.Name)
		}
		if r.Dir != b.Dir {
			return nil, fmt.Errorf("result for %q was built from %s, but the catalog builds it from %s", r.Name, r.Dir, b.Dir)
		}
		if !digestRe.MatchString(r.Digest) || r.Digest == zeroDigest {
			return nil, fmt.Errorf("result for %q has an invalid digest %q", r.Name, r.Digest)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("two results for %q", r.Name)
		}
		seen[r.Name] = true
		for _, t := range b.Pins {
			if scopeIncludes(scope, t.Kind) {
				perFile[t.File] = append(perFile[t.File], edit{t, r.Digest})
			}
		}
	}
	var changes []PinChange
	for _, file := range sortedKeys(perFile) {
		p := filepath.Join(root, filepath.FromSlash(file))
		src, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out := src
		for _, e := range perFile[file] {
			var old string
			switch e.target.Kind {
			case "manifest":
				out, old, err = pinManifest(out, e.target.Image, e.digest)
			default:
				out, old, err = pinJSONImage(out, e.target.Image, e.digest)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			if old != e.digest {
				changes = append(changes, PinChange{File: file, Image: e.target.Image, Old: old, New: e.digest})
			}
		}
		if !bytes.Equal(out, src) {
			if err := os.WriteFile(p, out, 0o644); err != nil {
				return nil, err
			}
		}
	}
	return changes, nil
}

// pinManifest replaces the digest of images[name] in manifest YAML text. Only that scalar changes, so
// comments, quoting and layout stay byte for byte.
func pinManifest(src []byte, name, digest string) ([]byte, string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, "", err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, "", fmt.Errorf("not a YAML document")
	}
	images := yamlValue(doc.Content[0], "images")
	if images == nil || images.Kind != yaml.SequenceNode {
		return nil, "", fmt.Errorf("no images list")
	}
	var node *yaml.Node
	for _, item := range images.Content {
		if n := yamlValue(item, "name"); n != nil && n.Value == name {
			node = yamlValue(item, "digest")
			break
		}
	}
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil, "", fmt.Errorf("image %q has no digest", name)
	}
	old := node.Value
	if old == digest {
		return src, old, nil
	}
	off, err := lineColumnOffset(src, node.Line, node.Column)
	if err != nil {
		return nil, "", err
	}
	if node.Style == yaml.DoubleQuotedStyle || node.Style == yaml.SingleQuotedStyle {
		off++
	}
	if !bytes.HasPrefix(src[off:], []byte(old)) {
		return nil, "", fmt.Errorf("image %q: digest text not found at line %d", name, node.Line)
	}
	out := make([]byte, 0, len(src))
	out = append(out, src[:off]...)
	out = append(out, digest...)
	out = append(out, src[off+len(old):]...)
	m, err := composer.ParseManifest(out)
	if err != nil {
		return nil, "", fmt.Errorf("pinned manifest no longer parses: %w", err)
	}
	if img, ok := m.Image(name); !ok || img.Digest != digest {
		return nil, "", fmt.Errorf("image %q: pin did not take effect", name)
	}
	return out, old, nil
}

// lineColumnOffset converts a yaml.v3 1-based line and column into a byte offset. The part of the line
// before the column must be ASCII (indentation and "digest: "), so columns and bytes agree.
func lineColumnOffset(src []byte, line, col int) (int, error) {
	off := 0
	for l := 1; l < line; l++ {
		i := bytes.IndexByte(src[off:], '\n')
		if i < 0 {
			return 0, fmt.Errorf("line %d out of range", line)
		}
		off += i + 1
	}
	for i := 0; i < col-1; i++ {
		if off+i >= len(src) || src[off+i] >= 0x80 || src[off+i] == '\n' {
			return 0, fmt.Errorf("line %d: unexpected text before column %d", line, col)
		}
	}
	return off + col - 1, nil
}

func yamlValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// pinJSONImage sets images.<name>.digest in a runtime-images.json style file and drops "unbuilt".
func pinJSONImage(src []byte, name, digest string) ([]byte, string, error) {
	doc, err := parseOrderedJSON(src)
	if err != nil {
		return nil, "", err
	}
	img := doc.get("images").get(name)
	if img == nil || img.kind != 'o' {
		return nil, "", fmt.Errorf("no image %q", name)
	}
	old, _ := img.get("digest").str()
	img.setString("digest", digest)
	img.del("unbuilt")
	out := doc.encode()
	if old == digest && bytes.Equal(out, src) {
		return src, old, nil
	}
	return out, old, nil
}

// extraImagesDoc is extra-images.json.
type extraImagesDoc struct {
	Schema   string `json:"schema"`
	Registry string `json:"registry"`
	Images   map[string]struct {
		Digest      string `json:"digest"`
		Source      string `json:"source"`
		LicenseSPDX string `json:"license_spdx"`
		Unbuilt     bool   `json:"unbuilt,omitempty"`
		Notes       string `json:"notes,omitempty"`
	} `json:"images"`
}

func loadExtraImages(root string) (*extraImagesDoc, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ExtraImagesFile)))
	if err != nil {
		return nil, err
	}
	var d extraImagesDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%s: %w", ExtraImagesFile, err)
	}
	if d.Schema != "sealed-extra-images/v1" {
		return nil, fmt.Errorf("%s: unknown schema %q", ExtraImagesFile, d.Schema)
	}
	for name, img := range d.Images {
		if !digestRe.MatchString(img.Digest) || (img.Digest == zeroDigest) != img.Unbuilt {
			return nil, fmt.Errorf("%s: %s: unbuilt must be true exactly when the digest is all zeros", ExtraImagesFile, name)
		}
	}
	return &d, nil
}

// PinSummary renders the PR body for a pin PR.
func PinSummary(scope, runURL, commit string, results []BuildResult, changes []PinChange) string {
	var b strings.Builder
	if scope == ScopeRuntime {
		b.WriteString("Pins the sidecar image digests built by the runtime image workflow.\n\n")
		b.WriteString("These digests are part of the composer version, because every composed stack names them. ")
		b.WriteString("Before this PR can merge, the composer owner bumps `composer.Version`, regenerates the goldens with ")
		b.WriteString("`go test ./runtime/composer -run Golden -update` and refreshes the copies of the goldens (see runtime/composer/README.md). ")
		b.WriteString("The composer golden test fails until then, by design.\n\n")
	} else {
		b.WriteString("Pins the catalog image digests built by the runtime image workflow (D-028). ")
		b.WriteString("Each pinned image changes its app's bundle, so the app needs a new `release_version` before its next release.\n\n")
	}
	if runURL != "" {
		fmt.Fprintf(&b, "Workflow run: %s\n", runURL)
	}
	if commit != "" {
		fmt.Fprintf(&b, "Built from commit: `%s`\n", commit)
	}
	b.WriteString("\n| image | digest | reproducible | critical (unwaived) | pinned in |\n|---|---|---|---|---|\n")
	files := map[string][]string{}
	for _, c := range changes {
		files[c.Image] = append(files[c.Image], c.File)
	}
	for _, r := range results {
		if len(files[r.Name]) == 0 {
			continue
		}
		repro := "not checked"
		if r.Reproducible != nil {
			repro = "yes"
			if !*r.Reproducible {
				repro = "no (rebuild gave " + r.RebuildDigest + ")"
			}
		}
		crit := "not scanned"
		if r.Scan != nil {
			crit = fmt.Sprintf("%d (%d)", r.Scan.Counts["critical"], len(r.Scan.Unwaived))
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n", r.Name, r.Digest, repro, crit, strings.Join(files[r.Name], ", "))
	}
	if len(changes) == 0 {
		b.WriteString("\nNo digest changed.\n")
	}
	return b.String()
}
