// Package secrets plans and generates the customer's app secrets (spec 8.4 `sealed secrets`, INTERFACES section
// 9, D-043): which Secret Manager entries a stack needs, how missing values are generated, and how cross-app
// references (`same_as: "<appId>/<NAME>"`) collapse two manifest entries into one stored secret.
package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Secret is one entry of a manifest's secrets list.
type Secret struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Generate    string `yaml:"generate"`
	Optional    bool   `yaml:"optional"`
	// SameAs is "<appId>/<NAME>": the value is the referenced app's secret, stored once under that app's name
	// (D-043). The key broker returns it under this app's name.
	SameAs string `yaml:"same_as"`
}

// App is the secrets view of one manifest.
type App struct {
	ID      string
	Secrets []Secret
}

var (
	appIDRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	secretNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Generators a manifest may name (catalog/schema, brief item 7).
var Generators = []string{"none", "hex32", "base64-32", "sk-hex32", "password"}

func knownGenerator(g string) bool {
	for _, k := range Generators {
		if g == k {
			return true
		}
	}
	return false
}

// ParseManifest reads the id and secrets of a manifest.yaml. It reads only those two fields, so it works on
// manifests from any composer version (runtime/composer validates the rest); unknown keys inside a secrets entry
// are errors.
func ParseManifest(data []byte) (*App, error) {
	var doc struct {
		ID      string      `yaml:"id"`
		Secrets []yaml.Node `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if !appIDRe.MatchString(doc.ID) {
		return nil, fmt.Errorf("manifest: id %q is not an app id", doc.ID)
	}
	app := &App{ID: doc.ID}
	seen := map[string]bool{}
	for i, n := range doc.Secrets {
		var s Secret
		dec := yaml.NewDecoder(bytes.NewReader(mustMarshal(&n)))
		dec.KnownFields(true)
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("manifest %s: secrets[%d]: %w", doc.ID, i, err)
		}
		if !secretNameRe.MatchString(s.Name) {
			return nil, fmt.Errorf("manifest %s: secrets[%d]: name %q", doc.ID, i, s.Name)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("manifest %s: secret %s declared twice", doc.ID, s.Name)
		}
		seen[s.Name] = true
		if s.Generate == "" {
			s.Generate = "none"
		}
		if !knownGenerator(s.Generate) {
			return nil, fmt.Errorf("manifest %s: secret %s: unknown generator %q", doc.ID, s.Name, s.Generate)
		}
		if s.SameAs != "" {
			ref, name, ok := strings.Cut(s.SameAs, "/")
			if !ok || !appIDRe.MatchString(ref) || !secretNameRe.MatchString(name) {
				return nil, fmt.Errorf("manifest %s: secret %s: same_as %q must be <appId>/<NAME>", doc.ID, s.Name, s.SameAs)
			}
			if ref == doc.ID {
				return nil, fmt.Errorf("manifest %s: secret %s: same_as must name another app", doc.ID, s.Name)
			}
		}
		app.Secrets = append(app.Secrets, s)
	}
	return app, nil
}

func mustMarshal(n *yaml.Node) []byte {
	b, err := yaml.Marshal(n)
	if err != nil {
		panic(err)
	}
	return b
}

// Secret returns the named secret.
func (a *App) Secret(name string) (Secret, bool) {
	for _, s := range a.Secrets {
		if s.Name == name {
			return s, true
		}
	}
	return Secret{}, false
}

// LoadCatalog reads catalog/apps/<id>/manifest.yaml for each id.
func LoadCatalog(dir string, ids []string) ([]*App, error) {
	var out []*App
	for _, id := range ids {
		if !appIDRe.MatchString(id) {
			return nil, fmt.Errorf("app id %q", id)
		}
		b, err := os.ReadFile(filepath.Join(dir, id, "manifest.yaml"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("app %s is not in the catalog at %s", id, dir)
			}
			return nil, err
		}
		app, err := ParseManifest(b)
		if err != nil {
			return nil, err
		}
		if app.ID != id {
			return nil, fmt.Errorf("%s/%s/manifest.yaml has id %q", dir, id, app.ID)
		}
		out = append(out, app)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
