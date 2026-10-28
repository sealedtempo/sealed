package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// CatalogDir is the catalog's app directory, relative to the repository root.
const CatalogDir = "catalog/apps"

// App is one manifest under catalog/apps.
type App struct {
	ID       string             // manifest id
	Dir      string             // repo-relative, slash separated (catalog/apps/<id> or a nested variant)
	Nested   bool               // a variant manifest below an app directory (for example fallback-opencode)
	Manifest *composer.Manifest // parsed and validated by the composer
	Raw      []byte             // manifest.yaml bytes
}

// ManifestFile is the repo-relative manifest path.
func (a App) ManifestFile() string { return path.Join(a.Dir, composer.ManifestFile) }

// Version is the release version hashed into releaseId.
func (a App) Version() string { return a.Manifest.Version() }

// LoadApps reads every manifest.yaml under <root>/catalog/apps. Top-level apps come first, sorted by id;
// nested variants follow, sorted by directory. With includeNested false only catalog/apps/<id>/manifest.yaml
// files are returned (the apps that get releases).
func LoadApps(root string, includeNested bool) ([]App, error) {
	base := filepath.Join(root, filepath.FromSlash(CatalogDir))
	var top, nested []App
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != composer.ManifestFile {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		isTop := path.Dir(rel) == CatalogDir
		if !isTop && !includeNested {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m, err := composer.ParseManifest(raw)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", rel, composer.ManifestFile, err)
		}
		app := App{ID: m.ID, Dir: rel, Nested: !isTop, Manifest: m, Raw: raw}
		if isTop {
			if path.Base(rel) != m.ID {
				return fmt.Errorf("%s/%s: id %q does not match its directory", rel, composer.ManifestFile, m.ID)
			}
			top = append(top, app)
		} else {
			nested = append(nested, app)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(top, func(i, j int) bool { return top[i].ID < top[j].ID })
	sort.Slice(nested, func(i, j int) bool { return nested[i].Dir < nested[j].Dir })
	return append(top, nested...), nil
}

// FindApp returns the top-level app with the given id.
func FindApp(apps []App, id string) (App, bool) {
	for _, a := range apps {
		if a.ID == id && !a.Nested {
			return a, true
		}
	}
	return App{}, false
}

// bundleInput reports whether a repo-relative path is an input of the app's release bundle
// (manifest.yaml, compose.fragment.yaml, egress.yaml, LICENSE-NOTICE, LICENSES/**). Changes to tests,
// READMEs, scripts and image sources do not change the bundle: image sources change it only through the
// digest pin in manifest.yaml.
func bundleInput(appDir, file string) bool {
	rel, ok := strings.CutPrefix(file, appDir+"/")
	if !ok {
		return false
	}
	switch rel {
	case composer.ManifestFile, composer.FragmentFile, composer.EgressFile, "LICENSE-NOTICE":
		return true
	}
	return strings.HasPrefix(rel, "LICENSES/")
}

// ChangedApps returns the ids of top-level apps with a changed bundle input among files (repo-relative).
func ChangedApps(apps []App, files []string) []string {
	var out []string
	for _, a := range apps {
		if a.Nested {
			continue
		}
		for _, f := range files {
			if bundleInput(a.Dir, strings.TrimSpace(f)) {
				out = append(out, a.ID)
				break
			}
		}
	}
	return out
}
