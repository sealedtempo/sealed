package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real catalog: every build source has a build entry, symlinked image dirs resolve, sidecars are
// included, and nothing is blocked: crm is EspoCRM (D-049a), so the never_mirror entry for Twenty (D-049) matches no
// manifest and the Twenty image is not mirrored.
func TestLoadImagesRealCatalog(t *testing.T) {
	set, err := LoadImages(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]BuildImage{}
	for _, b := range set.Build {
		byName[b.Name] = b
	}
	for _, name := range []string{"sealed-agent", "sealed-egress", "sealed-init", "sealed-mpp-payer", "sealed-verifierd", "relay",
		"litellm", "litellm-relay", "local-model", "tooljet", "scraper-runner-playwright", "opencode", "espocrm"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("build image %s missing", name)
		}
	}
	if lm := byName["local-model"]; lm.Dir != "runtime/images/local-model" || lm.Context != lm.Dir {
		t.Errorf("local-model resolves through the llm-gateway symlink to %q (context %q)", lm.Dir, lm.Context)
	}
	if r := byName["relay"]; r.Context != "." || r.Dockerfile != "catalog/apps/inference-relay/images/relay/Dockerfile" {
		t.Errorf("relay builds from the repository root: %+v", r)
	}
	if a := byName["sealed-agent"]; len(a.Pins) != 1 || a.Pins[0].Kind != "runtime" || a.Waivers[0] != RuntimeWaiversFile {
		t.Errorf("sealed-agent pin: %+v", a)
	}
	if o := byName["opencode"]; o.Waivers[0] != "catalog/apps/coding-agent/fallback-opencode/waivers.yaml" {
		t.Errorf("nested variant keeps its own waivers: %v", o.Waivers)
	}
	for _, b := range set.Build {
		if b.Repository != "ghcr.io/sealedtempo/"+b.Name {
			t.Errorf("%s repository %s", b.Name, b.Repository)
		}
	}
	var blocked []string
	for _, m := range set.Blocked {
		blocked = append(blocked, m.Name)
	}
	if len(blocked) != 0 {
		t.Errorf("blocked = %v, want none (crm is EspoCRM, D-049a)", blocked)
	}
	for _, m := range set.Mirror {
		if m.Name == "twenty" {
			t.Error("twenty must not be in the mirror list")
		}
		if !strings.HasPrefix(m.Target, "ghcr.io/sealedtempo/"+m.Name+"@sha256:") || !strings.HasSuffix(m.From, "@"+m.Digest) {
			t.Errorf("mirror %+v", m)
		}
	}
}

func TestLoadImagesFixture(t *testing.T) {
	root := fixtureRepo(t)
	set, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range set.Build {
		names = append(names, b.Name)
	}
	if got := strings.Join(names, ","); got != "gateway,sealed-agent,sealed-egress,sealed-init,sealed-mpp-payer,sealed-verifierd" {
		t.Fatalf("builds = %s (the optional key broker is skipped without key-broker/Dockerfile)", got)
	}
	// Mirrors: notes-web, postgres (fixture apps) and caddy (runtime images).
	var mirrors []string
	for _, m := range set.Mirror {
		mirrors = append(mirrors, m.Name+"="+m.To)
	}
	want := "caddy=ghcr.io/sealedtempo/caddy:2.11.7-alpine-eb4d35b7452d," +
		"notes-web=ghcr.io/sealedtempo/notes-web:1.0.0-111111111111," +
		"postgres=ghcr.io/sealedtempo/postgres:17.11-alpine-266d3c257594"
	if got := strings.Join(mirrors, ","); got != want {
		t.Fatalf("mirrors\n got %s\nwant %s", got, want)
	}

	// The key broker joins once its Dockerfile exists.
	writeFile(t, filepath.Join(root, "key-broker/Dockerfile"), "FROM scratch\n")
	set, err = LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range set.Build {
		if b.Name == "sealed-key-broker" {
			found = b.Pins[0].Kind == "extra" && b.Unbuilt() && b.Context == "."
		}
	}
	if !found {
		t.Fatal("sealed-key-broker should be built from key-broker/ and pinned in extra-images.json")
	}
}

func TestLoadImagesErrors(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, root string)
		want string
	}{
		{"build source without an entry", func(t *testing.T, root string) {
			s := strings.Replace(fixtureImagesYAML, "  catalog/apps/llm-gateway/images/gateway: {context: dir}\n", "", 1)
			writeFile(t, filepath.Join(root, BuildsFile), s)
		}, "has no entry in catalog/tools/release/images.yaml"},
		{"unused entry", func(t *testing.T, root string) {
			s := strings.Replace(fixtureImagesYAML, "builds:\n", "builds:\n  runtime/unused: {context: dir}\n", 1)
			writeFile(t, filepath.Join(root, BuildsFile), s)
		}, "runtime/unused is not referenced"},
		{"bad context", func(t *testing.T, root string) {
			s := strings.Replace(fixtureImagesYAML, "runtime/agent: {context: root}", "runtime/agent: {context: repo}", 1)
			writeFile(t, filepath.Join(root, BuildsFile), s)
		}, "context must be dir or root"},
		{"unknown settings key", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, BuildsFile), fixtureImagesYAML+"surprise: 1\n")
		}, "field surprise not found"},
		{"missing Dockerfile", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "runtime/egress/Dockerfile")); err != nil {
				t.Fatal(err)
			}
		}, "runtime/egress/Dockerfile does not exist"},
		{"build dir leaves the repo", func(t *testing.T, root string) {
			p := filepath.Join(root, CatalogDir, "llm-gateway/manifest.yaml")
			writeFile(t, p, strings.Replace(readFile(t, p), "build:images/gateway", "build:../../../../outside", 1))
		}, "build directory"},
		{"built and mirrored name", func(t *testing.T, root string) {
			p := filepath.Join(root, CatalogDir, "notes/manifest.yaml")
			s := strings.Replace(readFile(t, p), "  - name: notes-web\n", "  - name: gateway\n", 1)
			s = strings.ReplaceAll(s, "{{image:notes-web}}", "{{image:gateway}}")
			writeFile(t, p, s)
			f := filepath.Join(root, CatalogDir, "notes/compose.fragment.yaml")
			writeFile(t, f, strings.ReplaceAll(readFile(t, f), "{{image:notes-web}}", "{{image:gateway}}"))
			for _, d := range []string{"sbom", "scan"} {
				ext := ".spdx.json"
				if d == "scan" {
					ext = ".json"
				}
				_ = os.Rename(filepath.Join(root, CatalogDir, "notes", d, "notes-web"+ext), filepath.Join(root, CatalogDir, "notes", d, "gateway"+ext))
			}
		}, "both built and mirrored"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := fixtureRepo(t)
			c.edit(t, root)
			_, err := LoadImages(root)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestSelectBuilds(t *testing.T) {
	set := &ImageSet{Build: []BuildImage{
		{Name: "app-img", Dir: "catalog/apps/a/images/x", Context: "catalog/apps/a/images/x", CurrentDigest: "sha256:" + strings.Repeat("1", 64)},
		{Name: "root-img", Dir: "runtime/agent", Context: ".", CurrentDigest: "sha256:" + strings.Repeat("2", 64)},
		{Name: "unbuilt", Dir: "runtime/egress", Context: ".", CurrentDigest: zeroDigest},
	}}
	names := func(bs []BuildImage) string {
		var out []string
		for _, b := range bs {
			out = append(out, b.Name)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		changed []string
		all     bool
		only    []string
		want    string
	}{
		{nil, false, nil, "unbuilt"},
		{[]string{"catalog/apps/a/images/x/Dockerfile"}, false, nil, "app-img,unbuilt"},
		{[]string{"catalog/apps/a/manifest.yaml", "docs/x.md", ".github/workflows/ci.yml"}, false, nil, "unbuilt"},
		{[]string{"packages/core/src/index.ts"}, false, nil, "root-img,unbuilt"},
		{[]string{BuildsFile}, false, nil, "app-img,root-img,unbuilt"},
		{nil, true, nil, "app-img,root-img,unbuilt"},
		{nil, false, []string{"app-img"}, "app-img"},
	}
	for _, c := range cases {
		if got := names(SelectBuilds(set, c.changed, c.all, c.only)); got != c.want {
			t.Errorf("SelectBuilds(%v, all=%v, only=%v) = %s, want %s", c.changed, c.all, c.only, got, c.want)
		}
	}
}

func TestMirrorTag(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	for in, want := range map[string]string{
		"16.15":           "16.15-abababababab",
		"":                "sha256-abababababab",
		"v1.2.3+meta/odd": "v1.2.3-meta-odd-abababababab",
		".hidden":         "hidden-abababababab",
	} {
		if got := mirrorTag(in, d); got != want {
			t.Errorf("mirrorTag(%q) = %q, want %q", in, got, want)
		}
	}
	if got := mirrorTag(strings.Repeat("x", 200), d); len(got) > 128 {
		t.Errorf("tag too long: %d", len(got))
	}
}

func TestSplitSource(t *testing.T) {
	for in, want := range map[string][2]string{
		"docker.io/library/postgres:16.15":                {"docker.io/library/postgres", "16.15"},
		"localhost:5000/x/y:1":                            {"localhost:5000/x/y", "1"},
		"localhost:5000/x/y":                              {"localhost:5000/x/y", ""},
		"ghcr.io/a/b:1@sha256:" + strings.Repeat("0", 64): {"ghcr.io/a/b", "1"},
	} {
		repo, tag, err := splitSource(in)
		if err != nil || repo != want[0] || tag != want[1] {
			t.Errorf("splitSource(%q) = %q %q %v", in, repo, tag, err)
		}
	}
	if _, _, err := splitSource("postgres:16"); err == nil {
		t.Error("a source without a registry host must fail")
	}
}

func TestChangedApps(t *testing.T) {
	apps, err := LoadApps(repoRoot(t), true)
	if err != nil {
		t.Fatal(err)
	}
	got := ChangedApps(apps, []string{
		"catalog/apps/crm/README.md",                                // not a bundle input
		"catalog/apps/scraper/egress.yaml",                          // bundle input
		"catalog/apps/internal-tools/LICENSES/AGPL-3.0.txt",         // bundle input
		"catalog/apps/coding-agent/fallback-opencode/manifest.yaml", // nested variant: not released
		"catalog/apps/llm-gateway/images/litellm/Dockerfile",        // pinned later through the manifest
	})
	if strings.Join(got, ",") != "internal-tools,scraper" {
		t.Fatalf("ChangedApps = %v", got)
	}
}

func TestLoadAppsRealCatalog(t *testing.T) {
	top, err := LoadApps(repoRoot(t), false)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range top {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "coding-agent,crm,inference-relay,internal-tools,llm-gateway,scraper" {
		t.Fatalf("apps = %v", ids)
	}
	all, err := LoadApps(repoRoot(t), true)
	if err != nil {
		t.Fatal(err)
	}
	last := all[len(all)-1]
	if !last.Nested || last.ID != "coding-agent" || last.Dir != "catalog/apps/coding-agent/fallback-opencode" {
		t.Fatalf("nested variant: %+v", last)
	}
}
