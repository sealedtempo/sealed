package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/rimembed"
)

// FuzzParseManifest: ParseManifest never panics on any manifest.yaml. For a
// manifest the composer accepts, the three readers of its secrets (the
// composer, this CLI and the key broker, which reads same_as and share_with
// from the raw manifest) agree on every secret: name, generator, optional,
// same_as and share_with (D-043, D-059).
func FuzzParseManifest(f *testing.F) {
	for _, pattern := range []string{
		"../../../catalog/apps/*/manifest.yaml",
		"../../../runtime/composer/testdata/apps/*/manifest.yaml",
		"../../../runtime/composer/testdata/docker/apps/*/manifest.yaml",
	} {
		paths, _ := filepath.Glob(pattern)
		for _, p := range paths {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte("id: crm\nsecrets:\n  - &s {name: A, generate: hex32}\n  - *s\n"))
	f.Add([]byte("id: crm\nsecrets:\n  - name: A\n    <<: {optional: yes, same_as: llm-gateway/KEY}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		app, cliErr := ParseManifest(data)
		m, err := composer.ParseManifest(data)
		if err != nil {
			return
		}
		if cliErr != nil {
			t.Fatalf("composer accepts the manifest of %s, sealed secrets refuses it: %v", m.ID, cliErr)
		}
		if app.ID != m.ID || len(app.Secrets) != len(m.Secrets) {
			t.Fatalf("CLI reads %s with %d secrets, composer %s with %d", app.ID, len(app.Secrets), m.ID, len(m.Secrets))
		}
		for i, s := range m.Secrets {
			c := app.Secrets[i]
			gen := s.Generate
			if gen == "" {
				gen = "none"
			}
			if c.Name != s.Name || c.Generate != gen || c.Optional != s.Optional || c.SameAs != s.SameAs || !slices.Equal(c.ShareWith, s.ShareWith) {
				t.Fatalf("secret %d: CLI %+v, composer %+v", i, c, s)
			}
		}
		// The key broker plans a one-app stack from the raw manifest: every
		// secret under its own name unless it references another app.
		b := &composer.Bundle{Manifest: m, Files: map[string][]byte{composer.ManifestFile: data}}
		refs, err := keybroker.PlanSecrets([]string{m.ID}, map[string]*composer.Bundle{m.ID: b})
		hasRef := slices.ContainsFunc(m.Secrets, func(s composer.Secret) bool { return s.SameAs != "" })
		if hasRef {
			if err == nil {
				t.Fatalf("key broker resolved a same_as of %s alone in its stack", m.ID)
			}
			return
		}
		if err != nil {
			t.Fatalf("composer accepts the manifest of %s, the key broker refuses it: %v", m.ID, err)
		}
		got := map[string]bool{}
		for _, r := range refs {
			if r.Owner != m.ID {
				continue
			}
			s, ok := m.Secret(r.Name)
			if !ok || r.Optional != s.Optional || r.Source != keybroker.SecretID(m.ID, r.Name) {
				t.Fatalf("key broker plans %+v, the manifest has %+v", r, s)
			}
			got[r.Name] = true
		}
		if len(got) != len(m.Secrets) {
			t.Fatalf("key broker plans %d secrets of %s, the manifest has %d", len(got), m.ID, len(m.Secrets))
		}
	})
}

// sharingApps are the two fixture apps the sharing target adds secrets to.
var sharingApps = []string{"llm-gateway", "notes"}

// genSecrets turns fuzz bytes into extra secrets for app (index 0 or 1 of
// sharingApps): each byte picks a name, optional, a same_as target and a
// share_with list, from small sets that hit every D-043 and D-059 rule.
func genSecrets(app int, prog []byte) []map[string]any {
	other := sharingApps[1-app]
	names := []string{"FZ_A", "FZ_B", "FZ_C", "FZ_KEY"}
	var out []map[string]any
	seen := map[string]bool{}
	for _, b := range prog {
		name := names[b&3]
		if seen[name] {
			continue
		}
		seen[name] = true
		s := map[string]any{"name": name, "description": "fuzz", "generate": "hex32"}
		if b&4 != 0 {
			s["optional"] = true
		}
		switch (b >> 3) & 3 {
		case 1:
			s["same_as"] = other + "/FZ_KEY"
		case 2:
			s["same_as"] = other + "/" + names[(b>>6)&3]
		case 3:
			s["same_as"] = "crm/FZ_KEY" // an app not in the stack
		}
		if _, ref := s["same_as"]; ref {
			s["generate"] = "none"
		} else {
			switch (b >> 5) & 3 {
			case 1:
				s["share_with"] = []string{other}
			case 2:
				s["share_with"] = []string{"crm"}
			case 3:
				s["share_with"] = []string{"crm", other}
			}
		}
		out = append(out, s)
	}
	return out
}

func withSecrets(manifest []byte, extra []map[string]any) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(manifest, &doc); err != nil {
		return nil, err
	}
	list, _ := doc["secrets"].([]any)
	for _, e := range extra {
		list = append(list, e)
	}
	doc["secrets"] = list
	return yaml.Marshal(doc)
}

// FuzzSecretSharing gives the llm-gateway and notes fixtures extra secrets
// with same_as references and share_with lists, then asks the three
// implementations of D-043 and D-059 about the two-app stack: Compose
// (checkSameAs), the key broker (PlanSecrets) and the CLI (NewPlan). They
// must agree on whether the sharing is allowed, and when it is, every
// reference resolves to the referenced app's own stored secret.
func FuzzSecretSharing(f *testing.F) {
	base := map[string]map[string][]byte{}
	for _, app := range sharingApps {
		files, err := composer.CollectBundleFiles(composer.BuildInput{
			AppDir: filepath.Join("..", "..", "..", "runtime", "composer", "testdata", "apps", app), Registry: "ghcr.io/sealedtempo",
		})
		if err != nil {
			f.Fatal(err)
		}
		base[app] = files
	}
	cfgRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "runtime", "composer", "testdata", "config.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][2][]byte{
		{{0x03 | 0x20}, {0x00 | 0x08}},        // gateway FZ_KEY shared with notes; notes FZ_A same_as llm-gateway/FZ_KEY
		{{0x03}, {0x08}},                      // not shared
		{{0x03 | 0x20 | 0x04}, {0x08}},        // shared but optional, reference required
		{{0x03 | 0x20 | 0x04}, {0x08 | 0x04}}, // both optional
		{{0x03 | 0x60}, {0x08}},               // shared with crm and notes
		{{0x03 | 0x20}, {0x18}},               // same_as crm/FZ_KEY
		{{0x03 | 0x20, 0x08 | 0x01}, {0x10}},  // chains
		{{0x00 | 0x20}, {0x10 | 0x00, 0x01}},  // same_as llm-gateway/FZ_A
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, progGW, progNotes []byte) {
		if len(progGW) > 6 || len(progNotes) > 6 {
			return
		}
		bundles := map[string]*composer.Bundle{}
		var list []*composer.Bundle
		for i, prog := range [][]byte{progGW, progNotes} {
			app := sharingApps[i]
			files := map[string][]byte{}
			for k, v := range base[app] {
				files[k] = v
			}
			m, err := withSecrets(files[composer.ManifestFile], genSecrets(i, prog))
			if err != nil {
				t.Fatal(err)
			}
			files[composer.ManifestFile] = m
			tarBytes, err := composer.WriteTar(files)
			if err != nil {
				t.Fatal(err)
			}
			b, err := composer.LoadBundle(tarBytes)
			if err != nil {
				return // a manifest rule refused it (same_as with share_with, ...)
			}
			bundles[app] = b
			list = append(list, b)
		}
		var cfg composer.Config
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg.Apps = nil
		for _, b := range list {
			cfg.Apps = append(cfg.Apps, composer.ConfigApp{ID: b.Manifest.ID, ReleaseID: b.ReleaseID.Hex()})
		}
		sort.Slice(cfg.Apps, func(i, j int) bool { return cfg.Apps[i].ID < cfg.Apps[j].ID })
		cfg.EgressAdditions = map[string][]string{}
		_, cerr := rimembed.Compose(&cfg, list)
		var me *composer.ManifestError
		sharingErr := errors.As(cerr, &me) && strings.HasSuffix(me.Field, ".same_as")
		if cerr != nil && !sharingErr {
			t.Fatalf("compose failed for another reason: %v", cerr)
		}
		refs, kerr := keybroker.PlanSecrets(sharingApps, bundles)
		var apps []*App
		for _, app := range sharingApps {
			a, err := ParseManifest(bundles[app].Files[composer.ManifestFile])
			if err != nil {
				t.Fatalf("sealed secrets refuses a manifest the composer loaded: %v", err)
			}
			apps = append(apps, a)
		}
		plan, perr := NewPlan(apps)
		if (cerr == nil) != (kerr == nil) || (cerr == nil) != (perr == nil) {
			t.Fatalf("disagreement on sharing: compose %v / key broker %v / sealed secrets %v", cerr, kerr, perr)
		}
		if cerr != nil {
			return
		}
		for _, b := range list {
			for _, sec := range b.Manifest.Secrets {
				wantApp, wantName := b.Manifest.ID, sec.Name
				if ra, rn, ok := sec.SameAsRef(); ok {
					wantApp, wantName = ra, rn
				}
				var src string
				for _, r := range refs {
					if r.Owner == b.Manifest.ID && r.Name == sec.Name {
						src = r.Source
					}
				}
				if src != keybroker.SecretID(wantApp, wantName) {
					t.Fatalf("key broker releases %s/%s from %q, want %q", b.Manifest.ID, sec.Name, src, keybroker.SecretID(wantApp, wantName))
				}
				e, ok := plan.Find(b.Manifest.ID, sec.Name)
				if !ok || e.Stored != StoredName(wantApp, wantName) {
					t.Fatalf("sealed secrets stores %s/%s as %q, want %q", b.Manifest.ID, sec.Name, e.Stored, StoredName(wantApp, wantName))
				}
			}
		}
	})
}
