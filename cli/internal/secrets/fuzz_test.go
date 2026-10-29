package secrets

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/runtime/composer"
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
