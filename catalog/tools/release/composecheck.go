package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sealedtempo/sealed/runtime/composer"
)

// ComposeTemplate is the composer's own fixture config. Its owner keeps it valid for the current composer
// version, so the compose check only swaps the app list.
const ComposeTemplate = "runtime/composer/testdata/config.json"

// relayApp runs in the platform's relay stack, never next to customer apps.
const relayApp = "inference-relay"

// ComposeStack is one stack the compose check composes.
type ComposeStack struct {
	Name string   `json:"name"`
	Apps []string `json:"apps"`
}

// ComposeOutcome is the result for one stack.
type ComposeOutcome struct {
	ComposeStack
	StackHash   string   `json:"stackHash,omitempty"`
	ComposeFile string   `json:"composeFile,omitempty"`
	Unbuilt     []string `json:"unbuilt,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// DefaultStacks is every top-level app with the apps its secrets refer to (same_as, D-043), plus the
// customer stack of every app except the relay.
func DefaultStacks(apps []App) []ComposeStack {
	var all []string
	var out []ComposeStack
	for _, a := range apps {
		if a.Nested {
			continue
		}
		out = append(out, ComposeStack{Name: a.ID, Apps: withSameAsApps(apps, a.ID)})
		if a.ID != relayApp {
			all = append(all, a.ID)
		}
	}
	if len(all) > 1 {
		out = append(out, ComposeStack{Name: "customer-stack", Apps: all})
	}
	return out
}

// withSameAsApps returns id and every app its secrets refer to through same_as, transitively, sorted. The
// composer refuses a stack that lacks a referenced app, so an app with same_as never composes alone.
func withSameAsApps(apps []App, id string) []string {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		a, ok := FindApp(apps, id)
		if !ok {
			return
		}
		for _, s := range a.Manifest.Secrets {
			if ref, _, ok := s.SameAsRef(); ok {
				walk(ref)
			}
		}
	}
	walk(id)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ComposeCheck composes each stack from the catalog sources with the real composer and writes
// <outDir>/<stack>/docker-compose.json and app-compose.json. With dockerConfig set it also runs
// `docker compose config --quiet` on each composed document (the docker CLI with the compose plugin is
// enough; no daemon). Unbuilt images are allowed: their zero digests compose, and the release gate
// rejects them later.
func ComposeCheck(root string, apps []App, stacks []ComposeStack, outDir string, dockerConfig bool) ([]ComposeOutcome, error) {
	d, err := LoadDefaults(root)
	if err != nil {
		return nil, err
	}
	tmpl, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ComposeTemplate)))
	if err != nil {
		return nil, err
	}
	bundles := map[string]*composer.Bundle{}
	var out []ComposeOutcome
	for _, st := range stacks {
		o := ComposeOutcome{ComposeStack: st}
		res, err := composeStack(root, d, apps, st, tmpl, bundles)
		if err != nil {
			o.Error = err.Error()
			out = append(out, o)
			continue
		}
		o.StackHash, o.Unbuilt = res.StackHash.Hex(), res.Unbuilt
		dir := filepath.Join(outDir, st.Name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		o.ComposeFile = filepath.Join(dir, "docker-compose.json")
		if err := os.WriteFile(o.ComposeFile, res.ComposeJSON, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "app-compose.json"), res.AppCompose, 0o644); err != nil {
			return nil, err
		}
		if dockerConfig {
			cmd := exec.Command("docker", "compose", "-f", o.ComposeFile, "config", "--quiet")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				o.Error = fmt.Sprintf("docker compose config: %v: %s", err, strings.TrimSpace(stderr.String()))
			}
		}
		out = append(out, o)
	}
	return out, nil
}

func composeStack(root string, d Defaults, apps []App, st ComposeStack, tmpl []byte, cache map[string]*composer.Bundle) (*composer.Result, error) {
	ids := append([]string(nil), st.Apps...)
	sort.Strings(ids)
	var list []*composer.Bundle
	var entries []map[string]string
	for _, id := range ids {
		a, ok := FindApp(apps, id)
		if !ok {
			return nil, fmt.Errorf("no app %q", id)
		}
		b := cache[id]
		if b == nil {
			var err error
			b, err = composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join(root, filepath.FromSlash(a.Dir)),
				Registry: d.Registry, AllowMissingSBOM: true})
			if err != nil {
				return nil, fmt.Errorf("bundle %s: %w", id, err)
			}
			cache[id] = b
		}
		list = append(list, b)
		entries = append(entries, map[string]string{"id": id, "releaseId": b.ReleaseID.Hex()})
	}
	var cfg map[string]any
	dec := json.NewDecoder(bytes.NewReader(tmpl))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", ComposeTemplate, err)
	}
	cfg["apps"] = entries
	cfg["egressAdditions"] = map[string]any{}
	cfg["composerVersion"] = composer.Version
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	parsed, err := composer.ParseConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return composer.Compose(parsed, list)
}
