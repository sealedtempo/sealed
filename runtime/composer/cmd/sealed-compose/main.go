// Command sealed-compose is a debug entry point for humans: it builds or
// loads release bundles, composes a stack from a public config and prints
// the result. Production callers (key broker, sealed verify, verifierd) use
// the composer package directly.
//
//	sealed-compose bundle --app-dir catalog/apps/crm [--out crm.tar]
//	sealed-compose lint [--catalog catalog/apps] [--app-dir DIR...] [--bundle FILE...] [--require-sbom]
//	sealed-compose compose --config stack.json --app-dir DIR... [--bundle FILE...] [--print summary|app-compose|compose|egress|caddyfile|caddyfile-payment|stack|config|pre-launch] [--out DIR]
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/runtime/composer/lint"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "sealed-compose: %v\n", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type bundleFlags struct {
	appDirs, bundles multi
	defaults         string
	registry         string
	allowMissingSBOM bool
}

func (b *bundleFlags) register(fs *flag.FlagSet) {
	fs.Var(&b.appDirs, "app-dir", "catalog app directory to build a bundle from (repeatable)")
	fs.Var(&b.bundles, "bundle", "bundle tar file (repeatable)")
	fs.StringVar(&b.defaults, "defaults", "", "config/defaults.yaml (default: searched upward from the working directory)")
	fs.StringVar(&b.registry, "registry", "", "image registry for --app-dir builds (default: catalog.registry from defaults)")
	fs.BoolVar(&b.allowMissingSBOM, "allow-missing-sbom", false, "allow images without an SBOM (development only)")
}

func (b *bundleFlags) load(stderr io.Writer) ([]*composer.Bundle, error) {
	var out []*composer.Bundle
	if len(b.appDirs) > 0 && b.registry == "" {
		path := b.defaults
		if path == "" {
			found, err := findUp("config/defaults.yaml")
			if err != nil {
				return nil, err
			}
			path = found
		}
		d, err := composer.LoadDefaults(path)
		if err != nil {
			return nil, err
		}
		b.registry = d.Catalog.Registry
	}
	for _, dir := range b.appDirs {
		bun, err := composer.BuildBundle(composer.BuildInput{AppDir: dir, Registry: b.registry, AllowMissingSBOM: b.allowMissingSBOM})
		if err != nil {
			return nil, err
		}
		out = append(out, bun)
	}
	for _, f := range b.bundles {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		bun, err := composer.LoadBundle(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, bun)
	}
	if len(out) == 0 {
		return nil, errors.New("no bundles: pass --app-dir or --bundle")
	}
	return out, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: sealed-compose bundle|lint|compose [flags] (see -h)")
	}
	switch args[0] {
	case "bundle":
		return runBundle(args[1:], stdout, stderr)
	case "compose":
		return runCompose(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	}
	return fmt.Errorf("unknown command %q (want bundle, lint or compose)", args[0])
}

func runBundle(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var bf bundleFlags
	bf.register(fs)
	out := fs.String("out", "", "write the bundle tar here (one --app-dir only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundles, err := bf.load(stderr)
	if err != nil {
		return err
	}
	if *out != "" {
		if len(bundles) != 1 {
			return errors.New("--out needs exactly one bundle")
		}
		if err := os.WriteFile(*out, bundles[0].Tar, 0o644); err != nil {
			return err
		}
	}
	infos := make([]composer.ReleaseInfo, 0, len(bundles))
	for _, b := range bundles {
		infos = append(infos, b.Info())
	}
	return printJSON(stdout, infos)
}

func runCompose(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("compose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var bf bundleFlags
	bf.register(fs)
	configPath := fs.String("config", "", "public config JSON (sealed-config/v1)")
	fill := fs.Bool("fill-release-ids", false, "replace config releaseIds with the bundles' ids (development only)")
	printWhat := fs.String("print", "summary", "summary|app-compose|compose|egress|caddyfile|caddyfile-payment|stack|config|pre-launch")
	outDir := fs.String("out", "", "also write every artifact into this directory")
	requireBuilt := fs.Bool("require-built", false, "fail when any image still has the all-zero placeholder digest (release and approval flows)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("--config is required")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	bundles, err := bf.load(stderr)
	if err != nil {
		return err
	}
	if *fill {
		raw, err = fillReleaseIDs(raw, bundles)
		if err != nil {
			return err
		}
		fmt.Fprintln(stderr, "sealed-compose: warning: releaseIds replaced from local bundles")
	}
	cfg, err := composer.ParseConfig(raw)
	if err != nil {
		return err
	}
	res, err := composer.Compose(cfg, bundles)
	if err != nil {
		return err
	}
	if *requireBuilt {
		if err := res.RequireBuilt(); err != nil {
			return err
		}
	}
	artifacts := map[string][]byte{
		"app-compose.json":         res.AppCompose,
		"docker-compose.json":      res.ComposeJSON,
		"egress.json":              res.EgressConfig,
		"Caddyfile":                res.Caddyfile,
		"Caddyfile.payment-needed": res.CaddyfilePaymentNeeded,
		"stack.json":               res.StackInfo,
		"config.json":              res.ConfigJSON,
		"pre-launch.sh":            []byte(res.PreLaunchScript),
	}
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		for name, b := range artifacts {
			if err := os.WriteFile(filepath.Join(*outDir, name), b, 0o644); err != nil {
				return err
			}
		}
	}
	pick := map[string]string{
		"app-compose": "app-compose.json", "compose": "docker-compose.json", "egress": "egress.json",
		"caddyfile": "Caddyfile", "caddyfile-payment": "Caddyfile.payment-needed", "stack": "stack.json",
		"config": "config.json", "pre-launch": "pre-launch.sh",
	}
	if *printWhat == "summary" {
		return printJSON(stdout, summary(res, bundles))
	}
	name, ok := pick[*printWhat]
	if !ok {
		return fmt.Errorf("unknown --print %q", *printWhat)
	}
	_, err = stdout.Write(artifacts[name])
	return err
}

func summary(res *composer.Result, bundles []*composer.Bundle) map[string]any {
	releases := make([]composer.ReleaseInfo, 0, len(bundles))
	for _, b := range bundles {
		releases = append(releases, b.Info())
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].Slug < releases[j].Slug })
	return map[string]any{
		"stackHash":       res.StackHash.Hex(),
		"configHash":      res.ConfigHash.Hex(),
		"deploymentId":    res.DeploymentID.Hex(),
		"composerVersion": composer.Version,
		"appComposeBytes": len(res.AppCompose),
		"releases":        releases,
		"unbuilt":         res.Unbuilt,
	}
}

func fillReleaseIDs(raw []byte, bundles []*composer.Bundle) ([]byte, error) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	ids := map[string]string{}
	for _, b := range bundles {
		ids[b.Manifest.ID] = b.ReleaseID.Hex()
	}
	apps, _ := doc["apps"].([]any)
	for _, a := range apps {
		if m, ok := a.(map[string]any); ok {
			if id, ok := m["id"].(string); ok && ids[id] != "" {
				m["releaseId"] = ids[id]
			}
		}
	}
	return json.Marshal(doc)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func findUp(rel string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, rel)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%s not found; pass --defaults or --registry", rel)
		}
		dir = parent
	}
}

func runLint(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	catalog := fs.String("catalog", "", "lint every app under this directory (catalog/apps)")
	var appDirs, bundleFiles multi
	fs.Var(&appDirs, "app-dir", "catalog app directory (repeatable)")
	fs.Var(&bundleFiles, "bundle", "bundle tar file (repeatable)")
	requireSBOM := fs.Bool("require-sbom", false, "release mode: a missing SBOM or an unrecognized package license is an error")
	registry := fs.String("registry", "", "catalog.registry that bundle image refs must use (default: the runtime images registry)")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := lint.Options{RequireSBOM: *requireSBOM, Registry: *registry}
	var findings []lint.Finding
	if *catalog != "" {
		fsCat, err := lint.LintCatalog(*catalog, opts)
		if err != nil {
			return err
		}
		findings = append(findings, fsCat...)
	}
	for _, d := range appDirs {
		findings = append(findings, lint.LintApp(d, opts)...)
	}
	for _, f := range bundleFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		b, err := composer.LoadBundle(raw)
		if err != nil {
			findings = append(findings, lint.Finding{Severity: lint.Error, App: f, Code: "bundle", Message: err.Error()})
			continue
		}
		findings = append(findings, lint.LintBundle(b, opts)...)
	}
	if *catalog == "" && len(appDirs) == 0 && len(bundleFiles) == 0 {
		return errors.New("nothing to lint: pass --catalog, --app-dir or --bundle")
	}
	if *asJSON {
		if findings == nil {
			findings = []lint.Finding{}
		}
		if err := printJSON(stdout, findings); err != nil {
			return err
		}
	} else {
		for _, f := range findings {
			fmt.Fprintln(stdout, f.String())
		}
	}
	if lint.HasErrors(findings) {
		return errors.New("lint found errors")
	}
	return nil
}
