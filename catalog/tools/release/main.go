// Command release is the catalog release tooling used by the GitHub workflows and scripts/release.
//
//	go run ./catalog/tools/release <command> [flags]
//
// Commands (each prints JSON on stdout unless noted; see README.md):
//
//	images        built and mirrored images, or a build/mirror matrix
//	pin           write built digests into manifests, runtime-images.json and extra-images.json
//	waivers       check a Grype report against waivers.yaml, or lint every waivers.yaml
//	lint-gate     classify `sealed-compose lint --json` findings for a PR or a release
//	compose-check compose every app (and the customer stack) and run docker compose config
//	plan          the apps to release, with tags and asset names
//	assets        tag and asset names of one app version
//	bundle        build a release bundle with the composer and print its publishRelease inputs
//	info          publishRelease inputs of an existing bundle tar
//	sigstore      write the .sig and .crt assets from a cosign Sigstore bundle
//	release-doc   assemble <appId>-<version>.release.json
//	notes         render release notes from a release.json (markdown)
//	catalog-json  RegisterCatalog.s.sol input from the manifests
//	keystore      encrypt a key from the environment into a throwaway keystore (prints the address)
//	tx-summary    onchain record and MAINNET_LEDGER.md row from a receipt
//	workflows     check .github/workflows against the pinning and secrets policy
//	defaults      the config/defaults.yaml values the release scripts use
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

type command struct {
	name string
	run  func(args []string, stdout, stderr io.Writer) error
}

func commands() []command {
	return []command{
		{"images", cmdImages}, {"pin", cmdPin}, {"waivers", cmdWaivers}, {"lint-gate", cmdLintGate},
		{"compose-check", cmdComposeCheck}, {"plan", cmdPlan}, {"assets", cmdAssets}, {"bundle", cmdBundle},
		{"info", cmdInfo}, {"sigstore", cmdSigstore}, {"release-doc", cmdReleaseDoc}, {"notes", cmdNotes},
		{"catalog-json", cmdCatalogJSON}, {"keystore", cmdKeystore}, {"tx-summary", cmdTxSummary},
		{"workflows", cmdWorkflows}, {"defaults", cmdDefaults},
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		var names []string
		for _, c := range commands() {
			names = append(names, c.name)
		}
		return fmt.Errorf("usage: release <%s> [flags]", strings.Join(names, "|"))
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(args[1:], stdout, stderr)
		}
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "repository root (default: found from the working directory)")
	return fs, root
}

// resolveRoot returns --root, else $SEALED_REPO_ROOT (set by scripts/release/lib.sh), else the repository
// that holds the working directory.
func resolveRoot(root string) (string, error) {
	if root == "" {
		root = os.Getenv("SEALED_REPO_ROOT")
	}
	if root != "" {
		return filepath.Abs(root)
	}
	return FindRoot(".")
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func writeJSONFile(path string, v any) error {
	var b bytes.Buffer
	if err := printJSON(&b, v); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

// readLines reads a newline-separated file list ("-" is stdin).
func readLines(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func today(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC(), nil
	}
	return parseDay(s)
}

func cmdImages(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("images", stderr)
	format := fs.String("format", "json", "json (everything), build-matrix, mirror-matrix or scan-matrix")
	changed := fs.String("changed", "", "file listing changed paths; selects builds (build-matrix)")
	all := fs.Bool("all", false, "select every build (build-matrix)")
	names := fs.String("names", "", "comma-separated image names to select (build-matrix)")
	changedOnly := fs.Bool("changed-only", false, "with --changed: only the images a changed file touches, without the unbuilt ones (build-matrix, pull request check)")
	apps := fs.String("apps", "", "comma-separated app ids; limits the mirror and scan matrices to their images")
	failBlocked := fs.Bool("fail-on-blocked", false, "fail when a selected app names an image that must not be mirrored (mirror-matrix)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	set, err := LoadImages(r)
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		return printJSON(stdout, set)
	case "build-matrix":
		var files []string
		if *changed != "" {
			if files, err = readLines(*changed); err != nil {
				return err
			}
		}
		var sel []BuildImage
		if *changedOnly {
			if *changed == "" || *all || *names != "" {
				return errors.New("--changed-only needs --changed, and neither --all nor --names")
			}
			sel = ChangedBuilds(set, files)
		} else {
			sel = SelectBuilds(set, files, *all, splitList(*names))
		}
		if sel == nil {
			sel = []BuildImage{}
		}
		return printJSON(stdout, map[string]any{"include": sel})
	case "scan-matrix":
		return printJSON(stdout, map[string]any{"include": ScanMatrix(set, r, splitList(*apps))})
	case "mirror-matrix":
		want := splitList(*apps)
		out, blocked := []MirrorImage{}, []MirrorImage{}
		for _, m := range set.Mirror {
			if len(want) == 0 || mirrorUsedBy(m, want) {
				out = append(out, m)
			}
		}
		for _, m := range set.Blocked {
			if len(want) == 0 || mirrorUsedBy(m, want) {
				blocked = append(blocked, m)
				fmt.Fprintf(stderr, "::error file=%s,title=never-mirror::%s (%s) must not be mirrored: %s\n", m.Users[0], m.Name, m.Source, m.Blocked)
			}
		}
		if err := printJSON(stdout, map[string]any{"include": out, "blocked": blocked}); err != nil {
			return err
		}
		if *failBlocked && len(blocked) > 0 {
			return fmt.Errorf("%d image(s) must not be mirrored (images.yaml never_mirror)", len(blocked))
		}
		return nil
	}
	return fmt.Errorf("unknown --format %q", *format)
}

func mirrorUsedBy(m MirrorImage, apps []string) bool {
	for _, u := range m.Users {
		for _, a := range apps {
			if strings.HasPrefix(u, CatalogDir+"/"+a+"/") {
				return true
			}
		}
	}
	return false
}

func cmdPin(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("pin", stderr)
	results := fs.String("results", "", "directory of build result JSON files")
	scope := fs.String("scope", ScopeAll, "catalog (manifests), runtime (runtime-images.json, extra-images.json) or all")
	summary := fs.String("summary", "", "write the PR body (markdown) here")
	runURL := fs.String("run-url", "", "workflow run URL for the summary")
	commit := fs.String("commit", "", "source commit for the summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *results == "" {
		return errors.New("--results is required")
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	set, err := LoadImages(r)
	if err != nil {
		return err
	}
	res, err := LoadBuildResults(*results)
	if err != nil {
		return err
	}
	changes, err := Pin(r, set, res, *scope)
	if err != nil {
		return err
	}
	if *summary != "" {
		if err := os.WriteFile(*summary, []byte(PinSummary(*scope, *runURL, *commit, res, changes)), 0o644); err != nil {
			return err
		}
	}
	if changes == nil {
		changes = []PinChange{}
	}
	return printJSON(stdout, changes)
}

func cmdWaivers(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "lint") {
		return errors.New("usage: release waivers check|lint [flags]")
	}
	sub := args[0]
	fs, root := newFlags("waivers "+sub, stderr)
	file := fs.String("file", "", "waivers.yaml (check)")
	image := fs.String("image", "", "image name as in the manifest or runtime-images.json (check)")
	scan := fs.String("scan", "", "grype -o json report (check)")
	summary := fs.String("summary", "", "write the gate summary JSON here (check)")
	day := fs.String("today", "", "evaluation date YYYY-MM-DD (default: today, UTC)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	now, err := today(*day)
	if err != nil {
		return fmt.Errorf("--today: %w", err)
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	set, err := LoadImages(r)
	if err != nil {
		return err
	}
	if sub == "lint" {
		return lintAllWaivers(r, set, now, stdout)
	}
	if *file == "" || *image == "" || *scan == "" {
		return errors.New("waivers check needs --file, --image and --scan")
	}
	wf, err := LoadWaivers(*file)
	if err != nil {
		return err
	}
	images := waiverImages(set, r, *file)
	if !contains(images, *image) {
		return fmt.Errorf("image %q is not covered by %s (it covers %s)", *image, *file, strings.Join(images, ", "))
	}
	if errs := wf.Validate(images, now); len(errs) > 0 {
		return errors.Join(errs...)
	}
	raw, err := os.ReadFile(*scan)
	if err != nil {
		return err
	}
	rep, err := ParseGrype(raw)
	if err != nil {
		return err
	}
	s := Evaluate(rep, *image, wf, now)
	fmt.Fprint(stderr, s.Report())
	if *summary != "" {
		if err := writeJSONFile(*summary, s); err != nil {
			return err
		}
	}
	if err := printJSON(stdout, s); err != nil {
		return err
	}
	if !s.OK() {
		return fmt.Errorf("%s: %d critical finding(s) without a valid waiver in %s", *image, len(s.Unwaived), *file)
	}
	return nil
}

// waiverImages lists the image names a waivers file may name: the images of its app (and of the app's
// nested variants), or every runtime and extra image for runtime-waivers.yaml.
func waiverImages(set *ImageSet, root, file string) []string {
	abs, _ := filepath.Abs(file)
	rel, _ := filepath.Rel(root, abs)
	rel = filepath.ToSlash(rel)
	var out []string
	add := func(n string) {
		if !contains(out, n) {
			out = append(out, n)
		}
	}
	for _, b := range set.Build {
		if contains(b.Waivers, rel) {
			add(b.Name)
		}
	}
	if rel == RuntimeWaiversFile {
		for _, m := range set.Mirror {
			for _, u := range m.Users {
				if u == RuntimeImagesFile {
					add(m.Name)
				}
			}
		}
	}
	appDir := filepath.ToSlash(filepath.Dir(rel))
	for _, m := range set.Mirror {
		for _, u := range m.Users {
			if strings.HasPrefix(u, appDir+"/") {
				add(m.Name)
			}
		}
	}
	return out
}

func lintAllWaivers(root string, set *ImageSet, now time.Time, stdout io.Writer) error {
	apps, err := LoadApps(root, false)
	if err != nil {
		return err
	}
	files := []string{RuntimeWaiversFile}
	for _, a := range apps {
		files = append(files, a.Dir+"/waivers.yaml")
	}
	var errs []error
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		wf, err := LoadWaivers(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if wf.Legacy {
			fmt.Fprintf(stdout, "::warning file=%s,title=waivers-format::use the version 1 format of catalog/apps/scraper/waivers.yaml (version: 1, waivers: [...])\n", f)
		}
		for _, e := range wf.Validate(waiverImages(set, root, p), now) {
			errs = append(errs, e)
		}
		for _, w := range wf.Waivers {
			if w.expired(now) {
				fmt.Fprintf(stdout, "::warning file=%s,title=waiver-expired::%s for %s in %s expired on %s; remove it or renew it with a new reason\n", f, w.ID, w.Package, w.Image, w.Expires)
			}
		}
	}
	return errors.Join(errs...)
}

func cmdLintGate(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("lint-gate", stderr)
	findings := fs.String("findings", "", "sealed-compose lint --json output")
	mode := fs.String("mode", GateModePR, "pr or release")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*findings)
	if err != nil {
		return err
	}
	list, err := ParseLintFindings(raw)
	if err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	apps, err := LoadApps(r, false)
	if err != nil {
		return err
	}
	unbuilt := map[string][]string{}
	for _, a := range apps {
		for _, img := range a.Manifest.Images {
			if img.Unbuilt() {
				unbuilt[a.ID] = append(unbuilt[a.ID], img.Name)
			}
		}
	}
	g, err := LintGate(list, *mode, unbuilt)
	if err != nil {
		return err
	}
	g.Annotate(stdout)
	fmt.Fprintf(stderr, "lint gate (%s): %d blocking, %d deferred to the pin PR and release, %d warnings\n", *mode, len(g.Blocking), len(g.Deferred), len(g.Warnings))
	if len(g.Blocking) > 0 {
		return fmt.Errorf("%d blocking lint finding(s)", len(g.Blocking))
	}
	return nil
}

func cmdComposeCheck(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("compose-check", stderr)
	out := fs.String("out", "", "directory for the composed documents (required)")
	docker := fs.Bool("docker-config", false, "run docker compose config --quiet on each composed document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	apps, err := LoadApps(r, false)
	if err != nil {
		return err
	}
	res, err := ComposeCheck(r, apps, DefaultStacks(apps), *out, *docker)
	if err != nil {
		return err
	}
	if err := printJSON(stdout, res); err != nil {
		return err
	}
	var failed []string
	for _, o := range res {
		if o.Error != "" {
			fmt.Fprintf(stderr, "::error title=compose::%s: %s\n", o.Name, o.Error)
			failed = append(failed, o.Name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("compose check failed for %s", strings.Join(failed, ", "))
	}
	return nil
}

func cmdPlan(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("plan", stderr)
	changed := fs.String("changed", "", "file listing changed paths (apps with a changed bundle input are planned)")
	appsFlag := fs.String("apps", "", "comma-separated app ids, or \"all\"")
	strict := fs.Bool("strict", false, "fail when a planned app cannot be released (release job)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	apps, err := LoadApps(r, false)
	if err != nil {
		return err
	}
	var ids []string
	all := strings.TrimSpace(*appsFlag) == "all"
	switch {
	case all:
	case *appsFlag != "":
		ids = splitList(*appsFlag)
	case *changed != "":
		files, err := readLines(*changed)
		if err != nil {
			return err
		}
		ids = ChangedApps(apps, files)
	default:
		return errors.New("pass --changed, or --apps <ids>|all")
	}
	plan, err := Plan(d, apps, ids, all)
	if err != nil {
		return err
	}
	if plan == nil {
		plan = []PlannedRelease{}
	}
	if err := printJSON(stdout, plan); err != nil {
		return err
	}
	var problems []string
	for _, p := range plan {
		if p.Problem != "" {
			problems = append(problems, p.App+": "+p.Problem)
			level := "warning"
			if *strict {
				level = "error"
			}
			fmt.Fprintf(stderr, "::%s file=%s/manifest.yaml,title=release-plan::%s\n", level, p.Dir, p.Problem)
		}
	}
	if *strict && len(problems) > 0 {
		return fmt.Errorf("cannot release:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

func cmdAssets(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("assets", stderr)
	app := fs.String("app", "", "app id")
	version := fs.String("version", "", "release version (default: the manifest's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	apps, err := LoadApps(r, false)
	if err != nil {
		return err
	}
	a, ok := FindApp(apps, *app)
	if !ok {
		return fmt.Errorf("no app %q", *app)
	}
	v := *version
	if v == "" {
		v = a.Version()
	}
	var images []string
	for _, img := range a.Manifest.Images {
		images = append(images, img.Name)
	}
	names, err := Assets(d, a.ID, v, images)
	if err != nil {
		return err
	}
	return printJSON(stdout, names)
}

func cmdBundle(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("bundle", stderr)
	app := fs.String("app", "", "app id (catalog/apps/<id>)")
	sbom := fs.String("sbom-dir", "", "directory of <image>.spdx.json")
	scan := fs.String("scan-dir", "", "directory of <image>.json Grype reports")
	out := fs.String("out", "", "write the bundle tar here")
	registry := fs.String("registry", "", "catalog registry (default: config/defaults.yaml catalog.registry)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	if *registry == "" {
		*registry = d.Registry
	}
	if *sbom == "" || *scan == "" {
		return errors.New("--sbom-dir and --scan-dir are required (a release bundle carries both for every image)")
	}
	info, err := BuildBundleFile(filepath.Join(r, CatalogDir, *app), *sbom, *scan, *registry, *out)
	if err != nil {
		return err
	}
	if info.Slug != *app {
		return fmt.Errorf("bundle is for %q, not %q", info.Slug, *app)
	}
	return printJSON(stdout, info)
}

func cmdInfo(args []string, stdout, stderr io.Writer) error {
	fs, _ := newFlags("info", stderr)
	bundle := fs.String("bundle", "", "bundle tar")
	if err := fs.Parse(args); err != nil {
		return err
	}
	info, err := BundleFileInfo(*bundle)
	if err != nil {
		return err
	}
	return printJSON(stdout, info)
}

func cmdSigstore(args []string, stdout, stderr io.Writer) error {
	fs, _ := newFlags("sigstore", stderr)
	bundle := fs.String("bundle", "", "Sigstore bundle (cosign sign-blob --bundle)")
	blob := fs.String("blob", "", "the signed file")
	sig := fs.String("sig", "", "write the base64 signature here")
	crt := fs.String("crt", "", "write the PEM certificate here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*bundle)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*blob)
	if err != nil {
		return err
	}
	parts, err := ParseSigstoreBundle(raw, sha256.Sum256(data))
	if err != nil {
		return err
	}
	if *sig != "" {
		if err := os.WriteFile(*sig, []byte(parts.SignatureB64+"\n"), 0o644); err != nil {
			return err
		}
	}
	if *crt != "" {
		if err := os.WriteFile(*crt, parts.CertificatePEM, 0o644); err != nil {
			return err
		}
	}
	return printJSON(stdout, parts.Rekor)
}

func cmdReleaseDoc(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("release-doc", stderr)
	var in ReleaseInputs
	fs.StringVar(&in.Bundle, "bundle", "", "bundle tar")
	fs.StringVar(&in.ScanDir, "scans", "", "directory of <image>.summary.json")
	fs.StringVar(&in.SigstoreBundle, "sigstore", "", "Sigstore bundle of the bundle tar")
	fs.StringVar(&in.Commit, "commit", "", "source commit")
	fs.StringVar(&in.RunURL, "run-url", "", "workflow run URL")
	fs.StringVar(&in.Identity, "identity", "", "certificate identity (default: release.yml on main)")
	fs.StringVar(&in.Onchain, "onchain", "", "publish-release.sh result JSON")
	base := fs.String("base", "", "an existing release.json to add --onchain to (instead of --bundle and the scans)")
	out := fs.String("out", "", "write release.json here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	var doc *ReleaseDoc
	if *base != "" {
		doc, err = AddOnchain(*base, in.Onchain)
	} else {
		doc, err = BuildReleaseDoc(d, in)
	}
	if err != nil {
		return err
	}
	if *out != "" {
		return writeJSONFile(*out, doc)
	}
	return printJSON(stdout, doc)
}

func cmdNotes(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("notes", stderr)
	in := fs.String("release", "", "release.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	var doc ReleaseDoc
	if err := readJSONFile(*in, &doc); err != nil {
		return err
	}
	if doc.Schema != "sealed-release/v1" {
		return fmt.Errorf("%s: schema %q, want sealed-release/v1", *in, doc.Schema)
	}
	_, err = io.WriteString(stdout, doc.Notes(d))
	return err
}

func cmdCatalogJSON(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("catalog-json", stderr)
	apps := fs.String("apps", "", "comma-separated app ids (default: every app)")
	images := fs.String("images", "", "JSON array of platform images in RegisterCatalog format")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	list, err := LoadApps(r, false)
	if err != nil {
		return err
	}
	cat, err := RegisterCatalog(d, list, splitList(*apps), *images)
	if err != nil {
		return err
	}
	return printJSON(stdout, cat)
}

func cmdKeystore(args []string, stdout, stderr io.Writer) error {
	fs, _ := newFlags("keystore", stderr)
	keyEnv := fs.String("key-env", "", "environment variable holding the private key")
	dir := fs.String("dir", "", "directory for keystore.json and password (created with mode 0700)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyEnv == "" || *dir == "" {
		return errors.New("--key-env and --dir are required")
	}
	addr, err := WriteKeystore(*keyEnv, *dir)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, addr)
	return err
}

func cmdTxSummary(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("tx-summary", stderr)
	receipt := fs.String("receipt", "", "receipt JSON (cast send --json or cast receipt --json)")
	chainID := fs.Uint64("chain-id", 0, "chain id")
	registry := fs.String("to", "", "contract address")
	release := fs.String("release-id", "", "releaseId (publishRelease)")
	fromLabel := fs.String("from-label", "OPS", "sender label for the ledger")
	toLabel := fs.String("to-label", "AppRegistry", "contract label for the ledger")
	purpose := fs.String("purpose", "", "ledger purpose column")
	ts := fs.Int64("timestamp", 0, "block timestamp (unix seconds)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*receipt)
	if err != nil {
		return err
	}
	s, err := SummarizeTx(d, raw, *chainID, *registry, *release, *fromLabel, *toLabel, *purpose, *ts)
	if err != nil {
		return err
	}
	return printJSON(stdout, s)
}

func cmdWorkflows(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("workflows", stderr)
	dir := fs.String("dir", "", "workflow directory (default: <root>/.github/workflows)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		r, err := resolveRoot(*root)
		if err != nil {
			return err
		}
		*dir = filepath.Join(r, ".github", "workflows")
	}
	probs, err := CheckWorkflows(*dir)
	if err != nil {
		return err
	}
	for _, p := range probs {
		fmt.Fprintf(stdout, "::error file=.github/workflows/%s,line=%d,title=workflow-policy::%s\n", p.File, p.Line, p.Msg)
	}
	if len(probs) > 0 {
		return fmt.Errorf("%d workflow policy problem(s)", len(probs))
	}
	fmt.Fprintln(stderr, "workflow policy: ok")
	return nil
}

func cmdDefaults(args []string, stdout, stderr io.Writer) error {
	fs, root := newFlags("defaults", stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := resolveRoot(*root)
	if err != nil {
		return err
	}
	d, err := LoadDefaults(r)
	if err != nil {
		return err
	}
	return printJSON(stdout, map[string]any{"chainId": d.ChainID, "explorerUrl": d.ExplorerURL, "publicRpcUrl": d.PublicRPC,
		"feeToken": d.FeeToken, "registry": d.Registry, "releaseAssetBase": d.ReleaseAssetBase, "repoUrl": d.RepoURL(),
		"repo": d.RepoSlug(), "root": r})
}
