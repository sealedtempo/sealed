// Command release builds the sealed CLI release archives with the license texts of everything the binary links
// (license-audit.md F3). Each archive holds the binary, the repository's LICENSE (Apache-2.0), the CLI README and
// licenses/: the license and notice files of every linked module (go-ethereum's GPL-3.0 and LGPL-3.0 texts
// included), the Go distribution's LICENSE, and licenses/README with the LGPL notice and where the corresponding
// source is.
//
//	go run ./cli/release --version 0.1.0 --out dist                 # every target, plus SHA256SUMS
//	go run ./cli/release --version 0.1.0 --licenses-only dist/lic   # only licenses/ for this host's target
//
// Archives are reproducible: entries sorted, owner 0, mode 0644 or 0755, mtime SOURCE_DATE_EPOCH (default
// 1980-01-01), gzip without name or time; binaries are built with CGO_ENABLED=0 -trimpath -buildvcs=false and an
// empty build id.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sealed-dev/sealed/cli/internal/app"
	"github.com/sealed-dev/sealed/cli/internal/licenses"
	"github.com/sealed-dev/sealed/cli/internal/settings"
)

// DefaultTargets are the platforms the CLI is released for.
var DefaultTargets = []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64"}

const mainPackage = "./cli/cmd/sealed"

type options struct {
	root, out, version, tag, sourceURL, licensesOnly string
	targets                                          []string
	epoch                                            time.Time
	// build compiles the CLI for one target into dst (tests replace it).
	build func(ctx context.Context, root, goos, goarch, dst string) error
	// collect lists the linked modules' licenses (tests may replace it).
	collect func(ctx context.Context, o licenses.Options) (*licenses.Set, error)
	stderr  io.Writer
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Getenv, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) error {
	o, err := parseFlags(args, getenv, stderr)
	if err != nil {
		return err
	}
	return o.release(ctx)
}

func parseFlags(args []string, getenv func(string) string, stderr io.Writer) (*options, error) {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := &options{build: goBuild, collect: licenses.Collect, stderr: stderr}
	var targets string
	fs.StringVar(&o.root, "root", ".", "repository root (holds go.mod)")
	fs.StringVar(&o.out, "out", "dist", "output directory for the archives and SHA256SUMS")
	fs.StringVar(&o.version, "version", "", "release version; must equal the CLI's version (required)")
	fs.StringVar(&o.tag, "tag", "", "git tag of the release, for the corresponding-source link (default cli-v<version>)")
	fs.StringVar(&o.sourceURL, "source-url", "", "public repository URL (default from catalog.release_asset_base in config/defaults.yaml)")
	fs.StringVar(&targets, "targets", strings.Join(DefaultTargets, ","), "comma-separated GOOS/GOARCH list")
	fs.StringVar(&o.licensesOnly, "licenses-only", "", "only write licenses/ into this directory, for this host's target or the first of --targets; build nothing")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	explicitTargets := false
	fs.Visit(func(f *flag.Flag) { explicitTargets = explicitTargets || f.Name == "targets" })
	if o.licensesOnly != "" && !explicitTargets {
		targets = hostTarget()
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if o.version == "" {
		return nil, errors.New("--version is required")
	}
	if o.version != app.Version {
		return nil, fmt.Errorf("--version %s differs from the CLI's version %s (cli/internal/app.Version)", o.version, app.Version)
	}
	if o.tag == "" {
		o.tag = "cli-v" + o.version
	}
	if o.sourceURL == "" {
		s, err := settings.Load(settings.Options{})
		if err != nil {
			return nil, err
		}
		base := s.ReleaseAssetBase()
		if !strings.HasSuffix(base, "/releases/download") {
			return nil, fmt.Errorf("cannot derive the repository URL from %s: pass --source-url", base)
		}
		o.sourceURL = strings.TrimSuffix(base, "/releases/download")
	}
	if !strings.HasPrefix(o.sourceURL, "https://") {
		return nil, fmt.Errorf("--source-url %q must be https", o.sourceURL)
	}
	for _, t := range strings.Split(targets, ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		goos, goarch, ok := strings.Cut(t, "/")
		if !ok || goos == "" || goarch == "" || strings.ContainsAny(t, " \\") {
			return nil, fmt.Errorf("target %q is not GOOS/GOARCH", t)
		}
		o.targets = append(o.targets, t)
	}
	if len(o.targets) == 0 {
		return nil, errors.New("no targets")
	}
	o.epoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	if v := getenv("SOURCE_DATE_EPOCH"); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil || sec < o.epoch.Unix() {
			return nil, fmt.Errorf("SOURCE_DATE_EPOCH %q (at least %d, zip has no earlier time)", v, o.epoch.Unix())
		}
		o.epoch = time.Unix(sec, 0).UTC()
	}
	return o, nil
}

func (o *options) notice() licenses.Notice {
	return licenses.Notice{Program: "sealed", Version: o.version, License: "the Apache License 2.0", SourceURL: o.sourceURL, SourceRef: o.tag, BuildPkg: mainPackage}
}

// licensesFor collects one target's licenses and refuses copyleft the archive cannot carry: a module under the
// GPL or AGPL without the LGPL (static linking would make the whole binary GPL).
func (o *options) licensesFor(ctx context.Context, target string) (*licenses.Set, error) {
	goos, goarch, _ := strings.Cut(target, "/")
	set, err := o.collect(ctx, licenses.Options{Dir: o.root, Packages: []string{mainPackage}, GOOS: goos, GOARCH: goarch})
	if err != nil {
		return nil, err
	}
	for _, m := range set.Modules {
		var lgpl, gpl, agpl bool
		for _, f := range m.Files {
			lgpl = lgpl || bytes.Contains(f.Data, []byte("GNU LESSER GENERAL PUBLIC LICENSE"))
			gpl = gpl || bytes.Contains(f.Data, []byte("GNU GENERAL PUBLIC LICENSE"))
			agpl = agpl || bytes.Contains(f.Data, []byte("GNU AFFERO GENERAL PUBLIC LICENSE"))
		}
		if agpl || (gpl && !lgpl) {
			return nil, fmt.Errorf("%s %s is under the GPL or AGPL and would be statically linked into the CLI", m.Path, m.Version)
		}
	}
	return set, nil
}

func (o *options) release(ctx context.Context) error {
	if o.licensesOnly != "" {
		set, err := o.licensesFor(ctx, o.targets[0])
		if err != nil {
			return err
		}
		return set.WriteDir(o.licensesOnly, o.notice())
	}
	repoLicense, err := os.ReadFile(filepath.Join(o.root, "LICENSE"))
	if err != nil {
		return fmt.Errorf("the repository LICENSE: %w", err)
	}
	readme, err := os.ReadFile(filepath.Join(o.root, "cli", "README.md"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "sealed-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	var sums []string
	for _, t := range o.targets {
		goos, goarch, _ := strings.Cut(t, "/")
		set, err := o.licensesFor(ctx, t)
		if err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
		bin := "sealed"
		if goos == "windows" {
			bin += ".exe"
		}
		dst := filepath.Join(work, goos+"-"+goarch, bin)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := o.build(ctx, o.root, goos, goarch, dst); err != nil {
			return fmt.Errorf("%s: build: %w", t, err)
		}
		binary, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		base := fmt.Sprintf("sealed_%s_%s_%s", o.version, goos, goarch)
		entries := []entry{{Name: bin, Data: binary, Exec: true}, {Name: "LICENSE", Data: repoLicense}, {Name: "README.md", Data: readme}}
		for name, data := range set.Files(o.notice()) {
			entries = append(entries, entry{Name: "licenses/" + name, Data: data})
		}
		var archive []byte
		name := base + ".tar.gz"
		if goos == "windows" {
			name = base + ".zip"
			archive, err = zipArchive(base, entries, o.epoch)
		} else {
			archive, err = tarGzArchive(base, entries, o.epoch)
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(o.out, name), archive, 0o644); err != nil {
			return err
		}
		h := sha256.Sum256(archive)
		sums = append(sums, hex.EncodeToString(h[:])+"  "+name)
		fmt.Fprintf(o.stderr, "%s  %d modules, %d bytes\n", name, len(set.Modules), len(archive))
	}
	sort.Slice(sums, func(i, j int) bool { return sums[i][66:] < sums[j][66:] })
	return os.WriteFile(filepath.Join(o.out, "SHA256SUMS"), []byte(strings.Join(sums, "\n")+"\n"), 0o644)
}

// goBuild compiles the CLI reproducibly.
func goBuild(ctx context.Context, root, goos, goarch, dst string) error {
	c := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid=", "-o", dst, mainPackage)
	c.Dir = root
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch, "GOFLAGS=-mod=readonly", "GOWORK=off")
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	return c.Run()
}

type entry struct {
	Name string
	Data []byte
	Exec bool
}

func sorted(entries []entry) []entry {
	out := append([]entry(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// dirs returns every parent directory of the entries, sorted, each with a trailing slash.
func dirs(entries []entry) []string {
	seen := map[string]bool{}
	for _, e := range entries {
		for d := filepath.ToSlash(filepath.Dir(e.Name)); d != "."; d = filepath.ToSlash(filepath.Dir(d)) {
			seen[d+"/"] = true
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func tarGzArchive(base string, entries []entry, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	hdr := func(name string, mode int64, size int, typ byte) *tar.Header {
		return &tar.Header{Name: name, Mode: mode, Size: int64(size), Typeflag: typ, ModTime: mtime, Format: tar.FormatPAX, Uid: 0, Gid: 0}
	}
	if err := tw.WriteHeader(hdr(base+"/", 0o755, 0, tar.TypeDir)); err != nil {
		return nil, err
	}
	for _, d := range dirs(entries) {
		if err := tw.WriteHeader(hdr(base+"/"+d, 0o755, 0, tar.TypeDir)); err != nil {
			return nil, err
		}
	}
	for _, e := range sorted(entries) {
		mode := int64(0o644)
		if e.Exec {
			mode = 0o755
		}
		if err := tw.WriteHeader(hdr(base+"/"+e.Name, mode, len(e.Data), tar.TypeReg)); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zipArchive(base string, entries []entry, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, d := range append([]string{""}, dirs(entries)...) {
		h := &zip.FileHeader{Name: base + "/" + d, Method: zip.Store, Modified: mtime}
		h.SetMode(os.ModeDir | 0o755)
		if _, err := zw.CreateHeader(h); err != nil {
			return nil, err
		}
	}
	for _, e := range sorted(entries) {
		h := &zip.FileHeader{Name: base + "/" + e.Name, Method: zip.Deflate, Modified: mtime}
		mode := os.FileMode(0o644)
		if e.Exec {
			mode = 0o755
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// hostTarget is GOOS/GOARCH of this machine.
func hostTarget() string { return runtime.GOOS + "/" + runtime.GOARCH }
