// Package licenses collects the license and notice texts of everything statically linked into a Go binary, for
// the CLI's release archives (license-audit.md F3). The sealed binary links go-ethereum (LGPL-3.0-or-later), whose
// section 4 asks for a prominent notice, the GPL-3.0 and LGPL-3.0 texts and a way to relink against a modified
// library; the BSD, MIT and Apache-2.0 modules and the Go standard library ask for their notices with binary
// redistributions. Collect finds the module set exactly as `go build` links it for one GOOS/GOARCH, WriteDir lays
// out licenses/ with a README that carries the LGPL notice and where the corresponding source is.
package licenses

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// File is one license or notice file. Name is relative to the module root (for example "metrics/LICENSE" for a
// notice that covers only that package).
type File struct {
	Name string
	Data []byte
}

// Module is one linked third-party module.
type Module struct {
	Path, Version string
	Files         []File
}

// Set is everything a binary links, besides its own module.
type Set struct {
	GOOS, GOARCH string
	GoVersion    string
	Modules      []Module // sorted by path
	Go           []File   // the Go distribution's LICENSE and PATENTS
}

// Options select the binary.
type Options struct {
	Dir      string   // the main module's root
	Packages []string // the main packages, for example ./cli/cmd/sealed
	GOOS     string
	GOARCH   string
	Tags     string
	Go       string // go command, default "go"
}

var (
	licenseName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents|unlicense|authors)([._-].*)?$`)
	sourceExt   = regexp.MustCompile(`(?i)\.(go|s|c|h|json|ya?ml|sh|py|js|ts|html|tmpl|mod|sum)$`)
)

// IsLicenseFile reports whether a file name is a license, notice, patents or authors file.
func IsLicenseFile(name string) bool {
	return licenseName.MatchString(name) && !sourceExt.MatchString(name)
}

type listPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	Module     *listModule
}

type listModule struct {
	Path, Version, Dir string
	Main               bool
	Replace            *listModule
}

func (o Options) env() []string {
	env := append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off")
	if o.GOOS != "" {
		env = append(env, "GOOS="+o.GOOS)
	}
	if o.GOARCH != "" {
		env = append(env, "GOARCH="+o.GOARCH)
	}
	return env
}

func (o Options) run(ctx context.Context, args ...string) ([]byte, error) {
	bin := o.Go
	if bin == "" {
		bin = "go"
	}
	c := exec.CommandContext(ctx, bin, args...)
	c.Dir, c.Env = o.Dir, o.env()
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Collect lists the packages the binary links (go list -deps with CGO_ENABLED=0, as release builds use) and reads
// every license file of their modules: the module root's, plus any in a linked package's own directory or its
// parents below the root. A linked module without any license file is an error.
func Collect(ctx context.Context, o Options) (*Set, error) {
	if len(o.Packages) == 0 {
		return nil, errors.New("licenses: no packages")
	}
	args := []string{"list", "-deps", "-json"}
	if o.Tags != "" {
		args = append(args, "-tags", o.Tags)
	}
	out, err := o.run(ctx, append(args, o.Packages...)...)
	if err != nil {
		return nil, err
	}
	type mod struct {
		listModule
		pkgDirs []string
	}
	mods := map[string]*mod{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("licenses: go list output: %w", err)
		}
		if p.Standard || p.Module == nil || p.Module.Main {
			continue
		}
		m := *p.Module
		if r := m.Replace; r != nil {
			// Keep the module path the program imports; the files come from the replacement.
			m.Dir = r.Dir
			if r.Version != "" {
				m.Version = r.Version
			}
		}
		if m.Dir == "" {
			return nil, fmt.Errorf("licenses: module %s has no directory (run go mod download)", m.Path)
		}
		e := mods[m.Path]
		if e == nil {
			e = &mod{listModule: m}
			mods[m.Path] = e
		}
		e.pkgDirs = append(e.pkgDirs, p.Dir)
	}
	set := &Set{GOOS: o.GOOS, GOARCH: o.GOARCH}
	for _, m := range mods {
		files, err := moduleFiles(m.Dir, m.pkgDirs)
		if err != nil {
			return nil, fmt.Errorf("licenses: %s %s: %w", m.Path, m.Version, err)
		}
		if len(files) == 0 || !hasLicense(files) {
			return nil, fmt.Errorf("licenses: no license file in %s %s (%s)", m.Path, m.Version, m.Dir)
		}
		set.Modules = append(set.Modules, Module{Path: m.Path, Version: m.Version, Files: files})
	}
	sort.Slice(set.Modules, func(i, j int) bool { return set.Modules[i].Path < set.Modules[j].Path })

	env, err := o.run(ctx, "env", "-json", "GOROOT", "GOVERSION")
	if err != nil {
		return nil, err
	}
	var ge struct{ GOROOT, GOVERSION string }
	if err := json.Unmarshal(env, &ge); err != nil {
		return nil, err
	}
	set.GoVersion = ge.GOVERSION
	// The golang image keeps LICENSE in GOROOT; Homebrew keeps it one level up.
	for _, name := range []string{"LICENSE", "PATENTS"} {
		for _, dir := range []string{ge.GOROOT, filepath.Dir(ge.GOROOT)} {
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				set.Go = append(set.Go, File{Name: name, Data: b})
				break
			}
		}
	}
	if len(set.Go) == 0 || set.Go[0].Name != "LICENSE" {
		return nil, fmt.Errorf("licenses: the Go distribution's LICENSE is not near %s", ge.GOROOT)
	}
	return set, nil
}

func hasLicense(files []File) bool {
	for _, f := range files {
		base := strings.ToUpper(path.Base(f.Name))
		if !strings.HasPrefix(base, "AUTHORS") && !strings.HasPrefix(base, "NOTICE") {
			return true
		}
	}
	return false
}

// moduleFiles reads the license files of the module root and of every directory from a linked package up to it.
func moduleFiles(root string, pkgDirs []string) ([]File, error) {
	dirs := map[string]bool{root: true}
	for _, d := range pkgDirs {
		rel, err := filepath.Rel(root, d)
		if err != nil || !filepath.IsLocal(rel) && rel != "." {
			continue
		}
		for rel != "." {
			dirs[filepath.Join(root, rel)] = true
			rel = filepath.Dir(rel)
		}
	}
	var out []File
	for d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || !IsLicenseFile(e.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(d, e.Name()))
			if err != nil {
				return nil, err
			}
			rel, _ := filepath.Rel(root, filepath.Join(d, e.Name()))
			out = append(out, File{Name: filepath.ToSlash(rel), Data: b})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Module returns the linked module with that path.
func (s *Set) Module(p string) (Module, bool) {
	for _, m := range s.Modules {
		if m.Path == p {
			return m, true
		}
	}
	return Module{}, false
}

// lgpl reports whether a module carries an LGPL text.
func (m Module) lgpl() (lesser, gpl string) {
	for _, f := range m.Files {
		switch {
		case bytes.Contains(f.Data, []byte("GNU LESSER GENERAL PUBLIC LICENSE")):
			lesser = f.Name
		case bytes.Contains(f.Data, []byte("GNU GENERAL PUBLIC LICENSE")):
			gpl = f.Name
		}
	}
	return lesser, gpl
}

// Notice is what README says about the program itself.
type Notice struct {
	Program   string // "sealed"
	Version   string
	License   string // the program's own license, "Apache-2.0"
	SourceURL string // the public repository, for example https://github.com/sealedtempo/sealed
	SourceRef string // the release tag
	BuildPkg  string // ./cli/cmd/sealed
}

// README is the text of licenses/README.
func (s *Set) README(n Notice) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Third-party software in %s %s (%s/%s)\n\n", n.Program, n.Version, s.GOOS, s.GOARCH)
	fmt.Fprintf(&b, "%s is licensed under %s (see LICENSE next to this directory). The binary is statically linked\n", n.Program, n.License)
	fmt.Fprintf(&b, "with the Go modules listed below and with the Go standard library and runtime. The license and notice\n")
	fmt.Fprintf(&b, "files of each module are in licenses/<module path>/, those of Go in licenses/go/.\n")
	source := strings.TrimRight(n.SourceURL, "/") + "/tree/" + n.SourceRef
	for _, m := range s.Modules {
		lesser, gpl := m.lgpl()
		if lesser == "" {
			continue
		}
		fmt.Fprintf(&b, "\nGNU LGPL notice: %s\n\n", m.Path)
		fmt.Fprintf(&b, "This program uses the library %s %s, which is covered by the GNU Lesser General\n", m.Path, m.Version)
		fmt.Fprintf(&b, "Public License, version 3 or (at your option) any later version. The LGPL text is\n")
		fmt.Fprintf(&b, "licenses/%s/%s", m.Path, lesser)
		if gpl != "" {
			fmt.Fprintf(&b, " and the GPL text it builds on is licenses/%s/%s", m.Path, gpl)
		}
		fmt.Fprintf(&b, ".\nOther files of that directory cover the parts of it under other licenses.\n\n")
		fmt.Fprintf(&b, "Corresponding source: the complete source of this program is %s.\n", source)
		fmt.Fprintf(&b, "Its go.mod and go.sum pin the exact library version. To use a modified library, add\n")
		fmt.Fprintf(&b, "`go mod edit -replace %s=<your copy>` and rebuild with\n", m.Path)
		fmt.Fprintf(&b, "`CGO_ENABLED=0 go build -trimpath %s`.\n", n.BuildPkg)
	}
	fmt.Fprintf(&b, "\nModules (%d)\n\n", len(s.Modules))
	for _, m := range s.Modules {
		var names []string
		for _, f := range m.Files {
			names = append(names, f.Name)
		}
		fmt.Fprintf(&b, "  %s %s: %s\n", m.Path, m.Version, strings.Join(names, ", "))
	}
	var names []string
	for _, f := range s.Go {
		names = append(names, f.Name)
	}
	fmt.Fprintf(&b, "\nGo standard library and runtime (%s): go/%s\n", s.GoVersion, strings.Join(names, ", go/"))
	return b.String()
}

// Files returns the licenses/ tree: path relative to licenses/ to content, README included.
func (s *Set) Files(n Notice) map[string][]byte {
	out := map[string][]byte{"README": []byte(s.README(n))}
	for _, m := range s.Modules {
		for _, f := range m.Files {
			out[m.Path+"/"+f.Name] = f.Data
		}
	}
	for _, f := range s.Go {
		out["go/"+f.Name] = f.Data
	}
	return out
}

// WriteDir writes the licenses/ tree into dir.
func (s *Set) WriteDir(dir string, n Notice) error {
	for name, data := range s.Files(n) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if !filepath.IsLocal(filepath.FromSlash(name)) {
			return fmt.Errorf("licenses: path %q", name)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
