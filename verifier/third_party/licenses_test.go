// Package thirdparty holds the license tooling of the sealed-verifierd image.
// collect-licenses.sh runs in the build stage of verifier/Dockerfile and
// fills /licenses. The tests check, without a Docker daemon, that the script
// covers every module go list -deps reports for the image's target, that it
// fails when a linked module has no license text, and that the Dockerfile
// runs it for the same target and ships its output.
//
// The package is the same in key-broker/third_party; only the constants
// below differ.
package thirdparty

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	pkg        = "./verifier/cmd/sealed-verifierd"
	dockerfile = "verifier/Dockerfile"
	script     = "verifier/third_party/collect-licenses.sh"
	gethPath   = "github.com/ethereum/go-ethereum"
)

var (
	licenseText  = regexp.MustCompile(`(?i)^((un)?licen[cs]e|copying|copyright)([._-].*)?$`)
	licenseOther = regexp.MustCompile(`(?i)^(notice|patents|authors)([._-].*)?$`)
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// Read through os so that go test's cache notices dependency changes:
	// the script and go list run in subprocesses, which the cache cannot see.
	for _, f := range []string{"go.mod", "go.sum", script, dockerfile} {
		if _, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f))); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func needSh(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

// stages splits a Dockerfile into its stages; stage 0 is what precedes the
// first FROM.
func stages(df string) []string {
	return regexp.MustCompile(`(?m)^FROM\s`).Split(df, -1)
}

// instructions joins continuation lines and drops comments.
func instructions(stage string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(stage, "\n") {
		trimmed := strings.TrimSpace(line)
		if cur.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if strings.HasSuffix(trimmed, `\`) {
			cur.WriteString(strings.TrimSuffix(trimmed, `\`) + " ")
			continue
		}
		cur.WriteString(trimmed)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

// dockerTarget returns the GOOS, GOARCH and CGO_ENABLED the build stage sets
// with ENV, which both go build and the collector see.
func dockerTarget(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dockerfile)))
	if err != nil {
		t.Fatal(err)
	}
	st := stages(string(raw))
	if len(st) != 3 {
		t.Fatalf("%s has %d stages, want a build and a runtime stage", dockerfile, len(st)-1)
	}
	got := map[string]string{}
	for _, ins := range instructions(st[1]) {
		if rest, ok := strings.CutPrefix(ins, "ENV "); ok {
			for _, kv := range strings.Fields(rest) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					got[k] = v
				}
			}
		}
	}
	var env []string
	for _, k := range []string{"GOOS", "GOARCH", "CGO_ENABLED"} {
		if got[k] == "" {
			t.Fatalf("the build stage of %s sets no %s with ENV", dockerfile, k)
		}
		env = append(env, k+"="+got[k])
	}
	return env
}

func run(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out) + stderr.String(), err
	}
	return string(out), nil
}

func listDir(t *testing.T, dir string, re *regexp.Regexp) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && re.MatchString(e.Name()) && !strings.HasSuffix(strings.ToLower(e.Name()), ".go") {
			names = append(names, e.Name())
		}
	}
	return names
}

func sameFile(t *testing.T, src, dst string) {
	t.Helper()
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Errorf("%s was not collected: %v", src, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from %s", dst, src)
	}
}

// TestCollectLicensesCoversEveryLinkedModule runs the collector the way the
// Dockerfile does and checks its output against an independent go list -deps
// for the same target: every linked module has a license text, every license,
// notice, patents and authors file of a module root or of a linked package's
// directory is copied unchanged, the README lists exactly the linked modules,
// and every LGPL module (go-ethereum) gets the notice and source locations.
func TestCollectLicensesCoversEveryLinkedModule(t *testing.T) {
	needSh(t)
	root := repoRoot(t)
	env := dockerTarget(t, root)
	out := filepath.Join(t.TempDir(), "licenses")
	const sourceURL, sourceRef = "https://example.test/sealed", "v0.0.0-test"
	if msg, err := run(t, root, append(env, "SOURCE_URL="+sourceURL, "SOURCE_REF="+sourceRef, "DOCKERFILE="+dockerfile),
		"sh", script, out, pkg); err != nil {
		t.Fatalf("%s: %v\n%s", script, err, msg)
	}

	list, err := run(t, root, env, "go", "list", "-deps",
		"-f", `{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{"\t"}}{{$.Dir}}{{end}}{{end}}`, pkg)
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, list)
	}
	type module struct{ version, dir string }
	mods := map[string]module{}
	pkgDirs := map[string]map[string]bool{} // module path -> package dirs
	sc := bufio.NewScanner(strings.NewReader(list))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 4 {
			continue
		}
		mods[f[0]] = module{f[1], f[2]}
		if pkgDirs[f[0]] == nil {
			pkgDirs[f[0]] = map[string]bool{}
		}
		pkgDirs[f[0]][f[3]] = true
	}
	if len(mods) == 0 {
		t.Fatalf("go list -deps found no linked modules:\n%s", list)
	}

	var lgpl []string
	for path, m := range mods {
		dst := filepath.Join(out, filepath.FromSlash(path))
		texts := listDir(t, m.dir, licenseText)
		if len(texts) == 0 {
			t.Errorf("linked module %s %s has no license text in %s", path, m.version, m.dir)
		}
		for _, n := range append(texts, listDir(t, m.dir, licenseOther)...) {
			sameFile(t, filepath.Join(m.dir, n), filepath.Join(dst, n))
		}
		for _, n := range texts {
			raw, err := os.ReadFile(filepath.Join(m.dir, n))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("GNU LESSER GENERAL PUBLIC LICENSE")) {
				lgpl = append(lgpl, path)
				break
			}
		}
		// Files below the module root, in a linked package's directory or one
		// of its parents.
		seen := map[string]bool{}
		for d := range pkgDirs[path] {
			for ; d != m.dir && strings.HasPrefix(d, m.dir+string(filepath.Separator)); d = filepath.Dir(d) {
				if seen[d] {
					break
				}
				seen[d] = true
				rel, _ := filepath.Rel(m.dir, d)
				for _, n := range append(listDir(t, d, licenseText), listDir(t, d, licenseOther)...) {
					sameFile(t, filepath.Join(d, n), filepath.Join(dst, rel, n))
				}
			}
		}
	}
	if _, ok := mods[gethPath]; ok {
		if got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(gethPath), "metrics", "LICENSE")); err != nil || !bytes.Contains(got, []byte("Richard Crowley")) {
			t.Errorf("go-ethereum/metrics/LICENSE (BSD-2-Clause-Views, from rcrowley/go-metrics) was not collected: %v", err)
		}
		if !contains(lgpl, gethPath) {
			t.Errorf("go-ethereum is linked but its LGPL text was not found")
		}
	}

	if _, err := os.Stat(filepath.Join(out, "go", "LICENSE")); err != nil {
		t.Error("the Go distribution's LICENSE is missing")
	}
	mainPath, err := run(t, root, nil, "go", "list", "-m", "-f", "{{.Path}}")
	if err != nil {
		t.Fatalf("go list -m: %v\n%s", err, mainPath)
	}
	sameFile(t, filepath.Join(root, "LICENSE"), filepath.Join(out, filepath.FromSlash(strings.TrimSpace(mainPath)), "LICENSE"))

	readme, err := os.ReadFile(filepath.Join(out, "README"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)
	var listed, want []string
	if _, rest, ok := strings.Cut(text, "\nLinked modules:\n"); ok {
		for _, line := range strings.Split(rest, "\n") {
			if !strings.HasPrefix(line, "  ") {
				break
			}
			listed = append(listed, strings.TrimSpace(line))
		}
	}
	for path, m := range mods {
		want = append(want, path+" "+m.version)
	}
	sort.Strings(want)
	if strings.Join(listed, "\n") != strings.Join(want, "\n") {
		t.Errorf("README lists the modules\n%s\nwant\n%s", strings.Join(listed, "\n"), strings.Join(want, "\n"))
	}
	if len(lgpl) > 0 {
		for _, s := range []string{
			"GNU Lesser General Public License notice (LGPL-3.0 section 4)",
			"Application code: " + sourceURL + "/tree/" + sourceRef + ".",
			"go mod edit -replace",
			pkg,
			dockerfile + " in the application code",
		} {
			if !strings.Contains(text, s) {
				t.Errorf("README lacks %q:\n%s", s, text)
			}
		}
	} else if strings.Contains(text, "Lesser General Public License") {
		t.Errorf("README has an LGPL notice but no linked module is LGPL")
	}
	for _, path := range lgpl {
		m := mods[path]
		for _, s := range []string{
			"  " + path + " " + m.version + ": GNU LGPL version",
			"  " + path + ": https://proxy.golang.org/" + path + "/@v/" + m.version + ".zip",
		} {
			if !strings.Contains(text, s) {
				t.Errorf("README lacks %q:\n%s", s, text)
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

const (
	gplText  = "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"
	lgplText = "                   GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"
	mitText  = "MIT License\n\nCopyright (c) 2026 Example\n"
)

// fixture writes a main module that links example.com/dep (and its package
// example.com/dep/sub) from a local replacement holding files.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/app\n\ngo 1.26.0\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n")
	write("LICENSE", "Apache License\nVersion 2.0, January 2004\n")
	write("main.go", "package main\n\nimport _ \"example.com/dep/sub\"\n\nfunc main() {}\n")
	write("dep/go.mod", "module example.com/dep\n\ngo 1.26.0\n")
	write("dep/dep.go", "package dep\n")
	write("dep/sub/sub.go", "package sub\n\nimport _ \"example.com/dep\"\n")
	for name, body := range files {
		write("dep/"+name, body)
	}
	return dir
}

// TestCollectLicensesFixtures covers the cases that must stop an image build,
// and two layouts that must pass.
func TestCollectLicensesFixtures(t *testing.T) {
	needSh(t)
	collector := filepath.Join(repoRoot(t), filepath.FromSlash(script))
	env := []string{"GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off", "GOTOOLCHAIN=local", "SOURCE_URL=https://example.test/app"}
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string // "" means success
	}{
		{"no license text", map[string]string{"NOTICE": "Example\n", "README.md": "no license here\n"}, "no license text"},
		{"license only in a package directory", map[string]string{"sub/LICENSE": mitText}, "no license text"},
		{"GPL module", map[string]string{"COPYING": gplText}, "GPL or AGPL"},
		{"AGPL module", map[string]string{"LICENSE": "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n"}, "GPL or AGPL"},
		{"LGPL-3.0 without the GPL text", map[string]string{"COPYING.LESSER": lgplText}, "no GPL-3.0 text"},
		{"GPL text in a linked package of a permissive module", map[string]string{"LICENSE": mitText, "sub/COPYING": gplText}, "review it"},
		{"LGPL-3.0 with the GPL text", map[string]string{"COPYING.LESSER": lgplText, "COPYING": gplText, "AUTHORS": "A\n"}, ""},
		{"license in a package directory", map[string]string{"license.md": mitText, "sub/NOTICE.txt": "Example\n", "license.go": "package dep\n"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := fixture(t, tc.files)
			out := filepath.Join(t.TempDir(), "licenses")
			msg, err := run(t, dir, env, "sh", collector, out, ".")
			if tc.want != "" {
				if err == nil || !strings.Contains(msg, tc.want) {
					t.Fatalf("err = %v, output %q, want a failure mentioning %q", err, msg, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, msg)
			}
			for name := range tc.files {
				if strings.HasSuffix(name, ".go") {
					if _, err := os.Stat(filepath.Join(out, "example.com", "dep", name)); err == nil {
						t.Errorf("%s was collected", name)
					}
					continue
				}
				sameFile(t, filepath.Join(dir, "dep", filepath.FromSlash(name)), filepath.Join(out, "example.com", "dep", filepath.FromSlash(name)))
			}
			sameFile(t, filepath.Join(dir, "LICENSE"), filepath.Join(out, "example.com", "app", "LICENSE"))
			readme, err := os.ReadFile(filepath.Join(out, "README"))
			if err != nil {
				t.Fatal(err)
			}
			lgpl := tc.files["COPYING.LESSER"] != ""
			for s, want := range map[string]bool{
				"  example.com/dep v0.0.0 => ./dep\n":                                      true,
				"GNU Lesser General Public License notice":                                 lgpl,
				"example.com/dep v0.0.0: GNU LGPL version 3 (COPYING.LESSER) with the GNU": lgpl,
				"example.com/dep: the directory ./dep in the application code":             lgpl,
			} {
				if strings.Contains(string(readme), s) != want {
					t.Errorf("README contains %q = %v, want %v:\n%s", s, !want, want, readme)
				}
			}
		})
	}
}

// TestDockerfileShipsLicenses: the build stage sets the target once with ENV
// (so go build and the collector see the same module set), runs the
// collector for the package it builds with the same build tags after the
// sources are copied in, and the runtime stage copies /licenses and labels
// the image with the public source repository, which must be the repository
// config/defaults.yaml names.
func TestDockerfileShipsLicenses(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dockerfile)))
	if err != nil {
		t.Fatal(err)
	}
	dockerTarget(t, root)
	st := stages(string(raw))
	build, final := instructions(st[1]), instructions(st[2])

	var goBuild, collect string
	copied := false
	for _, ins := range build {
		if ins == "COPY . ." {
			copied = true
		}
		if !strings.HasPrefix(ins, "RUN ") {
			continue
		}
		if strings.Contains(ins, "go build") && strings.HasSuffix(ins, " "+pkg) {
			goBuild = ins
		}
		if strings.Contains(ins, "sh "+script+" /out/licenses "+pkg) {
			if !copied {
				t.Errorf("the collector runs before COPY . . brings %s in", script)
			}
			collect = ins
		}
	}
	if goBuild == "" || collect == "" {
		t.Fatalf("build stage: go build of %s %q, collector run %q", pkg, goBuild, collect)
	}
	for _, v := range []string{"GOOS=", "GOARCH=", "CGO_ENABLED="} {
		if strings.Contains(goBuild, v) || strings.Contains(collect, v) {
			t.Errorf("%s is set on a RUN line; set it once with ENV so the build and the collector agree", strings.TrimSuffix(v, "="))
		}
	}
	tags := regexp.MustCompile(`-tags[= ]+(\S+)`).FindStringSubmatch(goBuild)
	switch {
	case tags != nil && !strings.Contains(collect, "BUILD_TAGS="+tags[1]):
		t.Errorf("go build uses -tags %s but the collector does not get BUILD_TAGS=%s", tags[1], tags[1])
	case tags == nil && strings.Contains(collect, "BUILD_TAGS="):
		t.Errorf("the collector gets BUILD_TAGS but go build has no -tags")
	}
	if !strings.Contains(collect, "DOCKERFILE="+dockerfile+" ") {
		t.Errorf("the collector run should pass DOCKERFILE=%s for the README", dockerfile)
	}
	if !contains(final, "COPY --from=build /out/licenses/ /licenses/") {
		t.Error("the runtime stage does not copy /out/licenses/ to /licenses/")
	}
	if !contains(final, "LABEL org.opencontainers.image.source=$SOURCE_URL") || !contains(final, "ARG SOURCE_URL") {
		t.Error("the runtime stage does not label the image with ARG SOURCE_URL")
	}
	for _, a := range []string{"ARG SOURCE_URL", "ARG SOURCE_REF"} {
		if !contains(build, a) {
			t.Errorf("the build stage does not declare %s for the collector", a)
		}
	}

	m := regexp.MustCompile(`(?m)^ARG SOURCE_URL=(\S+)$`).FindStringSubmatch(st[0])
	if m == nil {
		t.Fatal("no global ARG SOURCE_URL=<public repository> before the first FROM")
	}
	defaults, err := os.ReadFile(filepath.Join(root, "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	base := regexp.MustCompile(`(?m)^\s*release_asset_base:\s*(\S+)\s*$`).FindSubmatch(defaults)
	if base == nil {
		t.Fatal("config/defaults.yaml has no catalog.release_asset_base")
	}
	if repo := strings.TrimSuffix(string(base[1]), "/releases/download"); m[1] != repo {
		t.Errorf("ARG SOURCE_URL=%s, but config/defaults.yaml names the public repository %s", m[1], repo)
	}

	ignore, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dockerfile+".dockerignore")))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(ignore), "\n") {
		p := strings.TrimSpace(line)
		if p == "" || strings.HasPrefix(p, "#") || strings.HasPrefix(p, "!") {
			continue
		}
		for _, f := range []string{script, "go.mod", "go.sum", "LICENSE"} {
			if ignored(p, f) {
				t.Errorf("%s.dockerignore pattern %q drops %s from the build context", dockerfile, p, f)
			}
		}
	}
}

// ignored reports whether a .dockerignore pattern excludes path (or one of
// its parent directories). It handles * and ? within a path element and a
// leading **/, which is all the ignore files here use.
func ignored(pattern, path string) bool {
	pattern = strings.TrimPrefix(pattern, "/")
	parts := strings.Split(path, "/")
	starts := []int{0}
	if rest, ok := strings.CutPrefix(pattern, "**/"); ok {
		pattern = rest
		starts = starts[:0]
		for i := range parts {
			starts = append(starts, i)
		}
	}
	for _, s := range starts {
		for e := s + 1; e <= len(parts); e++ {
			if ok, _ := filepath.Match(pattern, strings.Join(parts[s:e], "/")); ok {
				return true
			}
		}
	}
	return false
}
