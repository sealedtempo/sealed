package composer

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Validate refuses any composerVersion but Version before it checks the
// fields after it (config.go), and the stack checks do the same. A fuzz seed
// that names another version therefore reaches only that check, not the code
// it was added for. Nothing else fails when a version bump leaves such a seed
// behind: the seed is still refused, only for the wrong reason. So this test
// reads every Go seed corpus (testdata/fuzz/Fuzz*/) in the repository and
// fails on a seed that names any other composer version. A test of the
// version check itself belongs in TestParseConfig, not in a seed.

var seedComposerVersionRe = regexp.MustCompile(`"composerVersion"\s*:\s*"([^"]*)"`)

// seedArgs decodes the string and []byte arguments of a Go fuzz corpus file
// ("go test fuzz v1", then one value per line). Other values (numbers,
// booleans) are skipped. ok is false when the file is not a corpus file.
func seedArgs(raw []byte) (args [][]byte, ok bool, err error) {
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) == 0 || lines[0] != "go test fuzz v1" {
		return nil, false, nil
	}
	for i, line := range lines[1:] {
		for _, prefix := range []string{"[]byte(", "string("} {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			if !strings.HasSuffix(line, ")") {
				return nil, true, fmt.Errorf("line %d: %q is not closed", i+2, line)
			}
			s, uerr := strconv.Unquote(line[len(prefix) : len(line)-1])
			if uerr != nil {
				return nil, true, fmt.Errorf("line %d: %v", i+2, uerr)
			}
			args = append(args, []byte(s))
		}
	}
	return args, true, nil
}

// staleSeedVersions returns every composerVersion a corpus file names that
// is not this composer's.
func staleSeedVersions(raw []byte) ([]string, error) {
	args, ok, err := seedArgs(raw)
	if err != nil || !ok {
		return nil, err
	}
	var stale []string
	for _, a := range args {
		for _, m := range seedComposerVersionRe.FindAllSubmatch(a, -1) {
			if v := string(m[1]); v != Version {
				stale = append(stale, v)
			}
		}
	}
	return stale, nil
}

func TestFuzzSeedsNameThisComposer(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}
	seeds := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dependencies":
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Dir(path)
		if !strings.HasPrefix(filepath.Base(target), "Fuzz") || filepath.Base(filepath.Dir(target)) != "fuzz" ||
			filepath.Base(filepath.Dir(filepath.Dir(target))) != "testdata" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		stale, err := staleSeedVersions(raw)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		seeds++
		for _, v := range stale {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s names composerVersion %q, the composer is %s: the seed is refused at the version check before the code it was added for; change it to %q",
				filepath.ToSlash(rel), v, Version, Version)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d corpus files read", seeds)
}

// TestStaleSeedVersions checks the corpus reader on seeds in the format
// go test writes.
func TestStaleSeedVersions(t *testing.T) {
	cfg, err := os.ReadFile("testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cfg, []byte(`"composerVersion": "`+Version+`"`)) {
		t.Fatalf("testdata/config.json does not name composer %s", Version)
	}
	compact := regexp.MustCompile(`\s*\n\s*`).ReplaceAll(cfg, nil)
	old := bytes.Replace(compact, []byte(`"composerVersion": "`+Version+`"`), []byte(`"composerVersion":"1.4.0"`), 1)
	seed := func(args ...string) []byte {
		return []byte("go test fuzz v1\n" + strings.Join(args, "\n") + "\n")
	}
	for _, c := range []struct {
		name string
		raw  []byte
		want []string
	}{
		{"current version", seed(fmt.Sprintf("[]byte(%q)", compact)), nil},
		{"old version", seed(fmt.Sprintf("[]byte(%q)", old)), []string{"1.4.0"}},
		{"old version after other values", seed("uint8(0)", "uint8(2)", fmt.Sprintf("string(%q)", old)), []string{"1.4.0"}},
		{"two args", seed(fmt.Sprintf("[]byte(%q)", compact), fmt.Sprintf("[]byte(%q)", old)), []string{"1.4.0"}},
		{"no version", seed(`[]byte("version: 1\n")`), nil},
		{"not a corpus file", []byte(`{"composerVersion":"1.4.0"}`), nil},
	} {
		got, err := staleSeedVersions(c.raw)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: stale versions %v, want %v", c.name, got, c.want)
		}
	}
	if _, err := staleSeedVersions(seed(`[]byte("unterminated)`)); err == nil {
		t.Error("a corpus line that does not unquote is accepted")
	}
}
