package localtempo

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const root = "../.."

// The contracts, @sealed/core (the TypeScript harnesses and the devnet) and the Go harnesses run one hardfork.
func TestHardforkMatchesContractsAndCore(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	foundry := regexp.MustCompile(`(?m)^hardfork = "tempo:(t[0-9]+)"`).FindStringSubmatch(read("contracts/foundry.toml"))
	if foundry == nil {
		t.Fatal(`contracts/foundry.toml: no hardfork = "tempo:t<n>"`)
	}
	core := regexp.MustCompile(`export const LOCAL_HARDFORK = "(t[0-9]+)"`).FindStringSubmatch(read("packages/core/src/chain.ts"))
	if core == nil {
		t.Fatal("packages/core/src/chain.ts: no LOCAL_HARDFORK")
	}
	if want := strings.ToUpper(foundry[1]); Hardfork != want || strings.ToUpper(core[1]) != want {
		t.Fatalf("Hardfork %s, contracts/foundry.toml %s, @sealed/core LOCAL_HARDFORK %s: they must agree (D-053)", Hardfork, foundry[1], core[1])
	}
}

// Merge C found four Go harnesses still starting anvil at T4 after the contracts moved to T12: every one names
// Hardfork instead of a literal.
func TestNoGoHarnessPinsItsOwnHardfork(t *testing.T) {
	literal := regexp.MustCompile(`"--hardfork",\s*"[Tt][0-9]+"`)
	var found []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "dependencies", "tmp", ".git", "out", "cache":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if literal.Match(b) {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("anvil started with a literal --hardfork (use localtempo.Hardfork): %v", found)
	}
}
