package composer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/sealedtempo/sealed/runtime/egress/policy"
)

// Fuzz targets for what the composer reads from callers and release bundles:
// the public config, the bundle members (manifest.yaml,
// compose.fragment.yaml, egress.yaml) and the bundle tar. Properties: no
// panic; whatever is accepted composes deterministically (two runs give the
// same bytes), its config round-trips through CanonicalJSON, and sealed-egress
// accepts the egress config the composer wrote.

// fuzzApps are the fixture apps and the catalog apps every target can use.
var fuzzApps = []string{
	"testdata/apps/notes", "testdata/apps/llm-gateway", "testdata/apps/inference-relay",
	"../../catalog/apps/crm", "../../catalog/apps/coding-agent", "../../catalog/apps/internal-tools",
	"../../catalog/apps/llm-gateway", "../../catalog/apps/scraper", "../../catalog/apps/inference-relay",
}

type fuzzBase struct {
	dir   string
	files map[string][]byte
	b     *Bundle
}

var (
	fuzzBasesOnce sync.Once
	fuzzBases     []fuzzBase
)

func loadFuzzBases(f *testing.F) []fuzzBase {
	fuzzBasesOnce.Do(func() {
		for _, dir := range fuzzApps {
			files, err := CollectBundleFiles(BuildInput{AppDir: dir, Registry: testRegistry, AllowMissingSBOM: true})
			if err != nil {
				f.Logf("skip %s: %v", dir, err)
				continue
			}
			tarBytes, err := WriteTar(files)
			if err != nil {
				f.Fatalf("%s: %v", dir, err)
			}
			b, err := LoadBundle(tarBytes)
			if err != nil {
				f.Fatalf("%s: %v", dir, err)
			}
			fuzzBases = append(fuzzBases, fuzzBase{dir: dir, files: files, b: b})
		}
	})
	if len(fuzzBases) < 3 {
		f.Fatalf("only %d fuzz base bundles", len(fuzzBases))
	}
	return fuzzBases
}

// composeTwice composes cfg with bundles twice and fails if the results
// differ or if sealed-egress would refuse the egress config. It returns the
// error of the first run.
func composeTwice(t *testing.T, cfg *Config, bundles []*Bundle) error {
	t.Helper()
	r1, err1 := Compose(cfg, bundles)
	r2, err2 := Compose(cfg, bundles)
	if (err1 == nil) != (err2 == nil) || (err1 != nil && err1.Error() != err2.Error()) {
		t.Fatalf("compose is not deterministic: %v / %v", err1, err2)
	}
	if err1 != nil {
		return err1
	}
	if d := diffResults(r1, r2); d != "" {
		t.Fatalf("compose is not deterministic: %s differs", d)
	}
	canon, err := cfg.CanonicalJSON()
	if err != nil || !bytes.Equal(canon, r1.ConfigJSON) {
		t.Fatalf("Result.ConfigJSON is not the config's canonical JSON (%v)", err)
	}
	if h, _ := cfg.Hash(); h != r1.ConfigHash || SHA256(r1.AppCompose) != r1.StackHash {
		t.Fatal("configHash or stackHash do not match their documents")
	}
	ecfg, err := policy.Parse(r1.EgressConfig)
	if err != nil {
		t.Fatalf("sealed-egress refuses the composed egress config: %v", err)
	}
	if _, err := policy.Compile(ecfg); err != nil {
		t.Fatalf("sealed-egress cannot compile the composed egress config: %v", err)
	}
	if len(r1.AppCompose) > MaxAppComposeBytes {
		t.Fatalf("app-compose.json is %d bytes, over dstack's cap", len(r1.AppCompose))
	}
	return nil
}

func diffResults(a, b *Result) string {
	pairs := []struct {
		name string
		x, y []byte
	}{
		{"AppCompose", a.AppCompose, b.AppCompose}, {"ComposeJSON", a.ComposeJSON, b.ComposeJSON},
		{"ConfigJSON", a.ConfigJSON, b.ConfigJSON}, {"EgressConfig", a.EgressConfig, b.EgressConfig},
		{"Caddyfile", a.Caddyfile, b.Caddyfile}, {"CaddyfilePaymentNeeded", a.CaddyfilePaymentNeeded, b.CaddyfilePaymentNeeded},
		{"StackInfo", a.StackInfo, b.StackInfo}, {"PreLaunchScript", []byte(a.PreLaunchScript), []byte(b.PreLaunchScript)},
		{"Unbuilt", []byte(fmt.Sprint(a.Unbuilt)), []byte(fmt.Sprint(b.Unbuilt))},
	}
	for _, p := range pairs {
		if !bytes.Equal(p.x, p.y) {
			return p.name
		}
	}
	if a.StackHash != b.StackHash || a.ConfigHash != b.ConfigHash || a.DeploymentID != b.DeploymentID {
		return "hashes"
	}
	return ""
}

// FuzzParseConfig: ParseConfig never panics; an accepted config re-parses
// from its canonical JSON to the same canonical JSON and hash; and with its
// apps pointed at real bundles it composes deterministically.
func FuzzParseConfig(f *testing.F) {
	bases := loadFuzzBases(f)
	byID := map[string]*Bundle{}
	for _, b := range bases {
		if _, dup := byID[b.b.Manifest.ID]; !dup {
			byID[b.b.Manifest.ID] = b.b
		}
	}
	for _, p := range []string{"testdata/config.json", "testdata/golden/config.json"} {
		if raw, err := os.ReadFile(p); err == nil {
			f.Add(raw)
		}
	}
	for _, set := range [][]int{{0, 1}, {0}, {1, 2}, {3, 6}, {4, 6}, {5}, {7}, {8}} {
		var bs []*Bundle
		for _, i := range set {
			if i < len(bases) {
				bs = append(bs, bases[i].b)
			}
		}
		cfg := testConfig(bs...)
		if len(bs) > 0 && bs[0].Manifest.ID == "notes" {
			cfg.EgressAdditions = map[string][]string{"notes": {"smtp.example.com:587", "*.mail.example.com:465", "10.8.0.9:25"}}
			cfg.AllowedVpcRanges = []string{"10.8.0.0/16"}
			cfg.Debug = true
		}
		if raw, err := cfg.CanonicalJSON(); err == nil {
			f.Add(raw)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := ParseConfig(raw)
		if err != nil {
			return
		}
		canon, err := c.CanonicalJSON()
		if err != nil {
			t.Fatalf("accepted config has no canonical JSON: %v", err)
		}
		c2, err := ParseConfig(canon)
		if err != nil {
			t.Fatalf("canonical JSON of an accepted config is refused: %v\n%s", err, canon)
		}
		canon2, _ := c2.CanonicalJSON()
		h1, _ := c.Hash()
		h2, _ := c2.Hash()
		if !bytes.Equal(canon, canon2) || h1 != h2 {
			t.Fatalf("canonical JSON is not stable:\n%s\n%s", canon, canon2)
		}
		// Point the config's apps at real bundles so Compose runs past
		// planning; apps without a bundle stay as they are (Compose refuses).
		var bundles []*Bundle
		for i, a := range c.Apps {
			if b, ok := byID[a.ID]; ok {
				c.Apps[i].ReleaseID = b.ReleaseID.Hex()
				bundles = append(bundles, b)
			}
		}
		sort.Slice(c.Apps, func(i, j int) bool { return c.Apps[i].ID < c.Apps[j].ID })
		if c.Validate() != nil {
			return
		}
		_ = composeTwice(t, c, bundles)
	})
}

// FuzzBundleMember replaces one member of a real bundle (0 manifest.yaml,
// 1 compose.fragment.yaml, 2 egress.yaml) with the input. A bundle that
// loads must hash, round-trip through its tar and compose deterministically
// alone and next to another app.
func FuzzBundleMember(f *testing.F) {
	bases := loadFuzzBases(f)
	members := []string{ManifestFile, FragmentFile, EgressFile}
	for i, b := range bases {
		for m, name := range members {
			f.Add(uint8(i), uint8(m), b.files[name])
		}
	}
	f.Fuzz(func(t *testing.T, base, member uint8, data []byte) {
		bb := bases[int(base)%len(bases)]
		name := members[int(member)%len(members)]
		files := make(map[string][]byte, len(bb.files))
		for k, v := range bb.files {
			files[k] = v
		}
		files[name] = data
		tarBytes, err := WriteTar(files)
		if err != nil {
			return
		}
		b, err := LoadBundle(tarBytes)
		if err != nil {
			return
		}
		again, err := LoadBundle(b.Tar)
		if err != nil || again.ReleaseID != b.ReleaseID || again.EgressPolicyHash != b.EgressPolicyHash || again.SBOMHash != b.SBOMHash {
			t.Fatalf("bundle does not reload to the same hashes (%v)", err)
		}
		_ = composeTwice(t, testConfig(b), []*Bundle{b})
		// Next to an app with another id.
		for _, other := range bases {
			if other.b.Manifest.ID != b.Manifest.ID {
				pair := []*Bundle{b, other.b}
				sort.Slice(pair, func(i, j int) bool { return pair[i].Manifest.ID < pair[j].Manifest.ID })
				_ = composeTwice(t, testConfig(pair...), pair)
				break
			}
		}
	})
}

// FuzzLoadBundle: LoadBundle never panics on tar bytes; an accepted bundle is
// exactly its canonical tar (WriteTar of its files gives the input back) and
// every file passes the layout and text rules on reload.
func FuzzLoadBundle(f *testing.F) {
	for _, b := range loadFuzzBases(f) {
		f.Add(b.b.Tar)
	}
	if raw, err := os.ReadFile(filepath.Join("testdata", "golden", "stack.json")); err == nil {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, tarBytes []byte) {
		b, err := LoadBundle(tarBytes)
		if err != nil {
			return
		}
		if !bytes.Equal(b.Tar, tarBytes) || b.Hash != SHA256(tarBytes) {
			t.Fatal("bundle bytes or hash differ from the input")
		}
		w, err := WriteTar(b.Files)
		if err != nil || !bytes.Equal(w, tarBytes) {
			t.Fatalf("accepted tar is not canonical (%v)", err)
		}
		if b.ReleaseID != ReleaseID(b.AppID, b.Version(), b.Hash) || b.AppID != AppID(b.Manifest.ID) {
			t.Fatal("release id does not follow from the bundle")
		}
	})
}
