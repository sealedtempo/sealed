package composer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const testRegistry = "ghcr.io/sealedtempo"

func fixtureDir(app string) string { return filepath.Join("testdata", "apps", app) }

func buildFixture(t *testing.T, app string) *Bundle {
	t.Helper()
	b, err := BuildBundle(BuildInput{AppDir: fixtureDir(app), Registry: testRegistry})
	if err != nil {
		t.Fatalf("build %s: %v", app, err)
	}
	return b
}

// copyFixture copies an app fixture into a temp dir so tests can mutate it.
func copyFixture(t *testing.T, app string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), app)
	err := filepath.Walk(fixtureDir(app), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixtureDir(app), p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func testConfig(bundles ...*Bundle) *Config {
	c := &Config{
		Schema:           ConfigSchema,
		ChainID:          4217,
		Customer:         "0x00000000000000000000000000000000000000c1",
		Salt:             "0x" + strings.Repeat("5a", 32),
		ImageID:          "0x" + strings.Repeat("1d", 32),
		ComposerVersion:  Version,
		Hostnames:        Hostnames{Scheme: SchemeSslip, IP: "34.1.2.3"},
		EgressAdditions:  map[string][]string{},
		AllowedVpcRanges: []string{},
		Endpoints: Endpoints{
			KeyBroker:   "https://sealed-key-broker-xyz.a.run.app",
			PlatformAPI: "https://api.sealed.example",
			TempoRPC:    "https://rpc.tempo.xyz",
			Relay:       "https://relay.sealed.example",
			RelayAttest: "https://attest.relay.sealed.example/attest",
		},
		Contracts: Contracts{
			PlatformRegistry:   "0x00000000000000000000000000000000000000e1",
			AppRegistry:        "0x00000000000000000000000000000000000000e2",
			DeploymentRegistry: "0x00000000000000000000000000000000000000e3",
			FeeSplitter:        "0x00000000000000000000000000000000000000e4",
		},
		FeeToken:   "0x20c0000000000000000000000000000000000000",
		Settlement: Settlement{Mode: "access-key", IntervalMinutes: 60, GracePeriodMinutes: 1440, SpendLimitPerDay: "2000000"},
		RelayOwner: "0x00000000000000000000000000000000000000b1",
	}
	for _, b := range bundles {
		c.Apps = append(c.Apps, ConfigApp{ID: b.Manifest.ID, ReleaseID: b.ReleaseID.Hex()})
	}
	sort.Slice(c.Apps, func(i, j int) bool { return c.Apps[i].ID < c.Apps[j].ID })
	return c
}

func mustCompose(t *testing.T, cfg *Config, bundles ...*Bundle) *Result {
	t.Helper()
	r, err := Compose(cfg, bundles)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	return r
}

func fixtureStack(t *testing.T) (*Config, []*Bundle) {
	t.Helper()
	notes := buildFixture(t, "notes")
	gw := buildFixture(t, "llm-gateway")
	return testConfig(notes, gw), []*Bundle{notes, gw}
}
