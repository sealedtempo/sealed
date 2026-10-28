package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The composer's golden egress config (runtime/composer/testdata/golden/egress.json, composer 1.3.0) is what
// sealed-egress loads in the VM: it parses, compiles, and identifies every caller by each of its addresses
// (D-041), with the allowlists the composer wrote. The agent's app-network addresses and the payer's verifier
// network address reach nothing (review ws-int-agent 5); verifierd lives on the verifier network (D-061).
func TestComposerGoldenEgressConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "composer", "testdata", "golden", "egress.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("sealed-egress refuses the composer's config: %v", err)
	}
	p, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip, name, allowed, denied string
		port                      uint16
	}{
		{"172.30.0.3", "sealed-agent", "rpc.tempo.xyz", "github.com", 443},
		{"172.30.1.3", "sealed-agent--app-llm-gateway", "", "rpc.tempo.xyz", 443},
		{"172.30.0.5", "sealed-mpp-payer", "rpc.tempo.xyz", "github.com", 443},
		{"172.30.250.5", "sealed-mpp-payer--verifier", "", "rpc.tempo.xyz", 443},
		{"172.30.250.6", "sealed-verifierd", "github.com", "example.com", 443},
		{"172.30.250.6", "sealed-verifierd", "release-assets.githubusercontent.com", "api.github.com", 443},
		{"172.30.250.6", "sealed-verifierd", "objects.githubusercontent.com", "gist.githubusercontent.com", 443},
		{"172.30.0.17", "notes-web--apps", "api.example.com", "rpc.tempo.xyz", 443},
		{"172.30.2.16", "notes-web", "api.example.com", "rpc.tempo.xyz", 443},
	} {
		cp, ok := p.CallerByIP(netip.MustParseAddr(c.ip))
		if !ok || cp.Name != c.name {
			t.Fatalf("%s: caller %+v %v, want %s", c.ip, cp, ok, c.name)
		}
		if _, ok := cp.Allow.Match(c.allowed, c.port); c.allowed != "" && !ok {
			t.Errorf("%s may reach %s:%d", c.name, c.allowed, c.port)
		}
		if _, ok := cp.Allow.Match(c.denied, c.port); ok {
			t.Errorf("%s must not reach %s:%d", c.name, c.denied, c.port)
		}
	}
	for _, ip := range []string{"172.30.2.99", "172.30.0.6"} {
		if _, ok := p.CallerByIP(netip.MustParseAddr(ip)); ok {
			t.Errorf("%s: an address the composer did not assign is a caller", ip)
		}
	}
}
