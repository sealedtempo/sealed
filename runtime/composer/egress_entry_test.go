package composer

import (
	"slices"
	"testing"

	"github.com/sealedtempo/sealed/runtime/egress/policy"
)

// TestComposedAllowEntriesLoadInEgress is the runtime-2 regression: an
// allow entry the composer accepts must also load in sealed-egress, or the
// approved stack composes but never starts. Wildcards over an ICANN public
// suffix are refused at compose time. Wildcards over a private-section
// suffix (*.github.io) pass on both sides by design (INTERFACES section 12).
func TestComposedAllowEntriesLoadInEgress(t *testing.T) {
	refused := []string{"*.co.uk:443", "*.com.au:443", "*.com:443"}
	accepted := []string{"*.example.co.uk:443", "*.github.io:443", "*.vercel.app:443", "*.workers.dev:443", "*.appspot.com:443"}
	for _, entry := range append(slices.Clone(refused), accepted...) {
		cfg, bundles := fixtureStack(t)
		cfg.EgressAdditions = map[string][]string{"notes": {entry}}
		r, err := composeEmbedded(cfg, bundles)
		if slices.Contains(refused, entry) {
			if err == nil {
				t.Errorf("%s: composed (stackHash %x), but sealed-egress refuses it", entry, r.StackHash[:4])
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: composer refuses: %v", entry, err)
			continue
		}
		if _, err := policy.Parse(r.EgressConfig); err != nil {
			t.Errorf("%s: composed, but sealed-egress refuses the config: %v", entry, err)
		}
	}
	// The same check covers an app's own default_allow.
	src := "version: 1\ndefault_allow: [\"*.co.uk:443\"]\ncustomer_additions_allowed: false\n"
	if _, _, err := ParseEgressPolicy([]byte(src)); err == nil {
		t.Error("egress.yaml with *.co.uk:443 accepted")
	}
}
