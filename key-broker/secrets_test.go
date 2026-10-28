package keybroker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// fakeBundle carries only what PlanSecrets reads: the manifest id and the raw manifest.yaml.
func fakeBundle(id, secretsYAML string) *composer.Bundle {
	return &composer.Bundle{
		Manifest: &composer.Manifest{ID: id},
		Files:    map[string][]byte{composer.ManifestFile: []byte("schema: sealed-manifest/v1\nid: " + id + "\nsecrets:\n" + secretsYAML)},
	}
}

func refStrings(refs []SecretRef) []string {
	var out []string
	for _, r := range refs {
		s := r.Owner + "/" + r.Name + "<-" + r.Source
		if r.Optional {
			s += "?"
		}
		out = append(out, s)
	}
	return out
}

func TestPlanSecretsSameAs(t *testing.T) {
	bundles := map[string]*composer.Bundle{
		"llm-gateway": fakeBundle("llm-gateway", `
  - {name: MASTER_KEY, description: admin key, generate: sk-hex32}
  - {name: ANTHROPIC_API_KEY, description: byok, generate: none, optional: true}
`),
		"coding-agent": fakeBundle("coding-agent", `
  - {name: SESSION_KEY, description: s, generate: hex32}
  - {name: LLM_KEY, description: gateway key, generate: none, same_as: llm-gateway/MASTER_KEY}
  - {name: BYOK, description: b, generate: none, optional: true, same_as: llm-gateway/ANTHROPIC_API_KEY}
`),
		"crm": fakeBundle("crm", ""),
	}
	refs, err := PlanSecrets([]string{"coding-agent", "crm", "llm-gateway"}, bundles)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"coding-agent/BYOK<-sealed-llm-gateway-ANTHROPIC_API_KEY?",
		"coding-agent/LLM_KEY<-sealed-llm-gateway-MASTER_KEY",
		"coding-agent/SESSION_KEY<-sealed-coding-agent-SESSION_KEY",
		"llm-gateway/ANTHROPIC_API_KEY<-sealed-llm-gateway-ANTHROPIC_API_KEY?",
		"llm-gateway/MASTER_KEY<-sealed-llm-gateway-MASTER_KEY",
		"_gate/GATE_PASSWORD_BCRYPT<-sealed-gate-password",
	}
	if got := refStrings(refs); !slices.Equal(got, want) {
		t.Fatalf("plan\n%v\nwant\n%v", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	gate, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	store := NewMemorySecretStore(map[string]string{
		"sealed-llm-gateway-MASTER_KEY":   "sk-master",
		"sealed-coding-agent-SESSION_KEY": "sess",
		"sealed-coding-agent-LLM_KEY":     "must not be used: same_as wins",
		"sealed-crm-NOT_DECLARED":         "never",
		GateSecretID:                      string(gate),
	})
	vals, released, err := readSecrets(context.Background(), store, refs)
	if err != nil {
		t.Fatal(err)
	}
	if vals["coding-agent"]["LLM_KEY"] != "sk-master" || vals["llm-gateway"]["MASTER_KEY"] != "sk-master" || vals["coding-agent"]["SESSION_KEY"] != "sess" {
		t.Fatalf("values %v", vals)
	}
	if _, ok := vals["coding-agent"]["BYOK"]; ok {
		t.Fatal("a missing optional same_as secret was released")
	}
	if len(vals["crm"]) != 0 {
		t.Fatal("crm declares nothing")
	}
	// The referenced value is read once, however many apps share it.
	if store.Reads("sealed-llm-gateway-MASTER_KEY") != 1 || store.Reads("sealed-coding-agent-LLM_KEY") != 0 || store.Reads("sealed-crm-NOT_DECLARED") != 0 {
		t.Fatal("unexpected Secret Manager reads")
	}
	if !slices.Contains(released, "coding-agent/LLM_KEY") || slices.Contains(released, "coding-agent/BYOK") {
		t.Fatalf("released %v", released)
	}
}

func TestPlanSecretsRejectsBadReferences(t *testing.T) {
	for name, c := range map[string]struct {
		apps    []string
		bundles map[string]*composer.Bundle
	}{
		"app outside the stack": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: zz9/K}\n")}},
		"undeclared secret": {[]string{"a1", "b22"}, map[string]*composer.Bundle{
			"a1":  fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: b22/NOPE}\n"),
			"b22": fakeBundle("b22", "  - {name: K, description: d, generate: none}\n")}},
		"cycle": {[]string{"a1", "b22"}, map[string]*composer.Bundle{
			"a1":  fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: b22/K}\n"),
			"b22": fakeBundle("b22", "  - {name: K, description: d, generate: none, same_as: a1/K}\n")}},
		"malformed same_as": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: K}\n")}},
		"bad secret name": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: lower, description: d, generate: none}\n")}},
		"declared twice": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: K, description: d, generate: none}\n  - {name: K, description: d, generate: none}\n")}},
		"missing bundle": {[]string{"a1"}, map[string]*composer.Bundle{}},
	} {
		if _, err := PlanSecrets(c.apps, c.bundles); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadSecretsErrors(t *testing.T) {
	refs := []SecretRef{{Owner: "a1", Name: "K", Source: "sealed-a1-K"}}
	_, _, err := readSecrets(context.Background(), NewMemorySecretStore(nil), refs)
	var se *SecretError
	if !errors.As(err, &se) || se.Reason != ReasonSecretMissing {
		t.Fatalf("missing: %v", err)
	}
	big := NewMemorySecretStore(map[string]string{"sealed-a1-K": strings.Repeat("x", MaxSecretBytes+1)})
	if _, _, err := readSecrets(context.Background(), big, refs); !errors.As(err, &se) || se.Reason != ReasonSecretInvalid {
		t.Fatalf("oversized: %v", err)
	}
	down := NewMemorySecretStore(nil)
	down.Fail = errors.New("boom")
	if _, _, err := readSecrets(context.Background(), down, refs); err == nil || errors.As(err, &se) {
		t.Fatalf("store failure: %v", err)
	}
}

func TestSecretID(t *testing.T) {
	if SecretID("crm", "APP_SECRET") != "sealed-crm-APP_SECRET" || SecretID("llm-gateway", "MASTER_KEY") != "sealed-llm-gateway-MASTER_KEY" {
		t.Fatal("naming")
	}
}

func TestLoadSecretsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(`{"sealed-a1-K":"v"}`), 0o600)
	m, err := LoadSecretsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := m.Access(context.Background(), "sealed-a1-K"); string(v) != "v" {
		t.Fatal("value")
	}
	_ = os.WriteFile(p, []byte(`{"other":"v"}`), 0o600)
	if _, err := LoadSecretsFile(p); err == nil {
		t.Fatal("accepted a secret outside the sealed- prefix")
	}
}
