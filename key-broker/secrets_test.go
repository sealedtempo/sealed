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

	"github.com/sealedtempo/sealed/runtime/composer"
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
  - {name: MASTER_KEY, description: admin key, generate: sk-hex32, share_with: [coding-agent]}
  - {name: ANTHROPIC_API_KEY, description: byok, generate: none, optional: true, share_with: [crm, coding-agent]}
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

// TestPlanSecretsNeedsShareWith (D-059): a same_as reference resolves only when the referenced secret lists the
// referencing app in share_with; listing another app, or nothing, is refused before any secret is read.
func TestPlanSecretsNeedsShareWith(t *testing.T) {
	ref := fakeBundle("coding-agent", "  - {name: LLM_KEY, description: k, generate: none, same_as: llm-gateway/APP_KEY_CODING_AGENT}\n")
	for name, c := range map[string]struct {
		gateway string
		ok      bool
	}{
		"no share_with":            {"  - {name: APP_KEY_CODING_AGENT, description: k, generate: hex32}\n", false},
		"empty share_with":         {"  - {name: APP_KEY_CODING_AGENT, description: k, generate: hex32, share_with: []}\n", false},
		"shared with another app":  {"  - {name: APP_KEY_CODING_AGENT, description: k, generate: hex32, share_with: [scraper]}\n", false},
		"shared with coding-agent": {"  - {name: APP_KEY_CODING_AGENT, description: k, generate: hex32, share_with: [coding-agent]}\n", true},
	} {
		refs, err := PlanSecrets([]string{"coding-agent", "llm-gateway"}, map[string]*composer.Bundle{
			"coding-agent": ref, "llm-gateway": fakeBundle("llm-gateway", c.gateway)})
		if c.ok {
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			if got := refStrings(refs); got[0] != "coding-agent/LLM_KEY<-sealed-llm-gateway-APP_KEY_CODING_AGENT" {
				t.Errorf("%s: plan %v", name, got)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "share_with") {
			t.Errorf("%s: %v, want a share_with refusal", name, err)
		}
	}
}

func TestPlanSecretsRejectsBadReferences(t *testing.T) {
	for name, c := range map[string]struct {
		apps    []string
		bundles map[string]*composer.Bundle
	}{
		"chain through a reference": {[]string{"a1", "b22", "c33"}, map[string]*composer.Bundle{
			"a1":  fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: b22/K}\n"),
			"b22": fakeBundle("b22", "  - {name: K, description: d, generate: none, same_as: c33/K, share_with: [a1]}\n"),
			"c33": fakeBundle("c33", "  - {name: K, description: d, generate: none, share_with: [b22, a1]}\n")}},
		"reference to its own app": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: a1/L}\n  - {name: L, description: d, generate: none, share_with: [a1]}\n")}},
		"required refers to optional": {[]string{"a1", "b22"}, map[string]*composer.Bundle{
			"a1":  fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: b22/K}\n"),
			"b22": fakeBundle("b22", "  - {name: K, description: d, generate: none, optional: true, share_with: [a1]}\n")}},
		"share_with entry is not an app id": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: K, description: d, generate: none, share_with: [\"Not An App\"]}\n")}},
		"app outside the stack": {[]string{"a1"}, map[string]*composer.Bundle{
			"a1": fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: zz9/K}\n")}},
		"undeclared secret": {[]string{"a1", "b22"}, map[string]*composer.Bundle{
			"a1":  fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: b22/NOPE}\n"),
			"b22": fakeBundle("b22", "  - {name: K, description: d, generate: none}\n")}},
		"cycle": {[]string{"a1", "b22"}, map[string]*composer.Bundle{
			"a1":  fakeBundle("a1", "  - {name: K, description: d, generate: none, same_as: b22/K, share_with: [b22]}\n"),
			"b22": fakeBundle("b22", "  - {name: K, description: d, generate: none, same_as: a1/K, share_with: [a1]}\n")}},
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

// The real catalog's same_as (D-043): coding-agent's LLM_GATEWAY_KEY is llm-gateway's APP_KEY_CODING_AGENT, read
// from the one Secret Manager entry `sealed secrets` stores (cli/internal/secrets TestRealCatalogManifests checks
// the same name on the CLI side).
func TestPlanSecretsRealCatalogSameAs(t *testing.T) {
	bundles := map[string]*composer.Bundle{}
	for _, app := range []string{"coding-agent", "llm-gateway"} {
		b, err := composer.BuildBundle(composer.BuildInput{AppDir: filepath.Join("..", "catalog", "apps", app), Registry: "ghcr.io/sealedtempo", AllowMissingSBOM: true})
		if err != nil {
			t.Fatal(err)
		}
		bundles[app] = b
	}
	refs, err := PlanSecrets([]string{"coding-agent", "llm-gateway"}, bundles)
	if err != nil {
		t.Fatal(err)
	}
	got := refStrings(refs)
	if !slices.Contains(got, "coding-agent/LLM_GATEWAY_KEY<-sealed-llm-gateway-APP_KEY_CODING_AGENT") {
		t.Fatalf("same_as not resolved to the referenced app's secret: %v", got)
	}
	if !slices.Contains(got, "llm-gateway/OLLAMA_GATE_KEY<-sealed-llm-gateway-OLLAMA_GATE_KEY") {
		t.Fatalf("llm-gateway's local-model key missing: %v", got)
	}
	if _, err := PlanSecrets([]string{"coding-agent"}, map[string]*composer.Bundle{"coding-agent": bundles["coding-agent"]}); err == nil {
		t.Fatal("coding-agent without llm-gateway resolved its same_as")
	}
}
