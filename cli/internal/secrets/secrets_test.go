package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/sealed-dev/sealed/cli/internal/gcp"
)

// memStore is an in-memory Secret Manager.
type memStore struct {
	versions map[string][][]byte
	labels   map[string]map[string]string
	creates  int
}

func newMem() *memStore {
	return &memStore{versions: map[string][][]byte{}, labels: map[string]map[string]string{}}
}

func (m *memStore) Exists(_ context.Context, name string) (bool, error) {
	_, ok := m.versions[name]
	return ok, nil
}

func (m *memStore) Create(_ context.Context, name string, labels map[string]string, _ string) error {
	m.creates++
	m.versions[name] = nil
	m.labels[name] = labels
	return nil
}

func (m *memStore) AddVersion(_ context.Context, name string, v []byte) (string, error) {
	m.versions[name] = append(m.versions[name], append([]byte(nil), v...))
	return name, nil
}

func (m *memStore) List(_ context.Context, prefix string) ([]gcp.SecretInfo, error) {
	var out []gcp.SecretInfo
	for k := range m.versions {
		if strings.HasPrefix(k, prefix) {
			out = append(out, gcp.SecretInfo{Name: k, Labels: m.labels[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memStore) Delete(_ context.Context, name string) error {
	delete(m.versions, name)
	return nil
}

func TestGenerators(t *testing.T) {
	for kind, re := range map[string]string{
		"hex32":     `^[0-9a-f]{64}$`,
		"sk-hex32":  `^sk-[0-9a-f]{64}$`,
		"base64-32": `^[A-Za-z0-9+/]{43}=$`,
		"password":  `^[A-Za-z0-9]{24}$`,
	} {
		seen := map[string]bool{}
		for i := 0; i < 20; i++ {
			v, err := Generate(kind, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !regexp.MustCompile(re).MatchString(v) {
				t.Fatalf("%s: %q", kind, v)
			}
			if seen[v] {
				t.Fatalf("%s repeated a value", kind)
			}
			seen[v] = true
		}
	}
	v, _ := Generate("base64-32", nil)
	if b, err := base64.StdEncoding.DecodeString(v); err != nil || len(b) != 32 {
		t.Fatal("base64-32 is 32 bytes")
	}
	v, _ = Generate("hex32", bytes.NewReader(bytes.Repeat([]byte{0xab}, 32)))
	if v != strings.Repeat("ab", 32) {
		t.Fatalf("hex32 from fixed bytes %q", v)
	}
	// Rejection sampling: 248..255 are skipped, 0 maps to 'A', 61 to '9'.
	src := append(bytes.Repeat([]byte{255, 248}, 5), bytes.Repeat([]byte{0, 61}, 12)...)
	v, _ = Generate("password", bytes.NewReader(src))
	if v != strings.Repeat("A9", 12) {
		t.Fatalf("password sampling %q", v)
	}
	if _, err := Generate("none", nil); err == nil {
		t.Fatal("none has no generator")
	}
	if _, err := Generate("uuid", nil); err == nil {
		t.Fatal("unknown generator")
	}
	if _, err := Generate("hex32", bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("short random source")
	}
}

func TestStoredNames(t *testing.T) {
	if StoredName("llm-gateway", "APP_KEY_CODING_AGENT") != "sealed-llm-gateway-APP_KEY_CODING_AGENT" {
		t.Fatal("stored name")
	}
	for in, want := range map[string][2]string{
		"sealed-llm-gateway-APP_KEY_CODING_AGENT": {"llm-gateway", "APP_KEY_CODING_AGENT"},
		"sealed-crm-ADMIN_EMAIL":                  {"crm", "ADMIN_EMAIL"},
		"sealed-gate-password":                    {"gate", ""},
		"sealed-internal-tools-PGPASSWORD":        {"internal-tools", "PGPASSWORD"},
	} {
		app, name, ok := ParseStoredName(in)
		if !ok || app != want[0] || name != want[1] {
			t.Errorf("%s: %q %q %v", in, app, name, ok)
		}
	}
	for _, bad := range []string{"crm-APP", "sealed-", "sealed-crm", "sealed-crm-lower", "sealed--X"} {
		if _, _, ok := ParseStoredName(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestGateHash(t *testing.T) {
	h, err := GateHash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$2a$12$") || bcrypt.CompareHashAndPassword([]byte(h), []byte("correct horse battery")) != nil {
		t.Fatalf("hash %q", h)
	}
	if _, err := GateHash("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

const gatewayManifest = `
id: llm-gateway
name: x
secrets:
  - name: LITELLM_MASTER_KEY
    description: admin key
    generate: sk-hex32
  - name: APP_KEY_CODING_AGENT
    description: coding agent key
    generate: sk-hex32
    optional: true
  - name: BYOK_TINFOIL_API_KEY
    description: byok
    generate: none
    optional: true
`

const agentManifest = `
id: coding-agent
secrets:
  - name: OH_SECRET_KEY
    description: x
    generate: hex32
  - name: LLM_GATEWAY_KEY
    description: same as the gateway's coding-agent key
    generate: none
    same_as: llm-gateway/APP_KEY_CODING_AGENT
  - name: ADMIN_EMAIL
    description: first admin
    generate: none
`

func mustApp(t *testing.T, y string) *App {
	t.Helper()
	a, err := ParseManifest([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestParseManifestRejects(t *testing.T) {
	for name, y := range map[string]string{
		"unknown key":    "id: a\nsecrets:\n  - name: A\n    description: x\n    generate: hex32\n    rotate: true\n",
		"bad generator":  "id: a\nsecrets:\n  - name: A\n    description: x\n    generate: uuid\n",
		"bad name":       "id: a\nsecrets:\n  - name: a\n    description: x\n    generate: hex32\n",
		"duplicate":      "id: a\nsecrets:\n  - {name: A, description: x, generate: hex32}\n  - {name: A, description: x, generate: hex32}\n",
		"self reference": "id: a\nsecrets:\n  - {name: A, description: x, generate: none, same_as: a/B}\n",
		"bad reference":  "id: a\nsecrets:\n  - {name: A, description: x, generate: none, same_as: B}\n",
		"bad id":         "id: A\n",
	} {
		if _, err := ParseManifest([]byte(y)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPlanSameAs(t *testing.T) {
	gw, agent := mustApp(t, gatewayManifest), mustApp(t, agentManifest)
	p, err := NewPlan([]*App{agent, gw})
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := p.Find("coding-agent", "LLM_GATEWAY_KEY")
	if ref.Stored != "sealed-llm-gateway-APP_KEY_CODING_AGENT" || ref.Generate != "sk-hex32" {
		t.Fatalf("reference %+v", ref)
	}
	target, _ := p.Find("llm-gateway", "APP_KEY_CODING_AGENT")
	if target.Optional || len(target.ReferredBy) != 1 || target.ReferredBy[0] != "coding-agent/LLM_GATEWAY_KEY" {
		t.Fatalf("a required reference makes the target required: %+v", target)
	}
	for _, e := range p.Stored() {
		if e.SameAs != "" {
			t.Fatal("Stored lists references")
		}
	}
	// The gateway alone keeps the key optional.
	p2, _ := NewPlan([]*App{mustApp(t, gatewayManifest)})
	if e, _ := p2.Find("llm-gateway", "APP_KEY_CODING_AGENT"); !e.Optional {
		t.Fatal("without coding-agent the key stays optional")
	}
	// The referenced app must be in the stack.
	if _, err := NewPlan([]*App{mustApp(t, agentManifest)}); err == nil || !strings.Contains(err.Error(), "not in the stack") {
		t.Fatalf("missing target app: %v", err)
	}
	// And declare the secret.
	gw2 := mustApp(t, "id: llm-gateway\nsecrets: []\n")
	if _, err := NewPlan([]*App{mustApp(t, agentManifest), gw2}); err == nil || !strings.Contains(err.Error(), "does not declare") {
		t.Fatalf("undeclared target: %v", err)
	}
	// No chains.
	c := mustApp(t, "id: c\nsecrets:\n  - {name: X, description: x, generate: none, same_as: coding-agent/LLM_GATEWAY_KEY}\n")
	if _, err := NewPlan([]*App{agent, gw, c}); err == nil || !strings.Contains(err.Error(), "no chains") {
		t.Fatalf("chain: %v", err)
	}
}

func TestFillMissingAsksOnceAndGenerates(t *testing.T) {
	store := newMem()
	m := &Manager{Store: store}
	p, err := NewPlan([]*App{mustApp(t, agentManifest), mustApp(t, gatewayManifest)})
	if err != nil {
		t.Fatal(err)
	}
	// A value the customer already stored is never touched.
	store.versions["sealed-coding-agent-OH_SECRET_KEY"] = [][]byte{[]byte("keep")}
	var asked []string
	res, err := m.FillMissing(context.Background(), p, func(stored, _ string) (string, bool, error) {
		asked = append(asked, stored)
		return "admin@example.com", true, nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, ",") != "sealed-coding-agent-ADMIN_EMAIL" {
		t.Fatalf("asked %v", asked)
	}
	if string(store.versions["sealed-coding-agent-OH_SECRET_KEY"][0]) != "keep" || len(store.versions["sealed-coding-agent-OH_SECRET_KEY"]) != 1 {
		t.Fatal("existing secret changed")
	}
	if _, ok := store.versions["sealed-coding-agent-LLM_GATEWAY_KEY"]; ok {
		t.Fatal("a same_as secret is never stored twice")
	}
	if v := store.versions["sealed-llm-gateway-APP_KEY_CODING_AGENT"]; len(v) != 1 || !strings.HasPrefix(string(v[0]), "sk-") {
		t.Fatalf("referenced key generated once: %q", v)
	}
	if _, ok := store.versions["sealed-llm-gateway-BYOK_TINFOIL_API_KEY"]; ok {
		t.Fatal("optional secret without generator was set")
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "sealed-llm-gateway-BYOK_TINFOIL_API_KEY" {
		t.Fatalf("skipped %v", res.Skipped)
	}
	gate := store.versions[GateSecret]
	if len(gate) != 1 || bcrypt.CompareHashAndPassword(gate[0], []byte(res.GatePassword)) != nil {
		t.Fatal("gate stores the bcrypt hash of the shown password")
	}
	if bytes.Contains(gate[0], []byte(res.GatePassword)) {
		t.Fatal("gate plaintext stored")
	}
	if store.labels["sealed-llm-gateway-APP_KEY_CODING_AGENT"]["sealed-key"] != "app_key_coding_agent" {
		t.Fatalf("labels %v", store.labels["sealed-llm-gateway-APP_KEY_CODING_AGENT"])
	}
	// A second run changes nothing and asks nothing.
	asked = nil
	res2, err := m.FillMissing(context.Background(), p, func(string, string) (string, bool, error) {
		asked = append(asked, "x")
		return "", false, nil
	}, true)
	if err != nil || len(asked) != 0 || len(res2.Generated) != 0 || res2.GatePassword != "" {
		t.Fatalf("second run: %+v asked %v err %v", res2, asked, err)
	}
}

func TestFillMissingNonInteractiveReportsMissing(t *testing.T) {
	m := &Manager{Store: newMem()}
	p, _ := NewPlan([]*App{mustApp(t, agentManifest), mustApp(t, gatewayManifest)})
	res, err := m.FillMissing(context.Background(), p, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Missing, ",") != "sealed-coding-agent-ADMIN_EMAIL" {
		t.Fatalf("missing %v", res.Missing)
	}
}

func TestPutRefusesSilentRotation(t *testing.T) {
	store := newMem()
	m := &Manager{Store: store}
	ctx := context.Background()
	if created, err := m.Put(ctx, "sealed-crm-ENCRYPTION_KEY", nil, []byte("a"), false); err != nil || !created {
		t.Fatal(err)
	}
	if _, err := m.Put(ctx, "sealed-crm-ENCRYPTION_KEY", nil, []byte("b"), false); err == nil {
		t.Fatal("silent rotation")
	}
	if _, err := m.Put(ctx, "sealed-crm-ENCRYPTION_KEY", nil, []byte("b"), true); err != nil || len(store.versions["sealed-crm-ENCRYPTION_KEY"]) != 2 {
		t.Fatal("rotation with --rotate")
	}
	if _, err := m.Put(ctx, "sealed-crm-X", nil, nil, false); err == nil {
		t.Fatal("empty value stored")
	}
}

func TestRealCatalogManifests(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "catalog", "apps")
	ids := []string{"coding-agent", "crm", "internal-tools", "llm-gateway", "scraper"}
	apps, err := LoadCatalog(dir, ids)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPlan(apps)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Entries {
		if !strings.HasPrefix(e.Stored, Prefix) || len(e.Stored) > 255 {
			t.Errorf("stored name %q", e.Stored)
		}
		if e.Generate != "none" {
			if _, err := Generate(e.Generate, nil); err != nil {
				t.Errorf("%s: %v", e.Stored, err)
			}
		}
	}
	if _, ok := p.Find("crm", "ENCRYPTION_KEY"); !ok {
		t.Fatal("crm secrets missing from the plan")
	}
}
