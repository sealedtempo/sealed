package bootstrap

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/cli/internal/embedded"
)

// The key broker's environment contract (review-ws-key-broker F5): the Cloud Run env the bootstrap renders must be
// exactly what cmd/key-broker reads. tests/plan.tftest.hcl proves the Cloud Run service carries the env of
// modules/key-broker-env unchanged; this test renders that module with Terraform and hands the result to the
// broker's own config parser (loadConfig in key-broker/cmd/key-broker), then checks that the broker asked for every
// variable the bootstrap sets and that each customer choice (RPC, chain, registries, project, region, key, asset
// base) arrives in the effective config instead of a built-in default.
//
// The broker source is this checkout's key-broker/ when present (after the integration merge), otherwise the git
// ref SEALED_KEY_BROKER_REF (default ws/key-broker) of this repository. It needs terraform, git and go;
// SEALED_REQUIRE_KEY_BROKER=1 turns a skip into a failure.

// contractInputs are deliberately not the broker's defaults, so a variable the broker ignored would show up as a
// default value in its config.
var contractInputs = map[string]any{
	"customer_address":    "0x00000000000000000000000000000000000000C1",
	"tempo_rpc_url":       "https://tempo.customer-node.example/rpc",
	"chain_id":            4217,
	"platform_registry":   "0x00000000000000000000000000000000000000A1",
	"app_registry":        "0x00000000000000000000000000000000000000A2",
	"deployment_registry": "0x00000000000000000000000000000000000000A3",
	"release_asset_base":  "https://assets.customer.example/releases",
	"project_id":          "acme-prod-4417",
	"region":              "europe-west4",
	"kms_crypto_key":      "projects/acme-prod-4417/locations/europe-west4/keyRings/sealed/cryptoKeys/sealed-kb-hmac",
}

type renderedEnv struct {
	Env           map[string]string `json:"env"`
	RuntimeEnv    map[string]string `json:"runtime_env"`
	ContainerPort int               `json:"container_port"`
	KMSKeyVersion string            `json:"kms_key_version"`
}

func needTool(t *testing.T, tool string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		if os.Getenv("SEALED_REQUIRE_KEY_BROKER") == "1" || (tool == "terraform" && os.Getenv("SEALED_REQUIRE_TERRAFORM") == "1") {
			t.Fatalf("%s is required", tool)
		}
		t.Skipf("%s not installed", tool)
	}
}

// renderBrokerEnv runs terraform plan (no providers, no credentials) on a root module that calls the embedded
// modules/key-broker-env, the copy the sealed binary ships.
func renderBrokerEnv(t *testing.T, inputs map[string]any) *renderedEnv {
	t.Helper()
	needTool(t, "terraform")
	src, err := fs.ReadFile(embedded.BootstrapModule(), "modules/key-broker-env/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "env"), 0o755)
	os.WriteFile(filepath.Join(dir, "env", "main.tf"), src, 0o644)
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("module \"env\" {\n  source = \"./env\"\n")
	for _, k := range keys {
		v, _ := json.Marshal(inputs[k])
		fmt.Fprintf(&b, "  %s = %s\n", k, v)
	}
	b.WriteString("}\n\noutput \"env\" {\n  value = module.env\n}\n")
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(b.String()), 0o644)
	tf := func(args ...string) []byte {
		c := exec.Command("terraform", append([]string{"-chdir=" + dir}, args...)...)
		c.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
		var stderr bytes.Buffer
		c.Stderr = &stderr
		out, err := c.Output()
		if err != nil {
			t.Fatalf("terraform %s: %v\n%s\n%s", args[0], err, out, stderr.String())
		}
		return out
	}
	tf("init", "-input=false", "-backend=false", "-no-color")
	tf("plan", "-input=false", "-no-color", "-out=env.tfplan")
	var plan struct {
		PlannedValues struct {
			Outputs map[string]struct {
				Value json.RawMessage `json:"value"`
			} `json:"outputs"`
		} `json:"planned_values"`
	}
	if err := json.Unmarshal(tf("show", "-json", "env.tfplan"), &plan); err != nil {
		t.Fatal(err)
	}
	r := &renderedEnv{}
	if err := json.Unmarshal(plan.PlannedValues.Outputs["env"].Value, r); err != nil {
		t.Fatal(err)
	}
	return r
}

// brokerTree returns a module root that holds key-broker/cmd/key-broker: this checkout, or the broker ref
// extracted with git archive.
func brokerTree(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "key-broker", "cmd", "key-broker", "main.go")); err == nil {
		return root
	}
	skip := func(format string, a ...any) {
		t.Helper()
		if os.Getenv("SEALED_REQUIRE_KEY_BROKER") == "1" {
			t.Fatalf(format, a...)
		}
		t.Skipf(format, a...)
	}
	needTool(t, "git")
	ref := os.Getenv("SEALED_KEY_BROKER_REF")
	if ref == "" {
		ref = "ws/key-broker"
	}
	if out, err := exec.Command("git", "-C", root, "rev-parse", "--verify", "--quiet", ref+"^{commit}").Output(); err != nil || len(out) == 0 {
		skip("no key-broker/ in this checkout and git ref %s not found (set SEALED_KEY_BROKER_REF)", ref)
	}
	archive, err := exec.Command("git", "-C", root, "archive", "--format=tar", ref).Output()
	if err != nil {
		t.Fatalf("git archive %s: %v", ref, err)
	}
	dst := t.TempDir()
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.FromSlash(h.Name)
		if !filepath.IsLocal(name) {
			t.Fatalf("archive entry %q", h.Name)
		}
		p := filepath.Join(dst, name)
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o755)
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(p, b, 0o644)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "key-broker", "cmd", "key-broker", "main.go")); err != nil {
		skip("git ref %s has no key-broker/cmd/key-broker", ref)
	}
	return dst
}

// probeTest runs in package main of key-broker/cmd/key-broker (added with go test -overlay, never written into
// the tree). It calls the broker's own loadConfig with exactly the given environment and records which variables
// the parser asked for.
const probeTest = `package main

import (
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestZZSealedBootstrapEnvContract(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("SEALED_CONTRACT_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	asked := map[string]bool{}
	c, err := loadConfig(nil, func(k string) string { asked[k] = true; return env[k] }, io.Discard)
	res := map[string]any{"asked": asked}
	if err != nil {
		res["error"] = err.Error()
	} else {
		res["config"] = c
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("SEALED_CONTRACT_OUT"), out, 0o600); err != nil {
		t.Fatal(err)
	}
}
`

type brokerView struct {
	Error  string          `json:"error"`
	Asked  map[string]bool `json:"asked"`
	Config *struct {
		Listen   string
		Customer string
		ChainID  uint64
		RPCURL   string
		Addrs    struct {
			PlatformRegistry, AppRegistry, DeploymentRegistry string
		}
		ReleaseBase string
		Project     string
		Region      string
		KMSKey      string
	} `json:"config"`
}

// runBrokerParser hands env to the broker's loadConfig.
func runBrokerParser(t *testing.T, tree string, env map[string]string) *brokerView {
	t.Helper()
	needTool(t, "go")
	// The go command matches overlay paths against the resolved package directory (macOS temp dirs sit
	// behind the /var symlink).
	tree, err := filepath.EvalSymlinks(tree)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	in, out := filepath.Join(work, "env.json"), filepath.Join(work, "config.json")
	raw, _ := json.Marshal(env)
	os.WriteFile(in, raw, 0o600)
	probe := filepath.Join(work, "probe_test.go")
	os.WriteFile(probe, []byte(probeTest), 0o644)
	pkg := filepath.Join(tree, "key-broker", "cmd", "key-broker")
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(pkg, "zz_sealed_bootstrap_env_contract_test.go"): probe}})
	ov := filepath.Join(work, "overlay.json")
	os.WriteFile(ov, overlay, 0o600)
	c := exec.Command("go", "test", "-v", "-count=1", "-vet=off", "-overlay", ov, "-run", "^TestZZSealedBootstrapEnvContract$", "./key-broker/cmd/key-broker")
	c.Dir = tree
	c.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "SEALED_CONTRACT_IN="+in, "SEALED_CONTRACT_OUT="+out)
	logs, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("running the broker's config parser: %v\n%s", err, logs)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, logs)
	}
	v := &brokerView{}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return v
}

func TestKeyBrokerEnvContract(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	r := renderBrokerEnv(t, contractInputs)
	tree := brokerTree(t)

	env := map[string]string{"PORT": fmt.Sprint(r.ContainerPort)} // set by Cloud Run from container_port
	for k, v := range r.Env {
		env[k] = v
	}
	v := runBrokerParser(t, tree, env)
	if v.Error != "" {
		t.Fatalf("the broker refuses the bootstrap's environment: %s\nenv: %v", v.Error, r.Env)
	}

	// Every variable the bootstrap sets is one the broker reads: none is silently ignored.
	for k := range r.Env {
		if !v.Asked[k] {
			t.Errorf("the bootstrap sets %s, which the broker never reads (its default would be used instead)", k)
		}
	}
	// The Go runtime variables are not broker configuration and must not collide with it.
	for k := range r.RuntimeEnv {
		if v.Asked[k] || strings.HasPrefix(k, "SEALED_") || strings.HasPrefix(k, "TEMPO_") {
			t.Errorf("runtime variable %s is broker configuration", k)
		}
	}
	// The broker's required settings are all set by the bootstrap.
	for _, k := range []string{"SEALED_CUSTOMER", "SEALED_TEMPO_RPC", "SEALED_CHAIN_ID", "SEALED_GCP_PROJECT", "SEALED_KMS_KEY"} {
		if _, ok := r.Env[k]; !ok {
			t.Errorf("the bootstrap does not set %s", k)
		}
	}

	// Each customer choice arrives in the effective config.
	c := v.Config
	eq := func(what, got, want string) {
		t.Helper()
		if !strings.EqualFold(got, want) {
			t.Errorf("%s: broker uses %q, the bootstrap chose %q", what, got, want)
		}
	}
	eq("customer", c.Customer, contractInputs["customer_address"].(string))
	eq("tempo rpc", c.RPCURL, contractInputs["tempo_rpc_url"].(string))
	if c.ChainID != uint64(contractInputs["chain_id"].(int)) {
		t.Errorf("chain id: broker uses %d", c.ChainID)
	}
	eq("PlatformRegistry", c.Addrs.PlatformRegistry, contractInputs["platform_registry"].(string))
	eq("AppRegistry", c.Addrs.AppRegistry, contractInputs["app_registry"].(string))
	eq("DeploymentRegistry", c.Addrs.DeploymentRegistry, contractInputs["deployment_registry"].(string))
	eq("release asset base", c.ReleaseBase, contractInputs["release_asset_base"].(string))
	eq("project", c.Project, contractInputs["project_id"].(string))
	eq("region", c.Region, contractInputs["region"].(string))
	eq("KMS key version", c.KMSKey, r.KMSKeyVersion)
	eq("KMS key version", c.KMSKey, contractInputs["kms_crypto_key"].(string)+"/cryptoKeyVersions/1")
	eq("listen address", c.Listen, fmt.Sprintf(":%d", r.ContainerPort))
}

// TestKeyBrokerEnvContractCatchesOldNames proves the check above is not vacuous: the variable names the bootstrap
// used before review F5 are not read by the broker, and without SEALED_CUSTOMER it refuses to start.
func TestKeyBrokerEnvContractCatchesOldNames(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	tree := brokerTree(t)
	v := runBrokerParser(t, tree, map[string]string{
		"SEALED_CUSTOMER_ADDRESS": "0x00000000000000000000000000000000000000c1",
		"TEMPO_RPC_URL":           "https://tempo.customer-node.example/rpc",
		"TEMPO_CHAIN_ID":          "4217",
		"SEALED_GCP_PROJECT":      "acme-prod-4417",
		"SEALED_KMS_KEY_VERSION":  "projects/acme-prod-4417/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1",
	})
	for _, k := range []string{"SEALED_CUSTOMER_ADDRESS", "TEMPO_RPC_URL", "TEMPO_CHAIN_ID"} {
		if v.Asked[k] {
			t.Errorf("the broker reads %s; update the contract", k)
		}
	}
	if v.Error == "" || !strings.Contains(v.Error, "SEALED_CUSTOMER") {
		t.Fatalf("the broker started without SEALED_CUSTOMER: %+v", v)
	}
}
