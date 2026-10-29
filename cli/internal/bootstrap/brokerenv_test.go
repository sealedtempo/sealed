package bootstrap

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
// broker's own config parser (loadConfig in key-broker/cmd/key-broker). It fails when the broker refuses the env,
// when it ignores a variable (dropping or garbling the variable changes nothing), or when a customer choice (RPC,
// chain, registries, asset base, project, key) does not reach its effective config.
//
// The broker source is this checkout's key-broker/ when present (after the integration merge), otherwise the git
// ref SEALED_KEY_BROKER_REF, otherwise ws/integration or ws/key-broker, the first that has the broker. It needs
// terraform, git and go; SEALED_REQUIRE_KEY_BROKER=1 turns a skip into a failure.

// contractInputs are deliberately not the broker's defaults, so a variable the broker ignored would show up as a
// default value in its config. requiredInputs are the module's required variables; the rest are the optional ones
// (SEALED_FEE_SPLITTER, SEALED_FEE_TOKEN, SEALED_ALLOWED_IMAGES), which the module renders only when set.
var contractInputs = mergeInputs(requiredInputs, map[string]any{
	"fee_splitter":   "0x00000000000000000000000000000000000000E5",
	"fee_token":      "0x20C0000000000000000000000000000000000001",
	"allowed_images": []string{"0xAB00000000000000000000000000000000000000000000000000000000000001", "0x00000000000000000000000000000000000000000000000000000000000000cd"},
})

// optionalEnvNames are the variables the bootstrap sets only when the customer chose a value.
var optionalEnvNames = []string{"SEALED_ALLOWED_IMAGES", "SEALED_FEE_SPLITTER", "SEALED_FEE_TOKEN"}

func mergeInputs(a, b map[string]any) map[string]any {
	m := map[string]any{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}

var requiredInputs = map[string]any{
	"customer_address":    "0x00000000000000000000000000000000000000C1",
	"tempo_rpc_url":       "https://tempo.customer-node.example/rpc",
	"chain_id":            4217,
	"platform_registry":   "0x00000000000000000000000000000000000000A1",
	"app_registry":        "0x00000000000000000000000000000000000000A2",
	"deployment_registry": "0x00000000000000000000000000000000000000A3",
	"release_asset_base":  "https://assets.customer.example/releases",
	"project_id":          "acme-prod-4417",
	"project_number":      "123456789012",
	"kms_crypto_key":      "projects/acme-prod-4417/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac",
}

// informational variables carry no customer choice (the project number follows from the project id), so a broker
// may only record them; every other variable must change the broker's outcome when it is dropped or garbled.
var informational = map[string]bool{"SEALED_GCP_PROJECT_NUMBER": true}

type renderedEnv struct {
	Env           map[string]string `json:"env"`
	OptionalEnv   map[string]string `json:"optional_env"`
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

func hasBroker(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "key-broker", "cmd", "key-broker", "main.go"))
	return err == nil
}

// brokerTree returns a module root that holds key-broker/cmd/key-broker: this checkout, or a broker ref extracted
// with git archive.
func brokerTree(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if hasBroker(root) {
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
	refs := []string{"ws/integration", "ws/key-broker"}
	if r := os.Getenv("SEALED_KEY_BROKER_REF"); r != "" {
		refs = []string{r}
	}
	ref := ""
	for _, r := range refs {
		out, err := exec.Command("git", "-C", root, "ls-tree", "--name-only", r, "key-broker/cmd/key-broker/main.go").Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			ref = r
			break
		}
	}
	if ref == "" {
		skip("no key-broker/ in this checkout, and none of the git refs %v has it (set SEALED_KEY_BROKER_REF)", refs)
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
	t.Logf("key broker from git ref %s", ref)
	return dst
}

// loadConfigTakesMap reports whether the broker's loadConfig takes the environment as a map (or as a getenv
// function), read from the package's source.
func loadConfigTakesMap(t *testing.T, pkg string) bool {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(pkg, "*.go"))
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != "loadConfig" {
				continue
			}
			var types []ast.Expr
			for _, p := range fd.Type.Params.List {
				for range max(1, len(p.Names)) {
					types = append(types, p.Type)
				}
			}
			if len(types) != 3 {
				t.Fatalf("loadConfig has %d parameters; update the contract probe", len(types))
			}
			switch types[1].(type) {
			case *ast.MapType:
				return true
			case *ast.FuncType:
				return false
			}
			t.Fatalf("loadConfig's environment parameter is neither a map nor a function; update the contract probe")
		}
	}
	t.Fatalf("no loadConfig in %s; update the contract probe", pkg)
	return false
}

// probeTest runs in package main of key-broker/cmd/key-broker (added with go test -overlay, never written into
// the tree). It calls the broker's own loadConfig once per environment and records the error or the effective
// config.
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
	var envs []map[string]string
	if err := json.Unmarshal(raw, &envs); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	for _, env := range envs {
		c, err := loadConfig(nil, ENVARG, io.Discard)
		if err != nil {
			res = append(res, map[string]any{"error": err.Error()})
		} else {
			res = append(res, map[string]any{"config": c})
		}
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

type outcome struct {
	Error  string          `json:"error"`
	Config json.RawMessage `json:"config"`
}

type brokerConfig struct {
	Listen   string
	Customer string
	ChainID  uint64
	RPCURL   string
	Addrs    struct {
		PlatformRegistry, AppRegistry, DeploymentRegistry string
	}
	ReleaseBase   string
	Project       string
	KMSKey        string
	FeeSplitter   string
	FeeToken      string
	AllowedImages [][32]byte
}

// runBrokerParser hands each env to the broker's loadConfig.
func runBrokerParser(t *testing.T, tree string, envs []map[string]string) []outcome {
	t.Helper()
	needTool(t, "go")
	// The go command matches overlay paths against the resolved package directory (macOS temp dirs sit
	// behind the /var symlink).
	tree, err := filepath.EvalSymlinks(tree)
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(tree, "key-broker", "cmd", "key-broker")
	arg := "func(k string) string { return env[k] }"
	if loadConfigTakesMap(t, pkg) {
		arg = "env"
	}
	work := t.TempDir()
	in, out := filepath.Join(work, "env.json"), filepath.Join(work, "config.json")
	raw, _ := json.Marshal(envs)
	os.WriteFile(in, raw, 0o600)
	probe := filepath.Join(work, "probe_test.go")
	os.WriteFile(probe, []byte(strings.Replace(probeTest, "ENVARG", arg, 1)), 0o644)
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(pkg, "zz_sealed_bootstrap_env_contract_test.go"): probe}})
	ov := filepath.Join(work, "overlay.json")
	os.WriteFile(ov, overlay, 0o600)
	c := exec.Command("go", "test", "-count=1", "-vet=off", "-overlay", ov, "-run", "^TestZZSealedBootstrapEnvContract$", "./key-broker/cmd/key-broker")
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
	var res []outcome
	if err := json.Unmarshal(b, &res); err != nil || len(res) != len(envs) {
		t.Fatalf("%v: %s", err, b)
	}
	return res
}

func cloneEnv(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// contractProblems runs the broker's parser on env (as Cloud Run passes it: the rendered variables, the runtime
// variables and PORT) and on each variable dropped and garbled, and lists every way the contract is broken. inputs
// are the module inputs env was rendered from.
func contractProblems(t *testing.T, tree string, r *renderedEnv, env map[string]string, inputs map[string]any) []string {
	t.Helper()
	full := cloneEnv(env)
	for k, v := range r.RuntimeEnv {
		full[k] = v
	}
	full["PORT"] = fmt.Sprint(r.ContainerPort) // set by Cloud Run from container_port
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)
	envs := []map[string]string{full}
	for _, k := range names {
		dropped, garbled := cloneEnv(full), cloneEnv(full)
		delete(dropped, k)
		garbled[k] = "sealed-contract-garbled"
		envs = append(envs, dropped, garbled)
	}
	res := runBrokerParser(t, tree, envs)
	if res[0].Error != "" {
		return []string{"the broker refuses the bootstrap's environment: " + res[0].Error}
	}
	var problems []string
	for i, k := range names {
		same := func(o outcome) bool { return o.Error == "" && bytes.Equal(o.Config, res[0].Config) }
		if same(res[1+2*i]) && same(res[2+2*i]) && !informational[k] {
			problems = append(problems, fmt.Sprintf("the bootstrap sets %s, which the broker never reads (dropping or garbling it changes nothing)", k))
		}
	}
	var c brokerConfig
	if err := json.Unmarshal(res[0].Config, &c); err != nil {
		t.Fatal(err)
	}
	eq := func(what, got, want string) {
		if !strings.EqualFold(got, want) {
			problems = append(problems, fmt.Sprintf("%s: the broker uses %q, the bootstrap chose %q", what, got, want))
		}
	}
	eq("customer", c.Customer, inputs["customer_address"].(string))
	eq("tempo rpc", c.RPCURL, inputs["tempo_rpc_url"].(string))
	eq("chain id", fmt.Sprint(c.ChainID), fmt.Sprint(inputs["chain_id"]))
	eq("PlatformRegistry", c.Addrs.PlatformRegistry, inputs["platform_registry"].(string))
	eq("AppRegistry", c.Addrs.AppRegistry, inputs["app_registry"].(string))
	eq("DeploymentRegistry", c.Addrs.DeploymentRegistry, inputs["deployment_registry"].(string))
	eq("release asset base", c.ReleaseBase, inputs["release_asset_base"].(string))
	eq("project", c.Project, inputs["project_id"].(string))
	eq("KMS key version", c.KMSKey, inputs["kms_crypto_key"].(string)+"/cryptoKeyVersions/1")
	eq("KMS key version output", c.KMSKey, r.KMSKeyVersion)
	eq("listen address", c.Listen, fmt.Sprintf(":%d", r.ContainerPort))
	if v, ok := inputs["fee_splitter"].(string); ok && v != "" {
		eq("FeeSplitter", c.FeeSplitter, v)
	}
	if v, ok := inputs["fee_token"].(string); ok && v != "" {
		eq("fee token", c.FeeToken, v)
	}
	if ids, ok := inputs["allowed_images"].([]string); ok && len(ids) > 0 {
		var got []string
		for _, id := range c.AllowedImages {
			got = append(got, "0x"+hex.EncodeToString(id[:]))
		}
		eq("allowed images", strings.Join(got, ","), strings.Join(ids, ","))
	}
	return problems
}

func TestKeyBrokerEnvContract(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	r := renderBrokerEnv(t, contractInputs)
	tree := brokerTree(t)
	if p := contractProblems(t, tree, r, r.Env, contractInputs); len(p) > 0 {
		t.Fatalf("the bootstrap's key broker environment breaks the contract:\n  %s\nenv: %v", strings.Join(p, "\n  "), r.Env)
	}
	// Every optional variable is rendered when chosen, and only in optional_env besides env.
	var optional []string
	for k := range r.OptionalEnv {
		optional = append(optional, k)
		if r.Env[k] != r.OptionalEnv[k] {
			t.Errorf("%s: env %q, optional_env %q", k, r.Env[k], r.OptionalEnv[k])
		}
	}
	sort.Strings(optional)
	if strings.Join(optional, ",") != strings.Join(optionalEnvNames, ",") {
		t.Errorf("optional variables %v, want %v", optional, optionalEnvNames)
	}
	// Without the optional inputs none of them is set, and the broker still accepts the environment (its defaults are
	// mainnet's FeeSplitter and fee token and no allowlist of its own).
	plain := renderBrokerEnv(t, requiredInputs)
	for _, k := range optionalEnvNames {
		if _, ok := plain.Env[k]; ok {
			t.Errorf("%s is set although the customer chose no value", k)
		}
	}
	if len(plain.OptionalEnv) != 0 {
		t.Errorf("optional_env %v without optional inputs", plain.OptionalEnv)
	}
	if p := contractProblems(t, tree, plain, plain.Env, requiredInputs); len(p) > 0 {
		t.Fatalf("the bootstrap's key broker environment without optional inputs breaks the contract:\n  %s\nenv: %v", strings.Join(p, "\n  "), plain.Env)
	}
	// The Go runtime variables are not broker configuration.
	for k := range r.RuntimeEnv {
		if strings.HasPrefix(k, "SEALED_") || strings.HasPrefix(k, "TEMPO_") {
			t.Errorf("runtime variable %s looks like broker configuration", k)
		}
	}
}

// TestKeyBrokerEnvContractCatchesMistakes proves the check is not vacuous: a variable the broker does not know, an
// RPC under a name the broker does not read, and a missing customer each break the contract.
func TestKeyBrokerEnvContractCatchesMistakes(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	r := renderBrokerEnv(t, contractInputs)
	tree := brokerTree(t)
	for name, mutate := range map[string]func(map[string]string){
		"unknown variable": func(e map[string]string) { e["SEALED_UNUSED_SETTING"] = "1" },
		"renamed rpc": func(e map[string]string) {
			for k, v := range e {
				if v == contractInputs["tempo_rpc_url"] {
					delete(e, k)
				}
			}
			e["SEALED_CUSTOMER_RPC"] = contractInputs["tempo_rpc_url"].(string)
		},
		"fee splitter under another name": func(e map[string]string) {
			e["SEALED_FEESPLITTER"] = e["SEALED_FEE_SPLITTER"]
			delete(e, "SEALED_FEE_SPLITTER")
		},
		"allowlist dropped": func(e map[string]string) { delete(e, "SEALED_ALLOWED_IMAGES") },
		"no customer": func(e map[string]string) {
			for k, v := range e {
				if strings.EqualFold(v, contractInputs["customer_address"].(string)) {
					delete(e, k)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := cloneEnv(r.Env)
			mutate(env)
			if p := contractProblems(t, tree, r, env, contractInputs); len(p) == 0 {
				t.Fatal("the mistake was not detected")
			} else {
				t.Logf("detected: %s", strings.Join(p, "; "))
			}
		})
	}
}
