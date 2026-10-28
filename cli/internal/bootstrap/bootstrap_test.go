package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/cli/internal/embedded"
	"github.com/sealed-dev/sealed/cli/internal/token"
	"github.com/sealed-dev/sealed/verifier/chain"
)

func params() *Params {
	return &Params{
		Project: "acme-prod-4417", Region: "us-central1", Customer: "0x00000000000000000000000000000000000000C1",
		PlatformSA:     "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com",
		KeyBrokerImage: "ghcr.io/sealedtempo/sealed-key-broker@sha256:" + strings.Repeat("ab", 32),
		TempoRPC:       "https://rpc.tempo.xyz", ChainID: 4217,
		Registries: chain.Addresses{
			PlatformRegistry:   common.HexToAddress("0x18AB956ea44757587896dfD25632FB3e89F7002d"),
			AppRegistry:        common.HexToAddress("0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43"),
			DeploymentRegistry: common.HexToAddress("0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E"),
		},
		ReleaseAssetBase: "https://github.com/sealedtempo/sealed/releases/download", EnableAPIs: true,
	}
}

func TestValidate(t *testing.T) {
	if err := params().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Params){
		"project":       func(p *Params) { p.Project = "A" },
		"region":        func(p *Params) { p.Region = "central" },
		"customer":      func(p *Params) { p.Customer = "0x12" },
		"platform sa":   func(p *Params) { p.PlatformSA = "someone@gmail.com" },
		"own sa":        func(p *Params) { p.PlatformSA = "sealed-platform@acme-prod-4417.iam.gserviceaccount.com" },
		"tag image":     func(p *Params) { p.KeyBrokerImage = "ghcr.io/sealedtempo/sealed-key-broker:latest" },
		"placeholder":   func(p *Params) { p.KeyBrokerImage = DefaultKeyBrokerImage },
		"http rpc":      func(p *Params) { p.TempoRPC = "http://rpc.tempo.xyz" },
		"no registries": func(p *Params) { p.Registries = chain.Addresses{} },
	} {
		p := params()
		mut(p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMaterializeAndVars(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "work")
	if err := Materialize(dir, embedded.BootstrapModule()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"main.tf", "deployer.tf", "modules/iam/main.tf", ".terraform.lock.hcl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s not written", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "tests")); err == nil {
		t.Fatal("tests copied into the customer's root module")
	}
	// State and stale files: state is kept, a file the module dropped is removed.
	os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "old.tf"), []byte(""), 0o644)
	list, _ := os.ReadFile(filepath.Join(dir, managedList))
	os.WriteFile(filepath.Join(dir, managedList), append(list, []byte("old.tf\n")...), 0o644)
	if err := Materialize(dir, embedded.BootstrapModule()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.tf")); err == nil {
		t.Fatal("stale module file kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "terraform.tfstate")); err != nil {
		t.Fatal("state removed")
	}
	if err := WriteVars(dir, params()); err != nil {
		t.Fatal(err)
	}
	var vars map[string]any
	b, _ := os.ReadFile(filepath.Join(dir, "terraform.tfvars.json"))
	json.Unmarshal(b, &vars)
	if vars["customer_address"] != "0x00000000000000000000000000000000000000c1" || vars["deployment_registry"] != "0x254efb9d1809a95ec6d233cc57b3a10849bd2c8e" || vars["chain_id"].(float64) != 4217 {
		t.Fatalf("vars %v", vars)
	}
	if err := WriteBackend(dir, "acme-tf-state"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sealed_backend.tf")); !strings.Contains(string(b), `bucket = "acme-tf-state"`) {
		t.Fatalf("backend %s", b)
	}
	if err := WriteBackend(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sealed_backend.tf")); err == nil {
		t.Fatal("backend not removed")
	}
	if err := WriteBackend(dir, "Bad Bucket"); err == nil {
		t.Fatal("bad bucket accepted")
	}
}

type fakeRunner struct {
	calls  [][]string
	envs   [][]string
	output string
}

func (f *fakeRunner) Stream(_ context.Context, dir string, env []string, args ...string) error {
	f.calls = append(f.calls, append([]string{dir}, args...))
	f.envs = append(f.envs, env)
	return nil
}

func (f *fakeRunner) Capture(_ context.Context, dir string, env []string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{dir}, args...))
	return []byte(f.output), nil
}

const outputsJSON = `{
 "project_id": {"sensitive": false, "type": "string", "value": "acme-prod-4417"},
 "project_number": {"sensitive": false, "type": "string", "value": "123456789012"},
 "region": {"sensitive": false, "type": "string", "value": "us-central1"},
 "customer_address": {"sensitive": false, "type": "string", "value": "0x00000000000000000000000000000000000000c1"},
 "deployer_service_account": {"sensitive": false, "type": "string", "value": "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com"},
 "key_broker_service_account": {"sensitive": false, "type": "string", "value": "sealed-key-broker@acme-prod-4417.iam.gserviceaccount.com"},
 "key_broker_url": {"sensitive": false, "type": "string", "value": "https://sealed-key-broker-xyz-uc.a.run.app"},
 "subnetwork": {"sensitive": false, "type": "string", "value": "sealed-subnet"},
 "kms_key_version": {"sensitive": false, "type": "string", "value": "projects/acme-prod-4417/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1"}
}`

func TestRunApplyThenToken(t *testing.T) {
	f := &fakeRunner{output: outputsJSON}
	out, err := Run(context.Background(), f, Options{Dir: "/w", AutoApprove: true, AccessToken: "ya29.secret"})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, c := range f.calls {
		got = append(got, strings.Join(c[1:], " "))
	}
	want := "init -input=false -upgrade=false|apply -input=false -auto-approve|output -json"
	if strings.Join(got, "|") != want {
		t.Fatalf("calls %q", got)
	}
	if !strings.Contains(strings.Join(f.envs[0], " "), "GOOGLE_OAUTH_ACCESS_TOKEN=ya29.secret") {
		t.Fatal("the customer's token is handed to the provider")
	}
	tok, err := out.Token(time.Unix(1761600000, 0))
	if err != nil {
		t.Fatal(err)
	}
	c, err := token.Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.DeployerAccount != "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com" || c.KeyBrokerURL != "https://sealed-key-broker-xyz-uc.a.run.app" || c.Customer != "0x00000000000000000000000000000000000000c1" || c.IssuedAt != 1761600000 {
		t.Fatalf("token %+v", c)
	}
	// Interactive apply lets Terraform ask for confirmation.
	f2 := &fakeRunner{output: outputsJSON}
	if _, err := Run(context.Background(), f2, Options{Dir: "/w"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f2.calls[1][1:], " ") != "apply -input=true" {
		t.Fatalf("interactive apply %q", f2.calls[1])
	}
	// A plan never applies and reads no outputs.
	f3 := &fakeRunner{}
	if out, err := Run(context.Background(), f3, Options{Dir: "/w", PlanOnly: true}); err != nil || out != nil || len(f3.calls) != 2 || f3.calls[1][1] != "plan" {
		t.Fatalf("plan: %v %v", f3.calls, err)
	}
}

func TestParseOutputsRejectsMissing(t *testing.T) {
	if _, err := ParseOutputs([]byte(`{"project_id":{"value":"x"}}`)); err == nil {
		t.Fatal("missing outputs accepted")
	}
	if _, err := ParseOutputs([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestEmbeddedModuleValidates runs terraform init (no backend) and validate on the module exactly as the binary
// writes it. It needs the terraform binary and the hashicorp/google provider (downloaded once into
// TF_PLUGIN_CACHE_DIR when set); SEALED_REQUIRE_TERRAFORM=1 turns the skip into a failure.
func TestEmbeddedModuleValidates(t *testing.T) {
	if _, err := exec.LookPath("terraform"); err != nil {
		if os.Getenv("SEALED_REQUIRE_TERRAFORM") == "1" {
			t.Fatal("SEALED_REQUIRE_TERRAFORM=1 but terraform is not installed")
		}
		t.Skip("terraform not installed")
	}
	if testing.Short() {
		t.Skip("-short")
	}
	dir := filepath.Join(t.TempDir(), "work")
	if err := Materialize(dir, embedded.BootstrapModule()); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-input=false", "-backend=false"}, {"validate", "-no-color"}, {"fmt", "-check", "-recursive"}} {
		c := exec.Command("terraform", append([]string{"-chdir=" + dir}, args...)...)
		c.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("terraform %s: %v\n%s", args[0], err, out)
		}
	}
}

// Release CI publishes the key broker as sealed-key-broker and pins its digest in extra-images.json; the CLI
// deploys exactly that image.
func TestDefaultKeyBrokerImagePin(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "catalog", "tools", "release", "extra-images.json"))
	if err != nil {
		t.Fatal(err)
	}
	var extra struct {
		Registry string `json:"registry"`
		Images   map[string]struct {
			Digest string `json:"digest"`
		} `json:"images"`
	}
	if err := json.Unmarshal(raw, &extra); err != nil {
		t.Fatal(err)
	}
	kb, ok := extra.Images["sealed-key-broker"]
	if !ok {
		t.Fatal("extra-images.json has no sealed-key-broker")
	}
	if want := extra.Registry + "/sealed-key-broker@" + kb.Digest; DefaultKeyBrokerImage != want {
		t.Fatalf("DefaultKeyBrokerImage = %s, want %s (the pin in extra-images.json)", DefaultKeyBrokerImage, want)
	}
}
