package iamchecks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// rendered is the output of infra/terraform/customer-bootstrap/modules/iam.
type rendered struct {
	DeployerNamedPermissions   []string `json:"deployer_named_permissions"`
	DeployerNamedCondition     string   `json:"deployer_named_condition"`
	DeployerProjectPermissions []string `json:"deployer_project_permissions"`
	DeployerSubnetPermissions  []string `json:"deployer_subnet_permissions"`
	DeployerSAPolicyJSON       string   `json:"deployer_sa_policy_json"`
	KeyBrokerSAPolicyJSON      string   `json:"key_broker_sa_policy_json"`
	KeyBrokerSecretRole        string   `json:"key_broker_secret_role"`
	KeyBrokerSecretCondition   string   `json:"key_broker_secret_condition"`
	KeyBrokerKMSPolicyJSON     string   `json:"key_broker_kms_policy_json"`
	DeployerMember             string   `json:"deployer_member"`
	KeyBrokerMember            string   `json:"key_broker_member"`
	KeyBrokerLoggingRole       string   `json:"key_broker_logging_role"`
	DebugLogsRole              string   `json:"debug_logs_role"`
	DebugLogsSAPolicyJSON      string   `json:"debug_logs_sa_policy_json"`
	DebugLogsMember            string   `json:"debug_logs_member"`
	DebugVMScopes              []string `json:"debug_vm_scopes"`
}

const (
	tProject  = "acme-prod-4417"
	tNumber   = "123456789012"
	tPlatform = "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com"
)

// render runs terraform plan on a root module that only calls modules/iam (no providers, no credentials, nothing
// applied) and returns the module's outputs from the plan JSON.
func render(t *testing.T) *rendered {
	t.Helper()
	if _, err := exec.LookPath("terraform"); err != nil {
		if os.Getenv("SEALED_REQUIRE_TERRAFORM") == "1" {
			t.Fatal("SEALED_REQUIRE_TERRAFORM=1 but terraform is not installed")
		}
		t.Skip("terraform not installed")
	}
	src := filepath.Join("..", "..", "infra", "terraform", "customer-bootstrap", "modules", "iam", "main.tf")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "iam"), 0o755)
	os.WriteFile(filepath.Join(dir, "iam", "main.tf"), b, 0o644)
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(fmt.Sprintf(`module "iam" {
  source                     = "./iam"
  project_id                 = %q
  project_number             = %q
  region                     = "us-central1"
  subnetwork_name            = "sealed-subnet"
  platform_service_account   = %q
  deployer_service_account   = "sealed-deployer@%s.iam.gserviceaccount.com"
  key_broker_service_account = "sealed-key-broker@%s.iam.gserviceaccount.com"
  debug_logs_service_account = "sealed-debug-logs@%s.iam.gserviceaccount.com"
}

output "iam" {
  value = module.iam
}
`, tProject, tNumber, tPlatform, tProject, tProject, tProject)), 0o644)
	tf := func(args ...string) []byte {
		c := exec.Command("terraform", append([]string{"-chdir=" + dir}, args...)...)
		c.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
		out, err := c.Output()
		if err != nil {
			var stderr string
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = string(ee.Stderr)
			}
			t.Fatalf("terraform %s: %v\n%s\n%s", args[0], err, out, stderr)
		}
		return out
	}
	tf("init", "-input=false", "-backend=false", "-no-color")
	tf("plan", "-input=false", "-no-color", "-out=render.tfplan")
	var plan struct {
		PlannedValues struct {
			Outputs map[string]struct {
				Value json.RawMessage `json:"value"`
			} `json:"outputs"`
		} `json:"planned_values"`
	}
	if err := json.Unmarshal(tf("show", "-json", "render.tfplan"), &plan); err != nil {
		t.Fatal(err)
	}
	var r rendered
	if err := json.Unmarshal(plan.PlannedValues.Outputs["iam"].Value, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// --- a tiny evaluator for the condition subset the module uses ---

var (
	atomType    = regexp.MustCompile(`^resource\.type == "([^"]+)"$`)
	atomPrefix  = regexp.MustCompile(`^resource\.name\.startsWith\("([^"]+)"\)$`)
	atomExtract = regexp.MustCompile(`^resource\.name\.extract\("([^"{]*)\{name\}"\)\.startsWith\("([^"]+)"\)$`)
)

// extract mimics CEL's extract("/x/{name}"): the segment after the first "/x/", up to the next "/".
func extract(name, prefix string) string {
	i := strings.Index(name, prefix)
	if i < 0 {
		return ""
	}
	rest := name[i+len(prefix):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// evalAtom evaluates one atom. An atom it does not understand is an error, so every new kind of clause needs a
// semantic test here.
func evalAtom(atom, typ, name string) (bool, error) {
	atom = strings.TrimSpace(atom)
	if m := atomType.FindStringSubmatch(atom); m != nil {
		return typ == m[1], nil
	}
	if m := atomPrefix.FindStringSubmatch(atom); m != nil {
		return strings.HasPrefix(name, m[1]), nil
	}
	if m := atomExtract.FindStringSubmatch(atom); m != nil {
		return strings.HasPrefix(extract(name, m[1]), m[2]), nil
	}
	if strings.HasPrefix(atom, "(") && strings.HasSuffix(atom, ")") {
		// A parenthesized disjunction of atoms.
		for _, alt := range strings.Split(atom[1:len(atom)-1], " || ") {
			ok, err := evalAtom(alt, typ, name)
			if err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("condition atom the test does not understand: %q", atom)
}

func evalAll(atoms []string, typ, name string) (bool, error) {
	for _, atom := range atoms {
		ok, err := evalAtom(atom, typ, name)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// evalDeployer evaluates "(a && b && c) || (d && e) || ...".
func evalDeployer(cond, typ, name string) (bool, error) {
	for _, clause := range strings.Split(cond, " || (") {
		clause = strings.TrimSuffix(strings.TrimPrefix(clause, "("), ")")
		ok, err := evalAll(strings.Split(clause, " && "), typ, name)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// evalConj evaluates "x && y".
func evalConj(cond, typ, name string) (bool, error) {
	return evalAll(strings.Split(cond, " && "), typ, name)
}

func TestRenderedDeployerPolicy(t *testing.T) {
	r := render(t)
	sorted := func(s []string) []string { c := append([]string(nil), s...); sort.Strings(c); return c }
	if strings.Join(sorted(r.DeployerSubnetPermissions), " ") != "compute.subnetworks.use compute.subnetworks.useExternalIp" {
		t.Fatalf("subnet permissions %v", r.DeployerSubnetPermissions)
	}
	all := append(append(append([]string{}, r.DeployerNamedPermissions...), r.DeployerProjectPermissions...), r.DeployerSubnetPermissions...)
	for _, p := range all {
		for _, banned := range []string{"iam.", "secretmanager.", "run.", "cloudkms.", "resourcemanager.", "iap.", "storage.", "compute.firewalls.", "compute.networks.", "compute.projects."} {
			if strings.HasPrefix(p, banned) {
				t.Errorf("deployer permission %s (%s* is never allowed)", p, banned)
			}
		}
		switch p {
		case "compute.instances.setServiceAccount", "compute.instances.osLogin", "compute.instances.osAdminLogin",
			"compute.instances.getSerialPortOutput", "compute.instances.setIamPolicy", "compute.disks.setIamPolicy",
			"compute.instances.list", "compute.disks.list", "compute.subnetworks.setIamPolicy":
			t.Errorf("deployer permission %s is forbidden", p)
		}
	}
	// Only instance, disk and image permissions go behind the name condition (others would never be granted).
	for _, p := range r.DeployerNamedPermissions {
		if !strings.HasPrefix(p, "compute.instances.") && !strings.HasPrefix(p, "compute.disks.") && !strings.HasPrefix(p, "compute.images.") {
			t.Errorf("named role permission %s is on a type the condition cannot match", p)
		}
	}
	for _, p := range r.DeployerProjectPermissions {
		if !strings.HasPrefix(p, "compute.addresses.") && !strings.HasSuffix(p, "Operations.get") {
			t.Errorf("unconditioned permission %s must be an address or operation permission", p)
		}
	}
	for _, want := range []string{"compute.instances.create", "compute.instances.start", "compute.instances.stop", "compute.instances.delete", "compute.disks.create", "compute.disks.delete"} {
		if !contains(r.DeployerNamedPermissions, want) {
			t.Errorf("deployer lacks %s", want)
		}
	}
	if strings.Contains(r.DeployerNamedCondition, "!=") || strings.Contains(r.DeployerNamedCondition, "!") {
		t.Fatalf("negations widen the grant: %s", r.DeployerNamedCondition)
	}

	type probe struct {
		typ, name string
		want      bool
	}
	for _, p := range []probe{
		{"compute.googleapis.com/Instance", "projects/acme-prod-4417/zones/us-central1-a/instances/sealed-demo", true},
		{"compute.googleapis.com/Instance", "projects/acme-prod-4417/zones/us-central1-c/instances/sealed-x", true},
		{"compute.googleapis.com/Disk", "projects/acme-prod-4417/zones/us-central1-a/disks/sealed-demo-data", true},
		{"compute.googleapis.com/Image", "projects/acme-prod-4417/global/images/sealed-demo-shared-abc", true},
		{"compute.googleapis.com/Instance", "projects/acme-prod-4417/zones/us-central1-a/instances/prod-db", false},
		{"compute.googleapis.com/Instance", "projects/acme-prod-4417/zones/us-central1-a/instances/notsealed-x", false},
		{"compute.googleapis.com/Instance", "projects/acme-prod-4417/zones/europe-west4-a/instances/sealed-x", false},
		{"compute.googleapis.com/Instance", "projects/other-proj-1/zones/us-central1-a/instances/sealed-x", false},
		{"compute.googleapis.com/Disk", "projects/acme-prod-4417/zones/us-central1-a/disks/prod-db-data", false},
		{"compute.googleapis.com/Disk", "projects/acme-prod-4417/regions/us-central1/disks/sealed-regional", false},
		{"compute.googleapis.com/Image", "projects/acme-prod-4417/global/images/ubuntu", false},
		{"compute.googleapis.com/Image", "projects/other-proj-1/global/images/sealed-os", false},
		{"compute.googleapis.com/Snapshot", "projects/acme-prod-4417/global/snapshots/sealed-x", false},
		{"compute.googleapis.com/InstanceTemplate", "projects/acme-prod-4417/global/instanceTemplates/sealed-x", false},
		{"", "", false}, // types without resource attributes (IAM, Secret Manager, ...) get nothing
		{"secretmanager.googleapis.com/Secret", "projects/123456789012/secrets/sealed-crm-APP_SECRET", false},
		{"iam.googleapis.com/ServiceAccount", "projects/acme-prod-4417/serviceAccounts/sealed-key-broker@acme-prod-4417.iam.gserviceaccount.com", false},
	} {
		got, err := evalDeployer(r.DeployerNamedCondition, p.typ, p.name)
		if err != nil {
			t.Fatal(err)
		}
		if got != p.want {
			t.Errorf("deployer condition on %s %s = %v, want %v", p.typ, p.name, got, p.want)
		}
	}

	var sa struct {
		Bindings []struct {
			Role      string   `json:"role"`
			Members   []string `json:"members"`
			Condition any      `json:"condition"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(r.DeployerSAPolicyJSON), &sa); err != nil {
		t.Fatal(err)
	}
	if len(sa.Bindings) != 1 || sa.Bindings[0].Role != "roles/iam.serviceAccountTokenCreator" || len(sa.Bindings[0].Members) != 1 || sa.Bindings[0].Members[0] != "serviceAccount:"+tPlatform {
		t.Fatalf("deployer service account policy %s", r.DeployerSAPolicyJSON)
	}
	if r.DeployerMember != "serviceAccount:sealed-deployer@acme-prod-4417.iam.gserviceaccount.com" {
		t.Fatalf("member %s", r.DeployerMember)
	}
}

func TestRenderedKeyBrokerPolicy(t *testing.T) {
	r := render(t)
	if r.KeyBrokerSecretRole != "roles/secretmanager.secretAccessor" {
		t.Fatalf("secret role %s", r.KeyBrokerSecretRole)
	}
	for _, p := range []struct {
		typ, name string
		want      bool
	}{
		{"secretmanager.googleapis.com/SecretVersion", "projects/123456789012/secrets/sealed-crm-APP_SECRET/versions/latest", true},
		{"secretmanager.googleapis.com/Secret", "projects/123456789012/secrets/sealed-gate-password", true},
		{"secretmanager.googleapis.com/SecretVersion", "projects/123456789012/secrets/prod-db-password/versions/1", false},
		{"secretmanager.googleapis.com/SecretVersion", "projects/acme-prod-4417/secrets/sealed-crm-APP_SECRET/versions/1", false}, // ids never match
		{"secretmanager.googleapis.com/SecretVersion", "projects/999999999999/secrets/sealed-x/versions/1", false},
		{"storage.googleapis.com/Object", "projects/123456789012/secrets/sealed-x", false},
	} {
		got, err := evalConj(r.KeyBrokerSecretCondition, p.typ, p.name)
		if err != nil {
			t.Fatal(err)
		}
		if got != p.want {
			t.Errorf("key broker condition on %s %s = %v, want %v", p.typ, p.name, got, p.want)
		}
	}
	var kms struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	json.Unmarshal([]byte(r.KeyBrokerKMSPolicyJSON), &kms)
	if len(kms.Bindings) != 1 || kms.Bindings[0].Role != "roles/cloudkms.signer" || strings.Join(kms.Bindings[0].Members, ",") != "serviceAccount:sealed-key-broker@acme-prod-4417.iam.gserviceaccount.com" {
		t.Fatalf("kms policy %s", r.KeyBrokerKMSPolicyJSON)
	}
	if r.KeyBrokerSAPolicyJSON != `{"bindings":[]}` {
		t.Fatalf("key broker service account policy %s", r.KeyBrokerSAPolicyJSON)
	}
	if r.KeyBrokerLoggingRole != "roles/logging.logWriter" {
		t.Fatalf("key broker logging role %s", r.KeyBrokerLoggingRole)
	}
}

// TestRenderedDebugLogWriter: the debug VM identity (spec 5.8) may only write logs, nobody holds a role on it, and
// a debug VM gets only the logging.write scope.
func TestRenderedDebugLogWriter(t *testing.T) {
	r := render(t)
	if r.DebugLogsRole != "roles/logging.logWriter" || r.DebugLogsSAPolicyJSON != `{"bindings":[]}` ||
		r.DebugLogsMember != "serviceAccount:sealed-debug-logs@acme-prod-4417.iam.gserviceaccount.com" {
		t.Fatalf("debug log writer %s %s %s", r.DebugLogsRole, r.DebugLogsSAPolicyJSON, r.DebugLogsMember)
	}
	if strings.Join(r.DebugVMScopes, " ") != "https://www.googleapis.com/auth/logging.write" {
		t.Fatalf("debug VM scopes %v", r.DebugVMScopes)
	}
}

// TestScriptListsMatchModule keeps check.sh's expected permission lists equal to the module's.
func TestScriptListsMatchModule(t *testing.T) {
	r := render(t)
	script, err := os.ReadFile("check.sh")
	if err != nil {
		t.Fatal(err)
	}
	list := func(name string) []string {
		m := regexp.MustCompile(`(?m)^` + name + `="([^"]*)"`).FindSubmatch(script)
		if m == nil {
			t.Fatalf("check.sh has no %s", name)
		}
		f := strings.Fields(string(m[1]))
		sort.Strings(f)
		return f
	}
	for name, want := range map[string][]string{
		"NAMED_ALLOWED":   r.DeployerNamedPermissions,
		"PROJECT_ALLOWED": r.DeployerProjectPermissions,
		"SUBNET_ALLOWED":  r.DeployerSubnetPermissions,
		"KB_ROLES":        {r.KeyBrokerSecretRole, r.KeyBrokerLoggingRole},
		"DEBUG_ROLES":     {r.DebugLogsRole},
		"DEBUG_SCOPES":    r.DebugVMScopes,
	} {
		w := append([]string(nil), want...)
		sort.Strings(w)
		if strings.Join(list(name), " ") != strings.Join(w, " ") {
			t.Errorf("check.sh %s = %v, module = %v", name, list(name), w)
		}
	}
	// Nothing the deployer holds may appear in the forbidden probes (the probes would then always fail).
	for _, p := range list("FORBIDDEN_PROJECT") {
		if contains(r.DeployerProjectPermissions, p) || contains(r.DeployerNamedPermissions, p) {
			t.Errorf("forbidden probe %s is a granted permission", p)
		}
	}
}

func TestEvaluatorRejectsUnknownAtoms(t *testing.T) {
	if _, err := evalDeployer(`(resource.service == "compute.googleapis.com")`, "x", "y"); err == nil {
		t.Fatal("an unknown condition atom must fail the policy test")
	}
	if ok, err := evalDeployer(`(resource.type == "a" && resource.name.extract("/instances/{name}").startsWith("sealed-"))`, "a", "projects/p/zones/z/instances/sealed-1/x"); err != nil || !ok {
		t.Fatal("extract stops at the next slash")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
