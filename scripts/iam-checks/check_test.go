package iamchecks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The stubs replace gcloud and curl on PATH; jq and bash are real. curl answers from a response table:
// METHOD \t URL \t TOKEN \t BODY-SUBSTRING \t STATUS \t BODY-FILE, first match wins (TOKEN and BODY-SUBSTRING may
// be "*"). Every request is logged.
const curlStub = `#!/usr/bin/env bash
method=GET out="" tok=none data="" url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    -H) case "$2" in "Authorization: Bearer "*) tok="${2#Authorization: Bearer }" ;; esac; shift 2 ;;
    --data) data="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\t%s\t%s\t%s\n' "$method" "$url" "$tok" "$data" >> "$FAKE_LOG"
while IFS=$'\t' read -r m u t b status file; do
  [ "$m" = "$method" ] || continue
  [ "$u" = "$url" ] || continue
  [ "$t" = "*" ] || [ "$t" = "$tok" ] || continue
  [ "$b" = "*" ] || case "$data" in *"$b"*) ;; *) continue ;; esac
  cat "$FAKE_DIR/$file" > "$out"
  printf '%s' "$status"
  exit 0
done < "$FAKE_DIR/responses.tsv"
printf '{"error":{"code":404,"message":"not in the fake"}}' > "$out"
printf 404
`

const gcloudStub = `#!/usr/bin/env bash
case "$*" in
  "auth print-access-token") echo operator-token ;;
  "auth print-access-token --impersonate-service-account="*)
    [ "${FAKE_IMPERSONATE:-ok}" = ok ] || { echo "PERMISSION_DENIED" >&2; exit 1; }
    echo deployer-token ;;
  "projects describe "*) echo 123456789012 ;;
  "config get-value account") echo operator@example.com ;;
  *) echo "unexpected gcloud $*" >&2; exit 1 ;;
esac
`

type world struct {
	dir   string
	rows  []string
	files int
}

func (w *world) add(method, url, token, bodyHas string, status int, body any) {
	w.files++
	name := fmt.Sprintf("r%03d.json", w.files)
	var raw []byte
	switch b := body.(type) {
	case string:
		raw = []byte(b)
	default:
		raw, _ = json.Marshal(b)
	}
	os.WriteFile(filepath.Join(w.dir, name), raw, 0o600)
	w.rows = append(w.rows, strings.Join([]string{method, url, token, bodyHas, fmt.Sprint(status), name}, "\t"))
}

const (
	project  = "acme-prod-4417"
	deployer = "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com"
	kbSA     = "sealed-key-broker@acme-prod-4417.iam.gserviceaccount.com"
	debugSA  = "sealed-debug-logs@acme-prod-4417.iam.gserviceaccount.com"
	platform = "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com"
	crm      = "https://cloudresourcemanager.googleapis.com/v1/projects/" + project
	iamv1    = "https://iam.googleapis.com/v1/projects/" + project
	compute  = "https://compute.googleapis.com/compute/v1/projects/" + project
	sm       = "https://secretmanager.googleapis.com/v1/projects/" + project
	run      = "https://run.googleapis.com/v2/projects/" + project + "/locations/us-central1/services/sealed-key-broker"
	kmsKey   = "https://cloudkms.googleapis.com/v1/projects/" + project + "/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac"
	kbURL    = "https://sealed-key-broker-xyz-uc.a.run.app"
	gcs      = "https://storage.googleapis.com/storage/v1/b"
	customer = "0x00000000000000000000000000000000000000c1"
	binding  = "sealed-binding/v1 customer=" + customer + " key_broker=" + kbURL
)

func perms(p ...string) map[string]any { return map[string]any{"permissions": p} }

// compliant is a correctly bootstrapped project with one sealed VM and one secret. mutate edits it.
func compliant(w *world, mutate map[string]bool) {
	tokenCreator := []any{map[string]any{"role": "roles/iam.serviceAccountTokenCreator", "members": []string{"serviceAccount:" + platform}}}
	if mutate["extra-token-creator"] {
		tokenCreator = []any{map[string]any{"role": "roles/iam.serviceAccountTokenCreator", "members": []string{"serviceAccount:" + platform, "user:mallory@example.com"}}}
	}
	w.add("POST", iamv1+"/serviceAccounts/"+deployer+":getIamPolicy", "operator-token", "*", 200, map[string]any{"bindings": tokenCreator})
	cond := `(resource.type == "compute.googleapis.com/Instance" && resource.name.startsWith("projects/acme-prod-4417/zones/us-central1-") && resource.name.extract("/instances/{name}").startsWith("sealed-")) || (resource.type == "compute.googleapis.com/Disk" && resource.name.startsWith("projects/acme-prod-4417/zones/us-central1-") && resource.name.extract("/disks/{name}").startsWith("sealed-")) || (resource.type == "compute.googleapis.com/Image" && resource.name.startsWith("projects/acme-prod-4417/global/images/sealed-"))`
	bindings := []any{
		map[string]any{"role": "projects/" + project + "/roles/sealedDeployer", "members": []string{"serviceAccount:" + deployer}, "condition": map[string]string{"title": "sealed-named-resources", "expression": cond}},
		map[string]any{"role": "projects/" + project + "/roles/sealedDeployerAddresses", "members": []string{"serviceAccount:" + deployer}},
		map[string]any{"role": "roles/secretmanager.secretAccessor", "members": []string{"serviceAccount:" + kbSA}, "condition": map[string]string{"title": "sealed-secrets-only", "expression": `(resource.type == "secretmanager.googleapis.com/Secret" || resource.type == "secretmanager.googleapis.com/SecretVersion") && resource.name.startsWith("projects/123456789012/secrets/sealed-")`}},
		map[string]any{"role": "roles/owner", "members": []string{"user:owner@example.com"}},
	}
	if !mutate["kb-no-log-writer"] {
		bindings = append(bindings, map[string]any{"role": "roles/logging.logWriter", "members": []string{"serviceAccount:" + kbSA}})
	}
	debug := mutate["debug-vm"] || mutate["debug-vm-broad-scope"] || mutate["debug-sa-unlabeled"] || mutate["debug-sa-extra-role"]
	if debug {
		bindings = append(bindings, map[string]any{"role": "roles/logging.logWriter", "members": []string{"serviceAccount:" + debugSA}})
	}
	if mutate["debug-sa-extra-role"] {
		bindings = append(bindings, map[string]any{"role": "roles/storage.objectViewer", "members": []string{"serviceAccount:" + debugSA}})
	}
	if mutate["deployer-editor"] {
		bindings = append(bindings, map[string]any{"role": "roles/editor", "members": []string{"serviceAccount:" + deployer}})
	}
	w.add("POST", crm+":getIamPolicy", "operator-token", "*", 200, map[string]any{"bindings": bindings})
	named := []string{"compute.disks.create", "compute.disks.delete", "compute.disks.get", "compute.disks.setLabels", "compute.disks.use", "compute.images.create", "compute.images.delete", "compute.images.get", "compute.images.setLabels", "compute.images.useReadOnly", "compute.instances.create", "compute.instances.delete", "compute.instances.get", "compute.instances.setLabels", "compute.instances.setMetadata", "compute.instances.setTags", "compute.instances.start", "compute.instances.stop"}
	if mutate["role-actas"] {
		named = append(named, "compute.instances.setServiceAccount")
	}
	w.add("GET", iamv1+"/roles/sealedDeployer", "operator-token", "*", 200, map[string]any{"includedPermissions": named})
	w.add("GET", iamv1+"/roles/sealedDeployerAddresses", "operator-token", "*", 200, map[string]any{"includedPermissions": []string{"compute.addresses.create", "compute.addresses.delete", "compute.addresses.get", "compute.addresses.use", "compute.globalOperations.get", "compute.regionOperations.get", "compute.zoneOperations.get"}})
	w.add("GET", iamv1+"/roles/sealedSubnetUser", "operator-token", "*", 200, map[string]any{"includedPermissions": []string{"compute.subnetworks.get", "compute.subnetworks.use", "compute.subnetworks.useExternalIp"}})
	w.add("GET", compute+"/regions/us-central1/subnetworks/sealed-subnet/getIamPolicy?optionsRequestedPolicyVersion=3", "operator-token", "*", 200, map[string]any{"bindings": []any{map[string]any{"role": "projects/" + project + "/roles/sealedSubnetUser", "members": []string{"serviceAccount:" + deployer}}}})
	staging := []any{
		map[string]any{"role": "roles/storage.objectAdmin", "members": []string{"serviceAccount:" + deployer}},
		map[string]any{"role": "roles/storage.legacyBucketOwner", "members": []string{"projectOwner:" + project}},
	}
	if mutate["staging-extra-role"] {
		staging = append(staging, map[string]any{"role": "roles/storage.admin", "members": []string{"serviceAccount:" + deployer}})
	}
	w.add("GET", gcs+"/"+project+"-sealed-staging/iam?optionsRequestedPolicyVersion=3", "operator-token", "*", 200, map[string]any{"bindings": staging})
	w.add("GET", kmsKey+":getIamPolicy?options.requestedPolicyVersion=3", "operator-token", "*", 200, map[string]any{"bindings": []any{map[string]any{"role": "roles/cloudkms.signer", "members": []string{"serviceAccount:" + kbSA}}}})
	w.add("GET", run, "operator-token", "*", 200, map[string]any{"uri": kbURL, "template": map[string]any{"serviceAccount": kbSA, "containers": []any{map[string]any{"image": "us-central1-docker.pkg.dev/acme-prod-4417/sealed-ghcr/sealedtempo/sealed-key-broker@sha256:" + strings.Repeat("ab", 32)}}}})
	ingressPorts := []string{"80", "443"}
	if mutate["ssh-firewall"] {
		ingressPorts = []string{"22", "80", "443"}
	}
	w.add("GET", compute+"/global/firewalls", "operator-token", "*", 200, map[string]any{"items": []any{
		map[string]any{"name": "sealed-allow-web-ingress", "network": compute + "/global/networks/sealed-vpc", "direction": "INGRESS", "targetTags": []string{"sealed-vm"}, "allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": ingressPorts}}},
		map[string]any{"name": "sealed-deny-ingress", "network": compute + "/global/networks/sealed-vpc", "direction": "INGRESS", "denied": []any{map[string]any{"IPProtocol": "all"}}},
		map[string]any{"name": "sealed-allow-egress", "network": compute + "/global/networks/sealed-vpc", "direction": "EGRESS", "allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []string{"443", "53"}}, map[string]any{"IPProtocol": "udp", "ports": []string{"53"}}}},
		map[string]any{"name": "sealed-deny-egress", "network": compute + "/global/networks/sealed-vpc", "direction": "EGRESS", "denied": []any{map[string]any{"IPProtocol": "all"}}},
		map[string]any{"name": "default-allow-ssh", "network": compute + "/global/networks/default", "direction": "INGRESS", "allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []string{"22"}}}},
	}})
	// As the deployer.
	if mutate["deployer-actas"] {
		w.add("POST", crm+":testIamPermissions", "deployer-token", "iam.serviceAccounts.actAs", 200, perms("iam.serviceAccounts.actAs"))
	} else {
		w.add("POST", crm+":testIamPermissions", "deployer-token", "iam.serviceAccounts.actAs", 200, map[string]any{})
	}
	w.add("POST", crm+":testIamPermissions", "deployer-token", "compute.addresses.create", 200, perms("compute.addresses.create", "compute.zoneOperations.get"))
	// The subnet as the deployer: the connection binding.
	switch {
	case mutate["subnet-unreadable"]:
		w.add("GET", compute+"/regions/us-central1/subnetworks/sealed-subnet", "deployer-token", "*", 403, `{"error":{"code":403}}`)
	case mutate["no-binding"]:
		w.add("GET", compute+"/regions/us-central1/subnetworks/sealed-subnet", "deployer-token", "*", 200, map[string]any{"name": "sealed-subnet"})
	case mutate["binding-other-broker"]:
		w.add("GET", compute+"/regions/us-central1/subnetworks/sealed-subnet", "deployer-token", "*", 200, map[string]any{"name": "sealed-subnet", "description": "sealed-binding/v1 customer=" + customer + " key_broker=https://evil-broker.example"})
	case mutate["binding-uppercase"]:
		w.add("GET", compute+"/regions/us-central1/subnetworks/sealed-subnet", "deployer-token", "*", 200, map[string]any{"name": "sealed-subnet", "description": "sealed-binding/v1 customer=0x00000000000000000000000000000000000000C1 key_broker=" + kbURL})
	default:
		w.add("GET", compute+"/regions/us-central1/subnetworks/sealed-subnet", "deployer-token", "*", 200, map[string]any{"name": "sealed-subnet", "description": binding})
	}
	bootProbe := gcs + "/" + project + "-sealed-boot/iam/testPermissions?permissions=storage.objects.create&permissions=storage.objects.get&permissions=storage.objects.delete&permissions=storage.buckets.setIamPolicy"
	if mutate["boot-bucket-writable"] {
		w.add("GET", bootProbe, "deployer-token", "*", 200, perms("storage.objects.create", "storage.objects.get"))
	} else {
		w.add("GET", bootProbe, "deployer-token", "*", 200, map[string]any{"kind": "storage#testIamPermissionsResponse"})
	}
	w.add("GET", sm+"/secrets?filter=name:sealed-&pageSize=250", "operator-token", "*", 200, map[string]any{"secrets": []any{map[string]any{"name": "projects/123456789012/secrets/sealed-gate-password"}}})
	if mutate["secret-readable"] {
		w.add("POST", sm+"/secrets/sealed-gate-password:testIamPermissions", "deployer-token", "*", 200, perms("secretmanager.versions.access"))
		w.add("GET", sm+"/secrets/sealed-gate-password/versions/latest:access", "deployer-token", "*", 200, map[string]any{"payload": map[string]string{"data": "VE9QU0VDUkVU"}, "plaintext": "TOPSECRET"})
	} else {
		w.add("POST", sm+"/secrets/sealed-gate-password:testIamPermissions", "deployer-token", "*", 200, map[string]any{})
		w.add("GET", sm+"/secrets/sealed-gate-password/versions/latest:access", "deployer-token", "*", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`)
	}
	w.add("POST", run+":testIamPermissions", "deployer-token", "*", 200, map[string]any{})
	w.add("POST", kmsKey+":testIamPermissions", "deployer-token", "*", 200, map[string]any{})
	accounts := []any{map[string]string{"email": deployer}, map[string]string{"email": kbSA}}
	if debug {
		accounts = append(accounts, map[string]string{"email": debugSA})
	}
	w.add("GET", iamv1+"/serviceAccounts?pageSize=100", "operator-token", "*", 200, map[string]any{"accounts": accounts})
	for _, sa := range []string{deployer, kbSA, debugSA, "123456789012-compute@developer.gserviceaccount.com"} {
		if sa == kbSA && mutate["kb-actas"] {
			w.add("POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/"+sa+":testIamPermissions", "deployer-token", "*", 200, perms("iam.serviceAccounts.actAs"))
			continue
		}
		if strings.Contains(sa, "compute@") {
			w.add("POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/"+sa+":testIamPermissions", "deployer-token", "*", 404, `{}`)
			continue
		}
		w.add("POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/"+sa+":testIamPermissions", "deployer-token", "*", 200, map[string]any{})
	}
	md := []any{
		map[string]string{"key": "block-project-ssh-keys", "value": "TRUE"}, map[string]string{"key": "enable-oslogin", "value": "FALSE"},
		map[string]string{"key": "serial-port-enable", "value": "FALSE"},
	}
	if mutate["serial-on"] {
		md[2] = map[string]string{"key": "serial-port-enable", "value": "true"}
	}
	vm := map[string]any{"name": "sealed-demo", "confidentialInstanceConfig": map[string]string{"confidentialInstanceType": "TDX"}, "metadata": map[string]any{"items": md},
		"networkInterfaces": []any{map[string]any{"accessConfigs": []any{map[string]string{"natIP": "127.0.0.1"}}}}}
	if mutate["vm-sa"] {
		vm["serviceAccounts"] = []any{map[string]any{"email": "123456789012-compute@developer.gserviceaccount.com"}}
	}
	if debug {
		scopes := []string{"https://www.googleapis.com/auth/logging.write"}
		if mutate["debug-vm-broad-scope"] {
			scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
		}
		vm["serviceAccounts"] = []any{map[string]any{"email": debugSA, "scopes": scopes}}
		if !mutate["debug-sa-unlabeled"] {
			vm["labels"] = map[string]string{"sealed": "deployment", "sealed-variant": "debug"}
		}
	}
	w.add("GET", compute+"/zones/us-central1-a/instances?filter=name%3Dsealed-*", "operator-token", "*", 200, map[string]any{"items": []any{map[string]string{"name": "sealed-demo"}}})
	w.add("GET", compute+"/zones/us-central1-a/instances/sealed-demo", "operator-token", "*", 200, vm)
	w.add("POST", compute+"/zones/us-central1-a/instances/sealed-demo/testIamPermissions", "deployer-token", "setServiceAccount", 200, map[string]any{})
	w.add("POST", compute+"/zones/us-central1-a/instances/sealed-demo/testIamPermissions", "deployer-token", "compute.instances.start", 200, perms("compute.instances.start", "compute.instances.stop", "compute.instances.delete"))
	w.add("POST", compute+"/zones/us-central1-a/instances/sealed-demo/setServiceAccount", "deployer-token", "*", 403, `{}`)
	w.add("PATCH", run+"?updateMask=labels", "deployer-token", "*", 403, `{}`)
	// Key broker.
	w.add("GET", kbURL+"/v1/nonce", "none", "*", 200, map[string]any{"nonce": "0x" + strings.Repeat("12", 32), "expiresAt": 1})
	if mutate["kb-releases"] {
		w.add("POST", kbURL+"/v1/release", "none", "*", 200, map[string]any{"stackHash": "0x00"})
	} else {
		w.add("POST", kbURL+"/v1/release", "none", "0x5345414c454453494d31", 403, map[string]any{"decision": "denied", "reason": "quote_invalid"})
	}
}

func runCheck(t *testing.T, mutate map[string]bool, extra ...string) (int, string, string) {
	t.Helper()
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("SEALED_REQUIRE_IAM_SCRIPT") == "1" {
				t.Fatalf("%s is required", tool)
			}
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "curl"), []byte(curlStub), 0o755)
	os.WriteFile(filepath.Join(bin, "gcloud"), []byte(gcloudStub), 0o755)
	w := &world{dir: dir}
	compliant(w, mutate)
	os.WriteFile(filepath.Join(dir, "responses.tsv"), []byte(strings.Join(w.rows, "\n")+"\n"), 0o600)
	log := filepath.Join(dir, "requests.log")
	args := append([]string{"check.sh", "--project", project, "--platform-sa", platform}, extra...)
	cmd := exec.Command("bash", args...)
	env := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_DIR=" + dir, "FAKE_LOG=" + log, "HOME=" + dir,
		// A closed local port stands in for the VM's SSH port.
		"SEALED_IAMCHECK_SSH_PORT=1"}
	if mutate["no-impersonation"] {
		env = append(env, "FAKE_IMPERSONATE=denied")
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	reqs, _ := os.ReadFile(log)
	return code, string(out), string(reqs)
}

func TestCheckScriptPassesOnACompliantProject(t *testing.T) {
	code, out, reqs := runCheck(t, nil, "--attempt-mutations")
	if code != 0 || strings.Contains(out, "FAIL") || strings.Contains(out, "Terminated") || !strings.Contains(out, "summary: 30 passed, 0 failed, 1 skipped, 2 warnings") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"PASS  impersonated the deployer",
		"PASS  deployer identity: serviceAccountTokenCreator for the platform service account only",
		"PASS  deployer project roles: sealedDeployer and sealedDeployerAddresses only",
		"PASS  sealedDeployer is granted only on resources named sealed-*",
		"PASS  key broker identity: secretAccessor on sealed-* secrets only, and its decision log",
		"PASS  firewall: ingress 80/443 to sealed-vm only",
		"PASS  subnet sealed-subnet: the deployer may attach VMs to it",
		"PASS  staging bucket acme-prod-4417-sealed-staging: the deployer holds roles/storage.objectAdmin there and nothing else",
		"PASS  the deployer reads the connection binding on sealed-subnet: wallet " + customer + ", key broker " + kbURL,
		"PASS  deployer cannot read or write the boot bucket acme-prod-4417-sealed-boot",
		"PASS  deployer cannot attach a service account to sealed-demo, log in or call getSerialPortOutput",
		"WARN  the deployer holds compute.instances.setMetadata on sealed-* VMs, so it can set serial-port-enable and add ssh-keys at any time",
		"WARN  the deployer's static IP rights are project-wide: it can reserve, attach and release any regional address in acme-prod-4417, not only sealed-* ones",
		"PASS  KMS HMAC key: only the key broker may use it",
		"PASS  positive control: the impersonated deployer holds its own project permissions",
		"PASS  reading sealed-gate-password as the deployer is denied",
		"PASS  deployer cannot change, delete or re-permission the key broker",
		"PASS  deployer cannot act as or mint tokens for " + kbSA,
		"PASS  VM sealed-demo: TDX, no service account",
		"PASS  no SSH: port 1 on sealed-demo",
		"PASS  attaching the key broker identity to sealed-demo as the deployer is denied",
		"PASS  changing the key broker as the deployer is denied",
		"PASS  key broker refuses a VM without a TDX quote (403 quote_invalid)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// Every probe of a denial ran with the deployer's token, and no mutating request went out as you.
	for _, line := range strings.Split(strings.TrimSpace(reqs), "\n") {
		f := strings.Split(line, "\t")
		if (f[0] == "PATCH" || strings.HasSuffix(f[1], "/setServiceAccount")) && f[2] != "deployer-token" {
			t.Errorf("mutation not as the deployer: %s", line)
		}
		if strings.Contains(f[1], "versions/latest:access") && f[2] != "deployer-token" {
			t.Errorf("secret read as you: %s", line)
		}
	}
}

// TestCheckScriptAcceptsADebugVM: the one identity exception (spec 5.8) is a VM labeled sealed-variant=debug with
// exactly the log writer and its logging.write scope, and the log writer holds logging.logWriter only.
func TestCheckScriptAcceptsADebugVM(t *testing.T) {
	code, out, _ := runCheck(t, map[string]bool{"debug-vm": true})
	if code != 0 || strings.Contains(out, "FAIL") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"PASS  debug log writer identity: logging.logWriter only",
		"PASS  VM sealed-demo (debug): TDX, only the log writer with logging.write",
		"PASS  deployer cannot act as or mint tokens for " + debugSA,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestCheckScriptChangesNothingByDefault(t *testing.T) {
	code, out, reqs := runCheck(t, nil)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(reqs), "\n") {
		f := strings.Split(line, "\t")
		if f[0] == "PATCH" || f[0] == "DELETE" || strings.HasSuffix(f[1], "/setServiceAccount") {
			t.Errorf("mutating request without --attempt-mutations: %s", line)
		}
	}
}

func TestCheckScriptCatchesEachMisconfiguration(t *testing.T) {
	for name, want := range map[string]string{
		"extra-token-creator":  "FAIL  deployer identity policy",
		"deployer-editor":      "FAIL  deployer project roles",
		"role-actas":           "FAIL  custom role sealedDeployer permissions differ (extra: compute.instances.setServiceAccount",
		"ssh-firewall":         "FAIL  firewall rules of sealed-vpc",
		"deployer-actas":       "FAIL  deployer holds forbidden project permissions",
		"secret-readable":      "FAIL  reading sealed-gate-password as the deployer returned HTTP 200",
		"kb-actas":             "FAIL  deployer holds iam.serviceAccounts.actAs on service account " + kbSA,
		"serial-on":            "FAIL  VM sealed-demo: serial port not off",
		"vm-sa":                "FAIL  VM sealed-demo: has a service account",
		"debug-vm-broad-scope": "FAIL  VM sealed-demo: debug VM identity is not exactly " + debugSA + " with https://www.googleapis.com/auth/logging.write",
		"debug-sa-unlabeled":   "FAIL  VM sealed-demo: has a service account",
		"debug-sa-extra-role":  "FAIL  debug log writer " + debugSA + " holds [roles/logging.logWriter roles/storage.objectViewer]",
		"kb-no-log-writer":     "FAIL  key broker project roles [roles/secretmanager.secretAccessor]",
		"kb-releases":          "FAIL  key broker answered HTTP 200",
		"no-impersonation":     "FAIL  impersonate the deployer",
		"subnet-unreadable":    "FAIL  the deployer cannot read subnet sealed-subnet (HTTP 403)",
		"no-binding":           "FAIL  subnet sealed-subnet carries no connection binding",
		"binding-uppercase":    "FAIL  subnet sealed-subnet carries no connection binding",
		"binding-other-broker": "FAIL  the connection binding names key broker https://evil-broker.example, but sealed-key-broker is " + kbURL,
		"staging-extra-role":   "FAIL  staging bucket acme-prod-4417-sealed-staging: the deployer holds [roles/storage.admin roles/storage.objectAdmin]",
		"boot-bucket-writable": "FAIL  deployer holds [storage.objects.create storage.objects.get] on the boot bucket acme-prod-4417-sealed-boot",
	} {
		t.Run(name, func(t *testing.T) {
			code, out, _ := runCheck(t, map[string]bool{name: true})
			if code == 0 || !strings.Contains(out, want) {
				t.Fatalf("exit %d, want %q in\n%s", code, want, out)
			}
			if strings.Contains(out, "TOPSECRET") || strings.Contains(out, "VE9QU0VDUkVU") {
				t.Fatal("a secret value was printed")
			}
		})
	}
}

// TestCheckScriptChecksTheBindingWallet: with --customer-address the binding must name that wallet (any case on the
// command line), so a project bootstrapped for another wallet fails.
func TestCheckScriptChecksTheBindingWallet(t *testing.T) {
	code, out, _ := runCheck(t, nil, "--customer-address", "0x00000000000000000000000000000000000000C1")
	if code != 0 || !strings.Contains(out, "PASS  the deployer reads the connection binding on sealed-subnet: wallet "+customer) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	code, out, _ = runCheck(t, nil, "--customer-address", "0x00000000000000000000000000000000000000c2")
	if code == 0 || !strings.Contains(out, "FAIL  the connection binding names wallet "+customer+", want 0x00000000000000000000000000000000000000c2") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// TestCheckScriptClaimsOnlyWhatIAMEnforces: the deployer may edit sealed-* VM metadata, so the script never claims
// it cannot reach the serial port; it says what testIamPermissions shows and warns about the rest.
func TestCheckScriptClaimsOnlyWhatIAMEnforces(t *testing.T) {
	_, out, _ := runCheck(t, nil)
	for _, bad := range []string{"read its serial port", "or read the serial port"} {
		if strings.Contains(out, bad) {
			t.Errorf("check.sh still claims %q:\n%s", bad, out)
		}
	}
	script, err := os.ReadFile("check.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), `warn "the deployer holds compute.instances.setMetadata`) {
		t.Error("check.sh lost the setMetadata warning")
	}
}
