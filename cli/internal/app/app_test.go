package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/bcrypt"

	"github.com/sealedtempo/sealed/cli/internal/bootstrap"
	"github.com/sealedtempo/sealed/cli/internal/deploy"
	"github.com/sealedtempo/sealed/cli/internal/gcp"
	"github.com/sealedtempo/sealed/cli/internal/registry"
	"github.com/sealedtempo/sealed/cli/internal/secrets"
	"github.com/sealedtempo/sealed/cli/internal/settings"
	"github.com/sealedtempo/sealed/cli/internal/testkit"
	"github.com/sealedtempo/sealed/cli/internal/token"
)

// harness runs the CLI in-process against fakes.
type harness struct {
	t       *testing.T
	env     map[string]string
	chain   *testkit.MemChain
	bundles *testkit.BundleServer
	store   *memStore
	compute *fakeCompute
	shared  *fakeShared
	osImgs  *fakeOSImages
	tf      *fakeTerraform
	dir     string
	stdin   string
	tty     bool
	answers []string
	// real, when set, replaces the in-memory chain (anvil tests).
	real registry.Reader
	// dial, when set, makes commands dial the RPC and registries of their own settings, as the binary does.
	dial bool
	// now, when set, replaces the fixed clock testkit.HarnessNow (anvil tests use the node's head time).
	now func() time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, env: map[string]string{"HOME": t.TempDir()}, chain: testkit.NewMemChain(), store: newMemStore(),
		compute: newFakeCompute(), shared: &fakeShared{}, tf: &fakeTerraform{}, osImgs: &fakeOSImages{}, dir: t.TempDir()}
	h.bundles = testkit.NewBundleServer(t)
	// A deployments file naming the fake registries.
	dep := map[string]any{"chainId": 4217, "network": "test", "contracts": map[string]any{
		"PlatformRegistry":   map[string]string{"address": testkit.Addresses.PlatformRegistry.Hex()},
		"AppRegistry":        map[string]string{"address": testkit.Addresses.AppRegistry.Hex()},
		"DeploymentRegistry": map[string]string{"address": testkit.Addresses.DeploymentRegistry.Hex()},
		"FeeSplitter":        map[string]string{"address": "0x00000000000000000000000000000000000000E4"},
	}}
	b, _ := json.Marshal(dep)
	h.env["SEALED_DEPLOYMENTS_FILE"] = h.write("deployments.json", string(b))
	return h
}

func (h *harness) write(name, content string) string {
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Unix(testkit.HarnessNow, 0)
}

// run executes the CLI and returns exit code, stdout and stderr.
func (h *harness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errb bytes.Buffer
	e := &Env{
		Stdin: strings.NewReader(h.stdin), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return h.env[k] }, Now: h.clock,
		Interactive: h.tty,
		ReadSecret: func(string) (string, error) {
			if len(h.answers) == 0 {
				return "", io.EOF
			}
			a := h.answers[0]
			h.answers = h.answers[1:]
			return a, nil
		},
		NewTokens: func(string) (gcp.TokenSource, error) { return gcp.StaticToken("ya29.test"), nil },
		NewChain: func(ctx context.Context, s *settings.Settings) (registry.Reader, error) {
			if h.dial {
				return registry.Dial(ctx, s.RPCURL, s.Registries)
			}
			if h.real != nil {
				return h.real, nil
			}
			return h.chain, nil
		},
		NewSecretStore:   func(string, gcp.TokenSource) secrets.Store { return h.store },
		NewCompute:       func(string, gcp.TokenSource) deploy.Compute { return h.compute },
		NewShared:        func(string, string, gcp.TokenSource) deploy.SharedDisk { return h.shared },
		Terraform:        h.tf,
		ImportOSImages:   h.osImgs.ensure,
		HTTP:             h.bundles.Client(),
		AllowHTTPBundles: true,
	}
	full := append([]string{}, args...)
	switch args[0] {
	case "verify", "catalog", "release", "deploy", "secrets":
		full = append(full, "--release-asset-base", h.bundles.URL, "--bundle-cache", filepath.Join(h.dir, "cache"))
	}
	if args[0] == "verify" && !contains(args, "--collateral-cache") {
		// Never touch the real user cache dir from tests.
		full = append(full, "--collateral-cache", filepath.Join(h.dir, "pcs"))
	}
	code := Main(full, e)
	return code, out.String(), errb.String()
}

// --- fakes ---

type memStore struct{ v map[string][][]byte }

func newMemStore() *memStore { return &memStore{v: map[string][][]byte{}} }

func (m *memStore) Exists(_ context.Context, n string) (bool, error) {
	_, ok := m.v[n]
	return ok, nil
}
func (m *memStore) Create(_ context.Context, n string, _ map[string]string, _ string) error {
	m.v[n] = nil
	return nil
}
func (m *memStore) AddVersion(_ context.Context, n string, b []byte) (string, error) {
	m.v[n] = append(m.v[n], append([]byte(nil), b...))
	return n, nil
}
func (m *memStore) List(_ context.Context, prefix string) ([]gcp.SecretInfo, error) {
	var out []gcp.SecretInfo
	for n := range m.v {
		if strings.HasPrefix(n, prefix) {
			out = append(out, gcp.SecretInfo{Name: n, CreateTime: "2026-10-28T00:00:00Z"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (m *memStore) Delete(_ context.Context, n string) error {
	delete(m.v, n)
	return nil
}

type fakeCompute struct {
	addrs     map[string]*gcp.Address
	disks     map[string]*gcp.Disk
	instances map[string]*gcp.Instance
}

func newFakeCompute() *fakeCompute {
	return &fakeCompute{addrs: map[string]*gcp.Address{}, disks: map[string]*gcp.Disk{}, instances: map[string]*gcp.Instance{}}
}

func nf() error { return &gcp.APIError{HTTPStatus: 404} }

func (f *fakeCompute) GetAddress(_ context.Context, _, n string) (*gcp.Address, error) {
	if a, ok := f.addrs[n]; ok {
		return a, nil
	}
	return nil, nf()
}
func (f *fakeCompute) EnsureAddress(_ context.Context, _, n, _ string) (*gcp.Address, error) {
	if _, ok := f.addrs[n]; !ok {
		f.addrs[n] = &gcp.Address{Name: n, Address: "34.1.2.3"}
	}
	return f.addrs[n], nil
}
func (f *fakeCompute) EnsureDisk(_ context.Context, _ string, d gcp.Disk) (*gcp.Disk, bool, error) {
	if got, ok := f.disks[d.Name]; ok {
		return got, false, nil
	}
	d.SelfLink = "projects/p/zones/z/disks/" + d.Name
	f.disks[d.Name] = &d
	return &d, true, nil
}
func (f *fakeCompute) InsertInstance(_ context.Context, _ string, in *gcp.Instance, _ string) error {
	f.instances[in.Name] = in
	return nil
}
func (f *fakeCompute) GetInstance(_ context.Context, _, n string) (*gcp.Instance, error) {
	if in, ok := f.instances[n]; ok {
		return in, nil
	}
	return nil, nf()
}
func (f *fakeCompute) DeleteInstance(_ context.Context, _, n string) error {
	if _, ok := f.instances[n]; !ok {
		return nf()
	}
	delete(f.instances, n)
	return nil
}

type fakeShared struct{ names []string }

func (f *fakeShared) Ensure(_ context.Context, name string, _ map[string][]byte) (string, error) {
	f.names = append(f.names, name)
	return "projects/acme-prod-4417/global/images/" + name, nil
}

type fakeTerraform struct {
	calls [][]string
	dir   string
	// rpc, when set, is the tempo_rpc_url output.
	rpc string
}

func (f *fakeTerraform) Stream(_ context.Context, dir string, _ []string, args ...string) error {
	f.calls, f.dir = append(f.calls, args), dir
	return nil
}

func (f *fakeTerraform) Capture(_ context.Context, dir string, _ []string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	rpc := f.rpc
	if rpc == "" {
		rpc = "https://rpc.tempo.xyz"
	}
	return []byte(strings.Replace(`{
 "project_id": {"value": "acme-prod-4417"}, "region": {"value": "us-central1"},
 "customer_address": {"value": "0x00000000000000000000000000000000000000c1"},
 "deployer_service_account": {"value": "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com"},
 "key_broker_service_account": {"value": "sealed-key-broker@acme-prod-4417.iam.gserviceaccount.com"},
 "key_broker_url": {"value": "https://sealed-key-broker-xyz-uc.a.run.app"},
 "subnetwork": {"value": "sealed-subnet"}, "boot_bucket": {"value": "acme-prod-4417-sealed-boot"},
 "tempo_rpc_url": {"value": "RPC"}, "debug_log_service_account": {"value": ""},
 "connection_binding": {"value": "sealed-binding/v1 customer=0x00000000000000000000000000000000000000c1 key_broker=https://sealed-key-broker-xyz-uc.a.run.app"},
 "kms_key_version": {"value": "projects/acme-prod-4417/locations/us-central1/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1"}
}`, `"RPC"`, strconv.Quote(rpc), 1)), nil
}

// fakeOSImages stands in for bootstrap.OSImages.Ensure and records what bootstrap asked for.
type fakeOSImages struct {
	calls []bootstrap.OSImages
	err   error
}

func (f *fakeOSImages) ensure(_ context.Context, o *bootstrap.OSImages) ([]bootstrap.OSImage, error) {
	f.calls = append(f.calls, *o)
	if f.err != nil {
		return nil, f.err
	}
	var out []bootstrap.OSImage
	for i, role := range []string{"boot", "debugBoot", "systemDisk"} {
		name := o.Planned()[i]
		out = append(out, bootstrap.OSImage{Role: role, Name: name, Ref: "projects/" + o.Project + "/global/images/" + name, Created: true})
	}
	return out, nil
}

// --- verify ---

// world publishes a fixture stack on the fake chain and writes its evidence file.
func (h *harness) world(register bool) (*testkit.World, map[string]any, string) {
	w := testkit.NewWorld(h.t)
	for _, b := range w.Bundles {
		h.bundles.Put(h.t, b.Manifest.ID, b.Version(), b.Tar)
	}
	ev := w.Evidence(h.t)
	w.Populate(h.chain, ev, register)
	raw, _ := json.Marshal(ev)
	return w, ev, h.write("evidence.json", string(raw))
}

func TestVerifyEvidenceEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, ev, path := h.world(true)
	id := w.Result.DeploymentID.Hex()
	code, out, errs := h.run("verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated", "--collateral-cache", filepath.Join(h.dir, "pcs"))
	if code != ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"stack_recompute", "approval_releases", "onchain_record", "SIMULATED", "OK: every check passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	// JSON report, also written to a file.
	report := filepath.Join(h.dir, "report.json")
	code, out, _ = h.run("verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated", "--json", "--report", report)
	var doc struct {
		OK       bool `json:"ok"`
		Evidence struct {
			OK        bool `json:"ok"`
			Simulated bool `json:"simulated"`
			Checks    []struct {
				Name string `json:"name"`
				OK   bool   `json:"ok"`
			} `json:"checks"`
		} `json:"evidence"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil || !doc.OK || !doc.Evidence.Simulated || len(doc.Evidence.Checks) < 15 {
		t.Fatalf("json report: %d %s", code, out)
	}
	if b, err := os.ReadFile(report); err != nil || !bytes.Contains(b, []byte(`"stack_recompute"`)) {
		t.Fatal("report file not written")
	}

	// A chain head more than 60 s old fails the chain check (D-060), so a lagging RPC cannot hide a revocation.
	h.chain.HeadTime = testkit.HarnessNow - 61
	if code, _, errs := h.run("verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated"); code != ExitFailed || !strings.Contains(errs, "evidence/chain") {
		t.Fatalf("stale head: %d %s", code, errs)
	}
	h.chain.HeadTime = testkit.HarnessNow - 10

	// Another deployment id fails.
	other := "0x" + strings.Repeat("ab", 32)
	if code, _, errs := h.run("verify", "--deployment", other, "--evidence", path, "--dev-allow-simulated"); code != ExitFailed || !strings.Contains(errs, "deployment_id") {
		t.Fatalf("other id: %d %s", code, errs)
	}
	// A changed config byte fails (config_hash and more), so does a revoked release.
	ev2 := map[string]any{}
	for k, v := range ev {
		ev2[k] = v
	}
	ev2["configHash"] = "0x" + strings.Repeat("00", 32)
	raw, _ := json.Marshal(ev2)
	if code, _, errs := h.run("verify", "--deployment", id, "--evidence", h.write("bad.json", string(raw)), "--dev-allow-simulated"); code != ExitFailed || !strings.Contains(errs, "config_hash") {
		t.Fatalf("tampered: %d %s", code, errs)
	}
	h.chain.Releases[w.Bundles[0].ReleaseID].Status = 3 // revoked
	if code, _, errs := h.run("verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated"); code != ExitFailed || !strings.Contains(errs, "releases_active") {
		t.Fatalf("revoked release: %d %s", code, errs)
	}
}

func TestVerifyRefusesSimulatedQuotesInProduction(t *testing.T) {
	h := newHarness(t)
	w, _, path := h.world(true)
	// Without the dev flag the simulated quote fails the quote check.
	code, _, errs := h.run("verify", "--deployment", w.Result.DeploymentID.Hex(), "--evidence", path, "--collateral-cache", filepath.Join(h.dir, "pcs"))
	if code != ExitFailed || !strings.Contains(errs, "evidence/quote") {
		t.Fatalf("simulated quote accepted: %d %s", code, errs)
	}
	// And the dev flag is refused without SEALED_DEV_SIM=1.
	if code, _, _ := h.run("verify", "--deployment", w.Result.DeploymentID.Hex(), "--evidence", path, "--dev-allow-simulated"); code != ExitUsage {
		t.Fatalf("dev flag without SEALED_DEV_SIM: %d", code)
	}
}

func TestVerifyUnregisteredDeploymentFails(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, _, path := h.world(false)
	code, _, errs := h.run("verify", "--deployment", w.Result.DeploymentID.Hex(), "--evidence", path, "--dev-allow-simulated")
	if code != ExitFailed || !strings.Contains(errs, "onchain_record") {
		t.Fatalf("unregistered: %d %s", code, errs)
	}
}

func TestVerifyAliasAndEvidenceDownload(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, ev, _ := h.world(true)
	id := w.Result.DeploymentID.Hex()
	var sawAuth string
	api := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/verify":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["deploymentId"] != "dep_7Q2fK9mX" {
				json.NewEncoder(rw).Encode(map[string]any{"result": "not_found"})
				return
			}
			json.NewEncoder(rw).Encode(map[string]any{"result": "verified", "deploymentId": id, "alias": "dep_7Q2fK9mX"})
		case r.Method == "GET" && r.URL.Path == "/v1/deployments/"+id+"/evidence":
			sawAuth = r.Header.Get("Authorization")
			json.NewEncoder(rw).Encode(ev)
		default:
			http.NotFound(rw, r)
		}
	}))
	defer api.Close()
	h.env["SEALED_API_KEY"] = "sk_test_api"
	code, out, errs := h.run("verify", "--deployment", "dep_7Q2fK9mX", "--api", api.URL, "--dev-allow-simulated")
	if code != ExitOK {
		t.Fatalf("alias: %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "resolves to "+id) || sawAuth != "Bearer sk_test_api" {
		t.Fatalf("resolution %q auth %q", errs, sawAuth)
	}
	if code, _, errs := h.run("verify", "--deployment", "dep_AAAAAAAA", "--api", api.URL); code != ExitFailed || !strings.Contains(errs, "does not know") {
		t.Fatalf("unknown alias: %d %s", code, errs)
	}
	if code, _, _ := h.run("verify", "--deployment", "dep_7Q2fK9mX"); code != ExitUsage {
		t.Fatal("alias without --api")
	}
	if code, _, _ := h.run("verify", "--deployment", "nope"); code != ExitUsage {
		t.Fatal("bad id")
	}
}

func TestVerifyLive(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, ev, path := h.world(true)
	var srv *httptest.Server
	tamper := false
	srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		nonce, err := registry.ParseHash32(r.URL.Query().Get("nonce"))
		if r.URL.Path != "/attest" || err != nil {
			http.Error(rw, "bad request", 400)
			return
		}
		spki := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
		if tamper {
			spki[0] ^= 1 // a key that is not the one serving this connection
		}
		json.NewEncoder(rw).Encode(w.LiveAttest(h.t, nonce, spki))
	}))
	defer srv.Close()
	id := w.Result.DeploymentID.Hex()
	dev := []string{"--dev-allow-simulated", "--dev-insecure-live-tls", "--dev-live-allow-private"}
	code, out, errs := h.run(append([]string{"verify", "--deployment", id, "--live", srv.URL + "/attest", "--evidence", path}, dev...)...)
	if code != ExitOK || !strings.Contains(out, "== live check") || !strings.Contains(out, "tls_binding") || !strings.Contains(out, "== evidence check") {
		t.Fatalf("live: %d\n%s\n%s", code, out, errs)
	}
	tamper = true
	code, _, errs = h.run(append([]string{"verify", "--deployment", id, "--live", srv.URL + "/attest"}, dev...)...)
	if code != ExitFailed || !strings.Contains(errs, "live/tls_binding") {
		t.Fatalf("tampered TLS key: %d %s", code, errs)
	}
	// Private addresses and self-signed certificates are refused without the dev flags.
	if code, _, errs := h.run("verify", "--deployment", id, "--live", srv.URL+"/attest", "--dev-allow-simulated"); code != ExitFailed || !strings.Contains(errs, "live/live_fetch") {
		t.Fatalf("private live target: %d %s", code, errs)
	}
	_ = ev
}

// --- catalog and release ---

func TestCatalogListAndShow(t *testing.T) {
	h := newHarness(t)
	w, _, _ := h.world(false)
	code, out, errs := h.run("catalog", "list")
	if code != ExitOK || !strings.Contains(out, "llm-gateway") || !strings.Contains(out, "notes") || !strings.Contains(out, w.Bundles[1].Hash.Hex()) {
		t.Fatalf("list: %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = h.run("catalog", "list", "--json")
	var apps []AppView
	if code != ExitOK || json.Unmarshal([]byte(out), &apps) != nil || len(apps) != 2 || apps[0].Latest == nil {
		t.Fatalf("list json: %s", out)
	}
	code, out, errs = h.run("catalog", "show", "notes")
	if code != ExitOK {
		t.Fatalf("show: %d %s", code, errs)
	}
	for _, want := range []string{"A small notes app", "APP_SECRET (hex32)", "SMTP_PASSWORD (none, optional)", "api.example.com:443", "ghcr.io/sealedtempo/notes-web@sha256:", "1.0.0-sealed.1", "active", "/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if code, _, _ := h.run("catalog", "show", "nope"); code != ExitFailed {
		t.Fatal("unknown app")
	}
}

func TestReleaseBuildReproduces(t *testing.T) {
	h := newHarness(t)
	h.world(false)
	catalog := filepath.Join(testkit.RepoRoot(), "runtime", "composer", "testdata", "apps")
	notes := testkit.Bundle(t, "notes")
	out := filepath.Join(h.dir, "notes.tar")
	code, stdout, errs := h.run("release", "build", "notes", "--catalog", catalog, "--out", out)
	if code != ExitOK || !strings.Contains(stdout, notes.Hash.Hex()) || !strings.Contains(stdout, notes.ReleaseID.Hex()) {
		t.Fatalf("build: %d\n%s\n%s", code, stdout, errs)
	}
	if b, _ := os.ReadFile(out); !bytes.Equal(b, notes.Tar) {
		t.Fatal("written bundle differs")
	}
	code, stdout, errs = h.run("release", "build", "notes", "--catalog", catalog, "--check", "latest")
	if code != ExitOK || !strings.Contains(stdout, "reproduced: the bundle equals release 1.0.0-sealed.1") {
		t.Fatalf("check: %d\n%s\n%s", code, stdout, errs)
	}
	// A checkout whose fragment differs from the published release does not reproduce.
	mod := filepath.Join(h.dir, "apps")
	copyDir(t, filepath.Join(catalog, "notes"), filepath.Join(mod, "notes"))
	frag := filepath.Join(mod, "notes", "compose.fragment.yaml")
	b, _ := os.ReadFile(frag)
	os.WriteFile(frag, append(b, []byte("\n# local change\n")...), 0o644)
	code, stdout, _ = h.run("release", "build", "notes", "--catalog", mod, "--check", "latest")
	if code != ExitFailed || !strings.Contains(stdout, "NOT reproduced") || !strings.Contains(stdout, "differs: compose.fragment.yaml") {
		t.Fatalf("modified check: %d\n%s", code, stdout)
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// --- secrets ---

func TestSecretsCommands(t *testing.T) {
	h := newHarness(t)
	catalog := filepath.Join(testkit.RepoRoot(), "runtime", "composer", "testdata", "apps")
	conn, _ := token.Encode(token.Connection{V: 1, Project: "acme-prod-4417", Region: "us-central1",
		DeployerAccount: "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com", KeyBrokerURL: "https://kb.example.com", Customer: "0x00000000000000000000000000000000000000c1"})

	// set from stdin, refuse silent rotation, rotate explicitly.
	h.stdin = "s3cret-value\n"
	if code, out, errs := h.run("secrets", "set", "notes", "APP_SECRET", "--stdin", "--catalog", catalog, "--connection", conn); code != ExitOK || !strings.Contains(out, "created sealed-notes-APP_SECRET in project acme-prod-4417") {
		t.Fatalf("set: %d %s %s", code, out, errs)
	}
	if got := string(h.store.v["sealed-notes-APP_SECRET"][0]); got != "s3cret-value" {
		t.Fatalf("stored %q", got)
	}
	if code, _, errs := h.run("secrets", "set", "notes", "APP_SECRET", "--stdin", "--catalog", catalog, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "--rotate") {
		t.Fatalf("silent rotation: %d %s", code, errs)
	}
	if code, _, _ := h.run("secrets", "set", "notes", "APP_SECRET", "--generate", "--rotate", "--catalog", catalog, "--project", "acme-prod-4417"); code != ExitOK || len(h.store.v["sealed-notes-APP_SECRET"]) != 2 || len(h.store.v["sealed-notes-APP_SECRET"][1]) != 64 {
		t.Fatalf("rotate with generator: %v", h.store.v["sealed-notes-APP_SECRET"])
	}
	// Undeclared names and a generator-less secret with --generate are refused.
	if code, _, errs := h.run("secrets", "set", "notes", "NOPE", "--generate", "--catalog", catalog, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "does not declare") {
		t.Fatalf("undeclared: %d %s", code, errs)
	}
	if code, _, errs := h.run("secrets", "set", "notes", "SMTP_PASSWORD", "--generate", "--catalog", catalog, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "no generator") {
		t.Fatalf("no generator: %d %s", code, errs)
	}
	// Non-interactive without a value source is a usage error (values never come from flags).
	h.stdin = ""
	if code, _, _ := h.run("secrets", "set", "notes", "DB_PASSWORD", "--catalog", catalog, "--project", "acme-prod-4417"); code != ExitUsage {
		t.Fatal("no value source")
	}

	// --missing generates what it can, asks for the rest (interactive), and generates the gate password once.
	h.tty, h.answers = true, nil
	code, out, errs := h.run("secrets", "set", "--missing", "--apps", "notes,llm-gateway", "--catalog", catalog, "--project", "acme-prod-4417")
	if code != ExitOK {
		t.Fatalf("missing: %d %s %s", code, out, errs)
	}
	if !strings.Contains(out, "generated sealed-notes-DB_PASSWORD") || !strings.Contains(out, "optional  sealed-notes-SMTP_PASSWORD") || !strings.Contains(out, "Gate password (user sealed)") {
		t.Fatalf("missing output:\n%s", out)
	}
	gate := h.store.v[secrets.GateSecret]
	pw := strings.TrimSpace(out[strings.Index(out, "shown only now:")+len("shown only now:"):])
	pw = strings.Fields(pw)[0]
	if len(gate) != 1 || bcrypt.CompareHashAndPassword(gate[0], []byte(pw)) != nil {
		t.Fatal("the gate secret is the bcrypt hash of the printed password")
	}
	// list with the stack's apps shows status; plain list shows names only, never values.
	code, out, _ = h.run("secrets", "list", "--apps", "notes", "--catalog", catalog, "--project", "acme-prod-4417")
	if code != ExitOK || !strings.Contains(out, "sealed-notes-APP_SECRET") || !strings.Contains(out, "optional, not set") || strings.Contains(out, "s3cret") {
		t.Fatalf("list:\n%s", out)
	}
	code, out, _ = h.run("secrets", "list", "--project", "acme-prod-4417")
	if code != ExitOK || !strings.Contains(out, "sealed-gate-password") || strings.Contains(out, pw) {
		t.Fatalf("plain list:\n%s", out)
	}
	// rm needs confirmation.
	h.tty = false
	if code, _, _ := h.run("secrets", "rm", "notes", "APP_SECRET", "--project", "acme-prod-4417"); code != ExitUsage {
		t.Fatal("rm without --yes on a pipe")
	}
	h.tty, h.stdin = true, "n\n"
	if code, _, _ := h.run("secrets", "rm", "notes", "APP_SECRET", "--project", "acme-prod-4417"); code != ExitFailed || h.store.v["sealed-notes-APP_SECRET"] == nil {
		t.Fatal("rm answered no")
	}
	if code, _, _ := h.run("secrets", "rm", "notes", "APP_SECRET", "--project", "acme-prod-4417", "--yes"); code != ExitOK {
		t.Fatal("rm --yes")
	}
	if _, ok := h.store.v["sealed-notes-APP_SECRET"]; ok {
		t.Fatal("not deleted")
	}
	// gate with a typed password that is too short.
	h.answers = []string{"short"}
	if code, _, errs := h.run("secrets", "set", "gate", "--project", "acme-prod-4417", "--rotate"); code != ExitFailed || !strings.Contains(errs, "at least 12") {
		t.Fatalf("short gate: %d %s", code, errs)
	}
}

func TestSecretsSameAsIsStoredOnce(t *testing.T) {
	h := newHarness(t)
	cat := filepath.Join(h.dir, "cat")
	os.MkdirAll(filepath.Join(cat, "gw"), 0o755)
	os.MkdirAll(filepath.Join(cat, "agent"), 0o755)
	os.WriteFile(filepath.Join(cat, "gw", "manifest.yaml"), []byte("id: gw\nsecrets:\n  - {name: APP_KEY_AGENT, description: x, generate: sk-hex32, share_with: [agent]}\n"), 0o644)
	os.WriteFile(filepath.Join(cat, "agent", "manifest.yaml"), []byte("id: agent\nsecrets:\n  - {name: GW_KEY, description: x, generate: none, same_as: gw/APP_KEY_AGENT}\n"), 0o644)
	if code, _, errs := h.run("secrets", "set", "agent", "GW_KEY", "--generate", "--catalog", cat, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "set that one (sealed secrets set gw APP_KEY_AGENT)") {
		t.Fatalf("same_as set: %d %s", code, errs)
	}
	code, out, errs := h.run("secrets", "set", "--missing", "--apps", "agent,gw", "--catalog", cat, "--project", "acme-prod-4417")
	if code != ExitOK || !strings.Contains(out, "generated sealed-gw-APP_KEY_AGENT") {
		t.Fatalf("missing: %d %s %s", code, out, errs)
	}
	if _, ok := h.store.v["sealed-agent-GW_KEY"]; ok {
		t.Fatal("same_as stored twice")
	}
	code, out, _ = h.run("secrets", "list", "--apps", "agent,gw", "--catalog", cat, "--project", "acme-prod-4417")
	if code != ExitOK || !strings.Contains(out, "same as gw/APP_KEY_AGENT (set)") {
		t.Fatalf("list:\n%s", out)
	}

	// D-059: without share_with in gw's manifest, nothing is stored and every command says why.
	os.WriteFile(filepath.Join(cat, "gw", "manifest.yaml"), []byte("id: gw\nsecrets:\n  - {name: APP_KEY_AGENT, description: x, generate: sk-hex32}\n"), 0o644)
	delete(h.store.v, "sealed-gw-APP_KEY_AGENT")
	if code, _, errs := h.run("secrets", "set", "--missing", "--apps", "agent,gw", "--catalog", cat, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "gw does not share it with agent") {
		t.Fatalf("unshared --missing: %d %s", code, errs)
	}
	if _, ok := h.store.v["sealed-gw-APP_KEY_AGENT"]; ok {
		t.Fatal("an unshared reference was generated")
	}
	if code, _, errs := h.run("secrets", "set", "agent", "GW_KEY", "--generate", "--catalog", cat, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "gw does not share it with agent (its share_with)") {
		t.Fatalf("unshared set: %d %s", code, errs)
	}
	if code, _, errs := h.run("secrets", "list", "--apps", "agent,gw", "--catalog", cat, "--project", "acme-prod-4417"); code != ExitFailed || !strings.Contains(errs, "D-059") {
		t.Fatalf("unshared list: %d %s", code, errs)
	}
}

// --- deploy ---

func TestDeployCommand(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, _, _ := h.world(false)
	conn, _ := token.Encode(token.Connection{V: 1, Project: "acme-prod-4417", Region: "us-central1",
		DeployerAccount: "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com", KeyBrokerURL: "https://kb.example.com", Customer: w.Customer.Hex()})
	stack := h.write("stack.yaml", fmt.Sprintf(`schema: sealed-deploy/v1
name: demo
connection: %s
image:
  id: 0x%s
  boot: projects/sealed-images-1/global/images/sealed-os-0-6-1
  systemDisk: projects/sealed-images-1/global/images/sealed-dstack-data-v1
apps:
  - id: notes
  - id: llm-gateway
endpoints:
  platformApi: https://api.sealed.example
  relay: https://attest.relay.sealed.example
  relayAttest: https://attest.relay.sealed.example/attest
relayOwner: "0x00000000000000000000000000000000000000b1"
`, conn, hex.EncodeToString(w.ImageID[:])))
	// Not approved: exit 3, instructions, no VM.
	code, out, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check")
	if code != ExitNotApproved || !strings.Contains(errs, "approveStack(bytes32,bytes32[],bytes32,uint64)") || len(h.compute.instances) != 0 {
		t.Fatalf("unapproved: %d\n%s\n%s", code, out, errs)
	}
	stackHash := strings.Fields(out[strings.Index(out, "stackHash"):])[1]
	sh, _ := registry.ParseHash32(stackHash)
	var ids [][32]byte
	for _, b := range w.Bundles {
		ids = append(ids, b.ReleaseID)
	}
	h.chain.Approve(common.HexToAddress(w.Customer.Hex()), sh, ids, w.ImageID)
	// Missing secrets stop it before any VM.
	code, _, errs = h.run("deploy", "--config", stack, "--dev-allow-unbuilt")
	if code != ExitFailed || !strings.Contains(errs, "sealed-notes-APP_SECRET") || len(h.compute.instances) != 0 {
		t.Fatalf("secrets: %d %s", code, errs)
	}
	code, out, errs = h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check", "--json", "--write-config", filepath.Join(h.dir, "config.json"))
	if code != ExitOK {
		t.Fatalf("deploy: %d\n%s\n%s", code, out, errs)
	}
	var sum map[string]any
	json.Unmarshal([]byte(out), &sum)
	if sum["created"] != true || sum["attestUrl"] != "https://attest.34-1-2-3.sslip.io/attest" || sum["stackHash"] != stackHash {
		t.Fatalf("summary %v", sum)
	}
	if in := h.compute.instances["sealed-demo"]; in == nil || len(deploy.CheckInstance(in)) != 0 {
		t.Fatal("instance")
	}
	if b, _ := os.ReadFile(filepath.Join(h.dir, "config.json")); !bytes.Contains(b, []byte(`"keyBroker":"https://kb.example.com"`)) {
		t.Fatalf("config %s", b)
	}
	first := sum["deploymentId"]
	// An upgrade (here a changed config) keeps the salt; the running VM is replaced only with --replace.
	raw, _ := os.ReadFile(stack)
	upgraded := h.write("stack-v2.yaml", string(raw)+"egressAdditions:\n  notes: [\"smtp.example.com:587\"]\n")
	code, out, _ = h.run("deploy", "--config", upgraded, "--dev-allow-unbuilt", "--skip-secrets-check", "--plan")
	if code != ExitNotApproved {
		t.Fatalf("upgrade plan: %d %s", code, out)
	}
	sh2, _ := registry.ParseHash32(strings.Fields(out[strings.Index(out, "stackHash"):])[1])
	h.chain.Approve(common.HexToAddress(w.Customer.Hex()), sh2, ids, w.ImageID)
	if code, _, errs := h.run("deploy", "--config", upgraded, "--dev-allow-unbuilt", "--skip-secrets-check"); code != ExitFailed || !strings.Contains(errs, "--replace") {
		t.Fatalf("upgrade without --replace: %d %s", code, errs)
	}
	code, out, errs = h.run("deploy", "--config", upgraded, "--dev-allow-unbuilt", "--skip-secrets-check", "--replace", "--json")
	sum = nil
	json.Unmarshal([]byte(out), &sum)
	if code != ExitOK || sum["replaced"] != first || sum["deploymentId"] == first {
		t.Fatalf("upgrade: %d %v %s", code, sum, errs)
	}
	if in := h.compute.instances["sealed-demo"]; deploy.DeploymentIDOf(in) != sum["deploymentId"] || len(h.compute.disks) != 1 {
		t.Fatalf("after the upgrade: %v disks %d", deploy.DeploymentIDOf(in), len(h.compute.disks))
	}
	// Production mode refuses unbuilt images, and the dev flag needs SEALED_DEV_SIM.
	if code, _, errs := h.run("deploy", "--config", stack, "--skip-secrets-check"); code != ExitFailed || !strings.Contains(errs, "unbuilt") {
		t.Fatalf("unbuilt: %d %s", code, errs)
	}
	delete(h.env, "SEALED_DEV_SIM")
	if code, _, _ := h.run("deploy", "--config", stack, "--dev-allow-unbuilt"); code != ExitUsage {
		t.Fatal("dev flag without SEALED_DEV_SIM")
	}
}

func TestDeployDebugImageCommand(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, _, _ := h.world(false)
	h.chain.Images[w.ImageID].IsDebug = true
	conn, _ := token.Encode(token.Connection{V: 1, Project: "acme-prod-4417", Region: "us-central1",
		DeployerAccount: "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com", KeyBrokerURL: "https://kb.example.com", Customer: w.Customer.Hex()})
	body := fmt.Sprintf(`schema: sealed-deploy/v1
name: dbg
connection: %s
image:
  id: 0x%s
  boot: projects/sealed-images-1/global/images/sealed-os-debug-0-6-1
  systemDisk: projects/sealed-images-1/global/images/sealed-dstack-data-v1
  debug: true
apps:
  - id: notes
  - id: llm-gateway
endpoints:
  platformApi: https://api.sealed.example
  relay: https://attest.relay.sealed.example
  relayAttest: https://attest.relay.sealed.example/attest
relayOwner: "0x00000000000000000000000000000000000000b1"
`, conn, hex.EncodeToString(w.ImageID[:]))
	stack := h.write("debug.yaml", body)
	// The deployer can never attach the log writer (spec 8.6).
	if code, _, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--as-deployer"); code != ExitUsage || !strings.Contains(errs, "deployer can never") {
		t.Fatalf("debug as deployer: %d %s", code, errs)
	}
	// Without image.debug the debug image is refused.
	if code, _, errs := h.run("deploy", "--config", h.write("nodebug.yaml", strings.Replace(body, "  debug: true\n", "", 1)), "--dev-allow-unbuilt"); code != ExitFailed || !strings.Contains(errs, "is a debug image") {
		t.Fatalf("debug image without image.debug: %d %s", code, errs)
	}
	// No approval and no secrets needed: the key broker gives a debug image nothing.
	code, out, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--json")
	if code != ExitOK || !strings.Contains(errs, "DEBUG IMAGE") {
		t.Fatalf("debug deploy: %d %s %s", code, out, errs)
	}
	var sum map[string]any
	json.Unmarshal([]byte(out), &sum)
	if sum["debug"] != true || sum["created"] != true {
		t.Fatalf("summary %v", sum)
	}
	in := h.compute.instances["sealed-dbg"]
	if in == nil || len(deploy.CheckDebugInstance(in, "sealed-debug-logs@acme-prod-4417.iam.gserviceaccount.com")) != 0 {
		t.Fatalf("debug VM %+v", in)
	}
}

// --- bootstrap ---

func TestBootstrapPrintsConnectionToken(t *testing.T) {
	h := newHarness(t)
	work := filepath.Join(h.dir, "work")
	args := []string{"--project", "acme-prod-4417", "--customer-address", "0x00000000000000000000000000000000000000c1",
		"--platform-sa", "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com",
		"--key-broker-image", "ghcr.io/sealedtempo/sealed-key-broker@sha256:" + strings.Repeat("ab", 32), "--work-dir", work}
	// The default key broker image is a placeholder until it is published.
	if code, _, errs := h.run("bootstrap", "--project", "acme-prod-4417", "--customer-address", "0x00000000000000000000000000000000000000c1", "--platform-sa", "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com"); code != ExitUsage || !strings.Contains(errs, "not published yet") {
		t.Fatalf("placeholder: %d %s", code, errs)
	}
	// Not a terminal and no --yes.
	if code, _, _ := h.run(append([]string{"bootstrap"}, args...)...); code != ExitUsage {
		t.Fatal("apply without --yes on a pipe")
	}
	code, out, errs := h.run(append([]string{"connect", "gcp", "--yes"}, args...)...)
	if code != ExitOK {
		t.Fatalf("bootstrap: %d %s %s", code, out, errs)
	}
	i := strings.Index(out, "sct_")
	tok := strings.Fields(out[i:])[0]
	c, err := token.Decode(tok)
	if err != nil || c.DeployerAccount != "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com" || c.IssuedAt != 1793200300 {
		t.Fatalf("token %v %+v", err, c)
	}
	var vars map[string]any
	b, _ := os.ReadFile(filepath.Join(work, "terraform.tfvars.json"))
	json.Unmarshal(b, &vars)
	if vars["platform_registry"] != strings.ToLower(testkit.Addresses.PlatformRegistry.Hex()) || vars["region"] != "us-central1" || vars["tempo_rpc_url"] != "https://rpc.tempo.xyz" {
		t.Fatalf("vars %v", vars)
	}
	if _, err := os.Stat(filepath.Join(work, "deployer.tf")); err != nil {
		t.Fatal("module not written")
	}
	if len(h.tf.calls) != 3 || h.tf.calls[1][0] != "apply" || h.tf.calls[1][2] != "-auto-approve" {
		t.Fatalf("terraform calls %v", h.tf.calls)
	}
	// --plan runs init and plan only.
	h.tf.calls = nil
	if code, _, _ := h.run(append([]string{"bootstrap", "--plan"}, args...)...); code != ExitOK || len(h.tf.calls) != 2 || h.tf.calls[1][0] != "plan" {
		t.Fatalf("plan: %v", h.tf.calls)
	}
	if code, _, _ := h.run("connect", "aws"); code != ExitUsage {
		t.Fatal("connect aws")
	}
}

// TestBootstrapNeverDropsTheCustomersRPC: the RPC the customer gave this command reaches the key broker's
// variables when --tempo-rpc is not set (review F5), and is shown before Terraform runs.
func TestBootstrapNeverDropsTheCustomersRPC(t *testing.T) {
	base := []string{"bootstrap", "--plan", "--project", "acme-prod-4417", "--customer-address", "0x00000000000000000000000000000000000000c1",
		"--platform-sa", "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com",
		"--key-broker-image", "ghcr.io/sealedtempo/key-broker@sha256:" + strings.Repeat("ab", 32)}
	for name, tc := range map[string]struct {
		env   map[string]string
		args  []string
		want  string
		shown string // the RPC as the command prints it: never its path or query
	}{
		"default":       {want: "https://rpc.tempo.xyz", shown: "https://rpc.tempo.xyz."},
		"--rpc":         {args: []string{"--rpc", "https://tempo.customer-node.example/rpc"}, want: "https://tempo.customer-node.example/rpc", shown: "https://tempo.customer-node.example (path and query not shown)."},
		"TEMPO_RPC_URL": {env: map[string]string{"TEMPO_RPC_URL": "https://tempo.customer-node.example/env"}, want: "https://tempo.customer-node.example/env", shown: "https://tempo.customer-node.example (path and query not shown)."},
		"--tempo-rpc":   {args: []string{"--rpc", "https://reader.example", "--tempo-rpc", "https://broker.customer.example"}, want: "https://broker.customer.example", shown: "https://broker.customer.example."},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			for k, v := range tc.env {
				h.env[k] = v
			}
			work := filepath.Join(h.dir, "work")
			code, _, errs := h.run(append(append(append([]string{}, base...), "--work-dir", work), tc.args...)...)
			if code != ExitOK {
				t.Fatalf("%d %s", code, errs)
			}
			var vars map[string]any
			b, _ := os.ReadFile(filepath.Join(work, "terraform.tfvars.json"))
			json.Unmarshal(b, &vars)
			if vars["tempo_rpc_url"] != tc.want || vars["chain_id"] != float64(4217) || vars["enable_debug_logging"] != false {
				t.Fatalf("vars %v", vars)
			}
			if !strings.Contains(errs, "The key broker will read Tempo chain 4217 through "+tc.shown) {
				t.Fatalf("effective RPC not shown: %s", errs)
			}
		})
	}
	h := newHarness(t)
	work := filepath.Join(h.dir, "work")
	if code, _, errs := h.run(append(append([]string{}, base...), "--work-dir", work, "--debug-logging", "--rpc", "http://plain.example")...); code != ExitUsage || !strings.Contains(errs, "https") {
		t.Fatalf("plain http RPC for the broker: %d %s", code, errs)
	}
	if code, _, errs := h.run(append(append([]string{}, base...), "--work-dir", work, "--debug-logging")...); code != ExitOK {
		t.Fatalf("%d %s", code, errs)
	}
	var vars map[string]any
	b, _ := os.ReadFile(filepath.Join(work, "terraform.tfvars.json"))
	json.Unmarshal(b, &vars)
	if vars["enable_debug_logging"] != true {
		t.Fatalf("--debug-logging: %v", vars)
	}
}

// TestBootstrapNeverPrintsTheRPCKey: a keyed Tempo RPC reaches the key broker's variables in full, but
// bootstrap prints only its scheme and host, in the plan, the summary and the JSON.
func TestBootstrapNeverPrintsTheRPCKey(t *testing.T) {
	const keyed = "https://tempo.provider.example/v2/FAKEAPIKEY0123456789"
	args := []string{"--project", "acme-prod-4417", "--customer-address", "0x00000000000000000000000000000000000000c1",
		"--platform-sa", "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com",
		"--key-broker-image", "ghcr.io/sealedtempo/sealed-key-broker@sha256:" + strings.Repeat("ab", 32), "--tempo-rpc", keyed}
	for _, mode := range [][]string{{"--plan"}, {"--yes"}, {"--yes", "--json"}} {
		h := newHarness(t)
		h.tf.rpc = keyed
		work := filepath.Join(h.dir, "work")
		code, out, errs := h.run(append(append([]string{"bootstrap", "--work-dir", work}, mode...), args...)...)
		if code != ExitOK {
			t.Fatalf("%v: %d %s", mode, code, errs)
		}
		if strings.Contains(out+errs, "FAKEAPIKEY0123456789") {
			t.Fatalf("%v: bootstrap printed the RPC API key:\n%s\n%s", mode, out, errs)
		}
		if !strings.Contains(errs, "through https://tempo.provider.example (path and query not shown)") {
			t.Errorf("%v: the effective RPC host is not shown: %s", mode, errs)
		}
		var vars map[string]any
		b, _ := os.ReadFile(filepath.Join(work, "terraform.tfvars.json"))
		json.Unmarshal(b, &vars)
		if vars["tempo_rpc_url"] != keyed {
			t.Fatalf("%v: the broker must still get the full RPC: %v", mode, vars["tempo_rpc_url"])
		}
	}
}

// TestBootstrapCreatesTheOSImages (D-075): after the apply, bootstrap creates the boot and system disk images in
// the project with the customer's own credentials, staged in the boot bucket; --plan only says so, --no-os-images
// skips it, and a failure says how to finish.
func TestBootstrapCreatesTheOSImages(t *testing.T) {
	args := []string{"bootstrap", "--project", "acme-prod-4417", "--customer-address", "0x00000000000000000000000000000000000000c1",
		"--platform-sa", "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com",
		"--key-broker-image", "ghcr.io/sealedtempo/sealed-key-broker@sha256:" + strings.Repeat("ab", 32)}
	h := newHarness(t)
	work := filepath.Join(h.dir, "work")
	code, out, errs := h.run(append(args, "--yes", "--work-dir", work)...)
	if code != ExitOK || len(h.osImgs.calls) != 1 {
		t.Fatalf("%d %d calls %s", code, len(h.osImgs.calls), errs)
	}
	o := h.osImgs.calls[0]
	if o.Project != "acme-prod-4417" || o.Bucket != "acme-prod-4417-sealed-boot" || o.Version != bootstrap.DefaultOSImageVersion ||
		o.AssetBase != "https://github.com/sealedtempo/sealed/releases/download" || o.Images == nil || o.Storage == nil || o.Dir != filepath.Join(work, "os-images") {
		t.Fatalf("os images %+v", o)
	}
	for _, want := range []string{
		"Boot image         projects/acme-prod-4417/global/images/sealed-dstack-os-0-6-1-s4",
		"Debug boot image   projects/acme-prod-4417/global/images/sealed-dstack-os-debug-0-6-1-s4",
		"System disk image  projects/acme-prod-4417/global/images/sealed-dstack-data-v1",
		"Binding            sealed-binding/v1 customer=0x00000000000000000000000000000000000000c1 key_broker=https://sealed-key-broker-xyz-uc.a.run.app",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	// JSON names the refs for image.boot and image.systemDisk, and the binding.
	h.osImgs.calls = nil
	code, out, _ = h.run(append(args, "--yes", "--json", "--work-dir", work, "--os-image-version", "0.6.2-s3")...)
	var sum struct {
		OSImages          map[string]string `json:"osImages"`
		ConnectionBinding string            `json:"connectionBinding"`
	}
	json.Unmarshal([]byte(out), &sum)
	if code != ExitOK || sum.OSImages["boot"] != "projects/acme-prod-4417/global/images/sealed-dstack-os-0-6-2-s3" ||
		sum.OSImages["systemDisk"] != "projects/acme-prod-4417/global/images/sealed-dstack-data-v1" || !strings.HasPrefix(sum.ConnectionBinding, "sealed-binding/v1 ") ||
		h.osImgs.calls[0].Version != "0.6.2-s3" {
		t.Fatalf("json %d %s", code, out)
	}
	// --plan creates nothing and names what the apply will create.
	h.osImgs.calls = nil
	code, _, errs = h.run(append(args, "--plan", "--work-dir", work)...)
	if code != ExitOK || len(h.osImgs.calls) != 0 || !strings.Contains(errs, "sealed-dstack-os-0-6-1-s4, sealed-dstack-os-debug-0-6-1-s4, sealed-dstack-data-v1 from https://github.com/sealedtempo/sealed/releases/download/os-image-v0.6.1-s4") {
		t.Fatalf("plan: %d %d %s", code, len(h.osImgs.calls), errs)
	}
	// --no-os-images skips them.
	code, out, _ = h.run(append(args, "--yes", "--no-os-images", "--work-dir", work)...)
	if code != ExitOK || len(h.osImgs.calls) != 0 || strings.Contains(out, "Boot image") {
		t.Fatalf("--no-os-images: %d %d", code, len(h.osImgs.calls))
	}
	// A bad version is refused before Terraform runs.
	h.tf.calls = nil
	if code, _, errs := h.run(append(args, "--yes", "--os-image-version", "latest", "--work-dir", work)...); code != ExitUsage || len(h.tf.calls) != 0 || !strings.Contains(errs, "--os-image-version") {
		t.Fatalf("bad version: %d %v %s", code, h.tf.calls, errs)
	}
	// A failed import fails the command and says the rerun is safe.
	h.osImgs.err = fmt.Errorf("sealed-dstack-os-0.6.1-s4-gce.tar.gz has sha256 00, but the release's hashes file says 11")
	code, out, errs = h.run(append(args, "--yes", "--work-dir", work)...)
	if code != ExitFailed || strings.Contains(out, "sct_") || !strings.Contains(errs, "OS images are not ready: sealed-dstack-os-0.6.1-s4-gce.tar.gz has sha256 00") || !strings.Contains(errs, "Run the same sealed bootstrap command again") {
		t.Fatalf("failed import: %d %s %s", code, out, errs)
	}
}

func TestUsageAndVersion(t *testing.T) {
	h := newHarness(t)
	if code, out, _ := h.run("version"); code != ExitOK || !strings.HasPrefix(out, "sealed ") {
		t.Fatal("version")
	}
	if code, _, _ := h.run("frobnicate"); code != ExitUsage {
		t.Fatal("unknown command")
	}
	for _, args := range [][]string{{"verify"}, {"deploy"}, {"catalog"}, {"release"}, {"secrets"}, {"secrets", "set"}} {
		if code, _, _ := h.run(args...); code != ExitUsage {
			t.Errorf("%v: want usage error", args)
		}
	}
}

// TestNoEmDashInCopy keeps user-facing strings free of em-dashes (rule 12).
func TestNoEmDashInCopy(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if bytes.ContainsRune(b, '\u2014') {
			t.Errorf("%s contains an em-dash", f)
		}
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
