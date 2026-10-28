package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/cli/internal/fatimg"
	"github.com/sealed-dev/sealed/cli/internal/gcp"
	"github.com/sealed-dev/sealed/cli/internal/settings"
	"github.com/sealed-dev/sealed/cli/internal/testkit"
	"github.com/sealed-dev/sealed/cli/internal/token"
	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/verifier/chain"
)

type fakeCompute struct {
	addresses map[string]*gcp.Address
	disks     map[string]*gcp.Disk
	instances map[string]*gcp.Instance
	calls     []string
	// mutate lets a test change what the API stores (for example a default service account).
	mutate func(*gcp.Instance)
}

func newFakeCompute() *fakeCompute {
	return &fakeCompute{addresses: map[string]*gcp.Address{}, disks: map[string]*gcp.Disk{}, instances: map[string]*gcp.Instance{}}
}

func notFound() error { return &gcp.APIError{HTTPStatus: http.StatusNotFound} }

func (f *fakeCompute) GetAddress(_ context.Context, region, name string) (*gcp.Address, error) {
	if a, ok := f.addresses[region+"/"+name]; ok {
		return a, nil
	}
	return nil, notFound()
}

func (f *fakeCompute) EnsureAddress(ctx context.Context, region, name, _ string) (*gcp.Address, error) {
	f.calls = append(f.calls, "address "+name)
	if a, err := f.GetAddress(ctx, region, name); err == nil {
		return a, nil
	}
	a := &gcp.Address{Name: name, Address: "34.1.2.3", Status: "RESERVED"}
	f.addresses[region+"/"+name] = a
	return a, nil
}

func (f *fakeCompute) EnsureDisk(_ context.Context, zone string, d gcp.Disk) (*gcp.Disk, bool, error) {
	f.calls = append(f.calls, "disk "+d.Name)
	if got, ok := f.disks[zone+"/"+d.Name]; ok {
		return got, false, nil
	}
	d.SelfLink = "https://compute.googleapis.com/compute/v1/projects/acme-prod-4417/zones/" + zone + "/disks/" + d.Name
	f.disks[zone+"/"+d.Name] = &d
	return &d, true, nil
}

func (f *fakeCompute) InsertInstance(_ context.Context, zone string, in *gcp.Instance, reqID string) error {
	f.calls = append(f.calls, "instance "+in.Name+" "+reqID)
	if _, ok := f.instances[zone+"/"+in.Name]; ok {
		return gcp.ErrInstanceExists
	}
	cp := *in
	if f.mutate != nil {
		f.mutate(&cp)
	}
	f.instances[zone+"/"+in.Name] = &cp
	return nil
}

func (f *fakeCompute) GetInstance(_ context.Context, zone, name string) (*gcp.Instance, error) {
	if in, ok := f.instances[zone+"/"+name]; ok {
		return in, nil
	}
	return nil, notFound()
}

type fakeShared struct{ files map[string][]byte }

func (f *fakeShared) Ensure(_ context.Context, name string, files map[string][]byte) (string, error) {
	f.files = files
	return "projects/acme-prod-4417/global/images/" + name, nil
}

type memSecrets struct{ names map[string]bool }

func (m *memSecrets) Exists(_ context.Context, n string) (bool, error) { return m.names[n], nil }
func (m *memSecrets) Create(_ context.Context, n string, _ map[string]string, _ string) error {
	m.names[n] = true
	return nil
}
func (m *memSecrets) AddVersion(context.Context, string, []byte) (string, error) { return "", nil }
func (m *memSecrets) Delete(_ context.Context, n string) error {
	delete(m.names, n)
	return nil
}
func (m *memSecrets) List(_ context.Context, prefix string) ([]gcp.SecretInfo, error) {
	var out []gcp.SecretInfo
	for n := range m.names {
		if strings.HasPrefix(n, prefix) {
			out = append(out, gcp.SecretInfo{Name: n})
		}
	}
	return out, nil
}

var customer = common.HexToAddress("0x00000000000000000000000000000000000000c1")

func connection(t *testing.T) string {
	tok, err := token.Encode(token.Connection{V: 1, Project: "acme-prod-4417", Region: "us-central1",
		DeployerAccount: "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com",
		KeyBrokerURL:    "https://sealed-key-broker-abc-uc.a.run.app", Customer: customer.Hex()})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func stackYAML(t *testing.T, extra string) string {
	return fmt.Sprintf(`schema: sealed-deploy/v1
name: demo
connection: %s
image:
  id: 0x%x
  boot: projects/sealed-images-1/global/images/sealed-os-0-6-1
  systemDisk: projects/sealed-images-1/global/images/sealed-dstack-data-v1
  vmConfig: '{"spec_version":2}'
apps:
  - id: notes
  - id: llm-gateway
    release: 2.3.4
endpoints:
  platformApi: https://api.sealed.example
  relay: https://attest.relay.sealed.example
  relayAttest: https://attest.relay.sealed.example/attest
relayOwner: "0x00000000000000000000000000000000000000b1"
egressAdditions:
  notes: ["smtp.example.com:587"]
%s`, connection(t), testkit.SimImageID(false), extra)
}

type rig struct {
	d       *Deployer
	chain   *testkit.MemChain
	compute *fakeCompute
	shared  *fakeShared
	notes   *composer.Bundle
	gw      *composer.Bundle
	out     *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	s, err := settings.Load(settings.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Registries = testkit.Addresses
	notes, gw := testkit.Bundle(t, "notes"), testkit.Bundle(t, "llm-gateway")
	m := testkit.NewMemChain()
	m.Images[testkit.SimImageID(false)] = &chain.Image{MeasurementsHash: [32]byte{1}, Status: chain.ImageActive, Name: "sealed-sim", Version: "1.0.0"}
	for _, b := range []*composer.Bundle{notes, gw} {
		m.AddRelease(b.Manifest.ID, b.Version(), b.Hash, b.EgressPolicyHash, b.SBOMHash)
	}
	srv := testkit.NewBundleServer(t, notes, gw)
	r := &rig{chain: m, compute: newFakeCompute(), shared: &fakeShared{}, notes: notes, gw: gw, out: &bytes.Buffer{}}
	// The runtime sidecar images are not built yet (all-zero digests), so the rig composes in dev mode;
	// TestDeployRefusesUnbuiltImages covers the production default.
	r.d = &Deployer{Settings: s, Chain: m, Fetcher: srv.Fetcher(""), Compute: r.compute, Shared: r.shared, Out: r.out, AllowUnbuilt: true}
	return r
}

func (r *rig) plan(t *testing.T, extra string) *Plan {
	t.Helper()
	s, err := ParseStackFile([]byte(stackYAML(t, extra)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.d.Prepare(context.Background(), s, true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (r *rig) approve(p *Plan) {
	var ids [][32]byte
	for _, rel := range p.Releases {
		ids = append(ids, rel.ReleaseID)
	}
	r.chain.Approve(customer, p.Result.StackHash, ids, testkit.SimImageID(false))
}

func TestDeployStopsUntilApproved(t *testing.T) {
	r := newRig(t)
	p := r.plan(t, "")
	if p.Approval.Approved || len(p.Approval.Problems) == 0 {
		t.Fatalf("approval %+v", p.Approval)
	}
	if _, err := r.d.Apply(context.Background(), p); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("apply without approval: %v", err)
	}
	for _, c := range r.compute.calls {
		if !strings.HasPrefix(c, "address ") {
			t.Fatalf("created %s before approval", c)
		}
	}
	instr := p.ApprovalInstructions(testkit.Addresses.DeploymentRegistry, "https://rpc.tempo.xyz", "0x20c000000000000000000000b9537d11c60e8b50")
	for _, want := range []string{p.Result.StackHash.Hex(), p.Stack.Image.ID, "approveStack(bytes32,bytes32[],bytes32,uint64)", "--tempo.fee-token", "Nothing was created"} {
		if !strings.Contains(instr, want) {
			t.Errorf("instructions lack %q:\n%s", want, instr)
		}
	}
	if strings.Contains(instr, "\u2014") {
		t.Error("em-dash in copy")
	}
}

func TestDeployCreatesTheConfidentialVM(t *testing.T) {
	r := newRig(t)
	p := r.plan(t, "")
	// The config is exactly what the composer accepts, with the bootstrap's key broker and the reserved IP.
	cfg, err := composer.ParseConfig(p.ConfigJSON)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoints.KeyBroker != "https://sealed-key-broker-abc-uc.a.run.app" || cfg.Hostnames.IP != "34.1.2.3" || cfg.Customer != "0x00000000000000000000000000000000000000c1" {
		t.Fatalf("config %+v", cfg)
	}
	if cfg.ComposerVersion != composer.Version || cfg.Contracts.DeploymentRegistry != "0x00000000000000000000000000000000000000e3" || cfg.FeeToken != "0x20c000000000000000000000b9537d11c60e8b50" {
		t.Fatalf("config %+v", cfg)
	}
	if cfg.Apps[0].ID != "llm-gateway" || cfg.Apps[0].ReleaseID != r.gw.ReleaseID.Hex() || cfg.Apps[1].ReleaseID != r.notes.ReleaseID.Hex() {
		t.Fatalf("apps %+v", cfg.Apps)
	}
	r.approve(p)
	p = r.plan(t, "")
	if !p.Approval.Approved {
		t.Fatalf("approval %+v", p.Approval)
	}
	out, err := r.d.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Created || out.DeploymentID != p.Result.DeploymentID.Hex() || out.AttestURL != "https://attest.34-1-2-3.sslip.io/attest" {
		t.Fatalf("outcome %+v", out)
	}
	in := r.compute.instances["us-central1-a/sealed-demo"]
	if in == nil {
		t.Fatal("no instance")
	}
	if problems := CheckInstance(in); len(problems) > 0 {
		t.Fatalf("instance problems: %v", problems)
	}
	if in.MachineType != "zones/us-central1-a/machineTypes/c3-standard-8" || in.NetworkInterfaces[0].AccessConfigs[0].NatIP != "34.1.2.3" {
		t.Fatalf("machine %s nat %+v", in.MachineType, in.NetworkInterfaces[0])
	}
	if in.Disks[3].DeviceName != "sealed-data" || !strings.HasSuffix(in.Disks[3].Source, "/disks/sealed-demo-data") || in.Disks[3].AutoDelete {
		t.Fatalf("data disk %+v", in.Disks[3])
	}
	if d := r.compute.disks["us-central1-a/sealed-demo-data"]; d == nil || d.SizeGb != "50" || !strings.HasSuffix(d.Type, "pd-balanced") {
		t.Fatalf("data disk %+v", d)
	}
	for _, d := range in.Disks {
		if d.Interface != "NVME" {
			t.Fatal("TDX needs NVMe disks")
		}
		if d.InitializeParams != nil && !strings.HasPrefix(d.InitializeParams.DiskName, "sealed-") {
			t.Fatalf("disk name %q is outside the deployer's condition", d.InitializeParams.DiskName)
		}
	}
	// The shared disk carries the exact measured app-compose.json.
	if got := sha256.Sum256(r.shared.files["app-compose.json"]); got != [32]byte(p.Result.StackHash) {
		t.Fatal("shared app-compose.json is not the approved stack")
	}
	if !strings.Contains(string(r.shared.files[".sys-config.json"]), `"vm_config":"{\"spec_version\":2}"`) {
		t.Fatalf("sys config %s", r.shared.files[".sys-config.json"])
	}
	if strings.Contains(string(r.shared.files[".instance_info"]), "app_id") {
		t.Fatal("app_id must stay absent")
	}
	// Every created resource is named sealed-*.
	for _, c := range r.compute.calls {
		if !strings.Contains(c, " sealed-") {
			t.Fatalf("call %q", c)
		}
	}
	// A rerun is a no-op.
	r.compute.calls = nil
	out2, err := r.d.Apply(context.Background(), r.plan(t, ""))
	if err != nil || out2.Created {
		t.Fatalf("rerun: %+v %v", out2, err)
	}
	for _, c := range r.compute.calls {
		if strings.HasPrefix(c, "instance") || strings.HasPrefix(c, "disk") {
			t.Fatalf("rerun created %s", c)
		}
	}
}

func TestDeployRefusesNonCompliantReadBack(t *testing.T) {
	r := newRig(t)
	r.approve(r.plan(t, ""))
	r.compute.mutate = func(in *gcp.Instance) {
		in.ServiceAccounts = []gcp.ServiceAccount{{Email: "123-compute@developer.gserviceaccount.com", Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"}}}
	}
	_, err := r.d.Apply(context.Background(), r.plan(t, ""))
	if err == nil || !strings.Contains(err.Error(), "service account") {
		t.Fatalf("want a compliance error, got %v", err)
	}
}

func TestDeployChecksApprovalReleaseSet(t *testing.T) {
	r := newRig(t)
	p := r.plan(t, "")
	// Approved with another release list for the same stackHash (D-014).
	r.chain.Approve(customer, p.Result.StackHash, [][32]byte{p.Releases[0].ReleaseID}, testkit.SimImageID(false))
	p = r.plan(t, "")
	if p.Approval.Approved {
		t.Fatal("an approval naming other releases was accepted")
	}
}

func TestDeployRequiresSecrets(t *testing.T) {
	r := newRig(t)
	r.approve(r.plan(t, ""))
	store := &memSecrets{names: map[string]bool{}}
	r.d.Secrets = store
	p := r.plan(t, "")
	if len(p.MissingSecrets) == 0 || !strings.Contains(strings.Join(p.MissingSecrets, ","), "sealed-notes-APP_SECRET") || !strings.Contains(strings.Join(p.MissingSecrets, ","), "sealed-gate-password") {
		t.Fatalf("missing %v", p.MissingSecrets)
	}
	if strings.Contains(strings.Join(p.MissingSecrets, ","), "SMTP_PASSWORD") {
		t.Fatal("optional secret reported missing")
	}
	if _, err := r.d.Apply(context.Background(), p); err == nil || !strings.Contains(err.Error(), "missing secrets") {
		t.Fatalf("apply with missing secrets: %v", err)
	}
	for _, n := range p.MissingSecrets {
		store.names[n] = true
	}
	if p = r.plan(t, ""); len(p.MissingSecrets) != 0 {
		t.Fatalf("still missing %v", p.MissingSecrets)
	}
}

func TestDeployRefusesDebugImageAndRevokedRelease(t *testing.T) {
	r := newRig(t)
	r.chain.Images[testkit.SimImageID(false)].IsDebug = true
	s, _ := ParseStackFile([]byte(stackYAML(t, "")))
	if _, err := r.d.Prepare(context.Background(), s, true); err == nil || !strings.Contains(err.Error(), "production image") {
		t.Fatalf("debug image: %v", err)
	}
	r = newRig(t)
	r.chain.Releases[r.notes.ReleaseID].Status = chain.ReleaseRevoked
	s, _ = ParseStackFile([]byte(stackYAML(t, "")))
	if _, err := r.d.Prepare(context.Background(), s, true); err == nil || !strings.Contains(err.Error(), "no active release") {
		t.Fatalf("revoked latest: %v", err)
	}
	s, _ = ParseStackFile([]byte(strings.Replace(stackYAML(t, ""), "  - id: notes\n", "  - id: notes\n    release: "+r.notes.ReleaseID.Hex()+"\n", 1)))
	if _, err := r.d.Prepare(context.Background(), s, true); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked by id: %v", err)
	}
}

func TestDeployRefusesUnbuiltImages(t *testing.T) {
	r := newRig(t)
	r.d.AllowUnbuilt = false
	s, _ := ParseStackFile([]byte(stackYAML(t, "")))
	if _, err := r.d.Prepare(context.Background(), s, true); err == nil || !strings.Contains(err.Error(), "unbuilt") {
		t.Fatalf("unbuilt images accepted: %v", err)
	}
}

func TestPlanWithoutReservedIP(t *testing.T) {
	r := newRig(t)
	s, _ := ParseStackFile([]byte(stackYAML(t, "")))
	if _, err := r.d.Prepare(context.Background(), s, false); err == nil || !strings.Contains(err.Error(), "not reserved") {
		t.Fatalf("plan without IP: %v", err)
	}
	if len(r.compute.calls) != 0 {
		t.Fatal("a plan reserved an IP")
	}
}

func TestStackFileValidation(t *testing.T) {
	good := stackYAML(t, "")
	s, err := ParseStackFile([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if s.Project != "acme-prod-4417" || s.Zone != "us-central1-a" || s.Apps[0].ID != "llm-gateway" || s.Apps[1].Release != "latest" {
		t.Fatalf("normalized %+v", s)
	}
	if s.SaltHex() != s.SaltHex() || !strings.HasPrefix(s.SaltHex(), "0x") || len(s.SaltHex()) != 66 {
		t.Fatal("derived salt")
	}
	other, _ := ParseStackFile([]byte(strings.Replace(good, "name: demo", "name: demo2", 1)))
	if other.SaltHex() == s.SaltHex() {
		t.Fatal("salt must differ per name")
	}
	for name, edit := range map[string][2]string{
		"unknown key":       {"name: demo", "name: demo\nflavor: x"},
		"bad name":          {"name: demo", "name: Demo"},
		"bad zone":          {"name: demo", "name: demo\nzone: europe-west4-a"},
		"bad machine":       {"name: demo", "name: demo\nmachineType: n2-standard-8"},
		"project conflict":  {"name: demo", "name: demo\nproject: other-proj-123"},
		"tag image":         {"boot: projects/sealed-images-1/global/images/sealed-os-0-6-1", "boot: ubuntu"},
		"duplicate app":     {"  - id: notes\n", "  - id: notes\n  - id: notes\n"},
		"schema":            {"schema: sealed-deploy/v1", "schema: other"},
		"bad salt":          {"name: demo", "name: demo\nsalt: 0x12"},
		"bad relay owner":   {`relayOwner: "0x00000000000000000000000000000000000000b1"`, `relayOwner: "0x1"`},
		"small data disk":   {"name: demo", "name: demo\ndataDiskGb: 1"},
		"bad image id":      {"  id: 0x", "  id: 0xzz"},
		"bad boot bucket":   {"name: demo", "name: demo\nbootBucket: A"},
		"empty connection":  {"connection: sct_", "connection: nope_"},
		"no apps":           {"apps:\n  - id: notes\n  - id: llm-gateway\n    release: 2.3.4\n", "apps: []\n"},
		"custom zone match": {"name: demo", "name: demo\nzone: us-central1"},
	} {
		y := strings.Replace(good, edit[0], edit[1], 1)
		if y == good {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := ParseStackFile([]byte(y)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestBuildInstanceNeverSetsIdentityOrShell(t *testing.T) {
	in := BuildInstance(InstanceParams{Project: "p-123456", Region: "us-central1", Zone: "us-central1-a", Names: (&StackFile{Name: "x1"}).Names(),
		MachineType: "c3-standard-8", BootImage: "b", SystemDiskImage: "s", SharedDiskImage: "h", DataDiskSelfLink: "d", NatIP: "1.2.3.4", DeploymentID: "0x" + strings.Repeat("ab", 32)})
	if in.ServiceAccounts == nil || len(in.ServiceAccounts) != 0 {
		t.Fatal("service accounts must be an explicit empty list")
	}
	if p := CheckInstance(in); len(p) != 0 {
		t.Fatal(p)
	}
	if in.ShieldedInstanceConfig.EnableSecureBoot || !in.ShieldedInstanceConfig.EnableVtpm {
		t.Fatal("secure boot off, vTPM on (dstack)")
	}
	if in.Labels["sealed-deployment"] != strings.Repeat("ab", 8) {
		t.Fatalf("labels %v", in.Labels)
	}
	for _, mut := range []func(*gcp.Instance){
		func(i *gcp.Instance) {
			i.Metadata.Items = append(i.Metadata.Items, gcp.MetadataItem{Key: "ssh-keys", Value: "x"})
		},
		func(i *gcp.Instance) { i.Metadata.Items[3].Value = "TRUE" },
		func(i *gcp.Instance) { i.ConfidentialInstanceConfig = nil },
		func(i *gcp.Instance) { i.Tags = nil },
		func(i *gcp.Instance) { i.Disks[3].AutoDelete = true },
		func(i *gcp.Instance) { i.Scheduling.OnHostMaintenance = "MIGRATE" },
	} {
		c := BuildInstance(InstanceParams{Names: (&StackFile{Name: "x1"}).Names(), Zone: "z", Region: "r", Project: "p"})
		mut(c)
		if len(CheckInstance(c)) == 0 {
			t.Error("a violation was not detected")
		}
	}
}

type fakeImages struct {
	inserted *gcp.Image
	exists   bool
}

func (f *fakeImages) GetImage(context.Context, string) (*gcp.Image, error) {
	if f.exists {
		return &gcp.Image{Status: "READY"}, nil
	}
	return nil, notFound()
}

func (f *fakeImages) InsertImage(_ context.Context, img gcp.Image) error {
	f.inserted = &img
	return nil
}

type fakeUpload struct {
	bucket, object string
	data           []byte
}

func (f *fakeUpload) Upload(_ context.Context, bucket, object, _ string, data []byte) (string, error) {
	f.bucket, f.object, f.data = bucket, object, data
	return "https://storage.googleapis.com/" + bucket + "/" + object, nil
}

func TestGCESharedDisk(t *testing.T) {
	imgs, up := &fakeImages{}, &fakeUpload{}
	g := &GCEShared{Project: "acme-prod-4417", Bucket: "acme-prod-4417-sealed-boot", Images: imgs, Storage: up, PadTo: 32 << 20}
	files := map[string][]byte{"app-compose.json": []byte(`{"x":1}`), ".sys-config.json": []byte(`{}`)}
	ref, err := g.Ensure(context.Background(), "sealed-demo-shared-abc", files)
	if err != nil {
		t.Fatal(err)
	}
	if ref != "projects/acme-prod-4417/global/images/sealed-demo-shared-abc" || imgs.inserted == nil || imgs.inserted.RawDisk.Source != "https://storage.googleapis.com/acme-prod-4417-sealed-boot/sealed-demo-shared-abc.tar.gz" {
		t.Fatalf("ref %s image %+v", ref, imgs.inserted)
	}
	raw, name, err := readRawDisk(up.data)
	if err != nil || name != "disk.raw" || len(raw) != 32<<20 {
		t.Fatalf("tarball: %s %d %v", name, len(raw), err)
	}
	want, _ := fatimg.Build(files)
	if !bytes.Equal(raw[:len(want)], want) || bytes.ContainsFunc(raw[len(want):], func(r rune) bool { return r != 0 }) {
		t.Fatal("raw disk is not the FAT volume followed by zeros")
	}
	// An existing image is reused.
	imgs.exists, imgs.inserted = true, nil
	if _, err := g.Ensure(context.Background(), "sealed-demo-shared-abc", files); err != nil || imgs.inserted != nil {
		t.Fatal("existing image not reused")
	}
	if _, err := (&GCEShared{Images: &fakeImages{}, Storage: up}).Ensure(context.Background(), "x", files); err == nil {
		t.Fatal("no bucket accepted")
	}
}

func TestExampleStackFileParses(t *testing.T) {
	s, err := LoadStackFile(filepath.Join("..", "..", "examples", "stack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "demo" || len(s.Apps) != 2 || s.Apps[0].Release != "latest" || s.Names().DataDisk != "sealed-demo-data" {
		t.Fatalf("%+v", s)
	}
}
