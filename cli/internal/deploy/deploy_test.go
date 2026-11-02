package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/cli/internal/embedded"
	"github.com/sealedtempo/sealed/cli/internal/fatimg"
	"github.com/sealedtempo/sealed/cli/internal/gcp"
	"github.com/sealedtempo/sealed/cli/internal/settings"
	"github.com/sealedtempo/sealed/cli/internal/testkit"
	"github.com/sealedtempo/sealed/cli/internal/token"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/rimembed"
	"github.com/sealedtempo/sealed/verifier/chain"
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

func (f *fakeCompute) DeleteInstance(_ context.Context, zone, name string) error {
	f.calls = append(f.calls, "delete "+name)
	if _, ok := f.instances[zone+"/"+name]; !ok {
		return notFound()
	}
	delete(f.instances, zone+"/"+name)
	return nil
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
	// A released repo pins every sidecar, so compose one sidecar back to the placeholder to make the stack unbuilt.
	r.d.RuntimeImages = unbuiltRuntimeImages(t)
	s, _ := ParseStackFile([]byte(stackYAML(t, "")))
	if _, err := r.d.Prepare(context.Background(), s, true); err == nil || !strings.Contains(err.Error(), "unbuilt") {
		t.Fatalf("unbuilt images accepted: %v", err)
	}
}

// unbuiltRuntimeImages returns the embedded sidecar set with sealed-agent reset to the placeholder digest.
func unbuiltRuntimeImages(t *testing.T) *composer.RuntimeImages {
	t.Helper()
	ri, err := rimembed.Load()
	if err != nil {
		t.Fatal(err)
	}
	const zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	a := ri.Images["sealed-agent"]
	a.Digest = zero
	a.Unbuilt = true
	a.Ref = ri.Registry + "/sealed-agent@" + zero
	return ri
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

func TestDebugInstanceGetsOnlyTheLogWriter(t *testing.T) {
	sa := DebugLogServiceAccount("acme-prod-4417")
	if sa != "sealed-debug-logs@acme-prod-4417.iam.gserviceaccount.com" {
		t.Fatal(sa)
	}
	params := InstanceParams{Project: "acme-prod-4417", Region: "us-central1", Zone: "us-central1-a", Names: (&StackFile{Name: "dbg"}).Names(),
		MachineType: "c3-standard-8", DataDiskSelfLink: "d", DeploymentID: "0x" + strings.Repeat("cd", 32), DebugLogSA: sa}
	in := BuildInstance(params)
	if len(in.ServiceAccounts) != 1 || in.ServiceAccounts[0].Email != sa || strings.Join(in.ServiceAccounts[0].Scopes, ",") != "https://www.googleapis.com/auth/logging.write" {
		t.Fatalf("debug identity %+v", in.ServiceAccounts)
	}
	if in.Labels[VariantLabel] != "debug" || !strings.Contains(in.Description, "DEBUG") {
		t.Fatalf("labels %v description %q", in.Labels, in.Description)
	}
	if p := CheckDebugInstance(in, sa); len(p) != 0 {
		t.Fatal(p)
	}
	// Checked as production, the same VM fails: production VMs never have a service account.
	if p := CheckInstance(in); len(p) == 0 {
		t.Fatal("a VM with a service account passed the production check")
	}
	// A production VM never passes as a debug VM either, and carries no identity.
	prod := BuildInstance(InstanceParams{Names: (&StackFile{Name: "x1"}).Names(), Zone: "z", Region: "r", Project: "p"})
	if len(prod.ServiceAccounts) != 0 || prod.Labels[VariantLabel] != "production" || len(CheckDebugInstance(prod, sa)) == 0 {
		t.Fatalf("production %+v %v", prod.ServiceAccounts, prod.Labels)
	}
	if len(CheckDebugInstance(in, "")) == 0 {
		t.Fatal("a debug check without an identity passed")
	}
	for name, mut := range map[string]func(*gcp.Instance){
		"broad scope": func(i *gcp.Instance) {
			i.ServiceAccounts[0].Scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
		},
		"extra scope": func(i *gcp.Instance) {
			i.ServiceAccounts[0].Scopes = append(i.ServiceAccounts[0].Scopes, "https://www.googleapis.com/auth/devstorage.read_only")
		},
		"other identity": func(i *gcp.Instance) {
			i.ServiceAccounts[0].Email = "sealed-key-broker@acme-prod-4417.iam.gserviceaccount.com"
		},
		"two identities": func(i *gcp.Instance) { i.ServiceAccounts = append(i.ServiceAccounts, i.ServiceAccounts[0]) },
		"no identity":    func(i *gcp.Instance) { i.ServiceAccounts = nil },
		"not labeled":    func(i *gcp.Instance) { delete(i.Labels, VariantLabel) },
		"serial port":    func(i *gcp.Instance) { i.Metadata.Items[3].Value = "TRUE" },
	} {
		c := BuildInstance(params)
		mut(c)
		if len(CheckDebugInstance(c, sa)) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
	// The names and the scope match the bootstrap module (debug_logging.tf, modules/iam).
	mod := embedded.BootstrapModule()
	main, _ := fs.ReadFile(mod, "main.tf")
	iam, _ := fs.ReadFile(mod, "modules/iam/main.tf")
	if !strings.Contains(string(main), `debug_logs_sa_id  = "`+DebugLogAccountID+`"`) || !strings.Contains(string(iam), `debug_vm_scopes      = ["`+DebugLogScopes[0]+`"]`) {
		t.Fatal("the debug identity name or scope drifted from infra/terraform/customer-bootstrap")
	}
}

// debugRig is a rig whose image is registered as a debug image.
func debugRig(t *testing.T) *rig {
	r := newRig(t)
	r.chain.Images[testkit.SimImageID(false)].IsDebug = true
	return r
}

func TestDeployDebugImage(t *testing.T) {
	ctx := context.Background()
	// image.debug on a production image is refused: a production VM never gets an identity.
	r := newRig(t)
	s, _ := ParseStackFile([]byte(strings.Replace(stackYAML(t, ""), "  vmConfig:", "  debug: true\n  vmConfig:", 1)))
	if !s.Image.Debug {
		t.Fatal("image.debug not parsed")
	}
	if _, err := r.d.Prepare(ctx, s, true); err == nil || !strings.Contains(err.Error(), "production VMs never get a service account") {
		t.Fatalf("image.debug on a production image: %v", err)
	}

	r = debugRig(t)
	store := &memSecrets{names: map[string]bool{}}
	r.d.Secrets = store
	p, err := r.d.Prepare(ctx, s, true)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Debug || p.DebugLogSA != "sealed-debug-logs@acme-prod-4417.iam.gserviceaccount.com" || p.Approval.Approved || len(p.MissingSecrets) == 0 {
		t.Fatalf("plan debug=%v sa=%q approval=%+v missing=%v", p.Debug, p.DebugLogSA, p.Approval, p.MissingSecrets)
	}
	if composerHasDebug() {
		if !bytes.Contains(p.ConfigJSON, []byte(`"debug":true`)) {
			t.Fatalf("debug config %s", p.ConfigJSON)
		}
	} else if !strings.Contains(r.out.String(), "has no config.debug") {
		t.Fatalf("no warning about the missing config.debug:\n%s", r.out)
	}
	// Never approvable and never given secrets, so neither gates a debug VM.
	out, err := r.d.Apply(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Created || !out.Debug {
		t.Fatalf("outcome %+v", out)
	}
	in := r.compute.instances["us-central1-a/sealed-demo"]
	if p := CheckDebugInstance(in, "sealed-debug-logs@acme-prod-4417.iam.gserviceaccount.com"); len(p) != 0 {
		t.Fatal(p)
	}
	if d := r.compute.disks["us-central1-a/sealed-demo-data"]; d.Labels[VariantLabel] != "debug" {
		t.Fatalf("data disk labels %v", d.Labels)
	}

	// A debug VM never gets a production deployment's data disk.
	r = debugRig(t)
	r.compute.disks["us-central1-a/sealed-demo-data"] = &gcp.Disk{Name: "sealed-demo-data", Labels: map[string]string{VariantLabel: "production", DiskIDLabel: DiskID(customer.Hex(), s.SaltHex())}}
	p, err = r.d.Prepare(ctx, s, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.d.Apply(ctx, p); err == nil || !strings.Contains(err.Error(), "never gets production data") {
		t.Fatalf("debug VM on a production disk: %v", err)
	}
	if _, ok := r.compute.instances["us-central1-a/sealed-demo"]; ok {
		t.Fatal("a VM was created")
	}
	// Nor an unlabeled one (it may hold production data).
	r.compute.disks["us-central1-a/sealed-demo-data"].Labels = nil
	if _, err := r.d.Apply(ctx, p); err == nil || !strings.Contains(err.Error(), "never gets production data") {
		t.Fatalf("debug VM on an unlabeled disk: %v", err)
	}

	// A revoked debug image is refused.
	r = debugRig(t)
	r.chain.Images[testkit.SimImageID(false)].Status = chain.ImageRevoked
	if _, err := r.d.Prepare(ctx, s, true); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("revoked debug image: %v", err)
	}
}

// TestDeployUpgradeKeepsSaltAndDisk: D-058. The salt depends only on project and name, so an upgrade (here a
// changed config, which changes the stack and the deploymentId) keeps it, and with it the data disk key. The old VM
// is replaced only with Replace, after the kept disk was checked.
func TestDeployUpgradeKeepsSaltAndDisk(t *testing.T) {
	ctx := context.Background()
	base, _ := ParseStackFile([]byte(stackYAML(t, "")))
	for _, edit := range [][2]string{
		{"  - id: llm-gateway\n    release: 2.3.4\n", ""},
		{"    release: 2.3.4", "    release: 9.9.9"},
		{fmt.Sprintf("id: 0x%x", testkit.SimImageID(false)), "id: 0x" + strings.Repeat("ab", 32)},
		{`notes: ["smtp.example.com:587"]`, `notes: ["smtp.example.com:465"]`},
	} {
		up, err := ParseStackFile([]byte(strings.Replace(stackYAML(t, ""), edit[0], edit[1], 1)))
		if err != nil {
			t.Fatal(err)
		}
		if up.SaltHex() != base.SaltHex() {
			t.Fatalf("%q changed the salt", edit[1])
		}
	}

	r := newRig(t)
	first := r.plan(t, "")
	r.approve(first)
	first = r.plan(t, "")
	if _, err := r.d.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	disk := r.compute.disks["us-central1-a/sealed-demo-data"]
	if disk.Labels[DiskIDLabel] != DiskID(customer.Hex(), base.SaltHex()) || disk.Labels[VariantLabel] != "production" || len(disk.Labels[DiskIDLabel]) != 40 {
		t.Fatalf("data disk labels %v", disk.Labels)
	}

	upgraded := strings.Replace(stackYAML(t, ""), `notes: ["smtp.example.com:587"]`, `notes: ["smtp.example.com:465"]`, 1)
	plan := func() *Plan {
		s, err := ParseStackFile([]byte(upgraded))
		if err != nil {
			t.Fatal(err)
		}
		p, err := r.d.Prepare(ctx, s, true)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	next := plan()
	if next.Result.DeploymentID == first.Result.DeploymentID || next.Result.StackHash == first.Result.StackHash {
		t.Fatal("the upgrade did not change the stack")
	}
	c1, _ := composer.ParseConfig(first.ConfigJSON)
	c2, _ := composer.ParseConfig(next.ConfigJSON)
	if c1.Salt != c2.Salt || c1.Salt != base.SaltHex() {
		t.Fatalf("salt %s then %s", c1.Salt, c2.Salt)
	}
	r.approve(next)
	next = plan()

	// Without Replace the running VM is left alone, and the error says how to upgrade.
	r.compute.calls = nil
	if _, err := r.d.Apply(ctx, next); err == nil || !strings.Contains(err.Error(), "--replace") || !strings.Contains(err.Error(), "D-058") || !strings.Contains(err.Error(), first.Result.DeploymentID.Hex()) {
		t.Fatalf("upgrade without --replace: %v", err)
	}
	for _, c := range r.compute.calls {
		if strings.HasPrefix(c, "delete") || strings.HasPrefix(c, "instance") {
			t.Fatalf("changed the running VM: %s", c)
		}
	}

	// A changed salt would need another disk: refused before the old VM is touched.
	r.d.Replace = true
	other := strings.Replace(upgraded, "name: demo", "name: demo\nsalt: 0x"+strings.Repeat("ee", 32), 1)
	s, _ := ParseStackFile([]byte(other))
	po, err := r.d.Prepare(ctx, s, true)
	if err != nil {
		t.Fatal(err)
	}
	r.approve(po)
	po, _ = r.d.Prepare(ctx, s, true)
	r.compute.calls = nil
	if _, err := r.d.Apply(ctx, po); err == nil || !strings.Contains(err.Error(), "another wallet or salt") {
		t.Fatalf("new salt on the old disk: %v", err)
	}
	for _, c := range r.compute.calls {
		if strings.HasPrefix(c, "delete") {
			t.Fatal("the old VM was deleted before the disk check")
		}
	}

	// With Replace: the old VM goes, the disk stays, the new VM runs the new deployment on it.
	r.compute.calls = nil
	out, err := r.d.Apply(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if out.Replaced != first.Result.DeploymentID.Hex() || !out.Created || out.DeploymentID != next.Result.DeploymentID.Hex() {
		t.Fatalf("outcome %+v", out)
	}
	calls := strings.Join(r.compute.calls, "|")
	if !strings.Contains(calls, "delete sealed-demo|instance sealed-demo ") {
		t.Fatalf("calls %s", calls)
	}
	if r.compute.disks["us-central1-a/sealed-demo-data"] != disk {
		t.Fatal("the data disk was recreated")
	}
	in := r.compute.instances["us-central1-a/sealed-demo"]
	if DeploymentIDOf(in) != next.Result.DeploymentID.Hex() || !strings.HasSuffix(in.Disks[3].Source, "/disks/sealed-demo-data") || len(CheckInstance(in)) != 0 {
		t.Fatalf("new VM %+v", in)
	}

	// A VM whose data disk would go with it is never replaced, and neither is one sealed deploy did not create.
	r.compute.instances["us-central1-a/sealed-demo"].Disks[3].AutoDelete = true
	if _, err := r.d.Apply(ctx, first); err == nil || !strings.Contains(err.Error(), "data disk would be deleted") {
		t.Fatalf("auto-delete data disk: %v", err)
	}
	r.compute.instances["us-central1-a/sealed-demo"].Metadata = nil
	if _, err := r.d.Apply(ctx, first); err == nil || !strings.Contains(err.Error(), "not created by sealed deploy") {
		t.Fatalf("foreign VM: %v", err)
	}
}

func TestDeployWarnsOnUnlabeledDataDisk(t *testing.T) {
	r := newRig(t)
	r.approve(r.plan(t, ""))
	r.compute.disks["us-central1-a/sealed-demo-data"] = &gcp.Disk{Name: "sealed-demo-data", SelfLink: "projects/acme-prod-4417/zones/us-central1-a/disks/sealed-demo-data"}
	if _, err := r.d.Apply(context.Background(), r.plan(t, "")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.out.String(), "has no sealed-disk-id label") {
		t.Fatalf("no warning:\n%s", r.out)
	}
}
