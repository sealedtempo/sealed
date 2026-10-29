package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/cli/internal/bundles"
	"github.com/sealedtempo/sealed/cli/internal/gcp"
	"github.com/sealedtempo/sealed/cli/internal/registry"
	"github.com/sealedtempo/sealed/cli/internal/secrets"
	"github.com/sealedtempo/sealed/cli/internal/settings"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/cjson"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// Compute is the part of the Compute Engine API a deploy uses. *gcp.Compute implements it.
type Compute interface {
	GetAddress(ctx context.Context, region, name string) (*gcp.Address, error)
	EnsureAddress(ctx context.Context, region, name, description string) (*gcp.Address, error)
	EnsureDisk(ctx context.Context, zone string, d gcp.Disk) (*gcp.Disk, bool, error)
	InsertInstance(ctx context.Context, zone string, in *gcp.Instance, requestID string) error
	GetInstance(ctx context.Context, zone, name string) (*gcp.Instance, error)
	DeleteInstance(ctx context.Context, zone, name string) error
}

// SharedDisk turns the dstack shared files (app-compose.json, .sys-config.json, .instance_info) into a GCE image
// the VM boots with, and returns its resource path. The real implementation is in shareddisk.go.
type SharedDisk interface {
	Ensure(ctx context.Context, imageName string, files map[string][]byte) (string, error)
}

// Deployer runs deploys.
type Deployer struct {
	Settings *settings.Settings
	Chain    registry.Reader
	Fetcher  *bundles.Fetcher
	Compute  Compute
	Shared   SharedDisk
	// Secrets, when set, is checked for every required secret before any VM is created.
	Secrets secrets.Store
	Out     io.Writer
	Rand    io.Reader
	// PlatformAPI is used when the stack file does not name endpoints.platformApi.
	PlatformAPI string
	// AllowUnbuilt composes stacks whose sidecar or app images still carry the all-zero placeholder digest.
	// Such a stack cannot boot; the CLI allows it only in dev mode (SEALED_DEV_SIM=1).
	AllowUnbuilt bool
	// Replace lets Apply delete a VM of the same name that runs another deployment (an upgrade) and create the
	// new one; the data disk is kept and checked against the salt first (D-058).
	Replace bool
}

// Plan is a composed, checked deploy.
type Plan struct {
	Stack      *StackFile
	Names      ResourceNames
	Releases   []bundles.Release
	Bundles    []*composer.Bundle
	ConfigJSON []byte // canonical public config
	Result     *composer.Result
	IP         string
	IPReserved bool
	Approval   Approval
	Image      *chain.Image
	// MissingSecrets are required Secret Manager names without a value (nil when not checked).
	MissingSecrets []string
	MachineType    string
	DataDiskGB     int
	// Debug is a debug image deploy (spec 5.8): never approvable onchain, no production secrets, and the VM gets
	// DebugLogSA with the logging.write scope only.
	Debug      bool
	DebugLogSA string
}

// Approval is the onchain approval state of the plan's stack.
type Approval struct {
	Approved bool
	Problems []string
}

// ErrNotApproved stops a deploy whose stack the customer has not approved.
var ErrNotApproved = errors.New("stack not approved")

func (d *Deployer) logf(format string, a ...any) {
	if d.Out != nil {
		fmt.Fprintf(d.Out, format+"\n", a...)
	}
}

// ResolveRelease turns "latest", a version or a 0x releaseId into the onchain release.
func ResolveRelease(ctx context.Context, r registry.Reader, a App) (bundles.Release, error) {
	appID := composer.AppID(a.ID)
	if _, err := r.GetApp(ctx, appID); err != nil {
		return bundles.Release{}, fmt.Errorf("app %s: %w", a.ID, err)
	}
	var id [32]byte
	var err error
	switch {
	case a.Release == "latest":
		if id, err = r.LatestRelease(ctx, appID); err == nil && id == ([32]byte{}) {
			err = fmt.Errorf("no active release")
		}
	case strings.HasPrefix(a.Release, "0x"):
		id, err = registry.ParseHash32(a.Release)
	default:
		if id, err = r.ReleaseByVersion(ctx, appID, a.Release); err == nil && id == ([32]byte{}) {
			err = fmt.Errorf("no release with version %q", a.Release)
		}
	}
	if err != nil {
		return bundles.Release{}, fmt.Errorf("app %s release %s: %w", a.ID, a.Release, err)
	}
	rel, err := r.GetRelease(ctx, id)
	if err != nil {
		return bundles.Release{}, fmt.Errorf("app %s release 0x%x: %w", a.ID, id, err)
	}
	if rel.AppId != appID {
		return bundles.Release{}, fmt.Errorf("release 0x%x belongs to another app", id)
	}
	if rel.Status != chain.ReleaseActive && rel.Status != chain.ReleaseDeprecated {
		return bundles.Release{}, fmt.Errorf("app %s release %s (0x%x) is revoked", a.ID, rel.Version, id)
	}
	return bundles.Release{App: a.ID, ReleaseID: id, AppID: appID, Version: rel.Version, BundleHash: rel.BundleHash}, nil
}

// Prepare resolves, fetches, composes and checks. With reserveIP the static IP is reserved now (the sslip
// hostnames, and so the stackHash, depend on it); without it an existing reservation is used or the plan stops.
func (d *Deployer) Prepare(ctx context.Context, s *StackFile, reserveIP bool) (*Plan, error) {
	p := &Plan{Stack: s, Names: s.Names(), MachineType: s.MachineType, DataDiskGB: s.DataDiskGB}
	if p.MachineType == "" {
		p.MachineType = d.Settings.Defaults.DefaultMachineType
	}
	if p.DataDiskGB == 0 {
		p.DataDiskGB = d.Settings.Defaults.DataDiskGB
	}
	if id, err := d.Chain.ChainID(ctx); err != nil {
		return nil, fmt.Errorf("Tempo RPC: %w", err)
	} else if id != d.Settings.ChainID {
		return nil, fmt.Errorf("the RPC is chain %d, expected %d", id, d.Settings.ChainID)
	}
	for _, a := range s.Apps {
		r, err := ResolveRelease(ctx, d.Chain, a)
		if err != nil {
			return nil, err
		}
		b, err := d.Fetcher.Load(ctx, r)
		if err != nil {
			return nil, err
		}
		p.Releases = append(p.Releases, r)
		p.Bundles = append(p.Bundles, b)
		d.logf("release  %-16s %s  0x%x", a.ID, r.Version, r.ReleaseID)
	}

	imageID, _ := registry.ParseHash32(s.Image.ID)
	img, err := d.Chain.GetImage(ctx, imageID)
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", s.Image.ID, err)
	}
	approvedImage, err := d.Chain.IsApprovedImage(ctx, imageID)
	if err != nil {
		return nil, err
	}
	switch {
	case img.IsDebug && !s.Image.Debug:
		return nil, fmt.Errorf("image %s (%s %s) is a debug image, not an approved production image: it never receives production secrets (set image.debug: true to run it for development)", s.Image.ID, img.Name, img.Version)
	case !img.IsDebug && s.Image.Debug:
		return nil, fmt.Errorf("image.debug is set, but image %s (%s %s) is a production image: production VMs never get a service account (remove image.debug)", s.Image.ID, img.Name, img.Version)
	case img.IsDebug && img.Status != chain.ImageActive:
		return nil, fmt.Errorf("debug image %s (%s %s) is not active", s.Image.ID, img.Name, img.Version)
	case img.IsDebug:
		p.Debug, p.DebugLogSA = true, DebugLogServiceAccount(s.Project)
		d.logf("image    %s %s is a DEBUG image: the key broker gives it no secrets; container logs go to Cloud Logging as %s", img.Name, img.Version, p.DebugLogSA)
	case !approvedImage:
		return nil, fmt.Errorf("image %s (%s %s) is not an approved production image", s.Image.ID, img.Name, img.Version)
	}
	p.Image = img

	if s.Hostnames.Scheme == composer.SchemeSslip {
		if reserveIP {
			a, err := d.Compute.EnsureAddress(ctx, s.Region, p.Names.Address, "Sealed deployment "+s.Name)
			if err != nil {
				return nil, fmt.Errorf("reserve static IP: %w", err)
			}
			p.IP, p.IPReserved = a.Address, true
		} else if a, err := d.Compute.GetAddress(ctx, s.Region, p.Names.Address); err == nil {
			p.IP, p.IPReserved = a.Address, true
		} else if gcp.IsNotFound(err) {
			return nil, fmt.Errorf("static IP %s is not reserved yet; the sslip hostnames and the stackHash depend on it (run without --plan to reserve it)", p.Names.Address)
		} else {
			return nil, err
		}
	}

	cfg, err := d.buildConfig(s, p)
	if err != nil {
		return nil, err
	}
	if p.ConfigJSON, err = cfg.CanonicalJSON(); err != nil {
		return nil, err
	}
	if p.Result, err = composer.Compose(cfg, p.Bundles); err != nil {
		return nil, fmt.Errorf("compose: %w", err)
	}
	if err := p.Result.RequireBuilt(); err != nil && !d.AllowUnbuilt {
		return nil, err
	}
	if p.Debug {
		// approveStack requires an approved image, so a debug stack can never be approved, and the key broker
		// refuses it whatever the chain says. Nothing waits for the wallet.
		p.Approval = Approval{Problems: []string{"a debug image is never approved onchain; the key broker releases nothing to it"}}
	} else if p.Approval, err = d.checkApproval(ctx, s, p); err != nil {
		return nil, err
	}
	if d.Secrets != nil {
		if p.MissingSecrets, err = d.missingSecrets(ctx, p); err != nil {
			return nil, fmt.Errorf("check secrets: %w", err)
		}
	}
	return p, nil
}

func (d *Deployer) buildConfig(s *StackFile, p *Plan) (*composer.Config, error) {
	st := d.Settings
	cfg := &composer.Config{
		Schema:          composer.ConfigSchema,
		ChainID:         int64(st.ChainID),
		Customer:        s.Customer,
		Salt:            s.SaltHex(),
		ImageID:         s.Image.ID,
		ComposerVersion: composer.Version,
		Hostnames:       composer.Hostnames{Scheme: s.Hostnames.Scheme, IP: p.IP, Domains: s.Hostnames.Domains},
		Endpoints: composer.Endpoints{
			KeyBroker:   strings.TrimRight(s.KeyBroker, "/"),
			PlatformAPI: s.Endpoints.PlatformAPI,
			TempoRPC:    s.Endpoints.TempoRPC,
			Relay:       s.Endpoints.Relay,
			RelayAttest: s.Endpoints.RelayAttest,
		},
		Contracts: composer.Contracts{
			PlatformRegistry:   lowerHex(st.Registries.PlatformRegistry),
			AppRegistry:        lowerHex(st.Registries.AppRegistry),
			DeploymentRegistry: lowerHex(st.Registries.DeploymentRegistry),
			FeeSplitter:        lowerHex(st.FeeSplitter),
		},
		FeeToken:   strings.ToLower(st.Defaults.Chain.FeeToken),
		RelayOwner: strings.ToLower(s.RelayOwner),
		Settlement: composer.Settlement{
			Mode: "access-key", IntervalMinutes: st.Defaults.SettlementIntervalMinute,
			GracePeriodMinutes: st.Defaults.GracePeriodMinutes, SpendLimitPerDay: st.SpendLimitPerDay(),
		},
	}
	cfg.EgressAdditions = map[string][]string{}
	for k, v := range s.EgressAdd {
		cfg.EgressAdditions[k] = v
	}
	cfg.AllowedVpcRanges = append([]string{}, s.AllowedRange...)
	if cfg.Endpoints.PlatformAPI == "" {
		cfg.Endpoints.PlatformAPI = d.PlatformAPI
	}
	if cfg.Endpoints.PlatformAPI == "" {
		return nil, errors.New("endpoints.platformApi is required (the platform api the agent sends evidence to)")
	}
	if cfg.Endpoints.TempoRPC == "" {
		cfg.Endpoints.TempoRPC = st.Defaults.Chain.PublicRPCURL
	}
	if cfg.Endpoints.TempoRPC == "" {
		// A deployments file for another chain has no public RPC the VM could use (settings.Derived).
		return nil, fmt.Errorf("endpoints.tempoRpc is required: chain %d has no public RPC in the defaults", st.ChainID)
	}
	if s.Settlement != nil {
		if s.Settlement.Mode != "" {
			cfg.Settlement.Mode = s.Settlement.Mode
		}
		if s.Settlement.IntervalMinutes != 0 {
			cfg.Settlement.IntervalMinutes = s.Settlement.IntervalMinutes
		}
		if s.Settlement.GracePeriodMinutes != 0 {
			cfg.Settlement.GracePeriodMinutes = s.Settlement.GracePeriodMinutes
		}
		if s.Settlement.SpendLimitPerDay != "" {
			cfg.Settlement.SpendLimitPerDay = s.Settlement.SpendLimitPerDay
		}
	}
	for _, r := range p.Releases {
		cfg.Apps = append(cfg.Apps, composer.ConfigApp{ID: r.App, ReleaseID: "0x" + hex.EncodeToString(r.ReleaseID[:])})
	}
	// Round trip through the strict parser: it normalizes and validates exactly as the key broker will.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	debugSwitch := p.Debug && composerHasDebug()
	if debugSwitch {
		if raw, err = withConfigDebug(raw); err != nil {
			return nil, err
		}
	} else if p.Debug {
		d.logf("warning: composer %s has no config.debug, so containers log with the none driver and no container logs leave the debug VM", composer.Version)
	}
	canon, err := cjson.Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	parsed, err := composer.ParseConfig(canon)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if debugSwitch {
		if out, err := parsed.CanonicalJSON(); err != nil || !bytes.Contains(out, []byte(`"debug":true`)) {
			return nil, errors.New("config: the composer dropped debug: true")
		}
	}
	return parsed, nil
}

// composerHasDebug reports whether this composer's config has the debug switch (composer 1.2.0, integration item
// 13): with it, containers log with the local driver that the debug image's exporter reads.
func composerHasDebug() bool {
	b, err := json.Marshal(composer.Config{})
	if err != nil {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	_, ok := m["debug"]
	return ok
}

// withConfigDebug sets debug: true in a marshaled config.
func withConfigDebug(raw []byte) ([]byte, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	m["debug"] = true
	return json.Marshal(m)
}

// Data disk labels (D-058). The key broker derives the disk key from (customer, salt), both public in the config,
// so the disk records which pair it was formatted for, and whether it belongs to a production or a debug
// deployment. Deploy refuses to attach a disk the stack could not open, or production data to a debug VM.
const DiskIDLabel = "sealed-disk-id"

// DiskID names the (customer, salt) pair a data disk key belongs to without revealing anything else.
func DiskID(customer, salt string) string {
	h := sha256.Sum256([]byte("sealed/data-disk/v1\x00" + strings.ToLower(customer) + "\x00" + strings.ToLower(salt)))
	return hex.EncodeToString(h[:20])
}

func variantOf(debug bool) string {
	if debug {
		return "debug"
	}
	return "production"
}

// checkDataDisk refuses an existing data disk this plan's VM could not open or must not get.
func (d *Deployer) checkDataDisk(disk *gcp.Disk, p *Plan) error {
	want := DiskID(p.Stack.Customer, p.Stack.SaltHex())
	got, labeled := disk.Labels[DiskIDLabel]
	variant := disk.Labels[VariantLabel]
	switch {
	case labeled && got != want:
		return fmt.Errorf("data disk %s was created for another wallet or salt (disk id %s, this stack %s): the key broker derives the disk key from (customer, salt) (D-058), so this stack could not open it. Keep the salt the disk was created with, or deploy under a new name for a fresh disk", disk.Name, got, want)
	case p.Debug && variant != "debug":
		return fmt.Errorf("data disk %s is not a debug deployment's disk: a debug VM never gets production data; deploy the debug image under another name", disk.Name)
	case !p.Debug && variant == "debug":
		return fmt.Errorf("data disk %s belongs to a debug deployment; deploy the production image under another name", disk.Name)
	case !labeled:
		d.logf("warning: data disk %s has no %s label (created before D-058), so deploy cannot check that this salt opens it", disk.Name, DiskIDLabel)
	}
	return nil
}

// keepsDataDisk checks that deleting a VM leaves its data disk in place.
func keepsDataDisk(in *gcp.Instance, dataDisk string) error {
	for _, dk := range in.Disks {
		if dk.DeviceName != DataDeviceName {
			continue
		}
		if dk.AutoDelete {
			return fmt.Errorf("its data disk would be deleted with it")
		}
		if !strings.HasSuffix(dk.Source, "/disks/"+dataDisk) {
			return fmt.Errorf("its %s device is %s, not %s", DataDeviceName, dk.Source, dataDisk)
		}
		return nil
	}
	return fmt.Errorf("it has no %s disk", DataDeviceName)
}

func lowerHex(a common.Address) string { return "0x" + hex.EncodeToString(a[:]) }

func (d *Deployer) checkApproval(ctx context.Context, s *StackFile, p *Plan) (Approval, error) {
	customer := common.HexToAddress(s.Customer)
	stack := [32]byte(p.Result.StackHash)
	ok, err := d.Chain.IsStackApproved(ctx, customer, stack)
	if err != nil {
		return Approval{}, err
	}
	a := Approval{Approved: ok}
	if !ok {
		a.Problems = append(a.Problems, "DeploymentRegistry.isStackApproved is false")
	}
	appr, err := d.Chain.GetStackApproval(ctx, customer, stack)
	if err != nil {
		return Approval{}, err
	}
	if appr.ApprovedAt != 0 {
		var want [][32]byte
		for _, r := range p.Releases {
			want = append(want, r.ReleaseID)
		}
		if !sameSet(appr.ReleaseIDs, want) {
			a.Problems = append(a.Problems, "the approval names other releases than the stack (D-014)")
		}
		imageID, _ := registry.ParseHash32(s.Image.ID)
		if appr.ImageID != imageID {
			a.Problems = append(a.Problems, "the approval names another image")
		}
		if appr.Revoked {
			a.Problems = append(a.Problems, "the approval was revoked")
		}
	}
	a.Approved = a.Approved && len(a.Problems) == 0
	return a, nil
}

func sameSet(a, b [][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([][32]byte(nil), a...)
	y := append([][32]byte(nil), b...)
	cmp := func(p, q [32]byte) int { return strings.Compare(string(p[:]), string(q[:])) }
	slices.SortFunc(x, cmp)
	slices.SortFunc(y, cmp)
	return slices.Equal(x, y)
}

func (d *Deployer) missingSecrets(ctx context.Context, p *Plan) ([]string, error) {
	var apps []*secrets.App
	for _, b := range p.Bundles {
		a, err := secrets.ParseManifest(b.Files[composer.ManifestFile])
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	plan, err := secrets.NewPlan(apps)
	if err != nil {
		return nil, err
	}
	m := &secrets.Manager{Store: d.Secrets}
	st, gate, err := m.Inspect(ctx, plan)
	if err != nil {
		return nil, err
	}
	var missing []string
	seen := map[string]bool{}
	for _, e := range st {
		if !e.Optional && !e.Present && !seen[e.Stored] {
			seen[e.Stored] = true
			missing = append(missing, e.Stored)
		}
	}
	if !gate {
		missing = append(missing, secrets.GateSecret)
	}
	return missing, nil
}

// ApprovalInstructions explains how the customer's wallet approves the plan's stack.
func (p *Plan) ApprovalInstructions(registryAddr common.Address, rpcURL, feeToken string) string {
	var ids []string
	for _, r := range p.Releases {
		ids = append(ids, "0x"+hex.EncodeToString(r.ReleaseID[:]))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Your wallet %s has not approved this stack yet.\n", p.Stack.Customer)
	for _, pr := range p.Approval.Problems {
		fmt.Fprintf(&b, "  - %s\n", pr)
	}
	fmt.Fprintf(&b, "Approve exactly this stack with your wallet, in the console or with Foundry:\n")
	fmt.Fprintf(&b, "  stackHash  %s\n  releaseIds %s\n  imageId    %s\n", p.Result.StackHash.Hex(), strings.Join(ids, ","), p.Stack.Image.ID)
	fmt.Fprintf(&b, "  cast send %s 'approveStack(bytes32,bytes32[],bytes32,uint64)' %s '[%s]' %s 0 --rpc-url %s --tempo.fee-token %s\n",
		lowerHex(registryAddr), p.Result.StackHash.Hex(), strings.Join(ids, ","), p.Stack.Image.ID, rpcURL, feeToken)
	fmt.Fprintf(&b, "Then run sealed deploy again. Nothing was created.\n")
	return b.String()
}

// Outcome is a finished deploy.
type Outcome struct {
	DeploymentID string
	StackHash    string
	ConfigHash   string
	IP           string
	Instance     string
	Zone         string
	Created      bool // false when the VM already existed
	AttestURL    string
	// Replaced is the deploymentId of the VM an upgrade deleted (empty otherwise).
	Replaced string
	Debug    bool
}

// SharedFiles are the dstack shared disk files of a plan.
func (d *Deployer) SharedFiles(p *Plan) (map[string][]byte, error) {
	sys, err := cjson.Marshal(map[string]any{"gateway_urls": []any{}, "kms_urls": []any{}, "pccs_url": "", "vm_config": p.Stack.Image.VMConfig})
	if err != nil {
		return nil, err
	}
	seed := make([]byte, 20)
	rnd := d.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, err
	}
	// app_id stays absent: the guest then uses sha256(app-compose.json)[0..20], which the verifier expects.
	info, err := cjson.Marshal(map[string]any{"instance_id_seed": hex.EncodeToString(seed)})
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"app-compose.json": p.Result.AppCompose, ".sys-config.json": sys, ".instance_info": info}, nil
}

// Apply creates the data disk, the shared disk image and the VM for an approved plan (or a debug plan), then reads
// the VM back and checks spec 5.9 on what the API stored. A VM of the same name that runs another deployment is
// replaced only with Replace (an upgrade), after the kept data disk was checked against the salt.
func (d *Deployer) Apply(ctx context.Context, p *Plan) (*Outcome, error) {
	if !p.Approval.Approved && !p.Debug {
		return nil, ErrNotApproved
	}
	if len(p.MissingSecrets) > 0 && !p.Debug {
		return nil, fmt.Errorf("the key broker would refuse this stack: missing secrets %s (run sealed secrets set --config <stack file> --missing)", strings.Join(p.MissingSecrets, ", "))
	}
	if p.Stack.Hostnames.Scheme == composer.SchemeSslip && !p.IPReserved {
		return nil, errors.New("static IP not reserved")
	}
	s := p.Stack
	out := &Outcome{
		DeploymentID: p.Result.DeploymentID.Hex(), StackHash: p.Result.StackHash.Hex(), ConfigHash: p.Result.ConfigHash.Hex(),
		IP: p.IP, Instance: p.Names.Instance, Zone: s.Zone, Debug: p.Debug,
	}
	if host, err := attestHost(p); err == nil {
		out.AttestURL = "https://" + host + "/attest"
	}
	check := func(in *gcp.Instance) []string {
		if p.Debug {
			return CheckDebugInstance(in, p.DebugLogSA)
		}
		return CheckInstance(in)
	}
	running := ""
	if existing, err := d.Compute.GetInstance(ctx, s.Zone, p.Names.Instance); err == nil {
		running = DeploymentIDOf(existing)
		switch {
		case strings.EqualFold(running, out.DeploymentID):
			if problems := check(existing); len(problems) > 0 {
				return out, fmt.Errorf("instance %s exists and does not comply: %s", p.Names.Instance, strings.Join(problems, "; "))
			}
			d.logf("instance %s already runs this deployment; nothing to create", p.Names.Instance)
			return out, nil
		case running == "":
			return out, fmt.Errorf("instance %s exists but was not created by sealed deploy (no sealed-deployment-id); remove it or use another name", p.Names.Instance)
		case !d.Replace:
			return out, fmt.Errorf("instance %s runs deployment %s, not %s. To upgrade it, run sealed deploy again with --replace: the VM is deleted and created again with this stack, and the data disk %s is kept and opened with the same key, because the salt is unchanged (D-058)", p.Names.Instance, running, out.DeploymentID, p.Names.DataDisk)
		}
		if err := keepsDataDisk(existing, p.Names.DataDisk); err != nil {
			return out, fmt.Errorf("instance %s cannot be replaced safely: %w", p.Names.Instance, err)
		}
	} else if !gcp.IsNotFound(err) {
		return nil, err
	}

	files, err := d.SharedFiles(p)
	if err != nil {
		return nil, err
	}
	sharedName := p.Names.SharedImage + "-" + strings.TrimPrefix(p.Result.StackHash.Hex(), "0x")[:12]
	sharedImage, err := d.Shared.Ensure(ctx, sharedName, files)
	if err != nil {
		return nil, fmt.Errorf("shared disk image: %w", err)
	}
	d.logf("image    %s (app-compose.json, sha256 = stackHash)", sharedImage)

	disk, created, err := d.Compute.EnsureDisk(ctx, s.Zone, gcp.Disk{
		Name: p.Names.DataDisk, SizeGb: fmt.Sprint(p.DataDiskGB), Type: diskType(s.Zone),
		Labels: map[string]string{
			"sealed": "data", "sealed-name": s.Name,
			DiskIDLabel: DiskID(s.Customer, s.SaltHex()), VariantLabel: variantOf(p.Debug),
		},
		Description: "Sealed app data, LUKS2 inside the VM with the key broker's disk key",
	})
	if err != nil {
		return nil, fmt.Errorf("data disk: %w", err)
	}
	if created {
		d.logf("disk     %s created (%d GB pd-balanced)", p.Names.DataDisk, p.DataDiskGB)
	} else {
		if err := d.checkDataDisk(disk, p); err != nil {
			return out, err
		}
		d.logf("disk     %s kept (existing data, same salt)", p.Names.DataDisk)
	}
	if running != "" {
		d.logf("instance %s runs %s; deleting it to start %s (the data disk stays)", p.Names.Instance, running, out.DeploymentID)
		if err := d.Compute.DeleteInstance(ctx, s.Zone, p.Names.Instance); err != nil && !gcp.IsNotFound(err) {
			return out, fmt.Errorf("delete the old instance: %w", err)
		}
		out.Replaced = running
	}
	in := BuildInstance(InstanceParams{
		Project: s.Project, Region: s.Region, Zone: s.Zone, Names: p.Names, MachineType: p.MachineType,
		BootImage: s.Image.Boot, SystemDiskImage: s.Image.SystemDisk, SharedDiskImage: sharedImage,
		DataDiskSelfLink: disk.SelfLink, NatIP: p.IP, DeploymentID: out.DeploymentID, DebugLogSA: p.DebugLogSA,
	})
	if in.Disks[3].Source == "" {
		in.Disks[3].Source = "projects/" + s.Project + "/zones/" + s.Zone + "/disks/" + p.Names.DataDisk
	}
	reqID := requestID(p.Result.DeploymentID)
	if err := d.Compute.InsertInstance(ctx, s.Zone, in, reqID); err != nil && !errors.Is(err, gcp.ErrInstanceExists) {
		return out, fmt.Errorf("create instance: %w", err)
	}
	out.Created = true
	got, err := d.Compute.GetInstance(ctx, s.Zone, p.Names.Instance)
	if err != nil {
		return out, fmt.Errorf("read back instance: %w", err)
	}
	if problems := check(got); len(problems) > 0 {
		return out, fmt.Errorf("instance %s does not comply with spec 5.9: %s", p.Names.Instance, strings.Join(problems, "; "))
	}
	identity := "no service account"
	if p.Debug {
		identity = "DEBUG, log writer " + p.DebugLogSA + " only"
	}
	d.logf("instance %s created in %s (%s, TDX, %s)", p.Names.Instance, s.Zone, p.MachineType, identity)
	return out, nil
}

// requestID is a UUID-shaped id derived from the deploymentId, so a retried insert is idempotent.
func requestID(dep composer.Hash) string {
	h := hex.EncodeToString(dep[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func attestHost(p *Plan) (string, error) {
	cfg, err := composer.ParseConfig(p.ConfigJSON)
	if err != nil {
		return "", err
	}
	return cfg.Hostname("attest")
}
