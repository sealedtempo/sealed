package kbtest

import (
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/bcrypt"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/anvil"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/rimembed"
	"github.com/sealedtempo/sealed/runtime/composer/cjson"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// Test accounts. Customer is the broker's bootstrap customer; both are anvil dev accounts so they can sign on anvil.
var (
	Customer      = anvil.Addr(anvil.Customer)
	OtherCustomer = anvil.Addr(anvil.OtherCustomer)
)

// FeeSplitter and FeeToken are the fee contracts every test config names (Compose) and every test broker expects.
var (
	FeeSplitter = common.HexToAddress("0x00000000000000000000000000000000000000e4")
	FeeToken    = common.HexToAddress("0x20c000000000000000000000b9537d11c60e8b50")
)

// GatePassword is the gate password of every test world; GateHash is its bcrypt hash as stored in Secret Manager.
const GatePassword = "correct horse battery staple"

// FixtureApp returns the composer's fixture app directory (runtime/composer/testdata/apps/<name>).
func FixtureApp(t testing.TB, name string) string {
	t.Helper()
	root, err := anvil.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "runtime", "composer", "testdata", "apps", name)
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); err != nil {
		t.Fatalf("composer fixture app %s: %v", name, err)
	}
	return dir
}

// Registry is the catalog registry every bundle image ref must use.
func Registry(t testing.TB) string {
	t.Helper()
	ri, err := rimembed.Load()
	if err != nil {
		t.Fatal(err)
	}
	return ri.Registry
}

// BuildBundle builds the bundle of an app directory.
func BuildBundle(t testing.TB, dir string) *composer.Bundle {
	t.Helper()
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: dir, Registry: Registry(t)})
	if err != nil {
		t.Fatalf("build bundle %s: %v", dir, err)
	}
	return b
}

// CopyApp copies an app directory into a temp dir and applies edit to its manifest text.
func CopyApp(t testing.TB, src string, edit func(manifest string) string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
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
		if rel == "manifest.yaml" && edit != nil {
			b = []byte(edit(string(b)))
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// World is a set of registries, published releases and broker backends.
type World struct {
	Reg      Registrar
	Bundles  map[string]*composer.Bundle // by app slug: the current release
	Releases map[string][32]byte         // by app slug
	Source   *keybroker.MemoryBundleSource
	Secrets  *keybroker.MemorySecretStore
	MACKey   []byte
	GateHash string
	// SimImage and SimDebugImage are the sealed-sim images (INTERFACES.md section 15).
	SimImage      [32]byte
	SimDebugImage [32]byte
}

// NewWorld registers the sim images and publishes the notes and llm-gateway fixture releases.
func NewWorld(t testing.TB, reg Registrar) *World {
	t.Helper()
	gate, err := bcrypt.GenerateFromPassword([]byte(GatePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	w := &World{Reg: reg, Bundles: map[string]*composer.Bundle{}, Releases: map[string][32]byte{}, GateHash: string(gate)}
	w.MACKey = []byte(strings.Repeat("k", 32))
	w.SimImage = reg.AddImage(t, "sealed-sim", "0.6.1-sim", attest.SimMRTD, false)
	w.SimDebugImage = reg.AddImage(t, "sealed-sim-debug", "0.6.1-sim", attest.SimMRTDDebug, true)
	var all []*composer.Bundle
	for _, app := range []string{"notes", "llm-gateway"} {
		b := BuildBundle(t, FixtureApp(t, app))
		w.Publish(t, b)
		all = append(all, b)
	}
	w.Source = keybroker.NewMemoryBundleSource(all...)
	w.Secrets = keybroker.NewMemorySecretStore(map[string]string{
		"sealed-notes-APP_SECRET":         "notes-app-secret",
		"sealed-notes-DB_PASSWORD":        "notes-db-password",
		"sealed-llm-gateway-MASTER_KEY":   "sk-gateway-master",
		"sealed-unrelated-NOT_IN_A_STACK": "must never be released",
		keybroker.GateSecretID:            w.GateHash,
	})
	return w
}

// PublishOnly publishes a bundle onchain without making it the app's current release.
func (w *World) PublishOnly(t testing.TB, b *composer.Bundle) [32]byte {
	t.Helper()
	id := w.Reg.PublishRelease(t, b.Manifest.ID, b.Version(), b.Hash)
	if id != [32]byte(b.ReleaseID) {
		t.Fatalf("onchain releaseId %x differs from the bundle's %s", id, b.ReleaseID.Hex())
	}
	return id
}

// Publish publishes a bundle onchain as the app's current release.
func (w *World) Publish(t testing.TB, b *composer.Bundle) [32]byte {
	t.Helper()
	id := w.PublishOnly(t, b)
	w.Bundles[b.Manifest.ID] = b
	w.Releases[b.Manifest.ID] = id
	return id
}

// Stack is a composed stack ready to boot.
type Stack struct {
	Config     map[string]any
	ConfigJSON []byte
	Result     *composer.Result
	ReleaseIDs [][32]byte
	ImageID    [32]byte
	Customer   common.Address
}

// StackOptions shape a composed stack.
type StackOptions struct {
	Customer common.Address // zero means Customer
	ImageID  [32]byte       // zero means the sim image
	Apps     []string       // nil means notes
	// Edit changes the config before composing.
	Edit func(c *composer.Config)
	// Bundles replaces the world's current release of an app (for example an unpublished build).
	Bundles map[string]*composer.Bundle
}

// Variant builds the app's fixture with another release_version, which gives a different bundleHash.
func (w *World) Variant(t testing.TB, app, version string) *composer.Bundle {
	t.Helper()
	dir := CopyApp(t, FixtureApp(t, app), func(m string) string {
		lines := strings.Split(m, "\n")
		found := false
		for i, l := range lines {
			if strings.HasPrefix(l, "release_version:") {
				lines[i], found = "release_version: "+version, true
			}
		}
		if !found {
			t.Fatalf("%s manifest has no release_version line", app)
		}
		return strings.Join(lines, "\n")
	})
	return BuildBundle(t, dir)
}

// Compose builds the config and composes the stack from the world's current releases.
func (w *World) Compose(t testing.TB, o StackOptions) *Stack {
	t.Helper()
	if o.Customer == (common.Address{}) {
		o.Customer = Customer
	}
	if o.ImageID == ([32]byte{}) {
		o.ImageID = w.SimImage
	}
	if o.Apps == nil {
		o.Apps = []string{"notes"}
	}
	ct := w.Reg.Contracts()
	cfg := &composer.Config{
		Schema:           composer.ConfigSchema,
		ChainID:          int64(w.Reg.ChainID()),
		Customer:         strings.ToLower(o.Customer.Hex()),
		Salt:             "0x" + strings.Repeat("5a", 32),
		ImageID:          "0x" + hex.EncodeToString(o.ImageID[:]),
		ComposerVersion:  composer.Version,
		Hostnames:        composer.Hostnames{Scheme: composer.SchemeSslip, IP: "34.1.2.3"},
		EgressAdditions:  map[string][]string{},
		AllowedVpcRanges: []string{},
		Endpoints: composer.Endpoints{
			KeyBroker:   "https://sealed-key-broker-xyz.a.run.app",
			PlatformAPI: "https://api.sealed.example",
			TempoRPC:    "https://rpc.tempo.xyz",
			Relay:       "https://attest.relay.sealed.example",
			RelayAttest: "https://attest.relay.sealed.example/attest",
		},
		Contracts: composer.Contracts{
			PlatformRegistry:   strings.ToLower(ct.PlatformRegistry.Hex()),
			AppRegistry:        strings.ToLower(ct.AppRegistry.Hex()),
			DeploymentRegistry: strings.ToLower(ct.DeploymentRegistry.Hex()),
			FeeSplitter:        strings.ToLower(FeeSplitter.Hex()),
		},
		FeeToken:   strings.ToLower(FeeToken.Hex()),
		Settlement: composer.Settlement{Mode: "access-key", IntervalMinutes: 60, GracePeriodMinutes: 1440, SpendLimitPerDay: "2000000"},
		RelayOwner: "0x00000000000000000000000000000000000000b1",
	}
	apps := append([]string(nil), o.Apps...)
	sort.Strings(apps)
	var bundles []*composer.Bundle
	for _, a := range apps {
		b, ok := o.Bundles[a]
		if !ok {
			b, ok = w.Bundles[a]
		}
		if !ok {
			t.Fatalf("no release of %s in the world", a)
		}
		cfg.Apps = append(cfg.Apps, composer.ConfigApp{ID: a, ReleaseID: b.ReleaseID.Hex()})
		bundles = append(bundles, b)
	}
	if o.Edit != nil {
		o.Edit(cfg)
	}
	res, err := rimembed.Compose(cfg, bundles)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	raw, err := cfg.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	s := &Stack{Config: m, ConfigJSON: raw, Result: res, ImageID: o.ImageID, Customer: o.Customer}
	for _, a := range cfg.Apps {
		h, _ := composer.ParseHash(a.ReleaseID)
		s.ReleaseIDs = append(s.ReleaseIDs, [32]byte(h))
	}
	return s
}

// Approve approves the stack onchain as its customer, with its own releases and image.
func (w *World) Approve(t testing.TB, s *Stack) {
	t.Helper()
	w.Reg.ApproveStack(t, s.Customer, s.Result.StackHash, s.ReleaseIDs, s.ImageID)
}

// Register registers the stack's deployment onchain, as the oracle does after the first boot's evidence. The
// record's quote and event log hashes are placeholders; the broker reads only the deployment's status.
func (w *World) Register(t testing.TB, s *Stack, attestedAt uint64) {
	t.Helper()
	w.Reg.RegisterDeployment(t, chain.Record{DeploymentId: s.Result.DeploymentID, Customer: s.Customer, StackHash: s.Result.StackHash,
		ImageId: s.ImageID, QuoteHash: [32]byte{0x0a}, EventLogHash: [32]byte{0x0e}, ConfigHash: s.Result.ConfigHash,
		EnclaveSigner: common.HexToAddress("0x00000000000000000000000000000000000000e5"), AttestedAt: attestedAt})
}

// Close closes the stack's deployment onchain as its customer.
func (w *World) Close(t testing.TB, s *Stack) {
	t.Helper()
	w.Reg.CloseDeployment(t, s.Customer, s.Result.DeploymentID)
}

// Attempt is one boot's release request, built like sealed-agent builds it. Tests change fields before Body.
type Attempt struct {
	Nonce      [32]byte
	Priv       hpke.PrivateKey
	Pub        [32]byte
	Events     []attest.Event
	Quote      []byte
	Config     map[string]any
	AppCompose string
	ReleaseIDs []string
	ImageID    [32]byte
	// Drop removes fields from the body; Extra adds or replaces fields.
	Drop  []string
	Extra map[string]any
}

// InstanceAppID and InstanceID are the dstack app-id and instance-id the simulated boot reports.
var (
	InstanceAppID = [20]byte{0xa1, 0xa1, 0xa1}
	InstanceID    = [20]byte{0x1d, 0x1d, 0x1d}
)

// SimQuoteFor returns the simulated quote a dstack simulator gives for these events and report_data.
func SimQuoteFor(t testing.TB, evs []attest.Event, rd attest.ReportData, debug bool, mrtd *attest.Measurement) []byte {
	t.Helper()
	rtmr3, err := attest.ReplayAll(evs)
	if err != nil {
		t.Fatal(err)
	}
	return attest.NewSimQuote(attest.SimQuoteParams{Debug: debug, RTMR3: rtmr3, ReportData: rd, MRTD: mrtd})
}

// NewAttempt builds a correct request for stack s with the given nonce and a fresh ephemeral key.
func NewAttempt(t testing.TB, s *Stack, nonce [32]byte) *Attempt {
	t.Helper()
	priv, pub, err := keybroker.GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	evs := attest.ExpectedRuntimeEvents(attest.RuntimeParams{AppID: InstanceAppID, ComposeHash: s.Result.StackHash, InstanceID: InstanceID})
	a := &Attempt{Nonce: nonce, Priv: priv, Pub: pub, Events: evs, Config: s.Config, AppCompose: string(s.Result.AppCompose), ImageID: s.ImageID}
	for _, id := range s.ReleaseIDs {
		a.ReleaseIDs = append(a.ReleaseIDs, "0x"+hex.EncodeToString(id[:]))
	}
	a.Quote = SimQuoteFor(t, evs, attest.KeyReleaseReportData(nonce, pub), false, nil)
	return a
}

// Requote replaces the quote with a simulated one over the current events, for the attempt's nonce and key.
func (a *Attempt) Requote(t testing.TB, debug bool, mrtd *attest.Measurement) {
	t.Helper()
	a.Quote = SimQuoteFor(t, a.Events, attest.KeyReleaseReportData(a.Nonce, a.Pub), debug, mrtd)
}

// Body is the POST /v1/release JSON.
func (a *Attempt) Body(t testing.TB) []byte {
	t.Helper()
	evs, err := json.Marshal(a.Events)
	if err != nil {
		t.Fatal(err)
	}
	var evAny []any
	if err := json.Unmarshal(evs, &evAny); err != nil {
		t.Fatal(err)
	}
	ids := make([]any, len(a.ReleaseIDs))
	for i, id := range a.ReleaseIDs {
		ids[i] = id
	}
	m := map[string]any{
		"nonce":        "0x" + hex.EncodeToString(a.Nonce[:]),
		"ephemeralPub": "0x" + hex.EncodeToString(a.Pub[:]),
		"quote":        "0x" + hex.EncodeToString(a.Quote),
		"eventLog":     evAny,
		"config":       a.Config,
		"appCompose":   a.AppCompose,
		"releaseIds":   ids,
		"imageId":      "0x" + hex.EncodeToString(a.ImageID[:]),
	}
	for _, k := range a.Drop {
		delete(m, k)
	}
	for k, v := range a.Extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Open decrypts a 200 answer and parses the plaintext, requiring it to be canonical JSON.
func (a *Attempt) Open(t testing.TB, resp *keybroker.ReleaseResponse) *keybroker.ReleasePlaintext {
	t.Helper()
	enc, err := hex.DecodeString(strings.TrimPrefix(resp.Enc, "0x"))
	if err != nil || len(enc) != 32 {
		t.Fatalf("enc %q", resp.Enc)
	}
	ct, err := hex.DecodeString(strings.TrimPrefix(resp.Ciphertext, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := keybroker.OpenRelease(a.Priv, a.Nonce, enc, ct)
	if err != nil {
		t.Fatalf("open release: %v", err)
	}
	canon, err := cjson.Canonicalize(pt)
	if err != nil || string(canon) != string(pt) {
		t.Fatalf("release plaintext is not canonical JSON: %v", err)
	}
	var out keybroker.ReleasePlaintext
	dec := json.NewDecoder(strings.NewReader(string(pt)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &out
}
