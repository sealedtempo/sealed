// Package fixture builds consistent Sealed test worlds: a public config, a deterministic fake composer, a
// simulated quote and dstack event log, the evidence bundle, and the matching onchain state (in memory or on a
// local anvil node).
package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
	"github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/hexb"
)

// App is one app of the stack.
type App struct {
	Slug       string
	Version    string
	BundleHash [32]byte
}

// AppID is keccak256(slug).
func (a App) AppID() [32]byte { return crypto.Keccak256Hash([]byte(a.Slug)) }

// ReleaseID is keccak256(abi.encode(appId, version, bundleHash)).
func (a App) ReleaseID() [32]byte {
	return releaseID(a.AppID(), a.Version, a.BundleHash)
}

// World describes one deployment.
type World struct {
	ChainID       uint64
	Addrs         chain.Addresses
	Customer      common.Address
	EnclaveSigner common.Address
	Salt          [32]byte
	ImageID       [32]byte
	Apps          []App // sorted by slug
	Debug         bool  // build a debug sim quote
	Nonce2        [32]byte
	InstanceID    [20]byte
	// ConfigEdit, when set, edits the public config document before it is canonicalized.
	ConfigEdit func(doc map[string]any)
}

// NewWorld returns a two-app world on chainID with the given registry addresses.
func NewWorld(chainID uint64, addrs chain.Addresses, customer, enclave common.Address, imageID [32]byte) *World {
	w := &World{
		ChainID: chainID, Addrs: addrs, Customer: customer, EnclaveSigner: enclave, ImageID: imageID,
		Apps: []App{
			{Slug: "crm", Version: "1.0.0", BundleHash: sha256.Sum256([]byte("bundle crm 1.0.0"))},
			{Slug: "llm-gateway", Version: "1.0.0", BundleHash: sha256.Sum256([]byte("bundle llm-gateway 1.0.0"))},
		},
	}
	w.Salt = sha256.Sum256([]byte("salt"))
	w.Nonce2 = sha256.Sum256([]byte("nonce2"))
	inst := sha256.Sum256([]byte("instance"))
	copy(w.InstanceID[:], inst[:20])
	return w
}

// ReleaseIDs returns the release ids in config order.
func (w *World) ReleaseIDs() [][32]byte {
	out := make([][32]byte, len(w.Apps))
	for i, a := range w.Apps {
		out[i] = a.ReleaseID()
	}
	return out
}

// ConfigDoc returns the public config (sealed-config/v1) as a generic document.
func (w *World) ConfigDoc() map[string]any {
	apps := make([]map[string]any, len(w.Apps))
	sorted := append([]App(nil), w.Apps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slug < sorted[j].Slug })
	for i, a := range sorted {
		id := a.ReleaseID()
		apps[i] = map[string]any{"id": a.Slug, "releaseId": hexb.Enc(id[:])}
	}
	doc := map[string]any{
		"schema":           verify.ConfigSchema,
		"chainId":          w.ChainID,
		"customer":         lower(w.Customer),
		"salt":             hexb.Enc(w.Salt[:]),
		"imageId":          hexb.Enc(w.ImageID[:]),
		"composerVersion":  "1.0.0",
		"apps":             apps,
		"hostnames":        map[string]any{"scheme": "sslip", "ip": "34.1.2.3"},
		"egressAdditions":  map[string]any{},
		"allowedVpcRanges": []any{},
		"endpoints":        map[string]any{"keyBroker": "https://kb.example", "platformApi": "https://api.example", "tempoRpc": "https://rpc.tempo.xyz", "relay": "https://relay.example", "relayAttest": "https://attest.relay.example/attest"},
		"contracts": map[string]any{
			"platformRegistry":   lower(w.Addrs.PlatformRegistry),
			"appRegistry":        lower(w.Addrs.AppRegistry),
			"deploymentRegistry": lower(w.Addrs.DeploymentRegistry),
			"feeSplitter":        "0x0000000000000000000000000000000000000fee",
		},
		"feeToken":   "0x20c0000000000000000000000000000000000000",
		"settlement": map[string]any{"mode": "access-key", "intervalMinutes": 60, "gracePeriodMinutes": 1440, "spendLimitPerDay": "2000000"},
		"relayOwner": "0x0000000000000000000000000000000000000001",
	}
	if w.ConfigEdit != nil {
		w.ConfigEdit(doc)
	}
	return doc
}

// ConfigJSON returns the canonical config bytes.
func (w *World) ConfigJSON() json.RawMessage {
	b, err := cjson.Marshal(w.ConfigDoc())
	if err != nil {
		panic(err)
	}
	return b
}

func lower(a common.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// Composer is a deterministic stand-in for runtime/composer. It renders an app-compose.json in the dstack shape of
// INTERFACES.md section 6 whose docker_compose_file depends on every config byte and every bundle hash.
type Composer struct{}

// Compose implements verify.Composer.
func (Composer) Compose(_ context.Context, in verify.ComposeInput) (*verify.ComposeOutput, error) {
	canon, err := cjson.Canonicalize(in.Config)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Customer string `json:"customer"`
		Salt     string `json:"salt"`
	}
	if err := json.Unmarshal(canon, &cfg); err != nil {
		return nil, err
	}
	configHash := sha256.Sum256(canon)
	services := map[string]any{}
	for _, r := range in.Releases {
		services[r.App] = map[string]any{"image": fmt.Sprintf("ghcr.io/sealed-dev/%s@sha256:%x", r.App, r.BundleHash)}
	}
	compose, err := cjson.Marshal(map[string]any{
		"configs":  map[string]any{"sealed-config": map[string]any{"content": string(canon)}},
		"services": services,
	})
	if err != nil {
		return nil, err
	}
	appCompose, err := cjson.Marshal(map[string]any{
		"allowed_envs": []any{}, "docker_compose_file": string(compose), "gateway_enabled": false, "key_provider": "tpm",
		"key_provider_id": "", "kms_enabled": false, "local_key_provider_enabled": false, "manifest_version": 2,
		"name": fmt.Sprintf("sealed-%x", configHash[:4]), "no_instance_id": false, "public_logs": false,
		"public_sysinfo": false, "public_tcbinfo": true, "runner": "docker-compose", "secure_time": false, "storage_fs": "ext4",
	})
	if err != nil {
		return nil, err
	}
	stack := sha256.Sum256(appCompose)
	customer, err := hexb.Decode20(cfg.Customer)
	if err != nil {
		return nil, err
	}
	salt, err := hexb.Decode32(cfg.Salt)
	if err != nil {
		return nil, err
	}
	return &verify.ComposeOutput{
		AppCompose: appCompose, StackHash: stack, ConfigHash: configHash,
		DeploymentID: verify.DeploymentID(common.Address(customer), stack, salt),
	}, nil
}

// composeInput builds the composer input from the world's own releases (what the chain will hold).
func (w *World) composeInput() verify.ComposeInput {
	in := verify.ComposeInput{Config: w.ConfigJSON()}
	for _, a := range w.Apps {
		in.Releases = append(in.Releases, verify.ComposeRelease{App: a.Slug, ReleaseID: a.ReleaseID(), AppID: a.AppID(), Version: a.Version, BundleHash: a.BundleHash})
	}
	return in
}

// Compose runs the fake composer on the world.
func (w *World) Compose() *verify.ComposeOutput {
	out, err := Composer{}.Compose(context.Background(), w.composeInput())
	if err != nil {
		panic(err)
	}
	return out
}

// RuntimeEvents returns the RTMR3 event log for a stack hash.
func (w *World) RuntimeEvents(stackHash [32]byte) []attest.Event {
	return SimRuntimeEvents(stackHash, w.InstanceID)
}

// SimRuntimeEvents is the event log the dev simulator emits for a stack: the exact INTERFACES section 6 sequence
// with compose-hash = stackHash (app-id is the first 20 bytes of the stack hash, as the simulator derives it).
func SimRuntimeEvents(stackHash [32]byte, instanceID [20]byte) []attest.Event {
	p := attest.RuntimeParams{ComposeHash: stackHash, InstanceID: instanceID}
	copy(p.AppID[:], stackHash[:20])
	return attest.ExpectedRuntimeEvents(p)
}

// Bundle builds a self-consistent evidence bundle attested at attestedAt.
func (w *World) Bundle(attestedAt uint64) *verify.Bundle {
	return SimEvidence(EvidenceParams{
		ChainID: w.ChainID, Addrs: w.Addrs, Customer: w.Customer, EnclaveSigner: w.EnclaveSigner, ImageID: w.ImageID,
		ReleaseIDs: w.ReleaseIDs(), Config: w.ConfigJSON(), Compose: w.Compose(), Nonce2: w.Nonce2, InstanceID: w.InstanceID,
		AttestedAt: attestedAt, Debug: w.Debug,
	})
}

// EvidenceParams describe one attestation of a composed stack.
type EvidenceParams struct {
	ChainID       uint64
	Addrs         chain.Addresses
	Customer      common.Address
	EnclaveSigner common.Address
	ImageID       [32]byte
	ReleaseIDs    [][32]byte // config order
	Config        json.RawMessage
	Compose       *verify.ComposeOutput // the composer's output for Config
	Nonce2        [32]byte
	InstanceID    [20]byte
	AttestedAt    uint64
	Debug         bool // a debug sim quote (debug MRTD and attributes)
}

// SimEvidence is what sealed-agent produces with the dev simulator for a composed stack: the RTMR3 event log of the
// app-compose, a simulated quote whose report_data is the evidence construction (attestedAt included, D-047) and
// whose RTMR3 replays from that log, and the sealed-evidence/v1 bundle around them.
func SimEvidence(p EvidenceParams) *verify.Bundle {
	out := p.Compose
	evs := SimRuntimeEvents(out.StackHash, p.InstanceID)
	rtmr3, err := attest.ReplayAll(evs)
	if err != nil {
		panic(err)
	}
	rd := attest.EvidenceReportData(out.StackHash, out.ConfigHash, p.EnclaveSigner, p.Nonce2, p.AttestedAt)
	quote := attest.NewSimQuote(attest.SimQuoteParams{Debug: p.Debug, RTMR3: rtmr3, ReportData: rd})
	evJSON, err := json.Marshal(evs)
	if err != nil {
		panic(err)
	}
	evCanon, err := cjson.Canonicalize(evJSON)
	if err != nil {
		panic(err)
	}
	quoteHash := sha256.Sum256(quote)
	evHash := sha256.Sum256(evCanon)
	releaseIDs := make([]string, len(p.ReleaseIDs))
	for i, id := range p.ReleaseIDs {
		releaseIDs[i] = hexb.Enc(id[:])
	}
	return &verify.Bundle{
		Schema:  verify.EvidenceSchema,
		ChainID: p.ChainID,
		Contracts: verify.BundleContracts{
			PlatformRegistry: lower(p.Addrs.PlatformRegistry), AppRegistry: lower(p.Addrs.AppRegistry),
			DeploymentRegistry: lower(p.Addrs.DeploymentRegistry),
		},
		DeploymentID:  hexb.Enc(out.DeploymentID[:]),
		Customer:      lower(p.Customer),
		ImageID:       hexb.Enc(p.ImageID[:]),
		ReleaseIDs:    releaseIDs,
		Config:        p.Config,
		ConfigHash:    hexb.Enc(out.ConfigHash[:]),
		AppCompose:    string(out.AppCompose),
		StackHash:     hexb.Enc(out.StackHash[:]),
		EnclaveSigner: lower(p.EnclaveSigner),
		Nonce2:        hexb.Enc(p.Nonce2[:]),
		AttestedAt:    p.AttestedAt,
		Quote:         hexb.Enc(quote),
		QuoteHash:     hexb.Enc(quoteHash[:]),
		EventLog:      evCanon,
		EventLogHash:  hexb.Enc(evHash[:]),
		Runtime:       verify.RuntimeDstack,
	}
}

// Rehash recomputes quoteHash and eventLogHash after a test edited quote or eventLog, so only the intended check
// fails.
func Rehash(b *verify.Bundle) {
	q, err := hexb.Decode(b.Quote, -1)
	if err != nil {
		panic(err)
	}
	qh := sha256.Sum256(q)
	b.QuoteHash = hexb.Enc(qh[:])
	canon, err := cjson.Canonicalize(b.EventLog)
	if err != nil {
		panic(err)
	}
	eh := sha256.Sum256(canon)
	b.EventLogHash = hexb.Enc(eh[:])
}

// Record returns the DeploymentRegistry record matching b.
func Record(b *verify.Bundle) chain.Record {
	d32 := func(s string) [32]byte { v, _ := hexb.Decode32(s); return v }
	d20 := func(s string) common.Address { v, _ := hexb.Decode20(s); return common.Address(v) }
	return chain.Record{
		DeploymentId: d32(b.DeploymentID), Customer: d20(b.Customer), StackHash: d32(b.StackHash), ImageId: d32(b.ImageID),
		QuoteHash: d32(b.QuoteHash), EventLogHash: d32(b.EventLogHash), ConfigHash: d32(b.ConfigHash),
		EnclaveSigner: d20(b.EnclaveSigner), AttestedAt: b.AttestedAt,
	}
}

// LiveResponse builds the GET /attest response for nonce, served TLS key hash, and the world.
func (w *World) LiveResponse(nonce, tlsPubKeyHash [32]byte) map[string]any {
	out := w.Compose()
	evs := w.RuntimeEvents(out.StackHash)
	rtmr3, err := attest.ReplayAll(evs)
	if err != nil {
		panic(err)
	}
	rd := attest.LiveAttestReportData(nonce, tlsPubKeyHash, w.EnclaveSigner)
	quote := attest.NewSimQuote(attest.SimQuoteParams{Debug: w.Debug, RTMR3: rtmr3, ReportData: rd})
	ids := w.ReleaseIDs()
	releaseIDs := make([]string, len(ids))
	for i, id := range ids {
		releaseIDs[i] = hexb.Enc(id[:])
	}
	return map[string]any{
		"quote": hexb.Enc(quote), "eventLog": evs, "config": json.RawMessage(w.ConfigJSON()), "releaseIds": releaseIDs,
		"appCompose": string(out.AppCompose), "enclaveSigner": lower(w.EnclaveSigner),
		"tlsPubKeyHash": hexb.Enc(tlsPubKeyHash[:]), "reportData": hexb.Enc(rd[:]),
	}
}

func releaseID(appID [32]byte, version string, bundleHash [32]byte) [32]byte {
	strT, _ := abi.NewType("string", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: b32T}, {Type: strT}, {Type: b32T}}.Pack(appID, version, bundleHash)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(enc)
}

// SimImage is the image record of sealed-sim (or sealed-sim-debug).
func SimImage(debug bool) *chain.Image {
	name := "sealed-sim"
	if debug {
		name = "sealed-sim-debug"
	}
	return &chain.Image{MeasurementsHash: attest.SimMeasurementsHash(debug), IsDebug: debug, Status: chain.ImageActive, Name: name, Version: "1.0.0"}
}

// SimImageID is keccak256(abi.encode(name, version, measurementsHash)) of SimImage.
func SimImageID(debug bool) [32]byte {
	img := SimImage(debug)
	strT, _ := abi.NewType("string", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: strT}, {Type: strT}, {Type: b32T}}.Pack(img.Name, img.Version, img.MeasurementsHash)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(enc)
}

// Populate stores the world's image, releases, approval and (when register) its deployment record for b.
func (w *World) Populate(m *MemChain, b *verify.Bundle, register bool) {
	m.Images[w.ImageID] = SimImage(w.Debug)
	for _, a := range w.Apps {
		m.Releases[a.ReleaseID()] = &chain.Release{AppId: a.AppID(), BundleHash: a.BundleHash, Status: chain.ReleaseActive, Version: a.Version}
	}
	rec := Record(b)
	m.Approve(w.Customer, rec.StackHash, w.ReleaseIDs(), w.ImageID)
	if register {
		m.Register(rec)
	}
}
