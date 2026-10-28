// Package testkit builds test worlds for the CLI's tests: real release bundles from the composer's fixture apps,
// a server that serves them under the release asset URL rule, an in-memory registry, and evidence bundles with
// simulated quotes over the real composer's output. It is imported by tests only.
package testkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/cli/internal/bundles"
	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/runtime/composer/cjson"
	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// Registry is the catalog registry the fixtures are built for (runtime-images.json).
const Registry = "ghcr.io/sealedtempo"

// RepoRoot is the repository root.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// FixtureAppDir is runtime/composer/testdata/apps/<app>.
func FixtureAppDir(app string) string {
	return filepath.Join(RepoRoot(), "runtime", "composer", "testdata", "apps", app)
}

// Bundle builds the bundle of a composer fixture app (llm-gateway or notes).
func Bundle(t testing.TB, app string) *composer.Bundle {
	t.Helper()
	b, err := composer.BuildBundle(composer.BuildInput{AppDir: FixtureAppDir(app), Registry: Registry})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Addresses are fixed fake registry addresses.
var Addresses = chain.Addresses{
	PlatformRegistry:   common.HexToAddress("0x00000000000000000000000000000000000000e1"),
	AppRegistry:        common.HexToAddress("0x00000000000000000000000000000000000000e2"),
	DeploymentRegistry: common.HexToAddress("0x00000000000000000000000000000000000000e3"),
}

// BundleServer serves bundles at <base>/<app>-v<version>/<app>-<version>.bundle.tar and counts requests.
type BundleServer struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	Hits  map[string]int
}

// NewBundleServer starts a server for bs.
func NewBundleServer(t testing.TB, bs ...*composer.Bundle) *BundleServer {
	t.Helper()
	s := &BundleServer{files: map[string][]byte{}, Hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		b, ok := s.files[r.URL.Path]
		s.Hits[r.URL.Path]++
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(s.Close)
	for _, b := range bs {
		s.Put(t, b.Manifest.ID, b.Version(), b.Tar)
	}
	return s
}

// Put serves raw under app/version.
func (s *BundleServer) Put(t testing.TB, app, version string, raw []byte) {
	t.Helper()
	u, err := bundles.AssetURL(s.URL, app, version)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.files[strings.TrimPrefix(u, s.URL)] = raw
	s.mu.Unlock()
}

// Fetcher returns a fetcher for this server.
func (s *BundleServer) Fetcher(cacheDir string) *bundles.Fetcher {
	return &bundles.Fetcher{Base: s.URL, HTTP: s.Client(), CacheDir: cacheDir, AllowHTTP: true}
}

// SimImageID is the image id of the sealed-sim image (name sealed-sim, version 1.0.0).
func SimImageID(debug bool) [32]byte {
	name := "sealed-sim"
	if debug {
		name = "sealed-sim-debug"
	}
	return composer.ImageID(name, "1.0.0", attest.SimMeasurementsHash(debug))
}

// ConfigDoc returns a sealed-config/v1 document for the given bundles (sorted by app id) with the fake registries.
func ConfigDoc(customer common.Address, imageID [32]byte, bs ...*composer.Bundle) map[string]any {
	return ConfigDocAt(Addresses, customer, imageID, bs...)
}

// ConfigDocAt is ConfigDoc for other registry addresses.
func ConfigDocAt(addrs chain.Addresses, customer common.Address, imageID [32]byte, bs ...*composer.Bundle) map[string]any {
	sorted := append([]*composer.Bundle(nil), bs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Manifest.ID < sorted[j].Manifest.ID })
	var apps []any
	for _, b := range sorted {
		apps = append(apps, map[string]any{"id": b.Manifest.ID, "releaseId": b.ReleaseID.Hex()})
	}
	salt := sha256.Sum256([]byte("testkit salt"))
	return map[string]any{
		"schema": "sealed-config/v1", "chainId": 4217, "customer": lowerAddr(customer),
		"salt": "0x" + hex.EncodeToString(salt[:]), "imageId": "0x" + hex.EncodeToString(imageID[:]),
		"composerVersion": composer.Version, "apps": apps,
		"hostnames":       map[string]any{"scheme": "sslip", "ip": "34.1.2.3"},
		"egressAdditions": map[string]any{}, "allowedVpcRanges": []any{},
		"endpoints": map[string]any{
			"keyBroker": "https://sealed-key-broker-xyz.a.run.app", "platformApi": "https://api.sealed.example",
			"tempoRpc": "https://rpc.tempo.xyz", "relay": "https://attest.relay.sealed.example",
			"relayAttest": "https://attest.relay.sealed.example/attest",
		},
		"contracts": map[string]any{
			"platformRegistry": lowerAddr(addrs.PlatformRegistry), "appRegistry": lowerAddr(addrs.AppRegistry),
			"deploymentRegistry": lowerAddr(addrs.DeploymentRegistry), "feeSplitter": "0x00000000000000000000000000000000000000e4",
		},
		"feeToken":   "0x20c000000000000000000000b9537d11c60e8b50",
		"settlement": map[string]any{"mode": "access-key", "intervalMinutes": 60, "gracePeriodMinutes": 1440, "spendLimitPerDay": "2000000"},
		"relayOwner": "0x00000000000000000000000000000000000000b1",
	}
}

func lowerAddr(a common.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// World is one deployment with real bundles and the real composer.
type World struct {
	Addrs         chain.Addresses
	Customer      common.Address
	EnclaveSigner common.Address
	ImageID       [32]byte
	Bundles       []*composer.Bundle
	Config        []byte // canonical
	Result        *composer.Result
	Nonce2        [32]byte
	AttestedAt    uint64
}

// NewWorld composes a llm-gateway + notes stack on the fake registries.
func NewWorld(t testing.TB) *World {
	return NewWorldAt(t, Addresses, common.HexToAddress("0x00000000000000000000000000000000000000c1"))
}

// NewWorldAt composes the stack for customer on the given registries.
func NewWorldAt(t testing.TB, addrs chain.Addresses, customer common.Address) *World {
	t.Helper()
	w := &World{
		Addrs:         addrs,
		Customer:      customer,
		EnclaveSigner: common.HexToAddress("0x00000000000000000000000000000000000000d5"),
		ImageID:       SimImageID(false),
		Bundles:       []*composer.Bundle{Bundle(t, "llm-gateway"), Bundle(t, "notes")},
		Nonce2:        sha256.Sum256([]byte("nonce2")),
		AttestedAt:    1793200000,
	}
	cfgJSON, err := cjson.Marshal(ConfigDocAt(addrs, w.Customer, w.ImageID, w.Bundles...))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := composer.ParseConfig(cfgJSON)
	if err != nil {
		t.Fatal(err)
	}
	if w.Config, err = cfg.CanonicalJSON(); err != nil {
		t.Fatal(err)
	}
	if w.Result, err = composer.Compose(cfg, w.Bundles); err != nil {
		t.Fatal(err)
	}
	return w
}

// ReleaseIDs in config order.
func (w *World) ReleaseIDs() [][32]byte {
	var out [][32]byte
	for _, b := range w.Bundles {
		out = append(out, b.ReleaseID)
	}
	return out
}

// Evidence returns a self-consistent sealed-evidence/v1 document with a simulated quote.
func (w *World) Evidence(t testing.TB) map[string]any {
	t.Helper()
	stack := w.Result.StackHash
	evs, rtmr3 := w.runtimeEvents(t)
	rd := attest.EvidenceReportData(stack, w.Result.ConfigHash, w.EnclaveSigner, w.Nonce2, w.AttestedAt)
	quote := attest.NewSimQuote(attest.SimQuoteParams{RTMR3: rtmr3, ReportData: rd})
	evJSON, _ := json.Marshal(evs)
	evCanon, err := cjson.Canonicalize(evJSON)
	if err != nil {
		t.Fatal(err)
	}
	qh, eh := sha256.Sum256(quote), sha256.Sum256(evCanon)
	var ids []string
	for _, id := range w.ReleaseIDs() {
		ids = append(ids, "0x"+hex.EncodeToString(id[:]))
	}
	return map[string]any{
		"schema": verify.EvidenceSchema, "chainId": 4217,
		"contracts": map[string]any{
			"platformRegistry": lowerAddr(w.Addrs.PlatformRegistry), "appRegistry": lowerAddr(w.Addrs.AppRegistry),
			"deploymentRegistry": lowerAddr(w.Addrs.DeploymentRegistry),
		},
		"deploymentId": w.Result.DeploymentID.Hex(), "customer": lowerAddr(w.Customer),
		"imageId": "0x" + hex.EncodeToString(w.ImageID[:]), "releaseIds": ids,
		"config": json.RawMessage(w.Config), "configHash": w.Result.ConfigHash.Hex(),
		"appCompose": string(w.Result.AppCompose), "stackHash": stack.Hex(),
		"enclaveSigner": lowerAddr(w.EnclaveSigner), "nonce2": "0x" + hex.EncodeToString(w.Nonce2[:]),
		"attestedAt": w.AttestedAt, "quote": "0x" + hex.EncodeToString(quote), "quoteHash": "0x" + hex.EncodeToString(qh[:]),
		"eventLog": json.RawMessage(evCanon), "eventLogHash": "0x" + hex.EncodeToString(eh[:]), "runtime": verify.RuntimeDstack,
	}
}

// runtimeEvents is the RTMR3 event log of the stack and its replayed RTMR3.
func (w *World) runtimeEvents(t testing.TB) ([]attest.Event, attest.Measurement) {
	t.Helper()
	stack := w.Result.StackHash
	p := attest.RuntimeParams{ComposeHash: stack}
	copy(p.AppID[:], stack[:20])
	inst := sha256.Sum256([]byte("instance"))
	copy(p.InstanceID[:], inst[:20])
	evs := attest.ExpectedRuntimeEvents(p)
	rtmr3, err := attest.ReplayAll(evs)
	if err != nil {
		t.Fatal(err)
	}
	return evs, rtmr3
}

// LiveAttest is the GET /attest answer for nonce on a connection whose certificate has SPKI hash spki.
func (w *World) LiveAttest(t testing.TB, nonce, spki [32]byte) map[string]any {
	t.Helper()
	evs, rtmr3 := w.runtimeEvents(t)
	rd := attest.LiveAttestReportData(nonce, spki, w.EnclaveSigner)
	quote := attest.NewSimQuote(attest.SimQuoteParams{RTMR3: rtmr3, ReportData: rd})
	var ids []string
	for _, id := range w.ReleaseIDs() {
		ids = append(ids, "0x"+hex.EncodeToString(id[:]))
	}
	return map[string]any{
		"quote": "0x" + hex.EncodeToString(quote), "eventLog": evs, "config": json.RawMessage(w.Config), "releaseIds": ids,
		"appCompose": string(w.Result.AppCompose), "enclaveSigner": lowerAddr(w.EnclaveSigner),
		"tlsPubKeyHash": "0x" + hex.EncodeToString(spki[:]), "reportData": "0x" + hex.EncodeToString(rd[:]),
	}
}

// Populate stores the world's image, apps, releases, approval and (when register) deployment record.
func (w *World) Populate(m *MemChain, evidence map[string]any, register bool) {
	m.Images[w.ImageID] = &chain.Image{MeasurementsHash: attest.SimMeasurementsHash(false), Status: chain.ImageActive, Name: "sealed-sim", Version: "1.0.0"}
	for _, b := range w.Bundles {
		m.AddRelease(b.Manifest.ID, b.Version(), b.Hash, b.EgressPolicyHash, b.SBOMHash)
	}
	m.Approve(w.Customer, w.Result.StackHash, w.ReleaseIDs(), w.ImageID)
	if register {
		d32 := func(k string) [32]byte {
			var v [32]byte
			b, _ := hex.DecodeString(strings.TrimPrefix(evidence[k].(string), "0x"))
			copy(v[:], b)
			return v
		}
		m.Deployments[w.Result.DeploymentID] = &chain.Deployment{
			DeploymentId: w.Result.DeploymentID, Customer: w.Customer, AttestedAt: w.AttestedAt, Method: 1, LastMethod: 1,
			Status: chain.DeploymentActive, StackHash: w.Result.StackHash, ImageId: w.ImageID, QuoteHash: d32("quoteHash"),
			EventLogHash: d32("eventLogHash"), ConfigHash: w.Result.ConfigHash, EnclaveSigner: w.EnclaveSigner,
			LastAttestedAt: w.AttestedAt, RegisteredAt: w.AttestedAt + 60,
		}
	}
}

// MemChain is an in-memory registry implementing registry.Reader.
type MemChain struct {
	ID          uint64
	Addrs       chain.Addresses
	Images      map[[32]byte]*chain.Image
	AppsByID    map[[32]byte]*chain.App
	AppOrder    [][32]byte
	Releases    map[[32]byte]*chain.Release
	ReleaseList map[[32]byte][][32]byte
	Approvals   map[string]*chain.StackApproval
	Deployments map[[32]byte]*chain.Deployment
	// Err, when set, fails every call (RPC down).
	Err error
}

// NewMemChain returns an empty chain 4217 with Addresses.
func NewMemChain() *MemChain {
	return &MemChain{
		ID: 4217, Addrs: Addresses,
		Images: map[[32]byte]*chain.Image{}, AppsByID: map[[32]byte]*chain.App{}, Releases: map[[32]byte]*chain.Release{},
		ReleaseList: map[[32]byte][][32]byte{}, Approvals: map[string]*chain.StackApproval{}, Deployments: map[[32]byte]*chain.Deployment{},
	}
}

func approvalKey(c common.Address, s [32]byte) string { return c.Hex() + hex.EncodeToString(s[:]) }

// AddRelease registers app (if new) and an Active release.
func (m *MemChain) AddRelease(slug, version string, bundleHash, egressHash, sbomHash [32]byte) [32]byte {
	appID := composer.AppID(slug)
	if _, ok := m.AppsByID[appID]; !ok {
		m.AppsByID[appID] = &chain.App{Slug: slug, Name: slug, LicenseSpdx: "MIT", Maintainer: common.HexToAddress("0xa1"), MaintainerShareBps: 2000, RegisteredAt: 1}
		m.AppOrder = append(m.AppOrder, appID)
	}
	id := composer.ReleaseID(appID, version, bundleHash)
	m.Releases[id] = &chain.Release{AppId: appID, BundleHash: bundleHash, EgressPolicyHash: egressHash, SbomHash: sbomHash, Status: chain.ReleaseActive, PublishedAt: 2, Version: version}
	m.ReleaseList[appID] = append(m.ReleaseList[appID], id)
	return id
}

// Approve records an approval.
func (m *MemChain) Approve(customer common.Address, stack [32]byte, releases [][32]byte, image [32]byte) {
	m.Approvals[approvalKey(customer, stack)] = &chain.StackApproval{ReleaseIDs: releases, ImageID: image, ApprovedAt: 3}
}

func (m *MemChain) ChainID(context.Context) (uint64, error) { return m.ID, m.Err }
func (m *MemChain) Addresses() chain.Addresses              { return m.Addrs }

func (m *MemChain) GetImage(_ context.Context, id [32]byte) (*chain.Image, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if img, ok := m.Images[id]; ok {
		return img, nil
	}
	return nil, fmt.Errorf("ImageNotFound: %w", chain.ErrNotFound)
}

func (m *MemChain) IsApprovedImage(_ context.Context, id [32]byte) (bool, error) {
	img, ok := m.Images[id]
	return ok && img.Status == chain.ImageActive && !img.IsDebug, m.Err
}

func (m *MemChain) GetRelease(_ context.Context, id [32]byte) (*chain.Release, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if r, ok := m.Releases[id]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("ReleaseNotFound: %w", chain.ErrNotFound)
}

func (m *MemChain) IsActiveRelease(_ context.Context, id [32]byte) (bool, error) {
	r, ok := m.Releases[id]
	return ok && (r.Status == chain.ReleaseActive || r.Status == chain.ReleaseDeprecated), m.Err
}

func (m *MemChain) IsApprovableRelease(_ context.Context, id [32]byte) (bool, error) {
	r, ok := m.Releases[id]
	return ok && r.Status == chain.ReleaseActive, m.Err
}

func (m *MemChain) IsStackApproved(_ context.Context, c common.Address, s [32]byte) (bool, error) {
	a, ok := m.Approvals[approvalKey(c, s)]
	if !ok || a.Revoked {
		return false, m.Err
	}
	for _, id := range a.ReleaseIDs {
		if ok, _ := m.IsActiveRelease(context.Background(), id); !ok {
			return false, m.Err
		}
	}
	ok, _ = m.IsApprovedImage(context.Background(), a.ImageID)
	return ok, m.Err
}

func (m *MemChain) GetStackApproval(_ context.Context, c common.Address, s [32]byte) (*chain.StackApproval, error) {
	if a, ok := m.Approvals[approvalKey(c, s)]; ok {
		return a, m.Err
	}
	return &chain.StackApproval{}, m.Err
}

func (m *MemChain) GetDeployment(_ context.Context, id [32]byte) (*chain.Deployment, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if d, ok := m.Deployments[id]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("DeploymentNotFound: %w", chain.ErrNotFound)
}

func (m *MemChain) RecordDigest(_ context.Context, r chain.Record) ([32]byte, error) {
	b, _ := json.Marshal(r)
	return sha256.Sum256(b), m.Err
}

func (m *MemChain) GetApp(_ context.Context, id [32]byte) (*chain.App, error) {
	if a, ok := m.AppsByID[id]; ok {
		return a, m.Err
	}
	return nil, fmt.Errorf("AppNotFound: %w", chain.ErrNotFound)
}

func (m *MemChain) AppCount(context.Context) (uint64, error) { return uint64(len(m.AppOrder)), m.Err }

func (m *MemChain) AppAt(_ context.Context, i uint64) ([32]byte, error) {
	if i >= uint64(len(m.AppOrder)) {
		return [32]byte{}, fmt.Errorf("index out of range")
	}
	return m.AppOrder[i], m.Err
}

func (m *MemChain) ReleaseCount(_ context.Context, app [32]byte) (uint64, error) {
	return uint64(len(m.ReleaseList[app])), m.Err
}

func (m *MemChain) ReleaseAt(_ context.Context, app [32]byte, i uint64) ([32]byte, error) {
	l := m.ReleaseList[app]
	if i >= uint64(len(l)) {
		return [32]byte{}, fmt.Errorf("index out of range")
	}
	return l[i], m.Err
}

func (m *MemChain) LatestRelease(_ context.Context, app [32]byte) ([32]byte, error) {
	l := m.ReleaseList[app]
	for i := len(l) - 1; i >= 0; i-- {
		if m.Releases[l[i]].Status == chain.ReleaseActive {
			return l[i], m.Err
		}
	}
	return [32]byte{}, m.Err
}

func (m *MemChain) ReleaseByVersion(_ context.Context, app [32]byte, version string) ([32]byte, error) {
	for _, id := range m.ReleaseList[app] {
		if m.Releases[id].Version == version {
			return id, m.Err
		}
	}
	return [32]byte{}, m.Err
}
