package kbtest

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/key-broker/internal/anvil"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
)

func releaseID(appID [32]byte, version string, bundleHash [32]byte) [32]byte {
	return composer.ReleaseID(appID, version, bundleHash)
}

// Registrar writes registry state, in memory or as transactions on anvil, and exposes it as a keybroker.Chain.
type Registrar interface {
	Name() string
	Chain() keybroker.Chain
	ChainID() uint64
	Contracts() chain.Addresses
	// AddImage registers an image with the simulator's RTMR0-2 and the given MRTD.
	AddImage(t testing.TB, name, version string, mrtd attest.Measurement, debug bool) [32]byte
	RevokeImage(t testing.TB, id [32]byte)
	PublishRelease(t testing.TB, slug, version string, bundleHash [32]byte) [32]byte
	RevokeRelease(t testing.TB, id [32]byte)
	ApproveStack(t testing.TB, customer common.Address, stackHash [32]byte, releaseIDs [][32]byte, imageID [32]byte)
	RevokeStack(t testing.TB, customer common.Address, stackHash [32]byte)
	// RegisterDeployment registers an attested deployment record (oracle method 1); CloseDeployment closes it as
	// its customer.
	RegisterDeployment(t testing.TB, rec chain.Record)
	CloseDeployment(t testing.TB, customer common.Address, deploymentID [32]byte)
}

// MemRegistrar is a Registrar over MemChain.
type MemRegistrar struct {
	C *MemChain
}

// Fixed registry addresses of the in-memory chain.
var memContracts = chain.Addresses{
	PlatformRegistry:   common.HexToAddress("0x00000000000000000000000000000000000000e1"),
	AppRegistry:        common.HexToAddress("0x00000000000000000000000000000000000000e2"),
	DeploymentRegistry: common.HexToAddress("0x00000000000000000000000000000000000000e3"),
}

// MemChainID is the in-memory chain's id: a local chain, since simulated quotes are refused on mainnet (4217).
const MemChainID = 31337

// NewMemRegistrar returns an in-memory chain MemChainID.
func NewMemRegistrar() *MemRegistrar { return &MemRegistrar{C: NewMemChain(MemChainID)} }

func (m *MemRegistrar) Name() string               { return "memory" }
func (m *MemRegistrar) Chain() keybroker.Chain     { return m.C }
func (m *MemRegistrar) ChainID() uint64            { return MemChainID }
func (m *MemRegistrar) Contracts() chain.Addresses { return memContracts }

func (m *MemRegistrar) AddImage(t testing.TB, name, version string, mrtd attest.Measurement, debug bool) [32]byte {
	mh := attest.MeasurementsHash(mrtd, attest.SimRTMR0, attest.SimRTMR1, attest.SimRTMR2)
	id := anvil.ImageID(name, version, mh)
	m.C.AddImage(id, mh, name, version, debug)
	return id
}

func (m *MemRegistrar) RevokeImage(t testing.TB, id [32]byte) {
	m.C.SetImageStatus(id, chain.ImageRevoked)
}

func (m *MemRegistrar) PublishRelease(t testing.TB, slug, version string, bundleHash [32]byte) [32]byte {
	return m.C.PublishRelease(slug, version, bundleHash)
}

func (m *MemRegistrar) RevokeRelease(t testing.TB, id [32]byte) {
	m.C.SetReleaseStatus(id, chain.ReleaseRevoked)
}

func (m *MemRegistrar) ApproveStack(t testing.TB, customer common.Address, stackHash [32]byte, ids [][32]byte, imageID [32]byte) {
	t.Helper()
	if err := m.C.ApproveStack(customer, stackHash, ids, imageID); err != nil {
		t.Fatal(err)
	}
}

func (m *MemRegistrar) RevokeStack(t testing.TB, customer common.Address, stackHash [32]byte) {
	m.C.RevokeStack(customer, stackHash)
}

func (m *MemRegistrar) RegisterDeployment(t testing.TB, rec chain.Record) {
	t.Helper()
	if err := m.C.RegisterDeployment(rec); err != nil {
		t.Fatal(err)
	}
}

func (m *MemRegistrar) CloseDeployment(t testing.TB, customer common.Address, id [32]byte) {
	t.Helper()
	if err := m.C.CloseDeployment(id); err != nil {
		t.Fatal(err)
	}
}

// AnvilRegistrar is a Registrar over the real contracts on a local anvil node, read with the verifier's client.
type AnvilRegistrar struct {
	R      *anvil.Registries
	client *chain.Client
	heads  *keybroker.RPCHeads
	apps   map[string]bool
}

// NewAnvilRegistrar starts anvil, deploys the registries and dials them. It skips without anvil or forge.
func NewAnvilRegistrar(t testing.TB) *AnvilRegistrar {
	t.Helper()
	node := anvil.Start(t)
	r := anvil.DeployRegistries(t, node)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := chain.Dial(ctx, node.URL, chain.Addresses{PlatformRegistry: r.PlatformRegistry, AppRegistry: r.AppRegistry, DeploymentRegistry: r.DeploymentRegistry})
	if err != nil {
		t.Fatal(err)
	}
	heads, err := keybroker.DialRPCHeads(ctx, node.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &AnvilRegistrar{R: r, client: c, heads: heads, apps: map[string]bool{}}
}

func (a *AnvilRegistrar) Name() string           { return "anvil" }
func (a *AnvilRegistrar) Chain() keybroker.Chain { return keybroker.NewClientChain(a.client, a.heads) }
func (a *AnvilRegistrar) ChainID() uint64        { return a.R.Node.ChainID.Uint64() }
func (a *AnvilRegistrar) Contracts() chain.Addresses {
	return chain.Addresses{PlatformRegistry: a.R.PlatformRegistry, AppRegistry: a.R.AppRegistry, DeploymentRegistry: a.R.DeploymentRegistry}
}

// URL is the node's RPC URL.
func (a *AnvilRegistrar) URL() string { return a.R.Node.URL }

func (a *AnvilRegistrar) AddImage(t testing.TB, name, version string, mrtd attest.Measurement, debug bool) [32]byte {
	t.Helper()
	return a.R.AddImage(t, name, version, mrtd, attest.SimRTMR0, attest.SimRTMR1, attest.SimRTMR2, debug)
}

func (a *AnvilRegistrar) RevokeImage(t testing.TB, id [32]byte) { t.Helper(); a.R.RevokeImage(t, id) }

func (a *AnvilRegistrar) PublishRelease(t testing.TB, slug, version string, bundleHash [32]byte) [32]byte {
	t.Helper()
	if !a.apps[slug] {
		a.R.RegisterApp(t, slug)
		a.apps[slug] = true
	}
	return a.R.PublishRelease(t, composer.AppID(slug), version, bundleHash)
}

func (a *AnvilRegistrar) RevokeRelease(t testing.TB, id [32]byte) {
	t.Helper()
	a.R.RevokeRelease(t, id)
}

func (a *AnvilRegistrar) account(t testing.TB, addr common.Address) int {
	t.Helper()
	i := anvil.AccountOf(addr)
	if i < 0 {
		t.Fatalf("%s is not an anvil dev account", addr.Hex())
	}
	return i
}

func (a *AnvilRegistrar) ApproveStack(t testing.TB, customer common.Address, stackHash [32]byte, ids [][32]byte, imageID [32]byte) {
	t.Helper()
	a.R.ApproveStack(t, a.account(t, customer), stackHash, ids, imageID)
}

func (a *AnvilRegistrar) RevokeStack(t testing.TB, customer common.Address, stackHash [32]byte) {
	t.Helper()
	a.R.RevokeStack(t, a.account(t, customer), stackHash)
}

func (a *AnvilRegistrar) RegisterDeployment(t testing.TB, rec chain.Record) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	digest, err := a.client.RecordDigest(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	a.R.RegisterDeployment(t, rec, digest)
}

func (a *AnvilRegistrar) CloseDeployment(t testing.TB, customer common.Address, id [32]byte) {
	t.Helper()
	a.R.CloseDeployment(t, a.account(t, customer), id)
}
