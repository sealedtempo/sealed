package fixture

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// MemChain is an in-memory verify.ChainReader with the registries' view semantics.
type MemChain struct {
	mu          sync.Mutex
	ID          uint64
	Addrs       chain.Addresses
	Images      map[[32]byte]*chain.Image
	Releases    map[[32]byte]*chain.Release
	Approvals   map[common.Address]map[[32]byte]*chain.StackApproval
	Deployments map[[32]byte]*chain.Deployment
	Now         uint64
	// Head is the block number PinHead reports.
	Head uint64
	// FailCalls makes every read fail, like an unreachable RPC.
	FailCalls bool
}

// NewMemChain returns an empty chain.
func NewMemChain(id uint64, addrs chain.Addresses) *MemChain {
	return &MemChain{
		ID: id, Addrs: addrs,
		Images:      map[[32]byte]*chain.Image{},
		Releases:    map[[32]byte]*chain.Release{},
		Approvals:   map[common.Address]map[[32]byte]*chain.StackApproval{},
		Deployments: map[[32]byte]*chain.Deployment{},
		Now:         1_793_000_000,
		Head:        100,
	}
}

// PinHead implements verify.BlockPinner. The in-memory state has no history, so the reader is m itself.
func (m *MemChain) PinHead(context.Context) (verify.ChainReader, uint64, error) {
	if err := m.fail(); err != nil {
		return nil, 0, err
	}
	return m, m.Head, nil
}

var errRPC = fmt.Errorf("rpc unavailable")

func (m *MemChain) fail() error {
	if m.FailCalls {
		return errRPC
	}
	return nil
}

// ChainID implements verify.ChainReader.
func (m *MemChain) ChainID(context.Context) (uint64, error) { return m.ID, m.fail() }

// Addresses implements verify.ChainReader.
func (m *MemChain) Addresses() chain.Addresses { return m.Addrs }

// GetImage implements verify.ChainReader.
func (m *MemChain) GetImage(_ context.Context, id [32]byte) (*chain.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	img, ok := m.Images[id]
	if !ok {
		return nil, &chain.RevertError{Contract: "PlatformRegistry", Name: "ImageNotFound"}
	}
	c := *img
	return &c, nil
}

// IsApprovedImage implements verify.ChainReader.
func (m *MemChain) IsApprovedImage(_ context.Context, id [32]byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img, ok := m.Images[id]
	return ok && img.Status == chain.ImageActive && !img.IsDebug, m.fail()
}

// GetRelease implements verify.ChainReader.
func (m *MemChain) GetRelease(_ context.Context, id [32]byte) (*chain.Release, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	r, ok := m.Releases[id]
	if !ok {
		return nil, &chain.RevertError{Contract: "AppRegistry", Name: "ReleaseNotFound"}
	}
	c := *r
	return &c, nil
}

// IsActiveRelease implements verify.ChainReader.
func (m *MemChain) IsActiveRelease(_ context.Context, id [32]byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeRelease(id), m.fail()
}

func (m *MemChain) activeRelease(id [32]byte) bool {
	r, ok := m.Releases[id]
	return ok && (r.Status == chain.ReleaseActive || r.Status == chain.ReleaseDeprecated)
}

// IsStackApproved implements verify.ChainReader with DeploymentRegistry.isStackApproved semantics.
func (m *MemChain) IsStackApproved(_ context.Context, customer common.Address, stack [32]byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	a := m.Approvals[customer][stack]
	if a == nil || a.ApprovedAt == 0 || a.Revoked || (a.Expiry != 0 && m.Now >= a.Expiry) {
		return false, nil
	}
	img, ok := m.Images[a.ImageID]
	if !ok || img.Status != chain.ImageActive || img.IsDebug {
		return false, nil
	}
	for _, id := range a.ReleaseIDs {
		if !m.activeRelease(id) {
			return false, nil
		}
	}
	return true, nil
}

// GetStackApproval implements verify.ChainReader.
func (m *MemChain) GetStackApproval(_ context.Context, customer common.Address, stack [32]byte) (*chain.StackApproval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	a := m.Approvals[customer][stack]
	if a == nil {
		return &chain.StackApproval{}, nil
	}
	c := *a
	c.ReleaseIDs = slices.Clone(a.ReleaseIDs)
	return &c, nil
}

// GetDeployment implements verify.ChainReader.
func (m *MemChain) GetDeployment(_ context.Context, id [32]byte) (*chain.Deployment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	d, ok := m.Deployments[id]
	if !ok {
		return nil, &chain.RevertError{Contract: "DeploymentRegistry", Name: "DeploymentNotFound"}
	}
	c := *d
	return &c, nil
}

// RecordDigest implements verify.ChainReader with a stand-in digest (not EIP-712).
func (m *MemChain) RecordDigest(_ context.Context, r chain.Record) ([32]byte, error) {
	return crypto.Keccak256Hash(r.DeploymentId[:], r.QuoteHash[:]), m.fail()
}

// Approve stores an approval as approveStack would.
func (m *MemChain) Approve(customer common.Address, stack [32]byte, releaseIDs [][32]byte, imageID [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Approvals[customer] == nil {
		m.Approvals[customer] = map[[32]byte]*chain.StackApproval{}
	}
	m.Approvals[customer][stack] = &chain.StackApproval{ReleaseIDs: slices.Clone(releaseIDs), ImageID: imageID, ApprovedAt: m.Now}
}

// Register stores a deployment record as registerDeployment would.
func (m *MemChain) Register(r chain.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Deployments[r.DeploymentId] = &chain.Deployment{
		DeploymentId: r.DeploymentId, Customer: r.Customer, AttestedAt: r.AttestedAt, Method: 1, LastMethod: 1,
		Status: chain.DeploymentActive, StackHash: r.StackHash, ImageId: r.ImageId, QuoteHash: r.QuoteHash,
		EventLogHash: r.EventLogHash, ConfigHash: r.ConfigHash, EnclaveSigner: r.EnclaveSigner,
		LastAttestedAt: r.AttestedAt, RegisteredAt: m.Now,
	}
}
