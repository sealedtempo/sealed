// Package kbtest builds test worlds for the key broker: registries (in memory or on a local anvil node), release
// bundles from the composer's fixture apps, composed stacks, and an agent that requests releases with simulated
// quotes. Only tests import it.
package kbtest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// MemChain is an in-memory model of the three registries with the contracts' view semantics: isApprovedImage is
// Active and not debug, isActiveRelease is Active or Deprecated, isStackApproved requires an unrevoked, unexpired
// approval whose image and releases are all still approved or active, getDeployment reverts for an unknown id.
type MemChain struct {
	mu          sync.Mutex
	id          uint64
	block       uint64
	images      map[[32]byte]*chain.Image
	releases    map[[32]byte]*chain.Release
	approvals   map[common.Address]map[[32]byte]*chain.StackApproval
	deployments map[[32]byte]*chain.Deployment

	// FailReads makes every registry read fail (an RPC outage).
	FailReads error
	// HeadLag makes the head block that much older than the wall clock (a lagging or stuck RPC, D-060).
	HeadLag time.Duration
}

// NewMemChain returns an empty chain with the given id.
func NewMemChain(id uint64) *MemChain {
	return &MemChain{id: id, block: 1, images: map[[32]byte]*chain.Image{}, releases: map[[32]byte]*chain.Release{},
		approvals: map[common.Address]map[[32]byte]*chain.StackApproval{}, deployments: map[[32]byte]*chain.Deployment{}}
}

var _ keybroker.Chain = (*MemChain)(nil)
var _ keybroker.Registry = (*MemChain)(nil)

// ChainID implements keybroker.Chain.
func (m *MemChain) ChainID(context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailReads != nil {
		return 0, m.FailReads
	}
	return m.id, nil
}

// Pin implements keybroker.Chain. Reads are not snapshotted; tests do not change state during a release. The head's
// timestamp is the wall clock minus HeadLag.
func (m *MemChain) Pin(context.Context) (keybroker.Registry, keybroker.Head, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailReads != nil {
		return nil, keybroker.Head{}, m.FailReads
	}
	return m, keybroker.Head{Number: m.block, Time: time.Now().Add(-m.HeadLag).Truncate(time.Second)}, nil
}

// SetHeadLag sets HeadLag.
func (m *MemChain) SetHeadLag(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.HeadLag = d
}

func (m *MemChain) bump() { m.block++ }

func (m *MemChain) fail() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.FailReads
}

// GetImage implements keybroker.Registry.
func (m *MemChain) GetImage(_ context.Context, id [32]byte) (*chain.Image, error) {
	if err := m.fail(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	img, ok := m.images[id]
	if !ok {
		return nil, &chain.RevertError{Contract: "PlatformRegistry", Name: "ImageNotFound"}
	}
	cp := *img
	return &cp, nil
}

func (m *MemChain) approvedImageLocked(id [32]byte) bool {
	img, ok := m.images[id]
	return ok && img.Status == chain.ImageActive && !img.IsDebug
}

// IsApprovedImage implements keybroker.Registry.
func (m *MemChain) IsApprovedImage(_ context.Context, id [32]byte) (bool, error) {
	if err := m.fail(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.approvedImageLocked(id), nil
}

// GetRelease implements keybroker.Registry.
func (m *MemChain) GetRelease(_ context.Context, id [32]byte) (*chain.Release, error) {
	if err := m.fail(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.releases[id]
	if !ok {
		return nil, &chain.RevertError{Contract: "AppRegistry", Name: "ReleaseNotFound"}
	}
	cp := *r
	return &cp, nil
}

// IsStackApproved implements keybroker.Registry.
func (m *MemChain) IsStackApproved(_ context.Context, customer common.Address, stackHash [32]byte) (bool, error) {
	if err := m.fail(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[customer][stackHash]
	if !ok || a.ApprovedAt == 0 || a.Revoked || !m.approvedImageLocked(a.ImageID) {
		return false, nil
	}
	for _, id := range a.ReleaseIDs {
		r, ok := m.releases[id]
		if !ok || (r.Status != chain.ReleaseActive && r.Status != chain.ReleaseDeprecated) {
			return false, nil
		}
	}
	return true, nil
}

// GetStackApproval implements keybroker.Registry.
func (m *MemChain) GetStackApproval(_ context.Context, customer common.Address, stackHash [32]byte) (*chain.StackApproval, error) {
	if err := m.fail(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approvals[customer][stackHash]
	if !ok {
		return &chain.StackApproval{}, nil
	}
	cp := *a
	cp.ReleaseIDs = append([][32]byte(nil), a.ReleaseIDs...)
	return &cp, nil
}

// GetDeployment implements keybroker.Registry.
func (m *MemChain) GetDeployment(_ context.Context, id [32]byte) (*chain.Deployment, error) {
	if err := m.fail(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deployments[id]
	if !ok {
		return nil, &chain.RevertError{Contract: "DeploymentRegistry", Name: "DeploymentNotFound"}
	}
	cp := *d
	return &cp, nil
}

// RegisterDeployment records an Active deployment like DeploymentRegistry.registerDeployment (the record's
// signature is not modeled).
func (m *MemChain) RegisterDeployment(r chain.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.deployments[r.DeploymentId]; ok {
		return errors.New("DeploymentAlreadyRegistered")
	}
	m.deployments[r.DeploymentId] = &chain.Deployment{DeploymentId: r.DeploymentId, Customer: r.Customer, AttestedAt: r.AttestedAt,
		Method: 1, LastMethod: 1, Status: chain.DeploymentActive, StackHash: r.StackHash, ImageId: r.ImageId, QuoteHash: r.QuoteHash,
		EventLogHash: r.EventLogHash, ConfigHash: r.ConfigHash, EnclaveSigner: r.EnclaveSigner, LastAttestedAt: r.AttestedAt,
		RegisteredAt: uint64(time.Now().Unix())}
	m.bump()
	return nil
}

// CloseDeployment closes an Active deployment like DeploymentRegistry.closeDeployment.
func (m *MemChain) CloseDeployment(id [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deployments[id]
	if !ok || d.Status != chain.DeploymentActive {
		return errors.New("DeploymentNotActive")
	}
	d.Status, d.ClosedAt = chain.DeploymentClosed, uint64(time.Now().Unix())
	m.bump()
	return nil
}

// AddImage registers an image.
func (m *MemChain) AddImage(id, measurementsHash [32]byte, name, version string, debug bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.images[id] = &chain.Image{MeasurementsHash: measurementsHash, IsDebug: debug, Status: chain.ImageActive, AddedAt: 1, Name: name, Version: version}
	m.bump()
}

// SetImageStatus changes an image's status.
func (m *MemChain) SetImageStatus(id [32]byte, status uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.images[id].Status = status
	m.bump()
}

// PublishRelease records a release and returns its id.
func (m *MemChain) PublishRelease(slug, version string, bundleHash [32]byte) [32]byte {
	appID := crypto.Keccak256Hash([]byte(slug))
	id := releaseID(appID, version, bundleHash)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releases[id] = &chain.Release{AppId: appID, BundleHash: bundleHash, Status: chain.ReleaseActive, PublishedAt: 1, Version: version}
	m.bump()
	return id
}

// SetReleaseStatus changes a release's status.
func (m *MemChain) SetReleaseStatus(id [32]byte, status uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releases[id].Status = status
	m.bump()
}

// ApproveStack stores an approval like DeploymentRegistry.approveStack (first approval fixes the set).
func (m *MemChain) ApproveStack(customer common.Address, stackHash [32]byte, releaseIDs [][32]byte, imageID [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.approvedImageLocked(imageID) {
		return errors.New("ImageNotApproved")
	}
	if m.approvals[customer] == nil {
		m.approvals[customer] = map[[32]byte]*chain.StackApproval{}
	}
	if a, ok := m.approvals[customer][stackHash]; ok {
		a.Revoked = false
		return nil
	}
	m.approvals[customer][stackHash] = &chain.StackApproval{ReleaseIDs: append([][32]byte(nil), releaseIDs...), ImageID: imageID, ApprovedAt: m.block}
	m.bump()
	return nil
}

// RevokeStack revokes an approval.
func (m *MemChain) RevokeStack(customer common.Address, stackHash [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.approvals[customer][stackHash]; ok {
		a.Revoked = true
	}
	m.bump()
}
