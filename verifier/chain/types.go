package chain

import "github.com/ethereum/go-ethereum/common"

// The structs mirror the contract return tuples field by field (same names, types and order), so ABI decoding
// converts directly. Enums are uint8.

// Image status values (PlatformRegistry.ImageStatus).
const (
	ImageNone uint8 = iota
	ImageActive
	ImageDeprecated
	ImageRevoked
)

// Release status values (AppRegistry.ReleaseStatus).
const (
	ReleaseNone uint8 = iota
	ReleaseActive
	ReleaseDeprecated
	ReleaseRevoked
)

// Deployment status values (DeploymentRegistry.DeploymentStatus).
const (
	DeploymentNone uint8 = iota
	DeploymentActive
	DeploymentClosed
)

// Image is PlatformRegistry.getImage.
type Image struct {
	MeasurementsHash [32]byte
	IsDebug          bool
	Status           uint8
	AddedAt          uint64
	Name             string
	Version          string
	SourceURI        string
}

// App is AppRegistry.getApp.
type App struct {
	Slug               string
	Name               string
	LicenseSpdx        string
	MetadataURI        string
	Maintainer         common.Address
	MaintainerShareBps uint16
	RegisteredAt       uint64
}

// Release is AppRegistry.getRelease.
type Release struct {
	AppId            [32]byte
	BundleHash       [32]byte
	EgressPolicyHash [32]byte
	SbomHash         [32]byte
	Status           uint8
	PublishedAt      uint64
	Version          string
	ProvenanceURI    string
	SignatureURI     string
}

// StackApproval is DeploymentRegistry.getStackApproval. ApprovedAt is 0 when no approval exists.
type StackApproval struct {
	ReleaseIDs [][32]byte
	ImageID    [32]byte
	Expiry     uint64
	Revoked    bool
	ApprovedAt uint64
}

// Deployment is DeploymentRegistry.getDeployment.
type Deployment struct {
	DeploymentId   [32]byte
	Customer       common.Address
	AttestedAt     uint64
	Method         uint8
	LastMethod     uint8
	Status         uint8
	StackHash      [32]byte
	ImageId        [32]byte
	QuoteHash      [32]byte
	EventLogHash   [32]byte
	ConfigHash     [32]byte
	EnclaveSigner  common.Address
	LastAttestedAt uint64
	RegisteredAt   uint64
	ClosedAt       uint64
}

// Record is the IDeploymentRegistry.Record struct signed by the oracle (INTERFACES.md section 4.1).
type Record struct {
	DeploymentId  [32]byte
	Customer      common.Address
	StackHash     [32]byte
	ImageId       [32]byte
	QuoteHash     [32]byte
	EventLogHash  [32]byte
	ConfigHash    [32]byte
	EnclaveSigner common.Address
	AttestedAt    uint64
}
