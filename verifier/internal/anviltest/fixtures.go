package anviltest

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Measurements are the four 48-byte registers an image is registered with.
type Measurements struct{ MRTD, RTMR0, RTMR1, RTMR2 [48]byte }

// ImageID is keccak256(abi.encode(name, version, measurementsHash)) (INTERFACES.md section 2).
func ImageID(name, version string, measurementsHash [32]byte) [32]byte {
	strT, _ := abi.NewType("string", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: strT}, {Type: strT}, {Type: b32T}}.Pack(name, version, measurementsHash)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(enc)
}

// AppID is keccak256(bytes(slug)).
func AppID(slug string) [32]byte { return crypto.Keccak256Hash([]byte(slug)) }

// ReleaseID is keccak256(abi.encode(appId, version, bundleHash)).
func ReleaseID(appID [32]byte, version string, bundleHash [32]byte) [32]byte {
	strT, _ := abi.NewType("string", "", nil)
	b32T, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: b32T}, {Type: strT}, {Type: b32T}}.Pack(appID, version, bundleHash)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256Hash(enc)
}

func (r *Registries) abi(name string) abi.ABI { return r.Artifacts[name].ABI }

// AddImage registers an image (owner) and returns its imageId.
func (r *Registries) AddImage(t testing.TB, n *Node, name, version string, m Measurements, isDebug bool) [32]byte {
	t.Helper()
	mh := crypto.Keccak256Hash(m.MRTD[:], m.RTMR0[:], m.RTMR1[:], m.RTMR2[:])
	id := ImageID(name, version, mh)
	n.Call(t, Owner, r.PlatformRegistry, r.abi("PlatformRegistry"), "addImage", id, name, version,
		m.MRTD[:], m.RTMR0[:], m.RTMR1[:], m.RTMR2[:], isDebug, "https://example.invalid/"+name)
	return id
}

// RevokeImage revokes an image (owner).
func (r *Registries) RevokeImage(t testing.TB, n *Node, imageID [32]byte) {
	t.Helper()
	n.Call(t, Owner, r.PlatformRegistry, r.abi("PlatformRegistry"), "revokeImage", imageID, "test")
}

// RegisterApp registers slug with the Maintainer account (owner) and returns its appId.
func (r *Registries) RegisterApp(t testing.TB, n *Node, slug string) [32]byte {
	t.Helper()
	id := AppID(slug)
	n.Call(t, Owner, r.AppRegistry, r.abi("AppRegistry"), "registerApp", id, slug, slug, "MIT", Addr(Maintainer),
		uint16(2000), "https://example.invalid/"+slug)
	return id
}

// PublishRelease publishes a release (ops) and returns its releaseId.
func (r *Registries) PublishRelease(t testing.TB, n *Node, appID [32]byte, version string, bundleHash [32]byte) [32]byte {
	t.Helper()
	n.Call(t, Ops, r.AppRegistry, r.abi("AppRegistry"), "publishRelease", appID, version, bundleHash,
		crypto.Keccak256Hash([]byte("egress")), crypto.Keccak256Hash([]byte("sbom")), "", "")
	return ReleaseID(appID, version, bundleHash)
}

// RevokeRelease revokes a release (owner).
func (r *Registries) RevokeRelease(t testing.TB, n *Node, releaseID [32]byte) {
	t.Helper()
	n.Call(t, Owner, r.AppRegistry, r.abi("AppRegistry"), "revokeRelease", releaseID, "test")
}

// ApproveStack approves (stackHash, releaseIds, imageId) as dev account `customer`, with no expiry.
func (r *Registries) ApproveStack(t testing.TB, n *Node, customer int, stackHash [32]byte, releaseIDs [][32]byte, imageID [32]byte) {
	t.Helper()
	n.Call(t, customer, r.DeploymentRegistry, r.abi("DeploymentRegistry"), "approveStack", stackHash, releaseIDs, imageID, uint64(0))
}

// RevokeStack revokes the approval of stackHash as dev account `customer`.
func (r *Registries) RevokeStack(t testing.TB, n *Node, customer int, stackHash [32]byte) {
	t.Helper()
	n.Call(t, customer, r.DeploymentRegistry, r.abi("DeploymentRegistry"), "revokeStack", stackHash)
}

// Record mirrors IDeploymentRegistry.Record for packing.
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

// RegisterDeployment signs recordDigest(rec) with the Oracle key and submits registerDeployment from Ops.
func (r *Registries) RegisterDeployment(t testing.TB, n *Node, rec Record) {
	t.Helper()
	if err := r.TryRegisterDeployment(n, rec); err != nil {
		t.Fatalf("registerDeployment: %v", err)
	}
}

// TryRegisterDeployment is RegisterDeployment returning the error.
func (r *Registries) TryRegisterDeployment(n *Node, rec Record) error {
	a := r.abi("DeploymentRegistry")
	data, err := a.Pack("recordDigest", rec)
	if err != nil {
		return err
	}
	out, err := n.Client.CallContract(t0(), callMsg(r.DeploymentRegistry, data), nil)
	if err != nil {
		return err
	}
	vals, err := a.Unpack("recordDigest", out)
	if err != nil {
		return err
	}
	digest := vals[0].([32]byte)
	sig, err := crypto.Sign(digest[:], Key(Oracle))
	if err != nil {
		return err
	}
	sig[64] += 27
	bytesT, _ := abi.NewType("bytes", "", nil)
	evidence, err := abi.Arguments{{Type: bytesT}}.Pack(sig)
	if err != nil {
		return err
	}
	_, err = n.Try(Ops, r.DeploymentRegistry, a, "registerDeployment", rec, uint8(1), evidence)
	return err
}

// Now returns the latest block timestamp.
func (n *Node) Now(t testing.TB) uint64 {
	t.Helper()
	var head struct {
		Timestamp string `json:"timestamp"`
	}
	if err := n.Client.Client().CallContext(t0(), &head, "eth_getBlockByNumber", "latest", false); err != nil {
		t.Fatal(err)
	}
	ts, ok := new(big.Int).SetString(head.Timestamp[2:], 16)
	if !ok {
		t.Fatalf("bad timestamp %q", head.Timestamp)
	}
	return ts.Uint64()
}
