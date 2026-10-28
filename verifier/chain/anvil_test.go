package chain

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/sealed-dev/sealed/verifier/internal/anviltest"
)

// TestAnvilViews deploys the real contracts into a local Tempo node and reads every view the verifier uses.
func TestAnvilViews(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	n := anviltest.Start(t)
	r := anviltest.DeployRegistries(t, n)
	ctx := context.Background()
	c, err := New(n.Client, Addresses{PlatformRegistry: r.PlatformRegistry, AppRegistry: r.AppRegistry, DeploymentRegistry: r.DeploymentRegistry})
	if err != nil {
		t.Fatal(err)
	}

	m := anviltest.Measurements{}
	for i := range m.MRTD {
		m.MRTD[i], m.RTMR0[i], m.RTMR1[i], m.RTMR2[i] = 0x11, 0x22, 0x33, 0x44
	}
	imageID := r.AddImage(t, n, "sealed-sim", "1.0.0", m, false)
	dm := m
	for i := range dm.MRTD {
		dm.MRTD[i] = 0x55 // distinct measurements: PlatformRegistry may reject reusing a measurementsHash
	}
	debugID := r.AddImage(t, n, "sealed-sim-debug", "1.0.0", dm, true)
	appID := r.RegisterApp(t, n, "llm-gateway")
	relID := r.PublishRelease(t, n, appID, "1.0.0", [32]byte{0xb1})
	stack := [32]byte{0x5a}
	r.ApproveStack(t, n, anviltest.Customer, stack, [][32]byte{relID}, imageID)

	img, err := c.GetImage(ctx, imageID)
	if err != nil || img.Name != "sealed-sim" || img.IsDebug || img.Status != ImageActive {
		t.Fatalf("GetImage %+v %v", img, err)
	}
	if ok, _ := c.IsApprovedImage(ctx, imageID); !ok {
		t.Fatal("image not approved")
	}
	if ok, _ := c.IsApprovedImage(ctx, debugID); ok {
		t.Fatal("debug image approved")
	}
	if _, err := c.GetImage(ctx, [32]byte{0xee}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown image: %v", err)
	}
	app, err := c.GetApp(ctx, appID)
	if err != nil || app.Slug != "llm-gateway" || app.Maintainer != anviltest.Addr(anviltest.Maintainer) {
		t.Fatalf("GetApp %+v %v", app, err)
	}
	rel, err := c.GetRelease(ctx, relID)
	if err != nil || rel.AppId != appID || rel.BundleHash != [32]byte{0xb1} || rel.Version != "1.0.0" || rel.Status != ReleaseActive {
		t.Fatalf("GetRelease %+v %v", rel, err)
	}
	if _, err := c.GetRelease(ctx, [32]byte{0xee}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown release: %v", err)
	}
	cust := anviltest.Addr(anviltest.Customer)
	if ok, _ := c.IsStackApproved(ctx, cust, stack); !ok {
		t.Fatal("stack not approved")
	}
	ap, err := c.GetStackApproval(ctx, cust, stack)
	if err != nil || len(ap.ReleaseIDs) != 1 || ap.ReleaseIDs[0] != relID || ap.ImageID != imageID || ap.ApprovedAt == 0 || ap.Revoked {
		t.Fatalf("GetStackApproval %+v %v", ap, err)
	}

	rec := anviltest.Record{
		DeploymentId: [32]byte{0xd1}, Customer: cust, StackHash: stack, ImageId: imageID,
		QuoteHash: [32]byte{0x01}, EventLogHash: [32]byte{0x02}, ConfigHash: [32]byte{0x03},
		EnclaveSigner: anviltest.Addr(anviltest.Enclave), AttestedAt: n.Now(t),
	}
	r.RegisterDeployment(t, n, rec)
	d, err := c.GetDeployment(ctx, rec.DeploymentId)
	if err != nil || d.Status != DeploymentActive || d.QuoteHash != rec.QuoteHash || d.EnclaveSigner != rec.EnclaveSigner || d.LastAttestedAt != rec.AttestedAt {
		t.Fatalf("GetDeployment %+v %v", d, err)
	}
	if _, err := c.GetDeployment(ctx, [32]byte{0xee}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown deployment: %v", err)
	}

	// recordDigest must equal the EIP-712 digest of INTERFACES.md section 4.1 computed offchain.
	got, err := c.RecordDigest(ctx, Record(rec))
	if err != nil {
		t.Fatal(err)
	}
	if want := recordDigestOffchain(t, n.ChainID.Int64(), r.DeploymentRegistry, rec); got != want {
		t.Fatalf("recordDigest %x, offchain %x", got, want)
	}

	r.RevokeRelease(t, n, relID)
	if ok, _ := c.IsActiveRelease(ctx, relID); ok {
		t.Fatal("revoked release active")
	}
	if ok, _ := c.IsStackApproved(ctx, cust, stack); ok {
		t.Fatal("stack with revoked release still approved")
	}
	if id, err := c.ChainID(ctx); err != nil || id != 31337 {
		t.Fatalf("chain id %d %v", id, err)
	}
}

func recordDigestOffchain(t *testing.T, chainID int64, registry common.Address, r anviltest.Record) [32]byte {
	td := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {{Name: "name", Type: "string"}, {Name: "version", Type: "string"}, {Name: "chainId", Type: "uint256"}, {Name: "verifyingContract", Type: "address"}},
			"Record": {
				{Name: "deploymentId", Type: "bytes32"}, {Name: "customer", Type: "address"}, {Name: "stackHash", Type: "bytes32"},
				{Name: "imageId", Type: "bytes32"}, {Name: "quoteHash", Type: "bytes32"}, {Name: "eventLogHash", Type: "bytes32"},
				{Name: "configHash", Type: "bytes32"}, {Name: "enclaveSigner", Type: "address"}, {Name: "attestedAt", Type: "uint64"},
			},
		},
		PrimaryType: "Record",
		Domain: apitypes.TypedDataDomain{Name: "Sealed DeploymentRegistry", Version: "1",
			ChainId: math.NewHexOrDecimal256(chainID), VerifyingContract: registry.Hex()},
		Message: apitypes.TypedDataMessage{
			"deploymentId": r.DeploymentId[:], "customer": r.Customer.Hex(), "stackHash": r.StackHash[:],
			"imageId": r.ImageId[:], "quoteHash": r.QuoteHash[:], "eventLogHash": r.EventLogHash[:],
			"configHash": r.ConfigHash[:], "enclaveSigner": r.EnclaveSigner.Hex(),
			"attestedAt": math.NewHexOrDecimal256(int64(r.AttestedAt)),
		},
	}
	d, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], d)
	return out
}
