package chain

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// fakeBackend answers eth_call with ABI-packed values per method selector.
type fakeBackend struct {
	t       *testing.T
	results map[string][]byte // 4-byte selector hex -> return data
	reverts map[string]error
	calls   int
	blocks  []*big.Int // block argument of each call
	head    uint64
}

type dataErr struct{ data string }

func (e dataErr) Error() string          { return "execution reverted" }
func (e dataErr) ErrorCode() int         { return 3 }
func (e dataErr) ErrorData() interface{} { return e.data }

func (f *fakeBackend) CallContract(_ context.Context, call ethereum.CallMsg, block *big.Int) ([]byte, error) {
	f.calls++
	f.blocks = append(f.blocks, block)
	sel := hex.EncodeToString(call.Data[:4])
	if err, ok := f.reverts[sel]; ok {
		return nil, err
	}
	if out, ok := f.results[sel]; ok {
		return out, nil
	}
	f.t.Fatalf("unexpected call %s", sel)
	return nil, nil
}

func (f *fakeBackend) ChainID(context.Context) (*big.Int, error) { return big.NewInt(4217), nil }

func (f *fakeBackend) BlockNumber(context.Context) (uint64, error) { return f.head, nil }

var testAddrs = Addresses{
	PlatformRegistry:   common.HexToAddress("0x1000000000000000000000000000000000000001"),
	AppRegistry:        common.HexToAddress("0x1000000000000000000000000000000000000002"),
	DeploymentRegistry: common.HexToAddress("0x1000000000000000000000000000000000000003"),
}

func newFake(t *testing.T) (*Client, *fakeBackend) {
	fb := &fakeBackend{t: t, results: map[string][]byte{}, reverts: map[string]error{}}
	c, err := New(fb, testAddrs)
	if err != nil {
		t.Fatal(err)
	}
	return c, fb
}

func (f *fakeBackend) respond(c *Client, contract, method string, vals ...any) {
	m := c.abis[contract].Methods[method]
	out, err := m.Outputs.Pack(vals...)
	if err != nil {
		f.t.Fatal(err)
	}
	f.results[hex.EncodeToString(m.ID)] = out
}

func (f *fakeBackend) revert(c *Client, contract, method, errName string, args ...any) {
	e := c.abis[contract].Errors[errName]
	enc, err := e.Inputs.Pack(args...)
	if err != nil {
		f.t.Fatal(err)
	}
	f.reverts[hex.EncodeToString(c.abis[contract].Methods[method].ID)] = dataErr{"0x" + hex.EncodeToString(append(e.ID[:4], enc...))}
}

func TestDecodesViews(t *testing.T) {
	c, fb := newFake(t)
	img := Image{MeasurementsHash: [32]byte{1}, IsDebug: true, Status: ImageActive, AddedAt: 7, Name: "sealed-os", Version: "1", SourceURI: "u"}
	fb.respond(c, "PlatformRegistry", "getImage", img)
	fb.respond(c, "PlatformRegistry", "isApprovedImage", false)
	rel := Release{AppId: [32]byte{2}, BundleHash: [32]byte{3}, Status: ReleaseRevoked, Version: "1.2.3"}
	fb.respond(c, "AppRegistry", "getRelease", rel)
	fb.respond(c, "AppRegistry", "isActiveRelease", true)
	app := App{Slug: "crm", Name: "CRM", Maintainer: common.HexToAddress("0x2"), MaintainerShareBps: 2000, RegisteredAt: 9}
	fb.respond(c, "AppRegistry", "getApp", app)
	fb.respond(c, "DeploymentRegistry", "getStackApproval", [][32]byte{{4}, {5}}, [32]byte{6}, uint64(10), true, uint64(11))
	fb.respond(c, "DeploymentRegistry", "isStackApproved", true)
	dep := Deployment{DeploymentId: [32]byte{7}, Customer: common.HexToAddress("0x3"), Status: DeploymentActive, QuoteHash: [32]byte{8}, LastAttestedAt: 12}
	fb.respond(c, "DeploymentRegistry", "getDeployment", dep)
	fb.respond(c, "DeploymentRegistry", "recordDigest", [32]byte{9})

	ctx := context.Background()
	if got, err := c.GetImage(ctx, [32]byte{}); err != nil || *got != img {
		t.Fatalf("GetImage %+v %v", got, err)
	}
	if ok, err := c.IsApprovedImage(ctx, [32]byte{}); err != nil || ok {
		t.Fatal("IsApprovedImage")
	}
	if got, err := c.GetRelease(ctx, [32]byte{}); err != nil || *got != rel {
		t.Fatalf("GetRelease %+v %v", got, err)
	}
	if ok, err := c.IsActiveRelease(ctx, [32]byte{}); err != nil || !ok {
		t.Fatal("IsActiveRelease")
	}
	if got, err := c.GetApp(ctx, [32]byte{}); err != nil || *got != app {
		t.Fatalf("GetApp %+v %v", got, err)
	}
	ap, err := c.GetStackApproval(ctx, common.Address{}, [32]byte{})
	if err != nil || len(ap.ReleaseIDs) != 2 || ap.ReleaseIDs[1] != [32]byte{5} || ap.ImageID != [32]byte{6} || ap.Expiry != 10 || !ap.Revoked || ap.ApprovedAt != 11 {
		t.Fatalf("GetStackApproval %+v %v", ap, err)
	}
	if ok, err := c.IsStackApproved(ctx, common.Address{}, [32]byte{}); err != nil || !ok {
		t.Fatal("IsStackApproved")
	}
	if got, err := c.GetDeployment(ctx, [32]byte{}); err != nil || *got != dep {
		t.Fatalf("GetDeployment %+v %v", got, err)
	}
	if d, err := c.RecordDigest(ctx, Record{}); err != nil || d != [32]byte{9} {
		t.Fatal("RecordDigest")
	}
	if id, err := c.ChainID(ctx); err != nil || id != 4217 {
		t.Fatal("ChainID")
	}
}

func TestRevertsDecoded(t *testing.T) {
	c, fb := newFake(t)
	fb.revert(c, "DeploymentRegistry", "getDeployment", "DeploymentNotFound", [32]byte{1})
	fb.revert(c, "PlatformRegistry", "getImage", "ImageNotFound", [32]byte{2})
	fb.reverts[hex.EncodeToString(c.abis["AppRegistry"].Methods["getRelease"].ID)] = errors.New("connection refused")

	_, err := c.GetDeployment(context.Background(), [32]byte{1})
	var rev *RevertError
	if !errors.Is(err, ErrNotFound) || !errors.As(err, &rev) || rev.Name != "DeploymentNotFound" {
		t.Fatalf("GetDeployment err = %v", err)
	}
	if _, err := c.GetImage(context.Background(), [32]byte{2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetImage err = %v", err)
	}
	if _, err := c.GetRelease(context.Background(), [32]byte{3}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("transport error mapped to not found: %v", err)
	}
}

func TestAddresses(t *testing.T) {
	if _, err := New(&fakeBackend{t: t}, Addresses{}); err == nil {
		t.Fatal("empty addresses accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "local.json")
	doc := `{"chainId":31337,"network":"local","contracts":{
	  "PlatformRegistry":{"address":"0x5FbDB2315678afecb367f032d93F642f64180aa3"},
	  "AppRegistry":{"address":"0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"},
	  "DeploymentRegistry":{"address":"0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"},
	  "FeeSplitter":{"address":"0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"}}}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	d, a, err := LoadDeployments(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.ChainID != 31337 || a.DeploymentRegistry != common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9") {
		t.Fatalf("%+v %+v", d, a)
	}
	if err := os.WriteFile(path, []byte(`{"contracts":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDeployments(path); err == nil {
		t.Fatal("deployments without addresses accepted")
	}
}
