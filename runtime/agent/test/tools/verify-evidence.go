//go:build ignore

// Verifies a sealed-agent evidence bundle with the real verifier library (verifier, package verify) in
// dev simulator mode, for runtime/agent/test/catalog.e2e.test.ts. The chain is an in-memory stand-in
// that holds exactly what a customer's approval would put onchain for the bundle's config: the sim
// image (active, not debug), one active release per config app built from the given catalog app
// directories by the real composer, and the customer's approval of the bundle's stackHash. The stack
// is recomputed by the real composer from those bundles. Prints the verifier's report as JSON, plus
// whether the quote's report_data equals the D-047 construction (attestedAt bound), which the agent
// produces even before the verifier checks it.
//
//	go run ./runtime/agent/test/tools/verify-evidence.go --evidence bundle.json --registry R --app-dir DIR...
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/composer/rimembed"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type publicConfig struct {
	ChainID  uint64 `json:"chainId"`
	Customer string `json:"customer"`
	ImageID  string `json:"imageId"`
	Apps     []struct {
		ID        string `json:"id"`
		ReleaseID string `json:"releaseId"`
	} `json:"apps"`
	Contracts struct {
		PlatformRegistry   string `json:"platformRegistry"`
		AppRegistry        string `json:"appRegistry"`
		DeploymentRegistry string `json:"deploymentRegistry"`
	} `json:"contracts"`
}

func hex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		fail(fmt.Errorf("not a 32-byte hex value: %q", s))
	}
	copy(out[:], b)
	return out
}

// fakeChain is the onchain state after the customer approved the bundle's stack.
type fakeChain struct {
	cfg       publicConfig
	stackHash [32]byte
	releases  map[[32]byte]*composer.Bundle
}

func (f *fakeChain) ChainID(context.Context) (uint64, error) { return f.cfg.ChainID, nil }
func (f *fakeChain) Addresses() chain.Addresses {
	return chain.Addresses{
		PlatformRegistry:   common.HexToAddress(f.cfg.Contracts.PlatformRegistry),
		AppRegistry:        common.HexToAddress(f.cfg.Contracts.AppRegistry),
		DeploymentRegistry: common.HexToAddress(f.cfg.Contracts.DeploymentRegistry),
	}
}
func (f *fakeChain) GetImage(_ context.Context, id [32]byte) (*chain.Image, error) {
	if id != hex32(f.cfg.ImageID) {
		return nil, chain.ErrNotFound
	}
	return &chain.Image{MeasurementsHash: attest.SimMeasurementsHash(false), Status: chain.ImageActive, AddedAt: 1, Name: "sealed-sim", Version: "dev"}, nil
}
func (f *fakeChain) IsApprovedImage(_ context.Context, id [32]byte) (bool, error) {
	return id == hex32(f.cfg.ImageID), nil
}
func (f *fakeChain) GetRelease(_ context.Context, id [32]byte) (*chain.Release, error) {
	b, ok := f.releases[id]
	if !ok {
		return nil, chain.ErrNotFound
	}
	return &chain.Release{AppId: b.AppID, BundleHash: b.Hash, EgressPolicyHash: b.EgressPolicyHash, SbomHash: b.SBOMHash, Status: chain.ReleaseActive, PublishedAt: 1, Version: b.Version()}, nil
}
func (f *fakeChain) IsActiveRelease(_ context.Context, id [32]byte) (bool, error) {
	_, ok := f.releases[id]
	return ok, nil
}
func (f *fakeChain) IsStackApproved(_ context.Context, customer common.Address, stackHash [32]byte) (bool, error) {
	return customer == common.HexToAddress(f.cfg.Customer) && stackHash == f.stackHash, nil
}
func (f *fakeChain) GetStackApproval(_ context.Context, customer common.Address, stackHash [32]byte) (*chain.StackApproval, error) {
	if customer != common.HexToAddress(f.cfg.Customer) || stackHash != f.stackHash {
		return &chain.StackApproval{}, nil
	}
	ap := &chain.StackApproval{ImageID: hex32(f.cfg.ImageID), Expiry: 1<<63 - 1, ApprovedAt: 1}
	for _, a := range f.cfg.Apps {
		ap.ReleaseIDs = append(ap.ReleaseIDs, hex32(a.ReleaseID))
	}
	return ap, nil
}
func (f *fakeChain) GetDeployment(context.Context, [32]byte) (*chain.Deployment, error) {
	return nil, chain.ErrNotFound
}
func (f *fakeChain) RecordDigest(context.Context, chain.Record) ([32]byte, error) {
	return [32]byte{}, errors.New("not available in this stand-in")
}

// localComposer recomputes the stack from the locally built bundles, fetched "by bundleHash".
type localComposer struct{ byHash map[[32]byte]*composer.Bundle }

func (c *localComposer) Compose(_ context.Context, in verify.ComposeInput) (*verify.ComposeOutput, error) {
	cfg, err := composer.ParseConfig(in.Config)
	if err != nil {
		return nil, err
	}
	var bundles []*composer.Bundle
	for _, r := range in.Releases {
		b, ok := c.byHash[r.BundleHash]
		if !ok || sha256.Sum256(b.Tar) != r.BundleHash || [32]byte(b.ReleaseID) != r.ReleaseID {
			return nil, fmt.Errorf("no bundle for %s with bundleHash 0x%x", r.App, r.BundleHash)
		}
		bundles = append(bundles, b)
	}
	res, err := rimembed.Compose(cfg, bundles)
	if err != nil {
		return nil, err
	}
	return &verify.ComposeOutput{AppCompose: res.AppCompose, StackHash: res.StackHash, ConfigHash: res.ConfigHash, DeploymentID: res.DeploymentID}, nil
}

func main() {
	var appDirs multi
	evidencePath := flag.String("evidence", "", "evidence bundle (sealed-evidence/v1)")
	registry := flag.String("registry", "", "catalog image registry the bundles were built with")
	flag.Var(&appDirs, "app-dir", "catalog app directory (repeatable)")
	flag.Parse()
	raw, err := os.ReadFile(*evidencePath)
	if err != nil {
		fail(err)
	}
	b, err := verify.ParseBundle(raw)
	if err != nil {
		fail(err)
	}
	var cfg publicConfig
	if err := json.Unmarshal(b.Config, &cfg); err != nil {
		fail(err)
	}
	byHash := map[[32]byte]*composer.Bundle{}
	byRelease := map[[32]byte]*composer.Bundle{}
	for _, dir := range appDirs {
		bun, err := composer.BuildBundle(composer.BuildInput{AppDir: dir, Registry: *registry, AllowMissingSBOM: true})
		if err != nil {
			fail(err)
		}
		byHash[bun.Hash] = bun
		byRelease[bun.ReleaseID] = bun
	}
	quotes, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: true})
	if err != nil {
		fail(err)
	}
	now := time.Unix(int64(b.AttestedAt)+60, 0)
	deps := verify.Deps{
		Quotes: quotes,
		// The fake chain's head is fresh at the verification clock (D-060).
		Chain:    verify.WithHead(&fakeChain{cfg: cfg, stackHash: sha256.Sum256([]byte(b.AppCompose)), releases: byRelease}, 1, func() time.Time { return now }),
		Composer: &localComposer{byHash: byHash},
		Now:      func() time.Time { return now },
	}
	rep, err := verify.VerifyEvidence(context.Background(), b, deps, verify.Options{ChainID: cfg.ChainID, MaxEvidenceAge: 15 * time.Minute, AcceptSimulated: true,
		// Bundles built from the working tree carry no release CI signature (release_signature reports that).
		AcceptUnsignedReleases: true})
	if err != nil {
		fail(err)
	}
	// The D-047 construction, computed here independently of the verifier's own report_data check.
	q, err := quotes.ParseQuote(mustHex(b.Quote))
	if err != nil {
		fail(err)
	}
	stack, config, nonce2 := hex32(b.StackHash), hex32(b.ConfigHash), hex32(b.Nonce2)
	signer := common.HexToAddress(b.EnclaveSigner)
	h := sha256.New()
	h.Write([]byte("sealed/evidence/v1"))
	h.Write(stack[:])
	h.Write(config[:])
	h.Write(signer[:])
	h.Write(nonce2[:])
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], b.AttestedAt)
	h.Write(at[:])
	var want [64]byte
	copy(want[:], h.Sum(nil))
	out := map[string]any{"report": rep, "d047ReportData": q.ReportData == attest.ReportData(want)}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail(err)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		fail(err)
	}
	return b
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "verify-evidence:", err)
	os.Exit(1)
}
