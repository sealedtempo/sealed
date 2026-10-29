package verify_test

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
	"github.com/sealedtempo/sealed/verifier/internal/anviltest"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
)

func simMeasurements(debug bool) anviltest.Measurements {
	m := anviltest.Measurements{MRTD: attest.SimMRTD, RTMR0: attest.SimRTMR0, RTMR1: attest.SimRTMR1, RTMR2: attest.SimRTMR2}
	if debug {
		m.MRTD = attest.SimMRTDDebug
	}
	return m
}

// TestEndToEndAnvil runs VerifyEvidence over a simulated quote against the real contracts deployed into a local
// Tempo node, then walks the acceptance tamper cases (A7) against live chain state.
func TestEndToEndAnvil(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	n := anviltest.Start(t)
	r := anviltest.DeployRegistries(t, n)
	addrs := chain.Addresses{PlatformRegistry: r.PlatformRegistry, AppRegistry: r.AppRegistry, DeploymentRegistry: r.DeploymentRegistry}
	client, err := chain.New(n.Client, addrs)
	if err != nil {
		t.Fatal(err)
	}

	imageID := r.AddImage(t, n, "sealed-sim", "1.0.0", simMeasurements(false), false)
	debugImageID := r.AddImage(t, n, "sealed-sim-debug", "1.0.0", simMeasurements(true), true)
	if imageID != fixture.SimImageID(false) || debugImageID != fixture.SimImageID(true) {
		t.Fatal("imageId derivation differs between the fixture and the onchain registration")
	}
	cust := anviltest.Addr(anviltest.Customer)
	w := fixture.NewWorld(n.ChainID.Uint64(), addrs, cust, anviltest.Addr(anviltest.Enclave), imageID)
	for _, a := range w.Apps {
		appID := r.RegisterApp(t, n, a.Slug)
		if got := r.PublishRelease(t, n, appID, a.Version, a.BundleHash); got != a.ReleaseID() {
			t.Fatalf("releaseId derivation differs for %s", a.Slug)
		}
	}
	// Approve first: registerDeployment may require attestedAt >= approvedAt.
	stackHash := w.Compose().StackHash
	r.ApproveStack(t, n, anviltest.Customer, stackHash, w.ReleaseIDs(), imageID)
	b := w.Bundle(n.Now(t))
	rec := fixture.Record(b)
	r.RegisterDeployment(t, n, anviltest.Record(rec))

	deps := verify.Deps{Quotes: devVerifier(t), Chain: client, Composer: fixture.Composer{}}
	opts := verify.Options{ChainID: n.ChainID.Uint64(), RequireOnchainRecord: true, MaxEvidenceAge: 15 * time.Minute, AcceptSimulated: true}
	check := func(t *testing.T, b *verify.Bundle, want ...string) *verify.Report {
		t.Helper()
		rep, err := verify.VerifyEvidence(context.Background(), b, deps, opts)
		if err != nil {
			t.Fatal(err)
		}
		got := rep.Failed()
		sort.Strings(got)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Fatalf("failed checks %v, want %v\n%s", got, want, rep.Text())
		}
		return rep
	}
	clone := func() *verify.Bundle { c := *b; return &c }

	t.Run("registered deployment verifies", func(t *testing.T) {
		rep := check(t, b)
		if !rep.OK || !rep.Simulated {
			t.Fatal("not OK or not flagged simulated")
		}
		if head, _ := client.BlockNumber(context.Background()); rep.BlockNumber == 0 || rep.BlockNumber > head {
			t.Fatalf("reads not pinned to a block: %d (head %d)", rep.BlockNumber, head)
		}
		// The digest the report carries is the contract's recordDigest of the bundle's record.
		want, err := client.RecordDigest(context.Background(), rec)
		if err != nil || rep.RecordDigest != "0x"+hexString(want[:]) {
			t.Fatalf("recordDigest %s vs %x (%v)", rep.RecordDigest, want, err)
		}
	})
	t.Run("changed config byte", func(t *testing.T) {
		c := clone()
		c.Config = json.RawMessage(strings.Replace(string(c.Config), `"scheme":"sslip"`, `"scheme":"sslIp"`, 1))
		check(t, c, verify.CheckConfigHash, verify.CheckStackRecompute)
	})
	t.Run("changed stack byte", func(t *testing.T) {
		c := clone()
		c.AppCompose = strings.Replace(c.AppCompose, `"public_logs":false`, `"public_logs":true `, 1)
		check(t, c, verify.CheckComposeHash, verify.CheckDeploymentID, verify.CheckStackRecompute, verify.CheckStackApproved, verify.CheckApprovalReleases)
	})
	t.Run("wrong enclave signer", func(t *testing.T) {
		c := clone()
		c.EnclaveSigner = strings.ToLower(stranger.Hex())
		check(t, c, verify.CheckReportData, verify.CheckOnchainRecord)
	})
	t.Run("debug image", func(t *testing.T) {
		dw := fixture.NewWorld(n.ChainID.Uint64(), addrs, cust, anviltest.Addr(anviltest.Enclave), debugImageID)
		dw.Debug = true
		db := dw.Bundle(n.Now(t))
		drec := fixture.Record(db)
		// The contracts refuse to approve or register a stack on a debug image.
		if _, err := n.Try(anviltest.Customer, r.DeploymentRegistry, r.Artifacts["DeploymentRegistry"].ABI, "approveStack", drec.StackHash, dw.ReleaseIDs(), debugImageID, uint64(0)); err == nil {
			t.Fatal("approveStack accepted a debug image")
		}
		if err := r.TryRegisterDeployment(n, anviltest.Record(drec)); err == nil {
			t.Fatal("registerDeployment accepted an unapproved debug stack")
		}
		check(t, db, verify.CheckTDAttributes, verify.CheckImageApproved, verify.CheckStackApproved, verify.CheckApprovalReleases, verify.CheckOnchainRecord)
	})
	t.Run("approval re-issued with another release set (D-014)", func(t *testing.T) {
		// The contracts pin the release list of an existing approval; the verifier's own D-014 comparison is
		// covered against the in-memory registries (evidence tamper matrix).
		depABI := r.Artifacts["DeploymentRegistry"].ABI
		_, err := n.Try(anviltest.Customer, r.DeploymentRegistry, depABI, "approveStack", rec.StackHash, w.ReleaseIDs()[:1], imageID, uint64(0))
		if name := anviltest.RevertName(depABI, err); name != "ReleasesChanged" {
			t.Fatalf("approveStack with another release set: err %v (revert %q), want ReleasesChanged", err, name)
		}
		check(t, b)
	})
	t.Run("revoked approval", func(t *testing.T) {
		r.RevokeStack(t, n, anviltest.Customer, rec.StackHash)
		check(t, b, verify.CheckStackApproved)
		r.ApproveStack(t, n, anviltest.Customer, rec.StackHash, w.ReleaseIDs(), imageID)
		check(t, b)
	})
	t.Run("revoked release", func(t *testing.T) {
		r.RevokeRelease(t, n, w.Apps[1].ReleaseID())
		check(t, b, verify.CheckReleasesActive, verify.CheckStackApproved)
	})
	t.Run("revoked image", func(t *testing.T) {
		r.RevokeImage(t, n, imageID)
		check(t, b, verify.CheckReleasesActive, verify.CheckStackApproved, verify.CheckImageApproved)
	})
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
