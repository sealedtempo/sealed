package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealed-dev/sealed/cli/internal/registry"
	"github.com/sealed-dev/sealed/cli/internal/testchain"
	"github.com/sealed-dev/sealed/cli/internal/testkit"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// TestAnvilEndToEnd drives catalog, deploy, verify and release build against the real registries on a local
// Tempo node: register the sim image, the apps and their releases; deploy stops until the customer's wallet
// approves; the oracle registers the deployment; verify passes, and fails once a release is revoked.
func TestAnvilEndToEnd(t *testing.T) {
	n := testchain.Start(t)
	ctx := context.Background()
	customer := testchain.Addr(testchain.Customer)
	w := testkit.NewWorldAt(t, n.Addrs, customer)

	n.Call(t, testchain.Owner, n.Addrs.PlatformRegistry, "PlatformRegistry", "addImage", w.ImageID, "sealed-sim", "1.0.0",
		attest.SimMRTD[:], attest.SimRTMR0[:], attest.SimRTMR1[:], attest.SimRTMR2[:], false, "https://example.invalid/sim")
	var releaseIDs [][32]byte
	for _, b := range w.Bundles {
		n.Call(t, testchain.Owner, n.Addrs.AppRegistry, "AppRegistry", "registerApp", [32]byte(b.AppID), b.Manifest.ID, b.Manifest.Name,
			b.Manifest.Upstream.LicenseSPDX, testchain.Addr(testchain.Ops), uint16(2000), "https://example.invalid/"+b.Manifest.ID)
		n.Call(t, testchain.Ops, n.Addrs.AppRegistry, "AppRegistry", "publishRelease", [32]byte(b.AppID), b.Version(), [32]byte(b.Hash),
			[32]byte(b.EgressPolicyHash), [32]byte(b.SBOMHash), "https://example.invalid/provenance", "https://example.invalid/sig")
		releaseIDs = append(releaseIDs, b.ReleaseID)
	}

	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	dep, _ := json.Marshal(map[string]any{"chainId": 4217, "contracts": map[string]any{
		"PlatformRegistry":   map[string]string{"address": n.Addrs.PlatformRegistry.Hex()},
		"AppRegistry":        map[string]string{"address": n.Addrs.AppRegistry.Hex()},
		"DeploymentRegistry": map[string]string{"address": n.Addrs.DeploymentRegistry.Hex()},
		"FeeSplitter":        map[string]string{"address": "0x00000000000000000000000000000000000000E4"},
	}})
	h.env["SEALED_DEPLOYMENTS_FILE"] = h.write("anvil-deployments.json", string(dep))
	reader, err := registry.Dial(ctx, n.URL, n.Addrs)
	if err != nil {
		t.Fatal(err)
	}
	h.real = reader
	for _, b := range w.Bundles {
		h.bundles.Put(t, b.Manifest.ID, b.Version(), b.Tar)
	}

	// catalog list and show read AppRegistry's enumeration views.
	code, out, errs := h.run("catalog", "list", "--json")
	var apps []AppView
	if code != ExitOK || json.Unmarshal([]byte(out), &apps) != nil || len(apps) != 2 {
		t.Fatalf("catalog list: %d %s %s", code, out, errs)
	}
	for i, b := range w.Bundles {
		if apps[i].ID != b.Manifest.ID || apps[i].Latest == nil || apps[i].Latest.BundleHash != b.Hash.Hex() || apps[i].Latest.Status != "active" {
			t.Fatalf("app %d: %+v", i, apps[i])
		}
	}
	if code, out, _ := h.run("catalog", "show", "notes"); code != ExitOK || !strings.Contains(out, "provenance https://example.invalid/provenance") {
		t.Fatalf("catalog show: %d %s", code, out)
	}
	// release build reproduces the onchain bundleHash.
	catalog := filepath.Join(testkit.RepoRoot(), "runtime", "composer", "testdata", "apps")
	if code, out, errs := h.run("release", "build", "notes", "--catalog", catalog, "--check", "1.0.0-sealed.1"); code != ExitOK || !strings.Contains(out, "reproduced") {
		t.Fatalf("release check: %d %s %s", code, out, errs)
	}

	// deploy waits for the wallet, then creates the VM.
	stack := h.write("anvil-stack.yaml", fmt.Sprintf(`schema: sealed-deploy/v1
name: anvil
project: acme-prod-4417
region: us-central1
keyBroker: https://kb.example.com
customer: "%s"
image:
  id: 0x%s
  boot: projects/sealed-images-1/global/images/sealed-os-0-6-1
  systemDisk: projects/sealed-images-1/global/images/sealed-dstack-data-v1
apps:
  - id: notes
  - id: llm-gateway
    release: 2.3.4
endpoints:
  platformApi: https://api.sealed.example
  relay: https://relay.sealed.example
  relayAttest: https://attest.relay.sealed.example/attest
relayOwner: "0x00000000000000000000000000000000000000b1"
`, customer.Hex(), hex.EncodeToString(w.ImageID[:])))
	code, out, errs = h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check", "--json")
	if code != ExitNotApproved {
		t.Fatalf("deploy before approval: %d %s %s", code, out, errs)
	}
	var sum map[string]any
	json.Unmarshal([]byte(out), &sum)
	stackHash, _ := registry.ParseHash32(sum["stackHash"].(string))
	n.Call(t, testchain.Customer, n.Addrs.DeploymentRegistry, "DeploymentRegistry", "approveStack", stackHash, releaseIDs, w.ImageID, uint64(0))
	if code, out, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check"); code != ExitOK || h.compute.instances["sealed-anvil"] == nil {
		t.Fatalf("deploy after approval: %d %s %s", code, out, errs)
	}

	// The oracle registers the world's deployment from its evidence, then verify checks it against the chain.
	n.Call(t, testchain.Customer, n.Addrs.DeploymentRegistry, "DeploymentRegistry", "approveStack", [32]byte(w.Result.StackHash), releaseIDs, w.ImageID, uint64(0))
	w.AttestedAt = n.BlockTime(t) + 2
	ev := w.Evidence(t)
	raw, _ := json.Marshal(ev)
	evPath := h.write("anvil-evidence.json", string(raw))
	d32 := func(k string) [32]byte { v, _ := registry.ParseHash32(ev[k].(string)); return v }
	rec := chain.Record{
		DeploymentId: w.Result.DeploymentID, Customer: customer, StackHash: w.Result.StackHash, ImageId: w.ImageID,
		QuoteHash: d32("quoteHash"), EventLogHash: d32("eventLogHash"), ConfigHash: w.Result.ConfigHash,
		EnclaveSigner: w.EnclaveSigner, AttestedAt: w.AttestedAt,
	}
	digest, err := reader.RecordDigest(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(digest[:], testchain.Key(testchain.Oracle))
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	bytesT, _ := abi.NewType("bytes", "", nil)
	evidence, _ := abi.Arguments{{Type: bytesT}}.Pack(sig)
	n.Call(t, testchain.Ops, n.Addrs.DeploymentRegistry, "DeploymentRegistry", "registerDeployment", rec, uint8(1), evidence)

	id := w.Result.DeploymentID.Hex()
	code, out, errs = h.run("verify", "--deployment", id, "--evidence", evPath, "--dev-allow-simulated", "--json", "--collateral-cache", filepath.Join(h.dir, "pcs"))
	var rep struct {
		OK       bool `json:"ok"`
		Evidence struct {
			BlockNumber uint64 `json:"blockNumber"`
		} `json:"evidence"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &rep) != nil || !rep.OK || rep.Evidence.BlockNumber == 0 {
		t.Fatalf("verify: %d\n%s\n%s", code, out, errs)
	}

	// A revoked release fails verify and blocks a new deploy plan.
	n.Call(t, testchain.Owner, n.Addrs.AppRegistry, "AppRegistry", "revokeRelease", releaseIDs[1], "test")
	code, _, errs = h.run("verify", "--deployment", id, "--evidence", evPath, "--dev-allow-simulated")
	if code != ExitFailed || !strings.Contains(errs, "releases_active") || !strings.Contains(errs, "stack_approved") {
		t.Fatalf("verify after revoke: %d %s", code, errs)
	}
	if code, _, errs := h.run("deploy", "--config", stack, "--dev-allow-unbuilt", "--skip-secrets-check", "--plan"); code != ExitFailed || !strings.Contains(errs, "no active release") {
		t.Fatalf("deploy after revoke: %d %s", code, errs)
	}
}
