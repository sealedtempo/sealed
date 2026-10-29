package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/sealedtempo/sealed/cli/internal/registry"
	"github.com/sealedtempo/sealed/cli/internal/testchain"
	"github.com/sealedtempo/sealed/cli/internal/testkit"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// testnetChainID is a chain other than mainnet's 4217 (Tempo's public testnet uses this id).
const testnetChainID = 42431

// deploymentsOn writes a deployments file for chainID naming addrs, a FeeSplitter and, when feeToken is set, a fee
// token, and returns its path. It is the only chain input the commands get: no defaults file.
func (h *harness) deploymentsOn(chainID uint64, addrs chain.Addresses, feeToken string) string {
	h.t.Helper()
	doc := map[string]any{"chainId": chainID, "network": "tempo-testnet", "contracts": map[string]any{
		"PlatformRegistry":   map[string]string{"address": addrs.PlatformRegistry.Hex()},
		"AppRegistry":        map[string]string{"address": addrs.AppRegistry.Hex()},
		"DeploymentRegistry": map[string]string{"address": addrs.DeploymentRegistry.Hex()},
		"FeeSplitter":        map[string]string{"address": "0x00000000000000000000000000000000000000E4"},
	}}
	if feeToken != "" {
		doc["config"] = map[string]any{"feeToken": feeToken}
	}
	b, _ := json.Marshal(doc)
	return h.write("deployments-"+strings.ReplaceAll(feeToken, "0x", "")+".json", string(b))
}

// TestVerifyOnAnotherChainWithDeploymentsFileAlone: a deployments file for chain 42431 is all `sealed verify` needs
// besides an RPC of that chain. The embedded defaults are mainnet's; their chain id and public RPC are not used.
func TestVerifyOnAnotherChainWithDeploymentsFileAlone(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	h.chain.ID = testnetChainID
	h.env["SEALED_DEPLOYMENTS_FILE"] = h.deploymentsOn(testnetChainID, testkit.Addresses, "0x20c0000000000000000000000000000000000001")
	w := testkit.NewWorldOn(t, testnetChainID, testkit.Addresses, common.HexToAddress("0x00000000000000000000000000000000000000c1"))
	for _, b := range w.Bundles {
		h.bundles.Put(t, b.Manifest.ID, b.Version(), b.Tar)
	}
	ev := w.Evidence(t)
	w.Populate(h.chain, ev, true)
	raw, _ := json.Marshal(ev)
	path := h.write("evidence-testnet.json", string(raw))
	id := w.Result.DeploymentID.Hex()
	verifyArgs := []string{"verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated"}

	// The mainnet public RPC does not serve this chain: an RPC must be given.
	code, _, errs := h.run(verifyArgs...)
	if code != ExitFailed || !strings.Contains(errs, "pass --rpc (or TEMPO_RPC_URL) with an RPC of chain 42431") {
		t.Fatalf("no RPC for chain 42431: %d %s", code, errs)
	}

	rpc := "https://rpc.testnet.example/v1/KEY"
	code, out, errs := h.run(append(verifyArgs, "--rpc", rpc)...)
	if code != ExitOK || !strings.Contains(out, "OK: every check passed against Tempo chain 42431") {
		t.Fatalf("verify on chain 42431: %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "Checking on chain 42431 (tempo-testnet)") || strings.Contains(errs, "KEY") {
		t.Fatalf("the derived chain is not shown, or the RPC key leaked: %s", errs)
	}

	// --chain-id (or TEMPO_CHAIN_ID) states the expected chain; it must agree with the deployments file.
	if code, out, errs := h.run(append(verifyArgs, "--rpc", rpc, "--chain-id", "42431")...); code != ExitOK {
		t.Fatalf("--chain-id 42431: %d %s %s", code, out, errs)
	}
	if code, _, errs := h.run(append(verifyArgs, "--rpc", rpc, "--chain-id", "4217")...); code != ExitFailed || !strings.Contains(errs, "--chain-id (TEMPO_CHAIN_ID) 4217, but the deployments file is for chain 42431") {
		t.Fatalf("--chain-id 4217 against a 42431 file: %d %s", code, errs)
	}
	h.env["TEMPO_CHAIN_ID"] = "1"
	if code, _, errs := h.run(append(verifyArgs, "--rpc", rpc)...); code != ExitFailed || !strings.Contains(errs, "TEMPO_CHAIN_ID") {
		t.Fatalf("TEMPO_CHAIN_ID 1 against a 42431 file: %d %s", code, errs)
	}
	delete(h.env, "TEMPO_CHAIN_ID")

	// The checks still run against the chain: an RPC of another chain fails the chain check.
	h.chain.ID = 4217
	if code, _, errs := h.run(append(verifyArgs, "--rpc", rpc)...); code != ExitFailed || !strings.Contains(errs, "evidence/chain") {
		t.Fatalf("RPC of chain 4217 with a 42431 deployments file: %d %s", code, errs)
	}
	h.chain.ID = testnetChainID

	// The same evidence checked with the embedded mainnet deployments fails: the chain is not 4217.
	delete(h.env, "SEALED_DEPLOYMENTS_FILE")
	if code, _, errs := h.run(append(verifyArgs, "--rpc", rpc)...); code != ExitFailed || !strings.Contains(errs, "evidence/chain") {
		t.Fatalf("42431 evidence against mainnet settings: %d %s", code, errs)
	}
	// --chain-id other than mainnet's without a deployments file is refused before anything is read.
	if code, _, errs := h.run(append(verifyArgs, "--rpc", rpc, "--chain-id", "42431")...); code != ExitFailed || !strings.Contains(errs, "the embedded deployments are Tempo mainnet's") {
		t.Fatalf("--chain-id 42431 without deployments: %d %s", code, errs)
	}
}

// TestBootstrapBrokerFeesAndAllowlist: the FeeSplitter and fee token the key broker checks come from the deployments
// file when they are not mainnet's (SEALED_FEE_SPLITTER, SEALED_FEE_TOKEN), and the customer's imageId allowlist
// reaches it as SEALED_ALLOWED_IMAGES; the CLI reads the same names from its environment.
func TestBootstrapBrokerFeesAndAllowlist(t *testing.T) {
	base := []string{"bootstrap", "--plan", "--project", "acme-prod-4417", "--customer-address", "0x00000000000000000000000000000000000000c1",
		"--platform-sa", "sealed-platform@sealed-platform-1234.iam.gserviceaccount.com",
		"--key-broker-image", "ghcr.io/sealedtempo/key-broker@sha256:" + strings.Repeat("ab", 32)}
	img1, img2 := "0xAB"+strings.Repeat("00", 31), "0x"+strings.Repeat("00", 31)+"cd"
	type result struct {
		code int
		errs string
		vars map[string]any
	}
	run := func(t *testing.T, env map[string]string, args ...string) result {
		t.Helper()
		h := newHarness(t)
		for k, v := range env {
			if v == "" {
				delete(h.env, k)
				continue
			}
			h.env[k] = v
		}
		if p, ok := env["deployments"]; ok {
			delete(h.env, "deployments")
			h.env["SEALED_DEPLOYMENTS_FILE"] = p
		}
		work := filepath.Join(h.dir, "work")
		code, _, errs := h.run(append(append(append([]string{}, base...), "--work-dir", work), args...)...)
		r := result{code: code, errs: errs}
		if b, err := os.ReadFile(filepath.Join(work, "terraform.tfvars.json")); err == nil {
			json.Unmarshal(b, &r.vars)
		}
		return r
	}
	// writeDeployments writes a deployments file in a fresh dir for the subtests that need their own.
	writeDeployments := func(t *testing.T, doc map[string]any) string {
		p := filepath.Join(t.TempDir(), "deployments.json")
		b, _ := json.Marshal(doc)
		os.WriteFile(p, b, 0o600)
		return p
	}
	regs := map[string]any{
		"PlatformRegistry":   map[string]string{"address": testkit.Addresses.PlatformRegistry.Hex()},
		"AppRegistry":        map[string]string{"address": testkit.Addresses.AppRegistry.Hex()},
		"DeploymentRegistry": map[string]string{"address": testkit.Addresses.DeploymentRegistry.Hex()},
	}
	withSplitter := func(m map[string]any) map[string]any {
		c := map[string]any{"FeeSplitter": map[string]string{"address": "0x00000000000000000000000000000000000000E4"}}
		for k, v := range m {
			c[k] = v
		}
		return c
	}

	t.Run("mainnet deployments set nothing", func(t *testing.T) {
		r := run(t, map[string]string{"SEALED_DEPLOYMENTS_FILE": ""})
		if r.code != ExitOK {
			t.Fatalf("%d %s", r.code, r.errs)
		}
		for _, k := range []string{"fee_splitter", "fee_token", "key_broker_allowed_images"} {
			if _, ok := r.vars[k]; ok {
				t.Errorf("mainnet bootstrap sets %s: %v", k, r.vars)
			}
		}
	})
	t.Run("other registries bring their FeeSplitter", func(t *testing.T) {
		r := run(t, nil) // the harness deployments: test registries on chain 4217, FeeSplitter 0x..e4
		if r.code != ExitOK || r.vars["fee_splitter"] != "0x00000000000000000000000000000000000000e4" || r.vars["fee_token"] != nil {
			t.Fatalf("%d %s %v", r.code, r.errs, r.vars)
		}
		if strings.Contains(r.errs, "D-060") {
			t.Fatalf("mainnet chain warned about: %s", r.errs)
		}
		if !strings.Contains(r.errs, "It requires FeeSplitter 0x00000000000000000000000000000000000000e4 and fee token (mainnet's)") {
			t.Fatalf("the broker's fee contracts are not shown: %s", r.errs)
		}
	})
	t.Run("another chain brings its fee token", func(t *testing.T) {
		p := writeDeployments(t, map[string]any{"chainId": testnetChainID, "network": "tempo-testnet", "contracts": withSplitter(regs),
			"config": map[string]any{"feeToken": "0x20C0000000000000000000000000000000000001"}})
		r := run(t, map[string]string{"deployments": p}, "--rpc", "https://rpc.testnet.example")
		if r.code != ExitOK || r.vars["chain_id"] != float64(testnetChainID) || r.vars["fee_splitter"] != "0x00000000000000000000000000000000000000e4" ||
			r.vars["fee_token"] != "0x20c0000000000000000000000000000000000001" || r.vars["tempo_rpc_url"] != "https://rpc.testnet.example" {
			t.Fatalf("%d %s %v", r.code, r.errs, r.vars)
		}
		if !strings.Contains(r.errs, "refuses to start on chain 42431 (D-060)") {
			t.Fatalf("no warning that a production broker serves only mainnet: %s", r.errs)
		}
	})
	t.Run("another chain without a fee token is refused", func(t *testing.T) {
		p := writeDeployments(t, map[string]any{"chainId": testnetChainID, "contracts": withSplitter(regs)})
		r := run(t, map[string]string{"deployments": p}, "--rpc", "https://rpc.testnet.example")
		if r.code != ExitUsage || !strings.Contains(r.errs, "--fee-token (SEALED_FEE_TOKEN)") {
			t.Fatalf("%d %s", r.code, r.errs)
		}
		// Given explicitly, under the broker's name in the CLI's environment.
		r = run(t, map[string]string{"deployments": p, "SEALED_FEE_TOKEN": "0x20C0000000000000000000000000000000000002"}, "--rpc", "https://rpc.testnet.example")
		if r.code != ExitOK || r.vars["fee_token"] != "0x20c0000000000000000000000000000000000002" {
			t.Fatalf("%d %s %v", r.code, r.errs, r.vars)
		}
	})
	t.Run("other registries without a FeeSplitter are refused", func(t *testing.T) {
		p := writeDeployments(t, map[string]any{"chainId": 4217, "contracts": regs})
		r := run(t, map[string]string{"deployments": p})
		if r.code != ExitUsage || !strings.Contains(r.errs, "--fee-splitter (SEALED_FEE_SPLITTER)") {
			t.Fatalf("%d %s", r.code, r.errs)
		}
		r = run(t, map[string]string{"deployments": p}, "--fee-splitter", "0x00000000000000000000000000000000000000E7")
		if r.code != ExitOK || r.vars["fee_splitter"] != "0x00000000000000000000000000000000000000e7" {
			t.Fatalf("%d %s %v", r.code, r.errs, r.vars)
		}
	})
	t.Run("SEALED_FEE_SPLITTER wins over the deployments file", func(t *testing.T) {
		r := run(t, map[string]string{"SEALED_FEE_SPLITTER": "0x00000000000000000000000000000000000000E9"})
		if r.code != ExitOK || r.vars["fee_splitter"] != "0x00000000000000000000000000000000000000e9" {
			t.Fatalf("%d %s %v", r.code, r.errs, r.vars)
		}
	})
	t.Run("allowed images", func(t *testing.T) {
		r := run(t, nil, "--allowed-images", img1+", "+img2)
		want := []any{strings.ToLower(img1), img2}
		got, _ := r.vars["key_broker_allowed_images"].([]any)
		if r.code != ExitOK || len(got) != 2 || got[0] != want[0] || got[1] != want[1] || !strings.Contains(r.errs, "It releases only to your 2 allowed image(s)") {
			t.Fatalf("%d %s %v", r.code, r.errs, r.vars)
		}
		r = run(t, map[string]string{"SEALED_ALLOWED_IMAGES": img2})
		if got, _ := r.vars["key_broker_allowed_images"].([]any); r.code != ExitOK || len(got) != 1 || got[0] != img2 {
			t.Fatalf("SEALED_ALLOWED_IMAGES: %d %s %v", r.code, r.errs, r.vars)
		}
		for _, bad := range []string{"0x12", strings.Repeat("ab", 32), img1 + "," + strings.ToLower(img1)} {
			if r := run(t, nil, "--allowed-images", bad); r.code != ExitUsage || !strings.Contains(r.errs, "SEALED_ALLOWED_IMAGES") {
				t.Errorf("--allowed-images %s: %d %s", bad, r.code, r.errs)
			}
		}
	})
	t.Run("bad fee addresses", func(t *testing.T) {
		for _, args := range [][]string{{"--fee-splitter", "0x12"}, {"--fee-token", "usdc"}, {"--fee-token", "0x0000000000000000000000000000000000000000"}} {
			if r := run(t, nil, args...); r.code != ExitUsage {
				t.Errorf("%v: %d %s", args, r.code, r.errs)
			}
		}
	})
}

// TestAnvilVerifyOnAnotherChain runs `sealed verify` the way the binary does (it dials the RPC and the registries of
// its own settings) against a local Tempo node on chain 42431, with only a deployments file for that chain and
// --rpc: no defaults file, no mainnet value.
func TestAnvilVerifyOnAnotherChain(t *testing.T) {
	n := testchain.StartOn(t, testnetChainID)
	ctx := context.Background()
	if n.ChainID.Uint64() != testnetChainID {
		t.Fatalf("anvil runs chain %s", n.ChainID)
	}
	customer := testchain.Addr(testchain.Customer)
	w := testkit.NewWorldOn(t, testnetChainID, n.Addrs, customer)
	n.Call(t, testchain.Owner, n.Addrs.PlatformRegistry, "PlatformRegistry", "addImage", w.ImageID, "sealed-sim", "1.0.0",
		attest.SimMRTD[:], attest.SimRTMR0[:], attest.SimRTMR1[:], attest.SimRTMR2[:], false, "https://example.invalid/sim")
	for _, b := range w.Bundles {
		n.Call(t, testchain.Owner, n.Addrs.AppRegistry, "AppRegistry", "registerApp", [32]byte(b.AppID), b.Manifest.ID, b.Manifest.Name,
			b.Manifest.Upstream.LicenseSPDX, testchain.Addr(testchain.Ops), uint16(2000), "https://example.invalid/"+b.Manifest.ID)
		n.Call(t, testchain.Ops, n.Addrs.AppRegistry, "AppRegistry", "publishRelease", [32]byte(b.AppID), b.Version(), [32]byte(b.Hash),
			[32]byte(b.EgressPolicyHash), [32]byte(b.SBOMHash), "https://example.invalid/provenance", "https://example.invalid/sig")
	}
	n.Call(t, testchain.Customer, n.Addrs.DeploymentRegistry, "DeploymentRegistry", "approveStack", [32]byte(w.Result.StackHash), w.ReleaseIDs(), w.ImageID, uint64(0))

	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	h.dial = true
	deployments := h.deploymentsOn(testnetChainID, n.Addrs, "0x20c0000000000000000000000000000000000001")
	delete(h.env, "SEALED_DEPLOYMENTS_FILE")
	for _, b := range w.Bundles {
		h.bundles.Put(t, b.Manifest.ID, b.Version(), b.Tar)
	}

	// The oracle registers the deployment from its evidence (EIP-712 over chain 42431).
	reader, err := registry.Dial(ctx, n.URL, n.Addrs)
	if err != nil {
		t.Fatal(err)
	}
	w.AttestedAt = n.BlockTime(t) + 2
	ev := w.Evidence(t)
	raw, _ := json.Marshal(ev)
	evPath := h.write("anvil-testnet-evidence.json", string(raw))
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

	head := n.BlockTime(t)
	h.now = func() time.Time { return time.Unix(int64(head)+5, 0) }
	args := []string{"verify", "--deployment", w.Result.DeploymentID.Hex(), "--evidence", evPath, "--dev-allow-simulated", "--json",
		"--deployments", deployments, "--rpc", n.URL}
	code, out, errs := h.run(args...)
	var rep struct {
		OK       bool `json:"ok"`
		Evidence struct {
			BlockNumber uint64 `json:"blockNumber"`
			Checks      []struct {
				Name string         `json:"name"`
				OK   bool           `json:"ok"`
				Data map[string]any `json:"data"`
			} `json:"checks"`
		} `json:"evidence"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &rep) != nil || !rep.OK || rep.Evidence.BlockNumber == 0 {
		t.Fatalf("verify on chain 42431: %d\n%s\n%s", code, out, errs)
	}
	for _, c := range rep.Evidence.Checks {
		if c.Name == "chain" && c.Data["rpcChainId"] != float64(testnetChainID) {
			t.Fatalf("chain check data %v", c.Data)
		}
	}
	// A revoked release fails, as on mainnet.
	n.Call(t, testchain.Owner, n.Addrs.AppRegistry, "AppRegistry", "revokeRelease", w.ReleaseIDs()[1], "test")
	// Without the deployments file the embedded mainnet settings apply: chain 4217 and mainnet's registries.
	if code, _, errs := h.run(append(args[:len(args)-4:len(args)-4], "--rpc", n.URL)...); code != ExitFailed || !strings.Contains(errs, "evidence/chain") {
		t.Fatalf("verify with mainnet settings against chain 42431: %d %s", code, errs)
	}
	if code, _, errs := h.run(args...); code != ExitFailed || !strings.Contains(errs, "releases_active") {
		t.Fatalf("verify after revoke: %d %s", code, errs)
	}
}
