package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/internal/sigstoretest"
	"github.com/sealedtempo/sealed/runtime/composer"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
	"github.com/sealedtempo/sealed/verifier/internal/anviltest"
	"github.com/sealedtempo/sealed/verifier/internal/catalogtest"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
	"github.com/sealedtempo/sealed/verifier/internal/hexb"
	"github.com/sealedtempo/sealed/verifier/releasesig"
)

// composedWorld is one deployment of a stack composed from real release bundles on a local chain.
type composedWorld struct {
	n        *anviltest.Node
	r        *anviltest.Registries
	assets   *catalogtest.Server
	bundles  []*composer.Bundle
	addrs    chain.Addresses
	imageID  [32]byte
	config   []byte
	compose  *verify.ComposeOutput
	evidence *verify.Bundle
}

func simMeasurements() anviltest.Measurements {
	return anviltest.Measurements{MRTD: attest.SimMRTD, RTMR0: attest.SimRTMR0, RTMR1: attest.SimRTMR1, RTMR2: attest.SimRTMR2}
}

// daemon starts sealed-verifierd as main() would (loadConfig, newServer with the real composer) in dev mode
// (simulated quotes, plain-http release assets) against the world's chain and asset server, with a fresh bundle
// cache unless extra names one.
func (w *composedWorld) daemon(t *testing.T, extra ...string) *httptest.Server {
	t.Helper()
	return w.startDaemon(t, true, extra...)
}

// prodDaemon is daemon without --dev-allow-simulated.
func (w *composedWorld) prodDaemon(t *testing.T) *httptest.Server {
	t.Helper()
	return w.startDaemon(t, false)
}

func (w *composedWorld) startDaemon(t *testing.T, sim bool, extra ...string) *httptest.Server {
	t.Helper()
	args := []string{"--tempo-rpc", w.n.URL, "--chain-id", w.n.ChainID.String(),
		"--platform-registry", w.addrs.PlatformRegistry.Hex(), "--app-registry", w.addrs.AppRegistry.Hex(),
		"--deployment-registry", w.addrs.DeploymentRegistry.Hex(), "--collateral-cache-dir", t.TempDir(),
		"--release-asset-base", w.assets.Base, "--bundle-cache-dir", filepath.Join(t.TempDir(), "bundles")}
	if sim {
		args = append(args, "--dev-allow-simulated")
	}
	c, err := loadConfig(append(args, extra...), envMap(map[string]string{"SEALED_DEV_SIM": "1"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newServer(context.Background(), c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Deps.Composer == nil {
		t.Fatal("daemon has no composer")
	}
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)
	return api
}

func postJSON(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

type composeAnswer struct {
	AppCompose   string   `json:"appCompose"`
	StackHash    string   `json:"stackHash"`
	ConfigHash   string   `json:"configHash"`
	DeploymentID string   `json:"deploymentId"`
	Unbuilt      []string `json:"unbuilt"`
	Error        string   `json:"error"`
}

// verifyEvidence posts the bundle with the oracle's options and requires exactly the want checks to fail.
func verifyEvidence(t *testing.T, api *httptest.Server, b *verify.Bundle, want ...string) *verify.Report {
	t.Helper()
	status, raw := postJSON(t, api.URL+"/v1/verify/evidence", map[string]any{"bundle": b, "options": map[string]any{"maxEvidenceAgeSeconds": 900}})
	if status != http.StatusOK {
		t.Fatalf("HTTP %d: %s", status, raw)
	}
	var rep verify.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	got := rep.Failed()
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("failed checks %v, want %v\n%s", got, want, rep.Text())
	}
	if rep.OK != (len(want) == 0) {
		t.Fatalf("OK = %v", rep.OK)
	}
	return &rep
}

// TestComposedStackEndToEnd (brief items 19 and 20): bundles built from the composer's fixture apps are served like
// a GitHub release; the real contracts run on a local Tempo node with those releases; sealed-verifierd composes the
// stack (/v1/compose) through its bundle fetcher, the customer approves it, the dev simulator path produces the quote
// and event log for that app-compose, the oracle registers it, and the full evidence bundle verifies. Then each
// tamper case fails exactly the checks it should.
func TestComposedStackEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	w := &composedWorld{assets: catalogtest.NewServer(t), bundles: catalogtest.Bundles(t)}
	for _, b := range w.bundles {
		w.assets.Publish(t, b)
	}
	w.n = anviltest.Start(t)
	w.r = anviltest.DeployRegistries(t, w.n)
	w.addrs = chain.Addresses{PlatformRegistry: w.r.PlatformRegistry, AppRegistry: w.r.AppRegistry, DeploymentRegistry: w.r.DeploymentRegistry}
	w.imageID = w.r.AddImage(t, w.n, "sealed-sim", "1.0.0", simMeasurements(), false)
	var releaseIDs [][32]byte
	for _, b := range w.bundles {
		appID := w.r.RegisterApp(t, w.n, b.Manifest.ID)
		if got := w.r.PublishRelease(t, w.n, appID, b.Version(), b.Hash); got != b.ReleaseID {
			t.Fatalf("%s: onchain releaseId %x, composer %s", b.Manifest.ID, got, b.ReleaseID)
		}
		releaseIDs = append(releaseIDs, b.ReleaseID)
	}
	customer := anviltest.Addr(anviltest.Customer)
	w.config = catalogtest.Config(t, catalogtest.ConfigParams{
		ChainID: w.n.ChainID.Uint64(), Customer: customer, Salt: sha256.Sum256([]byte("e2e salt")), ImageID: w.imageID, Addrs: w.addrs,
	}, w.bundles)

	api := w.daemon(t)

	// The daemon composes the stack from the chain's releases and the fetched bundles; it is byte for byte what
	// runtime/composer gives for the same inputs.
	status, raw := postJSON(t, api.URL+"/v1/compose", map[string]any{"config": json.RawMessage(w.config)})
	var ans composeAnswer
	if err := json.Unmarshal(raw, &ans); err != nil || status != http.StatusOK {
		t.Fatalf("/v1/compose: HTTP %d %s", status, raw)
	}
	cfg, err := composer.ParseConfig(w.config)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := composer.Compose(cfg, w.bundles)
	if err != nil {
		t.Fatal(err)
	}
	if ans.AppCompose != string(direct.AppCompose) || ans.StackHash != direct.StackHash.Hex() || ans.ConfigHash != direct.ConfigHash.Hex() ||
		ans.DeploymentID != direct.DeploymentID.Hex() || strings.Join(ans.Unbuilt, ",") != strings.Join(direct.Unbuilt, ",") {
		t.Fatalf("/v1/compose differs from runtime/composer: %+v", ans)
	}
	if got := sha256.Sum256(w.config); got != direct.ConfigHash {
		t.Fatal("fixture config is not in normalized form")
	}
	for _, b := range w.bundles {
		if n := w.assets.Hits(t, b.Manifest.ID, b.Version()); n != 1 {
			t.Fatalf("%s fetched %d times", b.Manifest.ID, n)
		}
	}
	w.compose = &verify.ComposeOutput{AppCompose: direct.AppCompose, StackHash: direct.StackHash, ConfigHash: direct.ConfigHash, DeploymentID: direct.DeploymentID}

	// The customer approves the stack, the simulator attests it, the oracle registers it.
	w.r.ApproveStack(t, w.n, anviltest.Customer, w.compose.StackHash, releaseIDs, w.imageID)
	var inst [20]byte
	copy(inst[:], []byte("e2e instance id 0001"))
	w.evidence = fixture.SimEvidence(fixture.EvidenceParams{
		ChainID: w.n.ChainID.Uint64(), Addrs: w.addrs, Customer: customer, EnclaveSigner: anviltest.Addr(anviltest.Enclave),
		ImageID: w.imageID, ReleaseIDs: releaseIDs, Config: w.config, Compose: w.compose,
		Nonce2: sha256.Sum256([]byte("e2e nonce2")), InstanceID: inst, AttestedAt: w.n.Now(t),
	})
	rec := fixture.Record(w.evidence)
	w.r.RegisterDeployment(t, w.n, anviltest.Record(rec))
	clone := func() *verify.Bundle { c := *w.evidence; return &c }

	t.Run("full evidence bundle verifies", func(t *testing.T) {
		rep := verifyEvidence(t, api, w.evidence)
		if !rep.Simulated || rep.DeploymentID != w.evidence.DeploymentID || rep.StackHash != direct.StackHash.Hex() {
			t.Fatalf("report header %+v", rep)
		}
		for _, name := range []string{verify.CheckStackRecompute, verify.CheckReportData, verify.CheckFreshness, verify.CheckOnchainRecord, verify.CheckApprovalReleases} {
			if c := rep.Check(name); c == nil || !c.OK {
				t.Fatalf("%s missing or failed", name)
			}
		}
		if !strings.Contains(rep.Check(verify.CheckReportData).Detail, "uint64be(attestedAt)") {
			t.Fatal("report_data detail does not name the D-047 construction")
		}
	})

	// Evidence tampering, verified by the warm daemon.
	cases := []struct {
		name   string
		mutate func(b *verify.Bundle)
		fail   []string
	}{
		{"changed config byte", func(b *verify.Bundle) {
			b.Config = json.RawMessage(strings.Replace(string(b.Config), "34.1.2.3", "34.1.2.4", 1))
		}, []string{verify.CheckConfigHash, verify.CheckStackRecompute}},
		{"changed egress addition in the config", func(b *verify.Bundle) {
			b.Config = json.RawMessage(strings.Replace(string(b.Config), "smtp.example.com:587", "smtp.evil.example:587", 1))
			sum := sha256.Sum256(b.Config)
			b.ConfigHash = hexb.Enc(sum[:]) // the sender recomputes configHash; the quote still binds the original
		}, []string{verify.CheckReportData, verify.CheckStackRecompute, verify.CheckOnchainRecord}},
		{"changed app-compose byte", func(b *verify.Bundle) {
			b.AppCompose = strings.Replace(b.AppCompose, `"public_logs":false`, `"public_logs":true `, 1)
		}, []string{verify.CheckComposeHash, verify.CheckDeploymentID, verify.CheckStackRecompute, verify.CheckStackApproved, verify.CheckApprovalReleases}},
		{"attestedAt relabelled", func(b *verify.Bundle) { b.AttestedAt -= 60 },
			[]string{verify.CheckReportData, verify.CheckOnchainRecord}},
		{"nonce2 changed", func(b *verify.Bundle) {
			n, _ := hexb.Decode32(b.Nonce2)
			n[0] ^= 1
			b.Nonce2 = hexb.Enc(n[:])
		}, []string{verify.CheckReportData}},
		{"wrong enclave signer", func(b *verify.Bundle) { b.EnclaveSigner = "0x000000000000000000000000000000000000dead" },
			[]string{verify.CheckReportData, verify.CheckOnchainRecord}},
		{"event log reordered", func(b *verify.Bundle) {
			var evs []attest.Event
			json.Unmarshal(b.EventLog, &evs)
			evs[1], evs[2] = evs[2], evs[1]
			b.EventLog, _ = json.Marshal(evs)
			fixture.Rehash(b)
		}, []string{verify.CheckRTMR3, verify.CheckComposeHash, verify.CheckOnchainRecord}},
		{"quote with another image's measurements", func(b *verify.Bundle) {
			q, _ := hexb.Decode(b.Quote, -1)
			parsed, _ := attest.ParseQuote(q, attest.ParseOptions{AllowSimulated: true})
			other := attest.SimMRTDDebug
			b.Quote = hexb.Enc(attest.NewSimQuote(attest.SimQuoteParams{RTMR3: parsed.RTMR[3], ReportData: parsed.ReportData, MRTD: &other}))
			fixture.Rehash(b)
		}, []string{verify.CheckImageMeasurements, verify.CheckOnchainRecord}},
		{"bundle releaseIds differ from the config", func(b *verify.Bundle) { b.ReleaseIDs = b.ReleaseIDs[:1] },
			[]string{verify.CheckConfigBinding}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := clone()
			tc.mutate(b)
			verifyEvidence(t, api, b, tc.fail...)
		})
	}

	// Release asset tampering, each on a daemon with a cold cache.
	gw, notes := w.bundles[0], w.bundles[1]
	t.Run("served bundle changed by one byte", func(t *testing.T) {
		bad := bytes.Clone(notes.Tar)
		bad[len(bad)/2] ^= 0x01
		w.assets.PublishBytes(t, notes.Manifest.ID, notes.Version(), bad)
		defer w.assets.Publish(t, notes)
		rep := verifyEvidence(t, w.daemon(t), w.evidence, verify.CheckStackRecompute)
		if d := rep.Check(verify.CheckStackRecompute).Detail; !strings.Contains(d, "sha256 does not match the onchain bundleHash") || !strings.Contains(d, "notes") {
			t.Fatalf("detail %q", d)
		}
	})
	t.Run("another app's bundle served under the release asset URL", func(t *testing.T) {
		w.assets.PublishBytes(t, notes.Manifest.ID, notes.Version(), gw.Tar)
		defer w.assets.Publish(t, notes)
		verifyEvidence(t, w.daemon(t), w.evidence, verify.CheckStackRecompute)
	})
	t.Run("bundle missing from the release", func(t *testing.T) {
		w.assets.Remove(t, gw.Manifest.ID, gw.Version())
		defer w.assets.Publish(t, gw)
		rep := verifyEvidence(t, w.daemon(t), w.evidence, verify.CheckStackRecompute)
		if d := rep.Check(verify.CheckStackRecompute).Detail; !strings.Contains(d, "release asset not found") {
			t.Fatalf("detail %q", d)
		}
		status, raw := postJSON(t, w.daemon(t).URL+"/v1/compose", map[string]any{"config": json.RawMessage(w.config)})
		if status != http.StatusServiceUnavailable {
			t.Fatalf("/v1/compose without the asset: HTTP %d %s", status, raw)
		}
	})
	t.Run("a mirror serves what the catalog base lacks", func(t *testing.T) {
		mirror := catalogtest.NewServer(t)
		for _, b := range w.bundles {
			mirror.Publish(t, b)
		}
		w.assets.Remove(t, gw.Manifest.ID, gw.Version())
		defer w.assets.Publish(t, gw)
		verifyEvidence(t, w.daemon(t, "--release-asset-base", w.assets.Base+","+mirror.Base), w.evidence)
		if mirror.Hits(t, gw.Manifest.ID, gw.Version()) != 1 || mirror.Hits(t, notes.Manifest.ID, notes.Version()) != 0 {
			t.Fatal("mirror used for a bundle the catalog base served")
		}
	})
	t.Run("verified bundles are served from the cache while the asset host is down", func(t *testing.T) {
		cacheDir := filepath.Join(t.TempDir(), "bundles")
		first := w.daemon(t, "--bundle-cache-dir", cacheDir)
		verifyEvidence(t, first, w.evidence)
		w.assets.SetDown(true)
		defer w.assets.SetDown(false)
		verifyEvidence(t, first, w.evidence) // memory
		restarted := w.daemon(t, "--bundle-cache-dir", cacheDir)
		verifyEvidence(t, restarted, w.evidence) // disk, after a restart
		// A disk entry changed behind the daemon's back is dropped, and with the host down the stack fails closed.
		tar := filepath.Join(cacheDir, hex.EncodeToString(notes.Hash[:])+".bundle.tar")
		if err := os.WriteFile(tar, []byte("not the bundle"), 0o600); err != nil {
			t.Fatal(err)
		}
		verifyEvidence(t, w.daemon(t, "--bundle-cache-dir", cacheDir), w.evidence, verify.CheckStackRecompute)
		w.assets.SetDown(false)
		verifyEvidence(t, w.daemon(t, "--bundle-cache-dir", cacheDir), w.evidence) // refetched
	})
	t.Run("simulated quote on a production verifier", func(t *testing.T) {
		rep := verifyEvidence(t, w.prodDaemon(t), w.evidence, verify.CheckQuote, verify.CheckTDAttributes, verify.CheckImageMeasurements,
			verify.CheckRTMR3, verify.CheckComposeHash, verify.CheckReportData, verify.CheckReleaseSignature)
		if c := rep.Check(verify.CheckReleaseSignature); !strings.Contains(c.Detail, ".sigstore.json: HTTP 404") {
			t.Fatalf("release_signature: %s", c.Detail)
		}
	})
	t.Run("releases signed outside release CI on a production verifier", func(t *testing.T) {
		// Assets in exactly the shape release CI publishes, with release.yml's identity, from a Sigstore of our own:
		// the production verifier trusts only the public-good Fulcio and Rekor, so release_signature fails.
		local := sigstoretest.New(t)
		signer := sigstoretest.GitHubActions(releasesig.ReleaseWorkflow, releasesig.SourceRepository, releasesig.SourceRef, releasesig.ReleaseWorkflow)
		builder := sigstoretest.GitHubActions(releasesig.SLSABuilder, releasesig.SourceRepository, releasesig.SourceRef, releasesig.ReleaseWorkflow)
		for _, b := range w.bundles {
			sig, prov := local.ReleaseAssets(signer, builder, releasesig.SLSAPredicateType, composer.BundleAssetName(b.Manifest.ID, b.Version()), [32]byte(b.Hash))
			w.assets.PublishNext(t, b.Manifest.ID, b.Version(), releasesig.SignatureSuffix, sig)
			w.assets.PublishNext(t, b.Manifest.ID, b.Version(), releasesig.ProvenanceSuffix, prov)
		}
		rep := verifyEvidence(t, w.prodDaemon(t), w.evidence, verify.CheckQuote, verify.CheckTDAttributes, verify.CheckImageMeasurements,
			verify.CheckRTMR3, verify.CheckComposeHash, verify.CheckReportData, verify.CheckReleaseSignature)
		c := rep.Check(verify.CheckReleaseSignature)
		if !strings.Contains(c.Detail, "not signed by "+releasesig.ReleaseWorkflow) || strings.Contains(c.Detail, "HTTP 404") {
			t.Fatalf("release_signature: %s", c.Detail)
		}
		// A dev daemon still reports what it found, and passes.
		rep = verifyEvidence(t, w.daemon(t), w.evidence)
		if c := rep.Check(verify.CheckReleaseSignature); !c.OK || !strings.HasPrefix(c.Detail, "DEV: ") || !strings.Contains(c.Detail, "not signed by") {
			t.Fatalf("dev release_signature: %s", c.Detail)
		}
	})
	t.Run("compose refuses a config whose release belongs to another app", func(t *testing.T) {
		bad := strings.Replace(string(w.config), notes.ReleaseID.Hex(), gw.ReleaseID.Hex(), 1)
		status, raw := postJSON(t, api.URL+"/v1/compose", map[string]any{"config": json.RawMessage(bad)})
		if status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "belongs to app") {
			t.Fatalf("HTTP %d %s", status, raw)
		}
	})

	t.Run("a published but unapproved release of an app", func(t *testing.T) {
		// A newer notes release (packaging change) is published and served; a config that uses it composes to a
		// different stack, which the customer never approved and the oracle never registered.
		dir := catalogtest.CopyApp(t, "notes")
		manifest := filepath.Join(dir, "manifest.yaml")
		m, _ := os.ReadFile(manifest)
		if err := os.WriteFile(manifest, []byte(strings.Replace(string(m), "release_version: 1.0.0-sealed.1", "release_version: 1.0.0-sealed.2", 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		next := catalogtest.Build(t, dir)
		if next.Version() != "1.0.0-sealed.2" || next.Hash == notes.Hash {
			t.Fatalf("new notes release %s %s", next.Version(), next.Hash)
		}
		w.assets.Publish(t, next)
		w.r.PublishRelease(t, w.n, next.AppID, next.Version(), next.Hash)
		stack := []*composer.Bundle{gw, next}
		cfgNext := catalogtest.Config(t, catalogtest.ConfigParams{
			ChainID: w.n.ChainID.Uint64(), Customer: customer, Salt: sha256.Sum256([]byte("e2e salt")), ImageID: w.imageID, Addrs: w.addrs,
		}, stack)
		status, raw := postJSON(t, api.URL+"/v1/compose", map[string]any{"config": json.RawMessage(cfgNext)})
		var got composeAnswer
		if err := json.Unmarshal(raw, &got); err != nil || status != http.StatusOK || got.StackHash == ans.StackHash {
			t.Fatalf("/v1/compose of the new release: HTTP %d %s", status, raw)
		}
		parsed, _ := composer.ParseConfig(cfgNext)
		res, err := composer.Compose(parsed, stack)
		if err != nil || got.AppCompose != string(res.AppCompose) {
			t.Fatalf("new stack differs from runtime/composer: %v", err)
		}
		b := fixture.SimEvidence(fixture.EvidenceParams{
			ChainID: w.n.ChainID.Uint64(), Addrs: w.addrs, Customer: customer, EnclaveSigner: anviltest.Addr(anviltest.Enclave),
			ImageID: w.imageID, ReleaseIDs: [][32]byte{gw.ReleaseID, next.ReleaseID}, Config: cfgNext,
			Compose: &verify.ComposeOutput{AppCompose: res.AppCompose, StackHash: res.StackHash, ConfigHash: res.ConfigHash, DeploymentID: res.DeploymentID},
			Nonce2:  sha256.Sum256([]byte("e2e nonce2 next")), InstanceID: inst, AttestedAt: w.n.Now(t),
		})
		verifyEvidence(t, api, b, verify.CheckStackApproved, verify.CheckApprovalReleases, verify.CheckOnchainRecord)
	})

	// Chain state changes (last: revocations are terminal).
	t.Run("revoked approval", func(t *testing.T) {
		w.r.RevokeStack(t, w.n, anviltest.Customer, w.compose.StackHash)
		verifyEvidence(t, api, w.evidence, verify.CheckStackApproved)
		w.r.ApproveStack(t, w.n, anviltest.Customer, w.compose.StackHash, releaseIDs, w.imageID)
		verifyEvidence(t, api, w.evidence)
	})
	t.Run("revoked release", func(t *testing.T) {
		w.r.RevokeRelease(t, w.n, notes.ReleaseID)
		verifyEvidence(t, api, w.evidence, verify.CheckReleasesActive, verify.CheckStackApproved)
	})
	t.Run("revoked image", func(t *testing.T) {
		w.r.RevokeImage(t, w.n, w.imageID)
		verifyEvidence(t, api, w.evidence, verify.CheckReleasesActive, verify.CheckStackApproved, verify.CheckImageApproved)
	})
}
