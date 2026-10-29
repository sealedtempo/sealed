package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/internal/sigstoretest"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/verifier/releasesig"
)

// TestVerifyChecksReleaseSignatures (supply-2): sealed verify shows release_signature. Without the dev flag, releases
// that release CI did not sign fail it, also when their assets have exactly release CI's shape and identity but come
// from a Sigstore of our own; with --dev-allow-simulated the check reports what it found and passes.
func TestVerifyChecksReleaseSignatures(t *testing.T) {
	h := newHarness(t)
	h.env["SEALED_DEV_SIM"] = "1"
	w, _, path := h.world(true)
	id := w.Result.DeploymentID.Hex()

	code, out, errs := h.run("verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated")
	if code != ExitOK || !strings.Contains(out, "release_signature") || !strings.Contains(out, "DEV: releases without release CI's signature accepted") {
		t.Fatalf("dev verify: %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = h.run("verify", "--deployment", id, "--evidence", path, "--dev-allow-simulated", "--json")
	var doc struct {
		Evidence struct {
			Checks []struct {
				Name string         `json:"name"`
				OK   bool           `json:"ok"`
				Data map[string]any `json:"data"`
			} `json:"checks"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != ExitOK {
		t.Fatalf("json: %d %v", code, err)
	}
	found := false
	for _, c := range doc.Evidence.Checks {
		if c.Name == "release_signature" {
			found = c.OK && c.Data["acceptedUnsigned"] == true && len(c.Data["releases"].([]any)) == len(w.Bundles)
		}
	}
	if !found {
		t.Fatalf("json report lacks a dev-accepted release_signature: %s", out)
	}

	// Without the dev flag (the simulated quote fails too): no signature assets at all.
	code, _, errs = h.run("verify", "--deployment", id, "--evidence", path)
	if code != ExitFailed || !strings.Contains(errs, "evidence/release_signature") {
		t.Fatalf("unsigned releases: %d %s", code, errs)
	}

	// Assets in release CI's shape and identity, signed by a local Sigstore: still not signed by release CI.
	local := sigstoretest.New(t)
	signer := sigstoretest.GitHubActions(releasesig.ReleaseWorkflow, releasesig.SourceRepository, releasesig.SourceRef, releasesig.ReleaseWorkflow)
	builder := sigstoretest.GitHubActions(releasesig.SLSABuilder, releasesig.SourceRepository, releasesig.SourceRef, releasesig.ReleaseWorkflow)
	for _, b := range w.Bundles {
		sig, prov := local.ReleaseAssets(signer, builder, releasesig.SLSAPredicateType, composer.BundleAssetName(b.Manifest.ID, b.Version()), [32]byte(b.Hash))
		h.bundles.PutNext(t, b.Manifest.ID, b.Version(), releasesig.SignatureSuffix, sig)
		h.bundles.PutNext(t, b.Manifest.ID, b.Version(), releasesig.ProvenanceSuffix, prov)
	}
	code, out, errs = h.run("verify", "--deployment", id, "--evidence", path)
	if code != ExitFailed || !strings.Contains(errs, "evidence/release_signature") || !strings.Contains(out, "not signed by "+releasesig.ReleaseWorkflow) {
		t.Fatalf("locally signed releases: %d\n%s\n%s", code, out, errs)
	}
}
