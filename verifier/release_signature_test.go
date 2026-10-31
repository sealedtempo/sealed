package verify_test

import (
	"strings"
	"testing"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/internal/fixture"
)

// TestReleaseSignatureRequired (supply-2): every release of the stack must carry release CI's signature for its
// onchain bundleHash. Before the check existed, a release the OPS key published from a bundle release.yml never built
// or signed verified like any other.
func TestReleaseSignatureRequired(t *testing.T) {
	t.Run("signed releases pass and the report names the signer", func(t *testing.T) {
		e := newEnv(t, false)
		rep := e.run(t)
		c := rep.Check(verify.CheckReleaseSignature)
		if !rep.OK || c == nil || !c.OK || !strings.Contains(c.Detail, "2 releases signed by "+fixture.ReleaseSigner) {
			t.Fatalf("report:\n%s", rep.Text())
		}
		rels := c.Data["releases"].([]map[string]any)
		if len(rels) != 2 || rels[0]["signer"] != fixture.ReleaseSigner || rels[0]["provenanceUrl"] == "" || rels[0]["bundleHash"] == "" {
			t.Fatalf("data %v", c.Data)
		}
		if !strings.Contains(rep.Text(), "release_signature") {
			t.Fatal("text report lacks release_signature")
		}
	})
	t.Run("an unsigned release fails the report", func(t *testing.T) {
		e := newEnv(t, false)
		unsigned := e.w.Apps[1]
		e.deps.Signatures = fixture.Signatures{Unsigned: map[[32]byte]bool{unsigned.BundleHash: true}}
		rep := e.run(t)
		c := rep.Check(verify.CheckReleaseSignature)
		if rep.OK || c == nil || c.OK || !strings.Contains(c.Detail, unsigned.Slug+" "+unsigned.Version+": ") ||
			strings.Contains(c.Detail, e.w.Apps[0].Slug+" ") {
			t.Fatalf("report:\n%s", rep.Text())
		}
		if got := rep.Failed(); len(got) != 1 || got[0] != verify.CheckReleaseSignature {
			t.Fatalf("failed checks %v", got)
		}
	})
	t.Run("no signature verifier fails closed", func(t *testing.T) {
		e := newEnv(t, false)
		e.deps.Signatures = nil
		rep := e.run(t)
		if c := rep.Check(verify.CheckReleaseSignature); rep.OK || c == nil || c.OK || !strings.Contains(c.Detail, "no release signature verifier is configured") {
			t.Fatalf("report:\n%s", rep.Text())
		}
	})
	t.Run("releases unavailable fail closed", func(t *testing.T) {
		e := newEnv(t, false)
		delete(e.m.Releases, e.w.Apps[0].ReleaseID())
		rep := e.run(t)
		if c := rep.Check(verify.CheckReleaseSignature); c == nil || c.OK || c.Detail != "releases unavailable" {
			t.Fatalf("report:\n%s", rep.Text())
		}
	})
	t.Run("a dev verification accepts unsigned releases and says so", func(t *testing.T) {
		e := newEnv(t, false)
		e.deps.Signatures = fixture.Signatures{Unsigned: map[[32]byte]bool{e.w.Apps[0].BundleHash: true}}
		e.opts.AcceptUnsignedReleases = true
		rep := e.run(t)
		c := rep.Check(verify.CheckReleaseSignature)
		if !rep.OK || c == nil || !c.OK || !strings.HasPrefix(c.Detail, "DEV: ") || c.Data["acceptedUnsigned"] != true {
			t.Fatalf("report:\n%s", rep.Text())
		}
		e.deps.Signatures = nil
		if c := e.run(t).Check(verify.CheckReleaseSignature); !c.OK || !strings.Contains(c.Detail, "no release signature verifier") {
			t.Fatalf("no verifier in dev mode: %+v", c)
		}
		e.deps.Signatures = fixture.Signatures{}
		if c := e.run(t).Check(verify.CheckReleaseSignature); !c.OK || strings.Contains(c.Detail, "DEV") || c.Data["acceptedUnsigned"] != nil {
			t.Fatalf("signed releases in dev mode: %+v", c)
		}
	})
	t.Run("live verification checks release signatures too", func(t *testing.T) {
		e, as, opts := liveEnv(t)
		e.deps.Signatures = fixture.Signatures{Unsigned: map[[32]byte]bool{e.w.Apps[0].BundleHash: true}}
		rep := runLive(t, e, as.srv.URL+"/attest", opts)
		if got := rep.Failed(); rep.OK || len(got) != 1 || got[0] != verify.CheckReleaseSignature {
			t.Fatalf("failed %v:\n%s", got, rep.Text())
		}
	})
}
