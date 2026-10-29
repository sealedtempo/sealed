package composer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const testAssetBase = "https://github.com/sealedtempo/sealed/releases/download"

func TestReleaseAssetURLs(t *testing.T) {
	a, err := NewReleaseAssets(testAssetBase+"/", "crm", "2.52.0")
	if err != nil {
		t.Fatal(err)
	}
	want := testAssetBase + "/crm-v2.52.0/crm-2.52.0.bundle.tar"
	if a.Tag != "crm-v2.52.0" || a.Bundle != want || a.Signature != want+".sig" || a.Certificate != want+".crt" || a.Provenance != want+".intoto.jsonl" {
		t.Fatalf("%+v", a)
	}
	if s, err := a.SBOM("twenty"); err != nil || s != testAssetBase+"/crm-v2.52.0/sbom.twenty.spdx.json" {
		t.Errorf("sbom %q %v", s, err)
	}
	if SBOMPath("twenty") != "sbom/twenty.spdx.json" {
		t.Error(SBOMPath("twenty"))
	}
	// A leading v before a digit is not doubled in the tag (it read
	// internal-tools-vv3.20.251-lts before 1.4.0); the asset names keep the
	// version literally, as hashed into releaseId.
	for version, tag := range map[string]string{
		"v3.20.251-lts": "internal-tools-v3.20.251-lts", "V2": "internal-tools-v2", "3.20.251": "internal-tools-v3.20.251",
		"1.0.0-v2": "internal-tools-v1.0.0-v2", "0v1": "internal-tools-v0v1",
	} {
		a, err := NewReleaseAssets(testAssetBase, "internal-tools", version)
		want := testAssetBase + "/" + tag + "/internal-tools-" + version + ".bundle.tar"
		if err != nil || a.Tag != tag || a.Bundle != want || ReleaseTag("internal-tools", version) != tag || strings.Contains(a.Tag, "-vv") {
			t.Errorf("%s: %+v %v, want %s", version, a, err, want)
		}
	}
	if TagVersion("v1.58.2") != "1.58.2" || TagVersion("v") != "v" || TagVersion("1.58.2") != "1.58.2" {
		t.Error("TagVersion")
	}
	for _, bad := range []struct{ base, slug, version string }{
		{"ftp://example.com/x", "crm", "1.0.0"},
		{"https://user:pw@example.com/x", "crm", "1.0.0"},
		{"https://example.com/x?y=1", "crm", "1.0.0"},
		{"not a url", "crm", "1.0.0"},
		{testAssetBase, "Crm", "1.0.0"},
		{testAssetBase, "../crm", "1.0.0"},
		{testAssetBase, "crm", "1.0.0+sealed.1"},
		{testAssetBase, "crm", "1.0/0"},
		{testAssetBase, "crm", ""},
		// A leading v that no digit follows would double the tag's v.
		{testAssetBase, "crm", "vnext"},
		{testAssetBase, "crm", "v"},
		{testAssetBase, "crm", "Vv1"},
		{testAssetBase, "crm", "vv1.0.0"},
	} {
		if _, err := NewReleaseAssets(bad.base, bad.slug, bad.version); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := (ReleaseAssets{Base: testAssetBase, Tag: "crm-v1"}).SBOM("../x"); err == nil {
		t.Error("bad image name accepted")
	}
	// A bundle knows its own URLs.
	b := buildFixture(t, "notes")
	a, err = b.Assets(testAssetBase)
	if err != nil || a.Bundle != testAssetBase+"/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar" {
		t.Errorf("bundle assets %+v %v", a, err)
	}
}

// TestReleaseAssetBaseMatchesDefaults keeps the helper in step with config/defaults.yaml.
func TestReleaseAssetBaseMatchesDefaults(t *testing.T) {
	d, err := LoadDefaults(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReleaseAssets(d.Catalog.ReleaseAssetBase, "crm", "1.0.0"); err != nil {
		t.Fatalf("catalog.release_asset_base: %v", err)
	}
}

// sealed-verifierd fetches relay bundles from catalog.release_asset_base, so its egress names that host.
func TestReleaseAssetHostsMatchDefaults(t *testing.T) {
	d, err := LoadDefaults(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(d.Catalog.ReleaseAssetBase)
	if err != nil || u.Scheme != "https" {
		t.Fatalf("catalog.release_asset_base %q: %v", d.Catalog.ReleaseAssetBase, err)
	}
	if releaseAssetHosts[0] != u.Hostname()+":443" {
		t.Fatalf("verifierd egress %v does not name the release asset host %s", releaseAssetHosts, u.Hostname())
	}
}

// The in-VM verifierd's live checks may fetch only the relay's attest host.
func TestVerifierdLiveHosts(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	var doc struct {
		Services map[string]struct {
			Environment map[string]string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(r.ComposeJSON, &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Services["sealed-verifierd"].Environment["SEALED_VERIFIERD_LIVE_HOSTS"]; got != "attest.relay.sealed.example" {
		t.Fatalf("SEALED_VERIFIERD_LIVE_HOSTS = %q", got)
	}
}

func TestFetchBundle(t *testing.T) {
	b := buildFixture(t, "notes")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar":
			_, _ = w.Write(b.Tar)
		case "/tampered.tar":
			tam := append([]byte(nil), b.Tar...)
			tam[700] ^= 1
			_, _ = w.Write(tam)
		case "/redirect":
			http.Redirect(w, r, "/notes-v1.0.0-sealed.1/notes-1.0.0-sealed.1.bundle.tar", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a, err := b.Assets(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cache := DirCache{Dir: t.TempDir()}
	got, err := FetchBundle(ctx, srv.Client(), a.Bundle, b.Hash, cache)
	if err != nil || got.Hash != b.Hash || got.ReleaseID != b.ReleaseID {
		t.Fatalf("fetch: %v", err)
	}
	// The second fetch comes from the content-addressed cache.
	before := hits.Load()
	if _, err := FetchBundle(ctx, srv.Client(), a.Bundle, b.Hash, cache); err != nil || hits.Load() != before {
		t.Fatalf("cache miss: %v hits %d->%d", err, before, hits.Load())
	}
	// A one-byte change is refused with the onchain hash in the error.
	_, err = FetchBundle(ctx, srv.Client(), srv.URL+"/tampered.tar", b.Hash, nil)
	var mm *BundleHashMismatchError
	if !errors.As(err, &mm) || mm.Want != b.Hash {
		t.Fatalf("tampered bundle: %v", err)
	}
	if _, err := FetchBundle(ctx, srv.Client(), srv.URL+"/redirect", b.Hash, nil); err != nil {
		t.Fatalf("redirect (GitHub serves assets by redirect): %v", err)
	}
	if _, err := FetchBundle(ctx, srv.Client(), srv.URL+"/missing", b.Hash, nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing asset: %v", err)
	}
	// A corrupted cache entry is a miss, never a wrong bundle.
	if err := os.WriteFile(cache.path(b.Hash), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Get(b.Hash); ok {
		t.Fatal("corrupted cache entry returned")
	}
	if _, err := FetchBundle(ctx, srv.Client(), a.Bundle, b.Hash, cache); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Get(b.Hash); !ok {
		t.Fatal("cache not refilled")
	}
	if err := cache.Put(b.Hash, []byte("other")); err == nil {
		t.Fatal("cache accepted bytes for the wrong hash")
	}
}
