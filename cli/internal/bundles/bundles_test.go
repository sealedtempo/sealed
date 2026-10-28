package bundles_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/cli/internal/bundles"
	"github.com/sealed-dev/sealed/cli/internal/testkit"
	verify "github.com/sealed-dev/sealed/verifier"
)

func TestAssetURL(t *testing.T) {
	u, err := bundles.AssetURL("https://github.com/sealedtempo/sealed/releases/download/", "crm", "2.52.0-sealed.1")
	if err != nil || u != "https://github.com/sealedtempo/sealed/releases/download/crm-v2.52.0-sealed.1/crm-2.52.0-sealed.1.bundle.tar" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range [][2]string{{"Crm", "1"}, {"crm", "../x"}, {"crm", "1/2"}, {"crm", ""}} {
		if _, err := bundles.AssetURL("https://x.example", bad[0], bad[1]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestFetchChecksHashAndCaches(t *testing.T) {
	b := testkit.Bundle(t, "notes")
	srv := testkit.NewBundleServer(t, b)
	cache := t.TempDir()
	f := srv.Fetcher(cache)
	ctx := context.Background()
	got, err := f.Fetch(ctx, "notes", b.Version(), b.Hash)
	if err != nil || !bytes.Equal(got, b.Tar) {
		t.Fatalf("fetch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache, strings.TrimPrefix(b.Hash.Hex(), "0x")+".tar")); err != nil {
		t.Fatal("not cached by content hash")
	}
	// A second fetch is served from the cache.
	srv.Close()
	if _, err := f.Fetch(ctx, "notes", b.Version(), b.Hash); err != nil {
		t.Fatalf("cache miss: %v", err)
	}
	// A tampered cache entry is ignored, and with the server down the fetch fails rather than using it.
	os.WriteFile(filepath.Join(cache, strings.TrimPrefix(b.Hash.Hex(), "0x")+".tar"), []byte("tampered"), 0o600)
	if _, err := f.Fetch(ctx, "notes", b.Version(), b.Hash); err == nil {
		t.Fatal("tampered cache entry used")
	}
}

func TestFetchRejectsOtherBytes(t *testing.T) {
	b := testkit.Bundle(t, "notes")
	srv := testkit.NewBundleServer(t)
	srv.Put(t, "notes", b.Version(), append(append([]byte(nil), b.Tar...), 0))
	_, err := srv.Fetcher("").Fetch(context.Background(), "notes", b.Version(), b.Hash)
	if !errors.Is(err, bundles.ErrHashMismatch) {
		t.Fatalf("want hash mismatch, got %v", err)
	}
	// https is required outside tests.
	f := &bundles.Fetcher{Base: srv.URL}
	if _, err := f.Fetch(context.Background(), "notes", b.Version(), b.Hash); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http base accepted: %v", err)
	}
}

func TestLoadChecksRelease(t *testing.T) {
	notes, gw := testkit.Bundle(t, "notes"), testkit.Bundle(t, "llm-gateway")
	srv := testkit.NewBundleServer(t, notes)
	// The gateway's bytes served under the notes path, with the gateway's hash: right hash, wrong app.
	srv.Put(t, "notes", "9.9.9", gw.Tar)
	f := srv.Fetcher("")
	if _, err := f.Load(context.Background(), bundles.Release{App: "notes", Version: "9.9.9", BundleHash: gw.Hash}); err == nil || !strings.Contains(err.Error(), "for app") {
		t.Fatalf("wrong app accepted: %v", err)
	}
	if _, err := f.Load(context.Background(), bundles.Release{App: "notes", Version: notes.Version(), BundleHash: notes.Hash, ReleaseID: [32]byte{1}}); err == nil {
		t.Fatal("wrong releaseId accepted")
	}
	b, err := f.Load(context.Background(), bundles.Release{App: "notes", Version: notes.Version(), BundleHash: notes.Hash, ReleaseID: notes.ReleaseID, AppID: notes.AppID})
	if err != nil || b.Hash != notes.Hash {
		t.Fatal(err)
	}
}

func TestComposerRecomputesTheWorld(t *testing.T) {
	w := testkit.NewWorld(t)
	srv := testkit.NewBundleServer(t, w.Bundles...)
	c := &bundles.Composer{Fetcher: srv.Fetcher("")}
	in := verify.ComposeInput{Config: w.Config}
	for _, b := range w.Bundles {
		in.Releases = append(in.Releases, verify.ComposeRelease{App: b.Manifest.ID, ReleaseID: b.ReleaseID, AppID: b.AppID, Version: b.Version(), BundleHash: b.Hash})
	}
	out, err := c.Compose(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.StackHash != w.Result.StackHash || !bytes.Equal(out.AppCompose, w.Result.AppCompose) || out.DeploymentID != w.Result.DeploymentID {
		t.Fatal("recomputed stack differs")
	}
}
