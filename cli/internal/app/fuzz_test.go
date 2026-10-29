package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/cli/internal/bundles"
	"github.com/sealedtempo/sealed/runtime/composer"
)

type bodyTransport struct{ body []byte }

func (b *bodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b.body)), Header: http.Header{}, Request: r}, nil
}

// FuzzReleaseBundle is the CLI reading a published release bundle: the
// fetcher with the onchain bundleHash of the served bytes, Load's identity
// checks, `sealed catalog`'s manifest view and asset URLs, and `sealed
// release`'s diff against a local build. Properties: no panic; a loaded
// bundle is exactly the bytes whose hash the chain holds and the app and
// version the release names.
func FuzzReleaseBundle(f *testing.F) {
	var locals []*composer.Bundle
	for _, app := range []string{"notes", "llm-gateway", "inference-relay"} {
		b, err := composer.BuildBundle(composer.BuildInput{
			AppDir: filepath.Join("..", "..", "..", "runtime", "composer", "testdata", "apps", app), Registry: "ghcr.io/sealedtempo",
		})
		if err != nil {
			f.Fatal(err)
		}
		locals = append(locals, b)
		f.Add(b.Tar, uint8(len(locals)-1))
	}
	tr := &bodyTransport{}
	fetch := &bundles.Fetcher{Base: "https://github.com/sealedtempo/sealed/releases/download", HTTP: &http.Client{Transport: tr}}
	f.Fuzz(func(t *testing.T, raw []byte, which uint8) {
		local := locals[int(which)%len(locals)]
		tr.body = raw
		want := sha256.Sum256(raw)
		rel := bundles.Release{App: local.Manifest.ID, Version: local.Version(), BundleHash: want}
		b, err := fetch.Load(context.Background(), rel)
		if diff := diffBundles(local.Tar, raw); len(diff) == 0 {
			t.Fatal("diffBundles returned nothing")
		}
		if err != nil {
			return
		}
		if b.Hash != want || !bytes.Equal(b.Tar, raw) || b.Manifest.ID != rel.App || b.Version() != rel.Version {
			t.Fatalf("loaded %s %s (hash %x) for release %s %s (hash %x)", b.Manifest.ID, b.Version(), b.Hash, rel.App, rel.Version, want)
		}
		mv := manifestView(b)
		if len(mv.Images) != len(b.Manifest.Images) {
			t.Fatalf("manifest view lists %d images, the manifest %d", len(mv.Images), len(b.Manifest.Images))
		}
		if urls, err := releaseAssetURLs(b, fetch.Base); err == nil && !strings.HasPrefix(urls.Bundle, fetch.Base+"/") {
			t.Fatalf("bundle asset URL %q is outside the release asset base", urls.Bundle)
		}
		if bytes.Equal(raw, local.Tar) {
			if d := diffBundles(local.Tar, raw); len(d) != 1 || !strings.HasPrefix(d[0], "same files") {
				t.Fatalf("identical bundles diff as %v", d)
			}
		}
	})
}
