package bundles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealed-dev/sealed/runtime/composer"
	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/bundles"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/internal/catalogtest"
)

type stack struct {
	srv     *catalogtest.Server
	bundles []*composer.Bundle
	config  []byte
	in      verify.ComposeInput
	comp    *bundles.Composer
}

func newStack(t *testing.T) *stack {
	t.Helper()
	srv := catalogtest.NewServer(t)
	bs := catalogtest.Bundles(t)
	for _, b := range bs {
		srv.Publish(t, b)
	}
	cfg := catalogtest.Config(t, catalogtest.ConfigParams{
		ChainID: 4217, Customer: common.HexToAddress("0x00000000000000000000000000000000000000c1"), Salt: [32]byte{0x5a}, ImageID: [32]byte{0x1d},
		Addrs: chain.Addresses{PlatformRegistry: common.HexToAddress("0xe1"), AppRegistry: common.HexToAddress("0xe2"), DeploymentRegistry: common.HexToAddress("0xe3")},
	}, bs)
	in := verify.ComposeInput{Config: cfg}
	for _, b := range bs {
		in.Releases = append(in.Releases, verify.ComposeRelease{App: b.Manifest.ID, ReleaseID: b.ReleaseID, AppID: b.AppID, Version: b.Version(), BundleHash: b.Hash})
	}
	src, err := bundles.NewSource([]string{srv.Base}, "")
	if err != nil {
		t.Fatal(err)
	}
	return &stack{srv: srv, bundles: bs, config: cfg, in: in, comp: &bundles.Composer{Source: src}}
}

// TestComposerMatchesRuntimeComposer: fetched, verified bundles compose to exactly what runtime/composer gives for
// the same config and bundles.
func TestComposerMatchesRuntimeComposer(t *testing.T) {
	s := newStack(t)
	out, err := s.comp.Compose(context.Background(), s.in)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := composer.ParseConfig(s.config)
	if err != nil {
		t.Fatal(err)
	}
	want, err := composer.Compose(cfg, s.bundles)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.AppCompose, want.AppCompose) || out.StackHash != want.StackHash || out.ConfigHash != want.ConfigHash || out.DeploymentID != want.DeploymentID {
		t.Fatal("bundles.Composer differs from runtime/composer")
	}
	if strings.Join(out.Unbuilt, ",") != strings.Join(want.Unbuilt, ",") || len(out.Unbuilt) == 0 {
		t.Fatalf("unbuilt %v, want %v (the fixture sidecars have zero digests)", out.Unbuilt, want.Unbuilt)
	}
	// A second composition is served from the cache.
	hits := s.srv.TotalHits()
	if _, err := s.comp.Compose(context.Background(), s.in); err != nil || s.srv.TotalHits() != hits {
		t.Fatalf("recompose fetched again: %v", err)
	}
}

func TestComposerRefusesMismatches(t *testing.T) {
	s := newStack(t)
	gw, notes := s.bundles[0], s.bundles[1]
	cases := []struct {
		name   string
		mutate func(in *verify.ComposeInput)
		want   error
		detail string
	}{
		{"release of another app", func(in *verify.ComposeInput) { in.Releases[1].AppID = gw.AppID }, bundles.ErrReleaseMismatch, "belongs to app"},
		{"release order differs from config.apps", func(in *verify.ComposeInput) { in.Releases[0], in.Releases[1] = in.Releases[1], in.Releases[0] }, bundles.ErrReleaseMismatch, "config.apps[0]"},
		{"one release missing", func(in *verify.ComposeInput) { in.Releases = in.Releases[:1] }, bundles.ErrReleaseMismatch, "1 releases for 2"},
		{"onchain release id is not the config's", func(in *verify.ComposeInput) { in.Releases[1].ReleaseID = gw.ReleaseID }, bundles.ErrReleaseMismatch, "releaseId"},
		{"onchain fields do not derive the release id", func(in *verify.ComposeInput) { in.Releases[1].Version = "2.0.0" }, bundles.ErrReleaseMismatch, "is not keccak256"},
		{"bundle hash the server does not have", func(in *verify.ComposeInput) {
			// A consistent release (as a registrar could publish) whose bundle bytes are not what the asset serves.
			in.Releases[1].BundleHash = [32]byte{0x01}
			in.Releases[1].ReleaseID = composer.ReleaseID(notes.AppID, notes.Version(), composer.Hash{0x01})
			in.Config = []byte(strings.Replace(string(in.Config), notes.ReleaseID.Hex(), composer.Hash(in.Releases[1].ReleaseID).Hex(), 1))
		}, bundles.ErrHashMismatch, "sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := s.in
			in.Releases = append([]verify.ComposeRelease(nil), s.in.Releases...)
			tc.mutate(&in)
			_, err := s.comp.Compose(context.Background(), in)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("err %v, want %v containing %q", err, tc.want, tc.detail)
			}
		})
	}

	t.Run("bad config is refused before any download", func(t *testing.T) {
		before := s.srv.TotalHits()
		in := s.in
		in.Config = []byte(strings.Replace(string(s.config), `"composerVersion":"`+composer.Version+`"`, `"composerVersion":"0.0.1"`, 1))
		if _, err := s.comp.Compose(context.Background(), in); err == nil || !strings.Contains(err.Error(), "composerVersion") {
			t.Fatalf("old composer version: %v", err)
		}
		in.Config = json.RawMessage(`{"schema":"sealed-config/v1","Schema":"x"}`)
		if _, err := s.comp.Compose(context.Background(), in); err == nil {
			t.Fatal("ambiguous config accepted")
		}
		if s.srv.TotalHits() != before {
			t.Fatal("a bad config caused downloads")
		}
	})

	t.Run("bundle published under another app's release", func(t *testing.T) {
		// The asset path of notes serves the llm-gateway bundle, and the chain (a registrar mistake) records its hash
		// as a notes release: the manifest id gives it away.
		s2 := newStack(t)
		s2.srv.PublishBytes(t, "notes", "6.6.6", gw.Tar)
		in := s2.in
		in.Releases = append([]verify.ComposeRelease(nil), s2.in.Releases...)
		in.Releases[1].Version = "6.6.6"
		in.Releases[1].BundleHash = gw.Hash
		in.Releases[1].ReleaseID = composer.ReleaseID(notes.AppID, "6.6.6", gw.Hash)
		in.Config = []byte(strings.Replace(string(in.Config), notes.ReleaseID.Hex(), composer.Hash(in.Releases[1].ReleaseID).Hex(), 1))
		_, err := s2.comp.Compose(context.Background(), in)
		if !errors.Is(err, bundles.ErrReleaseMismatch) || !strings.Contains(err.Error(), "is llm-gateway") {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("asset host down", func(t *testing.T) {
		s3 := newStack(t)
		s3.srv.SetDown(true)
		if _, err := s3.comp.Compose(context.Background(), s3.in); !errors.Is(err, bundles.ErrUnavailable) {
			t.Fatalf("err %v", err)
		}
		s3.srv.SetDown(false)
		if _, err := s3.comp.Compose(context.Background(), s3.in); err != nil {
			t.Fatalf("after recovery: %v", err)
		}
	})

	t.Run("nil composer fails closed", func(t *testing.T) {
		var c *bundles.Composer
		if _, err := c.Compose(context.Background(), s.in); !errors.Is(err, verify.ErrComposerNotConfigured) {
			t.Fatal(err)
		}
	})
}
