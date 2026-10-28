package bundles

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/sealed-dev/sealed/runtime/composer"
	verify "github.com/sealed-dev/sealed/verifier"
)

// ErrReleaseMismatch is returned when the onchain release and the config or the bundle disagree.
var ErrReleaseMismatch = errors.New("release does not match")

// Composer recomputes a stack with runtime/composer from bundles that Source verified against their onchain
// bundleHash. It implements verify.Composer.
type Composer struct {
	Source *Source
}

var _ verify.Composer = (*Composer)(nil)

// Compose implements verify.Composer. The config is parsed (strict, normalized) before any download, and each
// release must belong to its config.apps entry: keccak256(slug) = appId, releaseId = keccak256(abi.encode(appId,
// version, bundleHash)), and the bundle's manifest id and version are the release's.
func (c *Composer) Compose(ctx context.Context, in verify.ComposeInput) (*verify.ComposeOutput, error) {
	if c == nil || c.Source == nil {
		return nil, verify.ErrComposerNotConfigured
	}
	cfg, err := composer.ParseConfig(in.Config)
	if err != nil {
		return nil, err
	}
	if len(in.Releases) != len(cfg.Apps) {
		return nil, fmt.Errorf("%w: %d releases for %d config.apps", ErrReleaseMismatch, len(in.Releases), len(cfg.Apps))
	}
	refs := make([]Ref, len(in.Releases))
	for i, r := range in.Releases {
		app := cfg.Apps[i]
		if r.App != app.ID {
			return nil, fmt.Errorf("%w: release %d is for %q, config.apps[%d] is %q", ErrReleaseMismatch, i, r.App, i, app.ID)
		}
		if composer.Hash(r.AppID) != composer.AppID(app.ID) {
			return nil, fmt.Errorf("%w: release 0x%x belongs to app 0x%x, not %q", ErrReleaseMismatch, r.ReleaseID, r.AppID, app.ID)
		}
		if composer.Hash(r.ReleaseID).Hex() != app.ReleaseID {
			return nil, fmt.Errorf("%w: config.apps[%d].releaseId %s, onchain release 0x%x", ErrReleaseMismatch, i, app.ReleaseID, r.ReleaseID)
		}
		if got := composer.ReleaseID(r.AppID, r.Version, r.BundleHash); got != composer.Hash(r.ReleaseID) {
			return nil, fmt.Errorf("%w: onchain release 0x%x is not keccak256(abi.encode(appId, %q, bundleHash)) = %s", ErrReleaseMismatch, r.ReleaseID, r.Version, got.Hex())
		}
		refs[i] = Ref{App: app.ID, Version: r.Version, Hash: r.BundleHash}
	}

	loaded := make([]*composer.Bundle, len(refs))
	// Not errgroup.WithContext: one failed bundle must not abandon the other downloads, which Source detaches from
	// their callers. Compose returns only once every download it started has ended, so none outlives it (writing into
	// the cache after the caller is gone, or failing a later call that joins it after the host recovered).
	var g errgroup.Group
	for i, ref := range refs {
		g.Go(func() error {
			raw, err := c.Source.Get(ctx, ref)
			if err != nil {
				return err
			}
			b, err := composer.LoadBundle(raw)
			if err != nil {
				return fmt.Errorf("bundle %s: %w", ref, err)
			}
			switch {
			case [32]byte(b.Hash) != ref.Hash:
				return fmt.Errorf("bundle %s: %w", ref, ErrHashMismatch)
			case b.Manifest.ID != ref.App || b.Version() != ref.Version:
				return fmt.Errorf("%w: bundle 0x%s is %s %s, onchain release is %s %s", ErrReleaseMismatch,
					hex.EncodeToString(ref.Hash[:]), b.Manifest.ID, b.Version(), ref.App, ref.Version)
			}
			loaded[i] = b
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	res, err := composer.Compose(cfg, loaded)
	if err != nil {
		return nil, err
	}
	return &verify.ComposeOutput{
		AppCompose:   res.AppCompose,
		StackHash:    res.StackHash,
		ConfigHash:   res.ConfigHash,
		DeploymentID: res.DeploymentID,
		Unbuilt:      res.Unbuilt,
	}, nil
}
