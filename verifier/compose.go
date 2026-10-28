package verify

import (
	"context"
	"encoding/json"
	"fmt"
)

// ComposeFromChain composes a stack for a public config, reading each config.apps release from AppRegistry (so
// bundles are fetched by their onchain bundleHash). It backs POST /v1/compose for services that must not
// reimplement the composer (D-006).
func ComposeFromChain(ctx context.Context, deps Deps, config json.RawMessage) (*ComposeOutput, error) {
	if deps.Composer == nil {
		return nil, ErrComposerNotConfigured
	}
	if deps.Chain == nil {
		return nil, fmt.Errorf("verify: Deps.Chain is nil")
	}
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, chainCallTimeout)
	defer cancel()
	reader, _, _, err := pinHead(ctx, deps.Chain)
	if err != nil {
		return nil, fmt.Errorf("eth_blockNumber: %w", err)
	}
	in := ComposeInput{Config: config}
	for i, id := range cfg.releaseIDs {
		rel, err := reader.GetRelease(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("config.apps[%d] (%s): %w", i, cfg.Apps[i].ID, err)
		}
		in.Releases = append(in.Releases, ComposeRelease{App: cfg.Apps[i].ID, ReleaseID: id, AppID: rel.AppId, Version: rel.Version, BundleHash: rel.BundleHash})
	}
	return deps.Composer.Compose(ctx, in)
}
