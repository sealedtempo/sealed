package main

// TODO(composer): once runtime/composer is merged, set composerFactory in an init() here with an adapter that
// implements verify.Composer: fetch each release bundle from the catalog release assets by its onchain
// bundleHash (config/defaults.yaml catalog.release_asset_base), check sha256(bundle.tar) == bundleHash, cache by
// hash, and call composer.Compose(cfg, bundles). Until then the daemon fails stack recomputation closed.
