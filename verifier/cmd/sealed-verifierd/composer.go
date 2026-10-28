package main

// TODO(composer): runtime/composer lives on branch ws/composer and is not merged into this branch. After the merge,
// set composerFactory in an init() here with an adapter that implements verify.Composer: fetch each release bundle
// by its onchain bundleHash (the release asset URL rule under config/defaults.yaml catalog.release_asset_base is
// not in INTERFACES.md yet), check sha256(bundle.tar) == bundleHash, cache by hash, then composer.LoadBundle and
// composer.Compose(cfg, bundles). Until then the daemon fails stack recomputation closed and /v1/compose answers
// 501, so no report can be OK.
