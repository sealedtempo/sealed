# releasesig test data

`sigstore-js-2.0.0-provenance.sigstore.json` is a real Sigstore public-good bundle: the npm provenance of
sigstore-js 2.0.0, signed in GitHub Actions by `https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main`
(Fulcio certificate with SCT, Rekor v1 entry). It is copied byte for byte from sigstore-go v1.3.0,
`pkg/testing/data/bundles/sigstore.js@2.0.0-provenance.sigstore.json` (Apache License 2.0, Copyright 2023 The Sigstore
Authors). `TestPublicGoodBundleOfAnotherRepository` uses it to show that the embedded trusted root verifies real
public-good data offline, and that a valid bundle from another repository's release.yml on main is still refused.
