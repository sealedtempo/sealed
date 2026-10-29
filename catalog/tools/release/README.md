# Catalog release tooling

`catalog/tools/release` is the Go command behind the catalog workflows (`.github/workflows/catalog.yml`,
`images.yml`, `mirror.yml`, `release.yml`) and the scripts in `scripts/release/`. It reuses the composer
(`runtime/composer`) for manifests, bundles and lint, so CI, `sealed release build` and the key broker agree
byte for byte.

```sh
go run ./catalog/tools/release <command> [flags]      # from anywhere in the repository
go test ./catalog/tools/release/                       # unit, script and workflow tests (see Tests)
```

## Commands

| command | does |
|---|---|
| `images [--format json\|build-matrix\|mirror-matrix\|scan-matrix]` | every built and mirrored image; matrices for the workflows (`--changed`, `--all`, `--names`, `--apps`, `--fail-on-blocked`) |
| `pin --scope catalog\|runtime --results <dir>` | write built digests into manifests (catalog) or `runtime-images.json` and `extra-images.json` (runtime); only the digest scalars change |
| `waivers check --file --image --scan [--summary]` | the Grype gate: fails on a critical finding without a valid, unexpired waiver |
| `waivers lint` | every `waivers.yaml` parses and validates |
| `lint-gate --findings <lint.json> --mode pr\|release` | classify `sealed-compose lint --json`; on PRs unbuilt images are deferred to the pin PR and the release |
| `compose-check --out <dir> [--docker-config]` | compose every app and the customer stack with the real composer, then `docker compose config` |
| `plan --changed <files> \| --apps <ids\|all> [--strict]` | apps to release with tags, asset names and image refs |
| `assets --app <id>` | tag and asset names of one version |
| `bundle --app --sbom-dir --scan-dir --out` | release bundle through the composer library, with its publishRelease inputs |
| `info --bundle <tar>` | publishRelease inputs of an existing bundle |
| `sigstore --bundle --blob --sig --crt` | the `.sig` and `.crt` assets from cosign's Sigstore bundle |
| `release-doc` / `notes` | `<appId>-<version>.release.json` (`sealed-release/v1`) and the release notes |
| `catalog-json [--apps] [--images]` | input of `contracts/script/RegisterCatalog.s.sol` from the manifests |
| `keystore --key-env <VAR> --dir <dir>` | throwaway encrypted keystore so cast never sees a raw key on its command line |
| `tx-summary --receipt <json>` | onchain record and `MAINNET_LEDGER.md` row from a receipt |
| `workflows` | the workflow policy: SHA pins from the reviewed list, permissions, secrets, script injection |
| `defaults` | the `config/defaults.yaml` values the scripts read |

## Files

- `images.yaml`: build context per image directory (`dir` or `root`), reproducibility exceptions, built images
  nothing else references (`extra`: the key broker), and `never_mirror` (Twenty, D-049). A `build:` source
  without an entry fails, so an image cannot be skipped silently.
- `extra-images.json`: digests of the `extra` images (same shape as `runtime-images.json`).
- `runtime-waivers.yaml`: Grype waivers for sidecar and extra images.

## Release assets (D-046)

`<release_asset_base>/<appId>-v<tagVersion>/` holds `<appId>-<version>.bundle.tar` and, next to it, `.sig`,
`.crt`, `.sigstore.json` and `.intoto.jsonl`; `sbom.<image>.spdx.json` and `scan.<image>.json` (GitHub
release assets cannot contain `/`; inside the bundle they are `sbom/<image>.spdx.json` and `scan/<image>.json`);
and `<appId>-<version>.release.json`. `tagVersion` is the version without one leading `v` or `V` that a digit
follows (composer `TagVersion`, since composer 1.4.0), so the tag's `v` is never doubled: coding-agent `v1.58.2`
is released as `coding-agent-v1.58.2` with `coding-agent-v1.58.2.bundle.tar`, and needs no `release_version`.
Asset names and releaseId keep the version as it is. A version may not contain `+` (GitHub renames such
assets) or start with `v` before anything but a digit (`vnext` would be tagged `<appId>-vvnext`). `1.2.3` and
`v1.2.3` share the tag `<appId>-v1.2.3`, so once one is released, pr-check refuses the other ("already
released").

## Waivers (`catalog/apps/<id>/waivers.yaml`)

```yaml
version: 1
waivers:
  - id: CVE-2026-12345      # or GHSA-..., matched against the finding and its related ids
    image: <manifest images[].name>
    package: <package name>
    reason: why it does not apply or what blocks the fix
    expires: 2026-12-31     # applies through this day (UTC), at most 90 days ahead
```

A bare list of the same entries is still accepted (`waivers lint` warns).

## Tests

`go test ./catalog/tools/release/` runs the unit tests, the scripts against fake `crane`, `docker`, `syft`,
`grype`, `cosign`, `gh` and `curl`, the publishRelease and registerApp scripts against a local Tempo node
(`anvil --network tempo`) with the real contracts, and `catalog.yml`, `images.yml` and `release.yml` in a
small Actions emulator (their real `run:` scripts, emulated actions). The chain tests need anvil, forge, cast,
jq and `contracts/dependencies` (`make -C contracts deps`); `SEALED_REQUIRE_ANVIL=1` makes them fail instead
of skipping.
