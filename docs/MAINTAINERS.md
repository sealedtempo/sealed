# Maintaining a Sealed catalog app

Every app is built from public source, pinned, scanned, signed and reviewed. You can verify that exactly that build is what runs. This guide is for the people who package those apps: how to submit one, what it must meet, how review and releases work, and how maintainers are paid.

Limits: confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access. Packaging cannot make an app safe; it makes what runs exact, reviewable and verifiable.

## How an app gets into a customer's VM

1. You open a pull request that adds or changes `catalog/apps/<id>/`.
2. CI validates the manifest, lints licenses, digests, telemetry switches, egress and secrets, builds an SBOM per image with Syft, scans it with Grype, and composes the app into a stack.
3. Reviewers approve it. For a new app, the operator registers it onchain with `AppRegistry.registerApp` from the OWNER key, run by hand, never from CI.
4. On merge, the release job mirrors your images to `ghcr.io/sealedtempo` with identical digests, builds the deterministic bundle, signs it with cosign keyless (Rekor), adds SLSA provenance, uploads a GitHub Release and calls `AppRegistry.publishRelease`.
5. A customer selects the app, approves the resulting stack with their wallet, and the key broker in their project releases secrets only to that exact stack. Every usage fee of your app pays you a share in USDC.e on Tempo.

## The app directory

```
catalog/apps/<id>/
  manifest.yaml            what the app is, its images, routes, secrets, metering (schema sealed-manifest/v1)
  compose.fragment.yaml    docker compose services and volumes, under the fragment rules below
  egress.yaml              the destinations the app may reach
  README.md                what it does, how it is configured, how to test it
  LICENSE-NOTICE           upstream license, source link, and the license of every component shipped in the images
  LICENSES/                optional: full license texts (bundled with LICENSE-NOTICE)
  waivers.yaml             accepted scanner findings with an expiry (often empty)
  images/<dir>/            optional: Dockerfiles for images built by the runtime image workflow
```

The bundle contains exactly `manifest.yaml`, `compose.fragment.yaml`, `egress.yaml`, `LICENSES/` (your `LICENSE-NOTICE` plus `LICENSES/`), `sbom/<image>.spdx.json` and `scan/<image>.json`. Tests, fixtures and image sources stay in the repository. Use the existing apps as templates: `scraper` (first-party, small), `llm-gateway` (bearer passthrough, callbacks), `crm` and `internal-tools` (bootstrap jobs, databases), `coding-agent` (`same_as` secrets).

## Requirements

### Manifest

Required fields: `schema`, `id`, `name`, `category`, `description`, `upstream {repo, version, license_spdx, source_url}`, `maintainer {name, payout_address}`, `maintainer_share_bps`, `compose_fragment: compose.fragment.yaml`, `egress_policy: egress.yaml`, `primary_service`, `images`, `resources {cpu, memory_gb, disk_gb}`, `routes`, `healthcheck`, `metering {unit, source}`, `secrets`, `telemetry_off_env`, `license_exclusions`. Optional: `release_version`, `telemetry_none_reason`, `license_exceptions`, `bootstrap`, `notes`. The schema is `catalog/schema/manifest.schema.json`; the composer validates it strictly.

- `id`: lowercase slug; `appId = keccak256(id)`. Reserved: `sealed`, `sealed-*`, `caddy`, `gate`, `localhost`.
- `release_version`: the version hashed into releaseId, default `upstream.version`. Bump it when only the packaging changes (for example `2.1.0-sealed.2`). It must match `^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$` (no `+`), because GitHub renames release assets with other characters. A version is used literally in the release tag (`<id>-v<version>`), so a version that already starts with `v` gives `<id>-vv...`.
- `maintainer.payout_address`: your Tempo address, or `${MAINTAINER_DEFAULT_ADDRESS}` for seed apps. The onchain value registered at `registerApp` is what pays; see Payouts.
- `maintainer_share_bps`: 2000 (20%) is the platform default. The contract allows at most 5000.

### Licenses (rule 9, D-021, D-050)

- Allowed for anything: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, LGPL, GPL-3.0, AGPL-3.0, plus PostgreSQL, Zlib, 0BSD, Unlicense, CC0-1.0, PSF-2.0, Python-2.0, BSL-1.0 (Boost), BlueOak-1.0.0, ZPL-2.1 and CNRI-Python. GPL-2.0-or-later counts as allowed.
- OS distribution packages only (Debian, Alpine and similar packages, including ones you add with apt or apk in your own layers): GPL-2.0-only and the other OSI-approved distribution licenses, plus X11, BSD-4-Clause, OpenSSL, curl, IJG, Libpng, libtiff, FTL, bzip2, GFDL, Ruby and Vim.
- Data-only packages on the reviewed list (today `caniuse-lite`): CC-BY-4.0.
- Never: SSPL, BUSL or BSL-1.1 (Business Source), FSL, Elastic License, Sustainable Use License, Commons Clause, RSAL, proprietary, and any enterprise directory or enterprise-licensed code of an open-core project. Expressions follow SPDX semantics: `OR` takes the best alternative (record the election), `AND` the worst.
- `license_exclusions`: paths that are never shipped (for example an upstream's `enterprise/` tree, `litellm_enterprise`, Playwright's Chromium). Lint requires them for known open-core upstreams and fails when an SBOM package or file matches one.
- `license_exceptions: [{decision, paths, reason}]` exists for exceptional cases, but lint accepts only decision ids listed in `runtime/composer/lint/exceptions.go`, which is empty. An exception needs a recorded decision first.
- `LICENSE-NOTICE` names the upstream license and a source link for every component in your images. For AGPL and GPL apps it is how customers get the corresponding source. Images whose official build carries files under a license that forbids redistribution cannot be mirrored (D-049): build a clean image from source instead.

### Images and digests

- Each `images[]` entry has `name`, `source` (the upstream reference with its tag, or `build:images/<dir>` for an image the runtime image workflow builds from your Dockerfile), `digest` (`sha256:...`), `platform: linux/amd64` and `license_spdx`. Pin either the multi-arch index digest or the linux/amd64 manifest digest, and say in a comment which one it is and what the other is (`crane digest <ref>` and `crane digest --platform linux/amd64 <ref>`).
- Fragments reference images only as `{{image:<name>}}`. Tags and literal references are rejected. The composer resolves each to `ghcr.io/sealedtempo/<name>@<digest>`; VMs pull only from the catalog registry.
- Images built here start with the all-zero digest; the image workflow builds them and opens a pull request that pins the digest (D-028). Lint reports `unbuilt-image` and a release is blocked until then.
- Flatten derived images so removed files are really gone, and pin every `FROM` by digest.

### Telemetry

- `telemetry_off_env` sets every switch that turns off telemetry, usage analytics, update checks and crash reporting (for example `DO_NOT_TRACK: "1"`). The composer adds it to every service of the app.
- An app with no switches needs `telemetry_none_reason` of at least 20 characters explaining why.
- Names the composer owns (proxy variables, `NODE_USE_ENV_PROXY`, `SEALED_PUBLIC_URL_*`) cannot be set.
- Anything that still tries to phone home is stopped by sealed-egress and shows up as blocked counts, which reviewers look at.

### Egress

```yaml
version: 1
default_allow: ["api.example.com:443"]
customer_additions_allowed: true
notes: >-
  Why each entry exists.
```

- Entries are `host:port` or `*.domain:port` (one label, never over a public suffix), at most 256. IPv4 literals must be public unicast. Everything not listed is blocked, DNS included.
- `customer_additions_allowed: false` stops customers from adding destinations for this app.
- Explain every entry in `notes`. Prefer no default destinations: the scraper ships with none, and customers add the sites they want.
- Every container gets `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` and uses sealed-egress as its DNS server. An app that ignores proxy variables simply cannot reach the internet; that is intended.

### Fragment rules

The full contract is [runtime/composer/README.md](../runtime/composer/README.md); the composer rejects anything else and names the field.

- Top level: `services`, `volumes` and `x-*` anchors only.
- Service names start with `<id>-`, are lowercase DNS labels of at most 57 characters, and contain no `--`.
- Allowed service keys: `image`, `command`, `entrypoint`, `environment`, `healthcheck`, `depends_on`, `volumes`, `tmpfs`, `user`, `working_dir`, `read_only`, `stop_grace_period`, `shm_size`, `ulimits`, `mem_limit`, `cpus`, `labels`, `x-sealed-secrets`. So no `privileged`, `cap_add`, `devices`, `network_mode`, `networks`, `ports`, `pid`, `ipc`, `security_opt`, `build`, `env_file`, `secrets`, `configs`, `extra_hosts`, `dns` or bind mounts.
- `entrypoint` is required on every service, as a list, because every service runs through envexec; declare `command` too if the image relies on it.
- `environment` holds public values only. No host passthrough (`KEY` without a value), no secret names, and no `$NAME` or `${...}` interpolation (`$$` is a literal `$`): the compose must not read unmeasured host environment.
- Volumes: named volumes of the app only, which become directories on the encrypted data disk, or `tmpfs`. Top-level volumes may declare `x-sealed-owner: "<uid>:<gid>"`; the agent creates the directory with that owner.
- `depends_on` only within the app. `cpus` as an integer or a quoted decimal: floats are not allowed in hashed documents.
- Networks are assigned by the composer (D-041): every service is on the app's own internal network, and only `primary_service` is also on the shared `apps` network with the alias `<id>`. Other apps can reach your primary service only; your database and workers are private to your app.

### Routes and the gate

- `routes[].service` must be the `primary_service`. Route names are a fixed set today (`gateway`, `scraper`, `crm`, `code`, `tools`, `relay`); a new app with a UI needs a new route name, which is a schema and composer change: ask for it in the pull request.
- `auth: gate` for every app UI: Caddy asks sealed-agent's password gate before every request (D-044). Only llm-gateway's `gateway` route may use `bearer-passthrough` and only inference-relay's `relay` route may be `public`.
- With the gate's cookie, your app's own `Authorization` header passes through untouched, so apps with their own logins and API tokens keep working.
- Every service of the app gets `SEALED_PUBLIC_URL_<ROUTE>=https://<host>` for the routes it owns.

### Secrets

- List every secret in `secrets` with `name`, `description` and `generate` (`none`, `hex32`, `base64-32`, `sk-hex32`, `password`), and `optional: true` where it is. Customers store them with `sealed secrets set`, which can generate them.
- A service that needs secrets lists them in `x-sealed-secrets` and gets exactly those files, read-only, at `/run/sealed/secrets/<id>/<NAME>`; envexec exports them as environment variables. Never put a secret in `environment`.
- `same_as: "<other-app>/<NAME>"` (with `generate: none`) reuses another app's secret, for example a gateway key. The other app must be in the stack. Reviewers check every reference, because it gives your app that value.
- `GATE_PASSWORD_BCRYPT` is reserved.

### Bootstrap, health and metering

- `bootstrap {service, done_file}`: a one-shot job (first admin, closing sign-up) that restarts on failure. `done_file` is `<volume>/<path>` on the data disk; the gate keeps your routes closed with 503 `starting` until it exists, so no customer ever sees a half-configured app. Keep the directories on its path readable by others.
- `healthcheck {service, http, port}`: an HTTP path on the primary service. App-hour metering counts healthy time.
- `metering.unit`: `tokens` or `pages` with `source: callback` (post `{"app","unit","quantity","id"}` to `http://sealed-agent:7070/v1/usage-events` from your own services; the `id` dedupes retries), or `app_hour` with `source: heartbeat`. Only counts leave your app. Prices are platform configuration (`config/defaults.yaml`), not part of the manifest.

## Scanner findings and waivers

Grype fails the pull request on any critical finding that is not waived. A waiver is an entry in `waivers.yaml`:

```yaml
version: 1
waivers:
  - id: CVE-2026-12345          # or GHSA-xxxx-xxxx-xxxx, as Grype reports it
    image: postgres             # manifest images[].name
    package: example-package
    reason: why it does not apply here, or what blocks the fix
    expires: 2026-12-31         # required; the waiver stops applying after this day
```

A plain list is accepted too. Lint rejects waivers without an expiry or with one in the past, and reviewers reject waivers whose reason is not specific. Fix by bumping the image when you can.

## Check your package locally

```sh
go run ./runtime/composer/cmd/sealed-compose lint --app-dir catalog/apps/<id>
go run ./runtime/composer/cmd/sealed-compose lint --catalog catalog/apps            # cross-app rules: routes, same_as
syft <registry>/<image>@sha256:<digest> -o spdx-json=catalog/apps/<id>/sbom/<image>.spdx.json
grype sbom:catalog/apps/<id>/sbom/<image>.spdx.json --fail-on critical
go run ./runtime/composer/cmd/sealed-compose lint --app-dir catalog/apps/<id> --require-sbom   # release mode
go run ./runtime/composer/cmd/sealed-compose compose --config runtime/composer/testdata/config.json \
  --app-dir catalog/apps/<id> --fill-release-ids --print summary                   # adapt the config's apps list
sealed release build <id>                                                           # bundleHash, egressPolicyHash, sbomHash, releaseId
```

`--fill-release-ids` and `--allow-missing-sbom` are for local experiments only. `catalog/tools/catalog-lint.mjs` and `catalog/tools/catalog_lint.py` wrap the same lint for an app's own test suite. Add tests for your package next to it (see `catalog/apps/*/tests`), and keep them runnable without a Docker daemon where possible.

## Review

Once branch protection is on (planned before launch), every merge to main needs two approving reviews, a code owner's approval for anything under `catalog/`, and the required checks. Reviewers check:

- the upstream repository, version and source link, and that the images are built from that source;
- licenses, `license_exclusions`, and that no enterprise or commercial-licensed code ships or is enabled;
- every image digest, and the SBOM and scan results;
- every egress entry and its note, and whether customer additions should be allowed;
- secrets, `same_as` references and generators;
- telemetry switches, and blocked counts from a test run;
- the bootstrap job (sign-up closed, first admin created), healthcheck and metering;
- the README and tests.

A release that later proves harmful is revoked onchain with `revokeRelease`: every stack that contains it fails its next boot and `sealed verify`. `deprecateRelease` is softer: running stacks keep working, but new approvals cannot use it (D-013).

## Releases

- Any change to an app's packaging is a new release with a new `release_version`. AppRegistry rejects a version the app already used and a bundleHash it already published, even after a revocation (CR-5).
- Assets of a release, under the tag `<id>-v<version>`: `<id>-<version>.bundle.tar`, its `.sigstore.json` (cosign bundle), `.sig` and `.crt`, `.intoto.jsonl` (SLSA provenance), and `sbom.<image>.spdx.json` per image (D-046).
- `sealed release build <id>` packs your checkout into the deterministic bundle (sorted ustar, mtime 0, uid and gid 0, LF endings) and prints `bundleHash`, `egressPolicyHash`, `sbomHash` and `releaseId`, the exact `publishRelease` arguments. `sealed release build <id> --check <version|latest>` rebuilds a published release (with the SBOMs and scans from the published bundle, since CI generates them) and requires the result to equal the onchain bundleHash byte for byte. Anyone can run it.

## Payouts

- Every payment of your app's fees goes through `FeeSplitter.payFees` (or `topUpFees`), which credits `amount x maintainerShareBps / 10000`, rounded down, to the app's current maintainer, and the rest to the treasury. With the default share that is 20% of every fee, in USDC.e (`0x20c000000000000000000000b9537d11c60e8b50`, 6 decimals) on Tempo mainnet.
- Fees accrue per settlement interval (hourly by default) from every deployment that runs your app: per token for llm-gateway, per page for the scraper, per app-hour for crm, coding-agent and internal-tools (see `config/defaults.yaml`).
- Credits stay in FeeSplitter until you withdraw. Withdrawals pay the caller only and work even while the contract is paused.

```sh
RPC=https://rpc.tempo.xyz
APPS=0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43
FEES=0x3D288c0756c3F26Da0f41257D688bAB3dB3d94AD
USDCE=0x20c000000000000000000000b9537d11c60e8b50
cast call $APPS "payoutInfo(bytes32)(address,uint16)" $(cast keccak <id>) --rpc-url $RPC
cast call $FEES "credited(address,address)(uint256)" $USDCE <your address> --rpc-url $RPC
cast send $FEES "withdraw(address)" $USDCE --rpc-url $RPC --tempo.fee-token $USDCE --account <your keystore>
```

Tempo has no native gas token: network fees are paid in a USD stablecoin, so the sending wallet needs a little USDC.e and names it with `--tempo.fee-token`. The console's maintainer page shows the same balance and a withdraw button.

### Changing the payout address

The payout address is the app's `maintainer` in AppRegistry. The current maintainer (or the owner) changes it onchain:

```sh
cast send $APPS "setMaintainer(bytes32,address)" $(cast keccak <id>) <new address> \
  --rpc-url $RPC --tempo.fee-token $USDCE --account <current maintainer keystore>
```

- From then on every new credit goes to the new address. Credits already in FeeSplitter stay with the old address: withdraw them from the old address, before or after the change.
- Never set the maintainer to FeeSplitter or to a token address: a share owed to an address that could never withdraw goes to the treasury instead.
- Update `maintainer.payout_address` in the manifest in your next release so the catalog matches the chain. The onchain value is what pays.
- Your share itself is changed only by the owner (`setMaintainerShare`, at most 50%).
- If you lose the maintainer key, the owner can set a new maintainer after verifying who you are.
