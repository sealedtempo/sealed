# verifier

Library and service that check a Sealed deployment end to end (spec 8.4 and 8.5, INTERFACES.md sections 2, 3, 6,
8, 9 and 15). Used by `sealed verify`, the key broker and the platform oracle (through `sealed-verifierd`).

| package | path | what it does |
|---|---|---|
| `attest` | `verifier/attest` | TDX quote v4/v5 parsing, Intel PCS verification with a caching collateral getter and our TCB policy, dstack RTMR3 replay with the exact event sequence, report_data builders, measurementsHash, dev simulator quotes |
| `chain` | `verifier/chain` | read-only Tempo client (eth_call, eth_chainId, eth_blockNumber) for PlatformRegistry, AppRegistry, DeploymentRegistry; reads pinned to one block; RPC URL redacted from errors; the embedded `contracts/deployments/tempo-mainnet.json` as the default addresses (`chain.Mainnet`, `chain.DefaultAddresses`) |
| `bundles` | `verifier/bundles` | release bundles for stack recomputation: the D-046 asset URL rule, download with mirrors, sha256 check against the onchain bundleHash, content-addressed cache (memory and disk), and `Composer`, the `verify.Composer` that runs runtime/composer on verified bundles |
| `verify` | `verifier` | `VerifyEvidence`, `VerifyLive` and `VerifyLiveSubmission` producing a `Report{OK, Simulated, BlockNumber, Checks[]}`, text and JSON |
| `httpapi` | `verifier/httpapi` | HTTP handlers of sealed-verifierd |
| | `verifier/cmd/sealed-verifierd` | the daemon |

## Checks

Every report lists one entry per check; a check whose inputs are missing fails with the reason (fail closed).
All chain reads of one verification run against the block in `blockNumber`. JSON inputs (bundle, config, event
log, /attest) must use case-sensitive, unique keys: a key that differs from a known field only by case, or two
keys equal under case folding, are refused.

| check | passes when |
|---|---|
| `bundle` | the evidence bundle or /attest response has every field, with the right schema and sizes |
| `chain` | RPC chain id = bundle chainId = config.chainId (= the configured chain); bundle and config registry addresses equal the verifier's |
| `quote_hash` | sha256(quote) = quoteHash |
| `quote` | exactly the signed quote (no trailing bytes), signature, PCK chain to the Intel root, QE report, collateral signatures and expiry, PCK and root CRLs; then the platform TCB level (PCK CPUSVN components, PCESVN, TDX components), the TDX module identity level (when TEE_TCB_SVN[1] > 0) and the QE level are matched, converged as Intel QVL does (an OutOfDate module makes the result OutOfDate, otherwise the platform wins), and the result and each level must be in `tcb_policy.allowed_statuses` with the union of advisories in `allowed_advisory_ids` (when set); a simulated quote passes only on a dev verifier and sets `simulated: true` |
| `td_attributes` | TD_ATTRIBUTES: no TUD bit (DEBUG and reserved debug bits), not MIGRATABLE, SEPT_VE_DISABLE set, no reserved bit (LASS, PKS, KL and PERFMON allowed) |
| `image_measurements` | keccak256(mrtd, rtmr0, rtmr1, rtmr2) = PlatformRegistry.getImage(imageId).measurementsHash |
| `image_approved` | isApprovedImage(imageId) and the image is not a debug image |
| `event_log_hash` | sha256(CJSON(eventLog)) = eventLogHash |
| `rtmr3` | the event log replays to the quote's RTMR3 with exactly the INTERFACES section 6 sequence |
| `compose_hash` | compose-hash event = sha256(appCompose) = stackHash |
| `config_hash` | sha256(CJSON(config)) = configHash |
| `config_binding` | bundle customer, imageId, chainId and releaseIds equal the config's; config.apps sorted |
| `deployment_id` | keccak256(abi.encode(customer, stackHash, salt)) = deploymentId (evidence), and = the requested `deploymentId` when one is given (evidence and live) |
| `report_data` | quote report_data = the evidence construction `sha256("sealed/evidence/v1" \|\| stackHash \|\| configHash \|\| enclaveSigner \|\| nonce2 \|\| uint64be(attestedAt))` then 32 zero bytes (D-047), or the live attest construction |
| `freshness` | evidence: attestedAt within the requested age and at most 5 minutes in the future (attestedAt is bound in report_data, so this holds before registration too); live: our nonce is bound |
| `releases_active` | each release exists, isActiveRelease, and belongs to the app named in config.apps |
| `stack_recompute` | each onchain release belongs to its config.apps entry (keccak256(slug) = appId, releaseId derives from appId, version and bundleHash); its bundle, fetched from `<release_asset_base>/<app>-v<version>/<app>-<version>.bundle.tar` (or the cache), hashes to the onchain bundleHash and its manifest names the same app and version; runtime/composer then recomputes appCompose byte for byte from the config and those bundles |
| `stack_approved` | DeploymentRegistry.isStackApproved(customer, stackHash) |
| `approval_releases` | getStackApproval names exactly the config's releases and image (D-014) |
| `onchain_record` | getDeployment is Active and its customer, stackHash, imageId, configHash, enclaveSigner match; in evidence mode also eventLogHash, quoteHash and attestedAt = lastAttestedAt; with `heartbeat`, the record must exist and the bundle must carry a new quote with attestedAt after lastAttestedAt |
| `expected_customer` | only when requested: config.customer is the expected owner |
| `expected_apps` | only when requested: every expected app id is among config.apps |
| `live_fetch`, `tls_binding` | live only: /attest fetched over TLS from an allowed public host; tlsPubKeyHash = sha256(SPKI of the certificate served on that connection). For a caller-fetched attestation (`live_submitted`), the nonce and SPKI hash are the caller's |

## sealed-verifierd HTTP API

Verification answers are HTTP 200 with the report; check `ok`. Add `?format=text` for the readable report
(control characters in details are escaped). 400 means the request itself was unusable; 429 (with
`Retry-After`) that `--max-in-flight` verifications are already running.

- `POST /v1/verify/evidence`: an evidence bundle, or `{"bundle": {...}, "options": {...}}`.
- `POST /v1/verify/live`: `{"url": "https://attest.<ip>.sslip.io/attest", "options": {...}}`. The daemon fetches
  with a fresh nonce, refuses non-public destinations after DNS resolution (unless through `HTTPS_PROXY`) and,
  with `--live-allowed-hosts`, any other host. Or a caller-fetched attestation (sealed-mpp-payer):
  `{"attestUrl", "nonce", "attest": {GET /attest document}, "observedTlsPubKeyHash", "expectedCustomer",
  "expectedAppIds", "options"}`; the report mode is `live_submitted` and freshness is relative to the caller's nonce.
- `POST /v1/compose`: `{"config": {...}}` or a bare config, returns `{appCompose, stackHash, configHash, deploymentId}`
  plus `unbuilt` (images still at the all-zero digest; such a stack cannot boot and must not be approved) when not
  empty. The releases are read from AppRegistry at one block and their bundles fetched as for `stack_recompute`.
  422 for a config or release that does not compose, 503 (with `Retry-After`) when a bundle cannot be fetched.
- `GET /healthz`: `{ok, chainId, allowSimulated, composer}`.

Options: `requireRecord` (default true; the oracle sends false before it registers), `maxEvidenceAgeSeconds`
(the oracle sends 900), `heartbeat` (the oracle sends true for heartbeat evidence), `deploymentId` (evidence and
live), `expectedCustomer` (the payer sends the operator for the relay), `expectedAppIds`.

Configuration: `--tempo-rpc` (TEMPO_RPC_URL), `--chain-id` (TEMPO_CHAIN_ID, default 4217), `--listen`
(SEALED_VERIFIERD_LISTEN, else `:$PORT`, else `:8088`). Registry addresses, first match: `--deployments`
(contracts/deployments/<network>.json), `--stack-config` (SEALED_CONFIG_FILE, the stack's public config, which also
gives the chain id and `endpoints.tempoRpc` when those are not set), the embedded
`contracts/deployments/tempo-mainnet.json` on chain 4217; `--platform-registry/--app-registry/--deployment-registry`
and `--fee-splitter` override single addresses. When the FeeSplitter is known, `config.contracts.feeSplitter` must
equal it. Bundles: `--release-asset-base` (SEALED_RELEASE_ASSET_BASE, comma-separated, the catalog's first and
mirrors after; default `catalog.release_asset_base` of `--defaults`, else
`https://github.com/sealedtempo/sealed/releases/download`; https only unless `SEALED_DEV_SIM=1`) and
`--bundle-cache-dir` (SEALED_BUNDLE_CACHE_DIR; memory only when unset). Also
`--defaults` (config/defaults.yaml, for tcb_policy and release_asset_base), `--collateral-cache-dir`, `--collateral-ttl` (1h),
`--live-allowed-hosts` (SEALED_VERIFIERD_LIVE_HOSTS, for example `*.sslip.io,relay.example.com`),
`--max-in-flight` (SEALED_VERIFIERD_MAX_IN_FLIGHT, default 8). `--dev-allow-simulated`, `--dev-insecure-live-tls`
and `--dev-live-allow-private` refuse to start unless `SEALED_DEV_SIM=1`. The RPC URL is logged and reported as
scheme and host only (provider keys in the path or query never appear).

Egress: the daemon needs `api.trustedservices.intel.com:443`, `certificates.trustedservices.intel.com:443`, the
Tempo RPC, the release asset hosts (`github.com:443` and `release-assets.githubusercontent.com:443`, where GitHub
redirects asset downloads, observed 2026-10-28) and, for live checks, the attest hosts.

Library use (`sealed verify`, the key broker): `src, _ := bundles.NewSource(bases, cacheDir)`, then
`verify.Deps{..., Composer: &bundles.Composer{Source: src}}`. `errors.Is(err, bundles.ErrHashMismatch)` marks bytes that
do not hash to the onchain bundleHash, `bundles.ErrUnavailable` a bundle no base could serve and
`bundles.ErrReleaseMismatch` a release that does not belong to its config entry or bundle.

## Tests

`make -C verifier test` (or `go test ./verifier/...`). The anvil tests start `anvil --network tempo`, build the
contracts with forge into `tmp/` (sources from `<repo>/contracts` or `SEALED_CONTRACTS_DIR`) and skip when anvil,
forge or the contracts are missing; CI sets `SEALED_REQUIRE_ANVIL=1` (`make -C verifier test-ci`) so they fail
instead. `go test -short` skips them. A test fails when `chain/abi` or `chain/deployments/tempo-mainnet.json` is not a
byte copy of `contracts/abi` and `contracts/deployments` (`make -C verifier abi` refreshes both). Fixtures and their
provenance: `attest/testdata/README.md`.

`cmd/sealed-verifierd` `TestComposedStackEndToEnd` is the full path: real bundles built from
`runtime/composer/testdata/apps` served like a GitHub release, the real contracts on anvil, `/v1/compose`, the
customer's approval, the dev simulator's quote and event log for that app-compose, the oracle's registration, a
passing evidence bundle, then evidence, release asset, cache and chain tamper cases that each fail exactly the
expected checks.

Quote producers send exactly the signed quote: bytes after the signature data are unsigned, so they are refused
(they would make quoteHash malleable). `attest.TrimQuote` strips the zero padding of fixed-size quote buffers.
