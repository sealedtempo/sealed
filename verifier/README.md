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
| `chain` | RPC chain id = bundle chainId = config.chainId = the configured chain (4217 when none is configured); bundle and config registry addresses equal the verifier's; every read is pinned to the head block, whose timestamp is at most `MaxChainHeadAge` (default 60 s, at most 300 s) old and not that far in the future, so a stale or lagging RPC cannot hide a revocation (D-060). The data always carries `blockNumber`, `headTimestamp`, `headLagSeconds` and `maxHeadLagSeconds`; a stale head fails with `reason: "chain_stale"`. A chain reader that cannot pin a block or read its timestamp fails this check |
| `quote_hash` | sha256(quote) = quoteHash |
| `quote` | exactly the signed quote (no trailing bytes), signature, PCK chain to the Intel root, QE report, collateral signatures and expiry, PCK and root CRLs; then the platform TCB level (PCK CPUSVN components, PCESVN, TDX components), the TDX module identity level (when TEE_TCB_SVN[1] > 0) and the QE level are matched, converged as Intel QVL does (an OutOfDate module makes the result OutOfDate, otherwise the platform wins), and the result and each level must be in `tcb_policy.allowed_statuses` with the union of advisories in `allowed_advisory_ids` (when set); a simulated quote sets `simulated: true` and passes only on a dev verifier (`AllowSimulated`) for a verification that opts in (`Options.AcceptSimulated`), so `ok` is never true for a simulated quote a caller did not ask for |
| `td_attributes` | TD_ATTRIBUTES: no TUD bit (DEBUG and reserved debug bits), not MIGRATABLE, SEPT_VE_DISABLE set, no reserved bit (LASS, PKS, KL and PERFMON allowed) |
| `image_measurements` | keccak256(mrtd, rtmr0, rtmr1, rtmr2) = PlatformRegistry.getImage(imageId).measurementsHash |
| `image_approved` | isApprovedImage(imageId) and the image is not a debug image |
| `event_log_hash` | sha256(CJSON(eventLog)) = eventLogHash |
| `rtmr3` | every event's digest is 96 lowercase hex characters and its payload lowercase hex (dstack's spelling, so a quote admits fewer event logs); the log replays to the quote's RTMR3 with exactly the INTERFACES section 6 sequence |
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
| `live_fetch`, `tls_binding` | live only: the URL is exactly `https://<host>/attest` (port 443 unless the dev private-address flag is set; no credentials, query or fragment: the verifier sends only its own `?nonce=`), the host is allowed, the destination public, no redirect; tlsPubKeyHash = sha256(SPKI of the certificate served on that connection). For a caller-fetched attestation (`live_submitted`), the nonce and SPKI hash are the caller's |

Besides the checks, a report carries `config` when the config parsed: what the customer approved beyond the hash
(`debug`, `endpoints` with the key broker that releases the disk key and secrets, `egressAdditions`,
`allowedVpcRanges`, `relayOwner`). URLs are shown without credentials, query or fragment, the Tempo RPC as scheme
and host only. The text report prints the key broker, the relay, every egress addition and a note when debug
logging is on.

## sealed-verifierd HTTP API

Verification answers are HTTP 200 with the report; check `ok`. Add `?format=text` for the readable report
(control characters in details are escaped). 400 means the request itself was unusable; 403 that the caller's
address is not in `--allowed-clients`, or that URL fetches are off (`--live-fetch=false`); 429 (with
`Retry-After`) that `--max-in-flight` verifications are already running.

- `POST /v1/verify/evidence`: an evidence bundle, or `{"bundle": {...}, "options": {...}}`.
- `POST /v1/verify/live`: `{"url": "https://attest.<ip>.sslip.io/attest", "options": {...}}`. The daemon fetches
  with a fresh nonce, only that exact path, refuses non-public destinations after DNS resolution (unless through
  `HTTPS_PROXY`) and, with `--live-allowed-hosts`, any other host. A daemon with `--live-fetch=false` (the default
  of the in-VM sidecar) answers 403 to this form. Or a caller-fetched attestation (sealed-mpp-payer):
  `{"attestUrl", "nonce", "attest": {GET /attest document}, "observedTlsPubKeyHash", "expectedCustomer",
  "expectedAppIds", "options"}`; the report mode is `live_submitted` and freshness is relative to the caller's nonce.
- `POST /v1/compose`: `{"config": {...}}` or a bare config, returns `{appCompose, stackHash, configHash, deploymentId}`
  plus `unbuilt` (images still at the all-zero digest; such a stack cannot boot and must not be approved) when not
  empty. The releases are read from AppRegistry at one block and their bundles fetched as for `stack_recompute`.
  422 for a config or release that does not compose, 503 (with `Retry-After`) when a bundle cannot be fetched.
- `GET /healthz`: `{ok, chainId, allowSimulated, composer, liveFetch}`.

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
`--max-in-flight` (SEALED_VERIFIERD_MAX_IN_FLIGHT, default 8), `--max-chain-head-age`
(SEALED_VERIFIERD_MAX_CHAIN_HEAD_AGE, default 60s, at most 5m, D-060). `--dev-allow-simulated`,
`--dev-insecure-live-tls` and `--dev-live-allow-private` refuse to start unless `SEALED_DEV_SIM=1`; a daemon started
with `--dev-allow-simulated` opts every request in to simulated quotes, and every such report says
`simulated: true` (its consumers, the payer and the oracle, refuse those outside dev mode). The RPC URL is logged
and reported as scheme and host only (provider keys in the path or query never appear).

Lockdown (D-061, review V-1). `--allowed-clients` (SEALED_VERIFIERD_ALLOWED_CLIENTS) is a comma-separated list of
source IP addresses or CIDR prefixes; when set, every other source gets 403 before its body is read. The TCP peer
address counts, never a forwarded header; loopback may also read `/healthz`. `--live-fetch`
(SEALED_VERIFIERD_LIVE_FETCH, true or false) lets `POST /v1/verify/live` fetch a caller's URL; it defaults to false
when the daemon runs as a stack sidecar (`--stack-config` or SEALED_CONFIG_FILE) and true otherwise. In a stack the
composer sets `SEALED_VERIFIERD_ALLOWED_CLIENTS` to sealed-mpp-payer's address, the only caller, which submits the
attestation it fetched itself; the daemon warns at startup when a sidecar runs without an allowlist.

Egress: the daemon needs `api.trustedservices.intel.com:443`, `certificates.trustedservices.intel.com:443`, the
Tempo RPC, the release asset hosts (`github.com:443`, plus `objects.githubusercontent.com:443` and
`release-assets.githubusercontent.com:443`, where GitHub redirects asset downloads; D-061) and, outside a stack,
the attest hosts for URL-form live checks. Bundle downloads follow at most 10 redirects and never from https to
another scheme.

Keeping bundles for P7: re-verification recomputes the stack from the release bundles, which the platform hosts as
GitHub release assets (hash-checked, so a mirror cannot change them). A customer who wants to verify after the
platform is gone keeps a copy: run with `--bundle-cache-dir` (every verified bundle is stored there by bundleHash)
or list a mirror of their own in `--release-asset-base`.

Library use (`sealed verify`, the key broker): `src, _ := bundles.NewSource(bases, cacheDir)`, then
`verify.Deps{..., Composer: &bundles.Composer{Source: src}}`. `Options.ChainID` defaults to 4217,
`Options.MaxChainHeadAge` to 60 s (capped at 300 s), and a simulated quote needs both a quote verifier with
`AllowSimulated` and `Options.AcceptSimulated`. The chain reader must be pinnable and report block times
(`*chain.Client` does, through `eth_getBlockByNumber` without transactions); an in-memory reader in a test or a
tool gets a head with `verify.WithHead(reader, number, clock)`. `errors.Is(err, bundles.ErrHashMismatch)` marks bytes that
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
