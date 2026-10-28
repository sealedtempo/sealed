# verifier

Library and service that check a Sealed deployment end to end (spec 8.4 and 8.5, INTERFACES.md sections 2, 3, 6,
8, 9 and 15). Used by `sealed verify`, the key broker and the platform oracle (through `sealed-verifierd`).

| package | path | what it does |
|---|---|---|
| `attest` | `verifier/attest` | TDX quote v4/v5 parsing, Intel PCS verification with a caching collateral getter and our TCB policy, dstack RTMR3 replay with the exact event sequence, report_data builders, measurementsHash, dev simulator quotes |
| `chain` | `verifier/chain` | read-only Tempo client (eth_call only) for PlatformRegistry, AppRegistry, DeploymentRegistry |
| `verify` | `verifier` | `VerifyEvidence` and `VerifyLive` producing a `Report{OK, Simulated, Checks[]}`, text and JSON |
| `httpapi` | `verifier/httpapi` | HTTP handlers of sealed-verifierd |
| | `verifier/cmd/sealed-verifierd` | the daemon |

## Checks

Every report lists one entry per check; a check whose inputs are missing fails with the reason (fail closed).

| check | passes when |
|---|---|
| `bundle` | the evidence bundle or /attest response has every field, with the right schema and sizes |
| `chain` | RPC chain id = bundle chainId = config.chainId (= the configured chain); bundle and config registry addresses equal the verifier's |
| `quote_hash` | sha256(quote) = quoteHash |
| `quote` | signature, PCK chain to the Intel root, QE report, collateral signatures and expiry, PCK and root CRLs, then TCB status in `tcb_policy.allowed_statuses`; a simulated quote passes only on a dev verifier and sets `simulated: true` |
| `td_attributes` | TD_ATTRIBUTES has neither DEBUG nor MIGRATABLE |
| `image_measurements` | keccak256(mrtd, rtmr0, rtmr1, rtmr2) = PlatformRegistry.getImage(imageId).measurementsHash |
| `image_approved` | isApprovedImage(imageId) and the image is not a debug image |
| `event_log_hash` | sha256(CJSON(eventLog)) = eventLogHash |
| `rtmr3` | the event log replays to the quote's RTMR3 with exactly the INTERFACES section 6 sequence |
| `compose_hash` | compose-hash event = sha256(appCompose) = stackHash |
| `config_hash` | sha256(CJSON(config)) = configHash |
| `config_binding` | bundle customer, imageId, chainId and releaseIds equal the config's; config.apps sorted |
| `deployment_id` | keccak256(abi.encode(customer, stackHash, salt)) = deploymentId |
| `report_data` | quote report_data = the evidence (or live attest) construction |
| `freshness` | evidence: attestedAt within the requested age; live: our nonce is bound |
| `releases_active` | each release exists, isActiveRelease, and belongs to the app named in config.apps |
| `stack_recompute` | the composer recomputes appCompose byte for byte from the config and the onchain releases |
| `stack_approved` | DeploymentRegistry.isStackApproved(customer, stackHash) |
| `approval_releases` | getStackApproval names exactly the config's releases and image (D-014) |
| `onchain_record` | getDeployment is Active and its customer, stackHash, imageId, configHash, enclaveSigner (and in evidence mode quoteHash and eventLogHash) match |
| `expected_customer` | only when requested: config.customer is the expected owner |
| `live_fetch`, `tls_binding` | live only: /attest fetched over TLS; tlsPubKeyHash = sha256(SPKI of the certificate served on that connection) |

## sealed-verifierd HTTP API

Verification answers are HTTP 200 with the report; check `ok`. Add `?format=text` for the readable report.
400 means the request itself was unusable.

- `POST /v1/verify/evidence`: an evidence bundle, or `{"bundle": {...}, "options": {...}}`.
- `POST /v1/verify/live`: `{"url": "https://attest.<ip>.sslip.io/attest", "options": {...}}`.
- `POST /v1/compose`: `{"config": {...}}` or a bare config, returns `{appCompose, stackHash, configHash, deploymentId}`. 501 until runtime/composer is wired in `cmd/sealed-verifierd/composer.go`.
- `GET /healthz`: `{ok, chainId, allowSimulated, composer}`.

Options: `requireRecord` (default true; the oracle sends false before it registers), `maxEvidenceAgeSeconds`
(the oracle sends 900), `deploymentId`, `expectedCustomer` (the payer sends the operator for the relay).

Configuration: `--tempo-rpc` (TEMPO_RPC_URL), `--chain-id` (TEMPO_CHAIN_ID, default 4217), `--deployments`
(contracts/deployments/<network>.json) or `--platform-registry/--app-registry/--deployment-registry`,
`--defaults` (config/defaults.yaml, for tcb_policy), `--collateral-cache-dir`, `--collateral-ttl` (1h).
`--dev-allow-simulated` and `--dev-insecure-live-tls` refuse to start unless `SEALED_DEV_SIM=1`.

Egress: the daemon needs `api.trustedservices.intel.com:443`, `certificates.trustedservices.intel.com:443`, the
Tempo RPC and, for live checks, the attest hosts.

## Tests

`make -C verifier test` (or `go test ./verifier/...`). The anvil tests start `anvil --network tempo`, build the
contracts with forge into `tmp/` (sources from `<repo>/contracts` or `SEALED_CONTRACTS_DIR`) and skip when anvil or
forge is missing. `go test -short` skips them. Fixtures and their provenance: `attest/testdata/README.md`.
