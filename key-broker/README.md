# key-broker

The Sealed key broker (spec 5.7, INTERFACES.md section 9). It runs on Cloud Run in the customer's own project,
deployed by the customer's bootstrap, and releases the customer's secrets only to an attested confidential VM that
runs a stack the customer approved onchain. The platform has no access to it.

## API

| method | path | answer |
|---|---|---|
| GET | `/v1/nonce` | `{"nonce":"0x<32 bytes>","expiresAt":<unix>}`. Single use, 5 minute lifetime. |
| POST | `/v1/release` | 200 `{"stackHash","deploymentId","enc","ciphertext"}`; 403 `{"decision":"denied","reason","detail"}`; 429 and 503 with `Retry-After`; see below |
| GET | `/healthz` | `{"status":"ok"}` |

Request body (strict JSON: unknown, duplicate or differently cased keys are refused):
`{"nonce","ephemeralPub","quote","eventLog","config","appCompose","releaseIds","imageId"}`.

The ciphertext is HPKE base mode (RFC 9180) X25519 / HKDF-SHA256 / AES-256-GCM to `ephemeralPub`, with
`info = "sealed/kb-release/v1"` and `aad = nonce`. `enc` (32 bytes) and `ciphertext` (the bare AEAD output) are
separate fields. The plaintext is canonical JSON:
`{"diskKey":"0x..","secrets":{"<appId>":{"<NAME>":".."},"_gate":{"GATE_PASSWORD_BCRYPT":".."}},"signerSeed":"0x.."}`.
Every app of the stack has an entry (possibly empty).

## Checks, in order

Each request runs these and stops at the first failure. The answer names the reason; the decision log records
every check with its data.

| check | fails with |
|---|---|
| `nonce`: issued here, unused, unexpired (consumed before anything else, so every attempt burns it) | `bad_nonce` |
| `request`: well-formed, sizes bounded | `bad_request` (400) |
| `slot`: a release slot is free (taken only now, after the body was read and validated) | 429 `rate_limited` |
| `quote`: the PCK chain in the quote ends at the Intel SGX Root CA (checked before any collateral fetch) | `quote_invalid` |
| `quote`: TDX quote v4/v5 verified with Intel PCS collateral; no quote at all is refused | `quote_invalid`; 503 `unavailable` when PCS cannot serve collateral |
| `quote`: TCB status allowed (`UpToDate`, `SWHardeningNeeded` by default) | `tcb_status` |
| `report_data`: `sha256("sealed/kb-release/v1" \|\| nonce \|\| ephemeralPub) \|\| 32 zero bytes` | `report_data_mismatch` |
| `chain`: the RPC serves the configured chain, and its head block is at most 60 s from the broker's clock (D-060); every read below is pinned to that block | 503 `chain_stale` |
| `image`: `getImage(imageId)` exists | `image_not_approved` |
| `image`: `keccak256(mrtd \|\| rtmr0 \|\| rtmr1 \|\| rtmr2)` equals its measurementsHash; MRCONFIGID and MROWNERCONFIG are zero | `measurements_mismatch` |
| `image`: not a debug image, and the TD has no debug, migratable or reserved attribute bits | `image_debug` |
| `image`: `isApprovedImage(imageId)`, and in `--allowed-images` when that is set | `image_not_approved` |
| `rtmr3`: the event log replays to the quote's RTMR3 with exactly the Sealed event sequence | `rtmr3_replay` |
| `compose_hash`: the compose-hash event equals `sha256(appCompose)` | `compose_mismatch` |
| `customer`: the config parses for this composer version and `config.customer` is the bootstrap customer | `compose_mismatch`, `customer_mismatch` |
| `config_chain`: `config.chainId`, `config.contracts` (registries and feeSplitter) and `config.feeToken` name this broker's chain and contracts | `stack_not_approved` |
| `stack_recompute`: `releaseIds` equal `config.apps[].releaseId`, each release is published for that app | `compose_mismatch` |
| `stack_recompute`: each bundle, fetched by the release asset URL rule, has the onchain bundleHash | `bundle_hash_mismatch` |
| `stack_recompute`: the composer recomputes `appCompose` byte for byte | `compose_mismatch` |
| `stack_approved`: `DeploymentRegistry.isStackApproved(customer, stackHash)` | `stack_not_approved` |
| `approval_releases`: the approval's releaseIds equal the config's as a set, and its imageId equals `config.imageId` and the request's (D-014) | `stack_not_approved` |
| `secrets`: every secret the stack's manifests name is stored (optional ones may be missing) | 503 `secret_missing` / `secret_invalid` |
| `keys`: `diskKey` and `signerSeed` from the KMS HMAC key | 503 |
| `seal`: HPKE to `ephemeralPub` | `bad_request` for an unusable key |

Dependency failures (RPC, catalog, Intel PCS, Secret Manager, KMS) answer 503 `unavailable`, so the agent retries.
A stale or foreign chain answers 503 `chain_stale` (recorded as a denial). An allowed release is answered only after
its decision was written to Cloud Logging; if that write fails the answer is 503 `decision_log_unavailable` and
nothing is released. Every other decision is written in the background.

## Resource limits (D-066)

- Per client address (the last `X-Forwarded-For` hop, which Cloud Run appends): 2 release requests per second with a
  burst of 20, and four times that for nonces (`--client-rate`, negative turns it off). 429 `rate_limited` beyond.
- The body is read before any slot is taken, with a 10 s deadline and a 2 MiB limit (413 beyond).
- At most 4 bodies are parsed at a time; at most `--max-in-flight` (8) releases run their checks at a time.
- Requests that fail before their nonce is accepted and their body validated are junk: answered at once, written to
  the decision log in the background in truncated form (names, reasons and details of at most 200 bytes, flagged
  `truncated`). The background queue is bounded; a full queue drops entries and the next written entry carries the
  count in `suppressed`. Junk never takes a release slot.
- The Go soft memory limit is 384 MiB unless `GOMEMLIMIT` is set.
- Nonces: at most `--nonce-capacity` (100,000) live, oldest evicted first. `--nonce-journal <file>` keeps live and
  consumed nonces across a restart; it helps only on durable storage (Cloud Run's own filesystem is memory).

## Secrets

Only secrets named in the manifests of the stack's releases are read, from Secret Manager in the bootstrap project:
`sealed-<appId>-<NAME>` for app secrets and `sealed-gate-password` for the bcrypt hash of the password gate (released
as `_gate/GATE_PASSWORD_BCRYPT`; a value that is not a bcrypt hash is refused). A manifest secret with
`same_as: "<appId>/<NAME>"` (D-043) is read from that app's secret and released under the referencing app's name.
The referenced app must be another app of the stack, declare that secret itself (no chains) and list the
referencing app in that secret's `share_with` (D-059); a required secret cannot refer to an optional one.

`diskKey = HMAC("sealed/disk/v2" || customer || salt)` and `signerSeed = HMAC("sealed/signer/v2" || customer || salt)`
(D-058; customer is the 20-byte address, salt the config's 32 bytes) with the bootstrap's Cloud KMS `HMAC_SHA256` key
(`cryptoKeyVersions.macSign`), so the root key never leaves KMS. A rebooted deployment, and an upgraded stack that
keeps its config salt (new releases, a new composer version), get the same disk key and enclave signer; a new salt
gives a fresh disk. Never rotate or destroy that key version.

## Configuration (set by the customer at bootstrap)

The environment names are exactly the ones the bootstrap module sets (`infra/terraform/customer-bootstrap`,
`key_broker.tf`; `TestBootstrapEnvContract` and `TestLoadConfigFromBootstrapEnv` compare the two). The production build refuses to start with any other
`SEALED_*` or `TEMPO_*` variable, including the names an earlier broker read (`SEALED_CUSTOMER`, `SEALED_TEMPO_RPC`,
`SEALED_CHAIN_ID`, `SEALED_KMS_KEY`), so a renamed setting never falls back to a default. A dev build with
`SEALED_DEV_SIM=1` only warns.

| flag | environment (bootstrap) | default |
|---|---|---|
| `--customer` | `SEALED_CUSTOMER_ADDRESS` | required |
| `--tempo-rpc` | `TEMPO_RPC_URL` | `https://rpc.tempo.xyz` (https; plain http only to a loopback address) |
| `--chain-id` | `TEMPO_CHAIN_ID` | `4217`; other chains only in a dev build with `SEALED_DEV_SIM=1` (D-060) |
| `--platform-registry`, `--app-registry`, `--deployment-registry` | `SEALED_PLATFORM_REGISTRY`, `SEALED_APP_REGISTRY`, `SEALED_DEPLOYMENT_REGISTRY` | mainnet (`contracts/deployments/tempo-mainnet.json`) |
| `--release-asset-base` | `SEALED_RELEASE_ASSET_BASE` | `https://github.com/sealedtempo/sealed/releases/download` (https only) |
| `--project` | `SEALED_GCP_PROJECT` | required |
| `--project-number` | `SEALED_GCP_PROJECT_NUMBER` | recorded only |
| | `SEALED_SECRET_PREFIX` | must be `sealed-` if set |
| `--kms-key-version` | `SEALED_KMS_KEY_VERSION` | required: `projects/../locations/../keyRings/../cryptoKeys/../cryptoKeyVersions/N` |

Set by the bootstrap only when the customer chose a value (`bootstrapOptionalEnv`; one `dynamic "env"` block per
name in `key_broker.tf`, also compared by `TestBootstrapEnvContract`):

| flag | environment (bootstrap, optional) | default |
|---|---|---|
| `--fee-splitter`, `--fee-token` | `SEALED_FEE_SPLITTER`, `SEALED_FEE_TOKEN` | mainnet FeeSplitter and USDC.e; `sealed bootstrap` sets both from its deployments file when the registries are not mainnet's |
| `--allowed-images` | `SEALED_ALLOWED_IMAGES` | empty (every image PlatformRegistry approves); otherwise comma-separated 0x imageIds, the customer's own allowlist (`sealed bootstrap --allowed-images`) |

| flag | environment (optional) | default |
|---|---|---|
| `--region` | `SEALED_GCP_REGION` | the metadata server's region on Cloud Run, else `us-central1` (log resource only) |
| `--decision-log-id` | `SEALED_DECISION_LOG_ID` | `sealed-key-broker-decisions` |
| `--tcb-allowed`, `--tcb-advisories` | `SEALED_TCB_ALLOWED`, `SEALED_TCB_ADVISORIES` | `UpToDate,SWHardeningNeeded`, any |
| `--max-in-flight`, `--nonce-capacity` | `SEALED_MAX_IN_FLIGHT`, `SEALED_NONCE_CAPACITY` | `8`, `100000` |
| `--chain-max-head-age` | | `60s`, at most `5m` |
| `--client-rate`, `--nonce-journal` | | `2`, none |
| `--listen` | `PORT` | `:8080` |

Optional API endpoint overrides (for example restricted VIPs, https only): `SEALED_SECRETMANAGER_ENDPOINT`,
`SEALED_KMS_ENDPOINT`, `SEALED_LOGGING_ENDPOINT`. Tokens come from the metadata server (`GCE_METADATA_HOST`).

## Cloud Run and IAM

- One instance only (`--max-instances 1`): nonces live in memory, so a nonce issued by one instance is unknown to
  another. Ingress all and unauthenticated invocations: the attestation is the authentication.
- Request timeout of at least `MaxRequestDuration` (10 s body read, 90 s release deadline, 15 s decision log write:
  115 s; the bootstrap sets 120 s); the broker bounds its own concurrency, so the per-instance request concurrency
  stays high (the bootstrap sets 80) without memory risk. `TestBootstrapCloudRunLimits` checks both against
  `key_broker.tf`, and that 80 bodies of the 2 MiB limit stay below half of `GOMEMLIMIT`.
- The broker's own service account: `roles/secretmanager.secretAccessor` on secrets named `sealed-*` (an IAM
  condition on the resource name), `roles/cloudkms.signer` on the one MAC key (`macSign` only), `roles/logging.logWriter` (the decision log); `infra/terraform/customer-bootstrap` grants exactly these.
- The platform's deployer account gets nothing on the broker, its service account, the secrets or the key.

## Builds

The production image (`key-broker/Dockerfile`, distroless static, nonroot, digests pinned) is built without build
tags. A dev build (`-tags sealeddev`) adds `--dev-allow-simulated`, `--dev-secrets-file`, `--dev-kms-key-file` and
`--dev-decision-log`, each refused unless `SEALED_DEV_SIM=1`. Simulated quotes are accepted only by such a binary.

```sh
make -C key-broker test       # production and dev builds; anvil tests need anvil, forge and contracts/dependencies
make -C key-broker test-ci    # with -race; missing anvil, node or the core build fail instead of skipping
# Local chains: anvil only mines on transactions, so its head goes stale after 60 s idle. Run it with
# --block-time 2 (or similar) for a dev broker that stays up longer than a test.
make -C key-broker build      # tmp/key-broker/key-broker
make -C key-broker image      # needs a Docker daemon
```
