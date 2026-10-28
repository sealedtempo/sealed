# key-broker

The Sealed key broker (spec 5.7, INTERFACES.md section 9). It runs on Cloud Run in the customer's own project,
deployed by the customer's bootstrap, and releases the customer's secrets only to an attested confidential VM that
runs a stack the customer approved onchain. The platform has no access to it.

## API

| method | path | answer |
|---|---|---|
| GET | `/v1/nonce` | `{"nonce":"0x<32 bytes>","expiresAt":<unix>}`. Single use, 5 minute lifetime. |
| POST | `/v1/release` | 200 `{"stackHash","deploymentId","enc","ciphertext"}`; 403 `{"decision":"denied","reason","detail"}`; see below |
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
| `quote`: TDX quote v4/v5 verified with Intel PCS collateral; no quote at all is refused | `quote_invalid` |
| `quote`: TCB status allowed (`UpToDate`, `SWHardeningNeeded` by default) | `tcb_status` |
| `report_data`: `sha256("sealed/kb-release/v1" \|\| nonce \|\| ephemeralPub) \|\| 32 zero bytes` | `report_data_mismatch` |
| `chain`: RPC serves the configured chain; every read below is pinned to one block | 503 |
| `image`: `getImage(imageId)` exists | `image_not_approved` |
| `image`: `keccak256(mrtd \|\| rtmr0 \|\| rtmr1 \|\| rtmr2)` equals its measurementsHash | `measurements_mismatch` |
| `image`: not a debug image, and the TD has no debug, migratable or reserved attribute bits | `image_debug` |
| `image`: `isApprovedImage(imageId)` | `image_not_approved` |
| `rtmr3`: the event log replays to the quote's RTMR3 with exactly the Sealed event sequence | `rtmr3_replay` |
| `compose_hash`: the compose-hash event equals `sha256(appCompose)` | `compose_mismatch` |
| `stack_recompute`: config parses for this composer version, `releaseIds` equal `config.apps[].releaseId`, each release is published for that app | `compose_mismatch` |
| `stack_recompute`: each bundle, fetched by the release asset URL rule, has the onchain bundleHash | `bundle_hash_mismatch` |
| `stack_recompute`: the composer recomputes `appCompose` byte for byte | `compose_mismatch` |
| `customer`: `config.customer` is the bootstrap customer | `customer_mismatch` |
| `config_chain`: `config.chainId` and `config.contracts` name this broker's chain and registries | `stack_not_approved` |
| `stack_approved`: `DeploymentRegistry.isStackApproved(customer, stackHash)` | `stack_not_approved` |
| `approval_releases`: the approval's releaseIds equal the config's as a set, and its imageId equals `config.imageId` and the request's (D-014) | `stack_not_approved` |
| `secrets`: every secret the stack's manifests name is stored (optional ones may be missing) | 503 `secret_missing` / `secret_invalid` |
| `keys`: `diskKey` and `signerSeed` from the KMS HMAC key | 503 |
| `seal`: HPKE to `ephemeralPub` | `bad_request` for an unusable key |

Dependency failures (RPC, catalog, Secret Manager, KMS) answer 503 `unavailable`, so the agent retries. An allowed
release is answered only after its decision was written to Cloud Logging; if that write fails the answer is 503
`decision_log_unavailable` and nothing is released.

## Secrets

Only secrets named in the manifests of the stack's releases are read, from Secret Manager in the bootstrap project:
`sealed-<appId>-<NAME>` for app secrets and `sealed-gate-password` for the bcrypt hash of the password gate (released
as `_gate/GATE_PASSWORD_BCRYPT`; a value that is not a bcrypt hash is refused). A manifest secret with
`same_as: "<appId>/<NAME>"` (D-043) is read from that app's secret and released under the referencing app's name;
the referenced app must be in the stack and declare that secret.

`diskKey = HMAC("sealed/disk/v1" || deploymentId)` and `signerSeed = HMAC("sealed/signer/v1" || deploymentId)` with
the bootstrap's Cloud KMS `HMAC_SHA256` key (`cryptoKeyVersions.macSign`), so the root key never leaves KMS and a
rebooted deployment gets the same disk key and enclave signer. Never rotate or destroy that key version.

## Configuration (set by the customer at bootstrap)

The environment names are the ones `infra/terraform/customer-bootstrap` (`key_broker.tf`) sets on the Cloud Run
service; `TestLoadConfigFromBootstrapEnv` keeps the two in step.

| flag | environment | default |
|---|---|---|
| `--customer` | `SEALED_CUSTOMER_ADDRESS` | required |
| `--tempo-rpc` | `TEMPO_RPC_URL` | `https://rpc.tempo.xyz` |
| `--chain-id` | `TEMPO_CHAIN_ID` | `4217` |
| `--platform-registry`, `--app-registry`, `--deployment-registry` | `SEALED_PLATFORM_REGISTRY`, `SEALED_APP_REGISTRY`, `SEALED_DEPLOYMENT_REGISTRY` | mainnet (`contracts/deployments/tempo-mainnet.json`) |
| `--release-asset-base` | `SEALED_RELEASE_ASSET_BASE` | `https://github.com/sealedtempo/sealed/releases/download` (https only) |
| `--project` | `SEALED_GCP_PROJECT` | required |
| `--kms-key` | `SEALED_KMS_KEY_VERSION` | required: the HMAC key's `cryptoKeyVersions/1` resource name (or a `cryptoKeys` name with `--kms-key-version`, default `1`) |
| (none) | `SEALED_SECRET_PREFIX` | when set, must be `sealed-` (the broker refuses to start otherwise) |
| `--region` | `SEALED_GCP_REGION` | `us-central1` (log resource only) |
| `--decision-log-id` | `SEALED_DECISION_LOG_ID` | `sealed-key-broker-decisions` |
| `--tcb-allowed`, `--tcb-advisories` | `SEALED_TCB_ALLOWED`, `SEALED_TCB_ADVISORIES` | `UpToDate,SWHardeningNeeded`, any |
| `--max-in-flight`, `--nonce-capacity` | `SEALED_MAX_IN_FLIGHT`, `SEALED_NONCE_CAPACITY` | `8`, `100000` |
| `--listen` | `PORT` | `:8080` |

Optional API endpoint overrides (for example restricted VIPs): `SEALED_SECRETMANAGER_ENDPOINT`,
`SEALED_KMS_ENDPOINT`, `SEALED_LOGGING_ENDPOINT`. Tokens come from the metadata server (`GCE_METADATA_HOST`).

## Cloud Run and IAM

- One instance only (`--max-instances 1`): nonces live in memory, so a nonce issued by one instance is unknown to
  another. Ingress all and unauthenticated invocations: the attestation is the authentication.
- The broker's own service account: `roles/secretmanager.secretAccessor` on secrets named `sealed-*` (an IAM
  condition on the resource name), `roles/cloudkms.signerVerifier` on the one MAC key, `roles/logging.logWriter`.
- The platform's deployer account gets nothing on the broker, its service account, the secrets or the key.

## Builds

The production image (`key-broker/Dockerfile`, distroless static, nonroot, digests pinned) is built without build
tags. A dev build (`-tags sealeddev`) adds `--dev-allow-simulated`, `--dev-secrets-file`, `--dev-kms-key-file` and
`--dev-decision-log`, each refused unless `SEALED_DEV_SIM=1`. Simulated quotes are accepted only by such a binary.

```sh
make -C key-broker test       # production and dev builds; anvil tests need anvil, forge and contracts/dependencies
make -C key-broker test-ci    # with -race; missing anvil, node or the core build fail instead of skipping
make -C key-broker build      # tmp/key-broker/key-broker
make -C key-broker image      # needs a Docker daemon
```
