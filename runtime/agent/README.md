# sealed-agent

The in-VM agent of a Sealed deployment (spec 5.6, INTERFACES 9-15). It releases the stack's keys from the customer's key broker against a TDX quote, unlocks the LUKS2 data disk, writes app secrets to tmpfs, sends attestation evidence, serves `/attest`, meters usage, signs usage and health reports and pays fees on Tempo.

## Boot sequence

1. Read the measured public config and the booted `app-compose.json` (dstack `GET /Info`, or `SEALED_APP_COMPOSE_PATH`).
2. Ephemeral X25519 key, `GET /v1/nonce`, quote over `sha256("sealed/kb-release/v1" || nonce || pub) || 0^32`, `POST /v1/release`, HPKE-open the payload. Denials are retried every minute with a fresh nonce.
3. Enclave signer: `HKDF-SHA256(ikm = signerSeed, salt = "sealed/enclave-signer/v1", info = [counter], L = 32)`, first counter giving a valid secp256k1 scalar.
4. Open or format the data disk (`cryptsetup luksFormat/open` with the key on stdin, `mkfs.ext4`, `mount`), create `<dataMount>/<app>/<volume>` for every bind mount in the compose.
5. Write `/run/sealed/secrets/<app>/<NAME>`, the payer key and limit under `sealed-mpp-payer/`, then `/run/sealed/ready`. Drop to `SEALED_RUN_AS`. `/healthz` turns 200.
6. Evidence bundle (`sealed-evidence/v1`, fresh `nonce2`) to `POST /v1/evidence`, retried with backoff; again every 24 hours.
7. Loops: app health polling (app-hour metering), settlement every `settlement.intervalMinutes`, signed health reports.

## Local API (:7070)

`GET /healthz`, `GET /v1/ready`, `POST /v1/usage-events` (`{"app","unit","quantity","id"?,"meta"?}`, `id` or `meta.call_id` dedupes), `POST /v1/spend` (flat scalar counters from sealed-mpp-payer), `GET /attest?nonce=0x...` (rate limited).

## Settlement

Usage is priced as it arrives (`@sealed/core` pricing, remainders carried per app and unit). When an app's fee in the open period would pass the FeeSplitter per-payment cap the period is cut, so every (report, app) fits one `payFees` call. Each settlement closes the period, signs the EIP-712 `UsageReport`, posts it to `POST /v1/usage` and pays every unpaid report of an app in one Tempo transaction: `approve(FeeSplitter, exact total)` plus one `payFees` per report, within the FeeSplitter daily cap and the payer's balance and access-key limit.

- `access-key` mode signs with `Account.fromSecp256k1(enclaveKey, { access: customer })`, so FeeSplitter sees the customer as `msg.sender`.
- `enclave-account` mode pays from the enclave signer's own pathUSD balance.

Deferrals because of the daily cap or a deployment that is not registered yet are not failures. Failures (no access key, spend limit, balance, reverted transaction) that last `settlement.gracePeriodMinutes` switch every app route to a 402 payment-needed page through Caddy's admin API; the attest route stays up and data is untouched. The next successful settlement restores the saved Caddy config.

## Environment

| variable | default |
|---|---|
| `SEALED_CONFIG_PATH` | `/etc/sealed/config.json` (public config, measured) |
| `SEALED_AGENT_APPS_PATH` | `/etc/sealed/agent-apps.json` (optional, see below) |
| `SEALED_APP_COMPOSE_PATH` | unset: read from the guest agent |
| `DSTACK_SIMULATOR_ENDPOINT` | unset: `/var/run/dstack.sock`; a socket path or `http://host:port` |
| `SEALED_DEFAULTS_PATH` | `/app/config/defaults.yaml` in the image |
| `SEALED_TEST_OVERRIDES` | `1` applies `test_overrides` from defaults.yaml |
| `SEALED_LISTEN` | `0.0.0.0:7070` |
| `SEALED_SECRETS_DIR`, `SEALED_READY_FILE` | `/run/sealed/secrets`, `/run/sealed/ready` |
| `SEALED_DATA_DEVICE`, `SEALED_LUKS_NAME`, `SEALED_DATA_MOUNT` | `/dev/disk/by-id/google-sealed-data`, `sealed-data`, `/mnt/sealed-data` |
| `SEALED_DISK_MODE` | `luks`; `dir` uses a plain directory (development only) |
| `SEALED_STATE_DIR` | `<dataMount>/.sealed-agent` |
| `SEALED_CADDY_ADMIN_SOCKET`, `SEALED_CADDY_DATA_DIR` | `/run/caddy-admin/admin.sock`, `/caddy-data` (read only) |
| `SEALED_EGRESS_STATS_URL` | `http://172.30.0.2:9100/v1/stats` |
| `SEALED_RUN_AS` | `10001:10001` in the image |
| `SEALED_REATTEST_HOURS`, `SEALED_HEALTH_INTERVAL_S`, `SEALED_POLL_INTERVAL_S` | `24`, `60`, `30` |

`agent-apps.json` (`sealed-agent-apps/v1`) carries what only the manifests know:

```json
{"schema":"sealed-agent-apps/v1","apps":{"crm":{"metering":{"unit":"app_hour","source":"heartbeat"},"healthcheck":"http://crm-server:3000/healthz"}}}
```

Without it every config app may post usage events of any unit and no app-hour polling happens.

## Dev simulator

```
node dist/sim.js --app-compose app-compose.json --socket /tmp/dstack.sock   # or --port 8090
DSTACK_SIMULATOR_ENDPOINT=/tmp/dstack.sock SEALED_DISK_MODE=dir node dist/main.js
```

Quotes are `SEALEDSIM1 || CJSON(...)` with the fixed sim measurements (INTERFACES 15) and an RTMR3 replayed from the exact dstack event sequence for the given compose. Production verifiers reject them.

## Tests

`pnpm --filter @sealed/agent test`. The chain tests start `anvil --network tempo --hardfork T4` and deploy the contracts from `contracts/out` (or `SEALED_CONTRACTS_DIR`); they are skipped when anvil or the contracts are missing.
