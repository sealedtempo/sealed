# sealed-agent

The in-VM agent of a Sealed deployment (spec 5.6, INTERFACES 9-15). It releases the stack's keys from the customer's key broker against a TDX quote, unlocks the LUKS2 data disk, writes app secrets to tmpfs, sends attestation evidence, serves `/attest`, meters usage, signs usage and health reports and pays fees on Tempo.

## Boot sequence

1. Read the public config (`SEALED_CONFIG_FILE`) and the booted `app-compose.json` (dstack `GET /Info`). Everything else the agent needs from the composer comes from the measured inline `configs` in that app-compose (the composer doubles `$`, the agent undoes it): `sealed-config` (must equal the config file), `sealed-stack` (sealed-stack/v1: per-app metering, healthcheck, service IPs; sidecar IPs; attest host), `sealed-caddyfile` and `sealed-caddyfile-payment-needed`. The files the composer also mounts (`SEALED_STACK_FILE`, `SEALED_CADDYFILE`, `SEALED_CADDYFILE_PAYMENT_NEEDED`) must hold the same bytes.
2. Ephemeral X25519 key, `GET /v1/nonce`, quote over `sha256("sealed/kb-release/v1" || nonce || pub) || 0^32`, `POST /v1/release`, HPKE-open the payload. The answer must name this stack's stackHash and deploymentId and decrypt under the ephemeral key with `aad = nonce`; anything else is retried with a fresh nonce. Denials are retried every minute.
3. Enclave signer: `HKDF-SHA256(ikm = signerSeed, salt = "sealed/enclave-signer/v1", info = [counter], L = 32)`, first counter giving a valid secp256k1 scalar (frozen by a test vector in `packages/core`).
4. Data disk (below), then every data directory of the stack: the compose's bind sources and sealed-stack/v1 `dataDirs` (host paths under `/mnt/sealed-data`, seen at `SEALED_DATA_DIR`). A volume whose manifest declares `x-sealed-owner` (sealed-stack/v1 `apps[].volumes[].owner`, `"<uid>:<gid>"`) gets that owner on every boot; otherwise a new directory gets the numeric `user` of the first service that mounts it. A symlink or a file in place of a directory fails the boot. All of this happens before the ready flag (brief item 11).
5. Secrets (D-042, composer 1.2): the compose binds the host's `/run/sealed/secrets` (on the CVM's `/run` tmpfs) into the agent only, and binds into each service exactly the files it lists, read-only, from the same host path. Before any key is released the agent reads those binds back and refuses to boot when a service can see another owner's secrets, mounts them writable, binds a host path other than its target, or when they differ from sealed-stack/v1 `secretFiles`. After the release it checks that the secrets root is on tmpfs (statfs `0x01021994`), creates the owner directories (0755, never through a symlink) and writes exactly the `secretFiles` entries (0444): the released value (a `same_as` secret arrives from the key broker under the referencing app), or an empty file for an optional secret the customer did not set (a missing bind source would stop the container). A missing required one is logged. The gate hash `_gate/GATE_PASSWORD_BCRYPT` is kept in memory only (Caddy holds no secret). The payer key and limit go to `sealed-mpp-payer/` only when the stack has the payer. Then `<SEALED_READY_DIR>/ok` (the shared `sealed-ready` tmpfs volume) opens the gate envexec waits for.
6. Fork the Caddy admin helper, drop to `SEALED_RUN_AS`, read the FeeSplitter per-payment cap, report ready (`/v1/ready` 200).
7. Evidence bundle (`sealed-evidence/v1`, fresh `nonce2`) to `POST /v1/evidence`, retried with backoff; again every 24 hours (a run that is still retrying is joined, not duplicated).
8. Loops: app health polling (app-hour metering), settlement every `settlement.intervalMinutes`, signed health reports.

## Data disk (D-017)

The host attaches the disk, so the agent trusts nothing on it:

- The LUKS2 volume key and the keyslot passphrase are derived from the broker's `diskKey`: `HKDF-SHA256(ikm = diskKey, salt = "sealed/disk/luks2/v1", info = "volume-key", L = 64)` and `info = "keyslot-passphrase", L = 32`. Format: `luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --volume-key-file /dev/fd/3 --pbkdf pbkdf2 --hash sha256 --key-file -`.
- Before unlocking, `cryptsetup luksDump --dump-json-metadata` must show exactly one luks2 keyslot (aes-xts-plain64 area, 512-bit, pbkdf2/sha256, af luks1/sha256), one crypt segment (aes-xts-plain64, no integrity, no flags), one digest, no tokens and no requirements (so no reencryption).
- Unlock with `--disable-keyring`, then `dmsetup table --showkeys` must show a single crypt target with aes-xts-plain64, exactly the derived volume key, IV offset 0, no integrity options, on the data device's major:minor. Otherwise the mapping is closed and boot fails. A header that did not come from `diskKey` (cipher_null, a keyslot any passphrase opens, a volume key the host knows) can never be mounted. The same check applies to a mapping that already exists after an agent restart.
- "Mounted" means the topmost `/proc/self/mountinfo` entry at the mount point is ext4 from `/dev/mapper/<name>`; the composer's bind mount of the host directory at the same path does not count.
- Limits: aes-xts has no integrity protection, so the host can still corrupt blocks or roll the disk back to an earlier copy of itself (it cannot read or forge plaintext).

## Local API (:7070)

| route | caller | rules |
|---|---|---|
| `GET /healthz`, `GET /v1/ready` | Docker, apps | 200 once secrets are written |
| `POST /v1/usage-events` | the app's own services | `{"app","unit","quantity","id"?,"meta"?}`; the source IP must be one of the app's service IPs in sealed-stack/v1 (403), the app must meter this unit by `callback` (422); per event at most 10M tokens / 10k pages / 3600 s and per app and unit per clock hour at most 1B tokens / 1M pages / 7200 s (422 / 429); one event may cut at most 8 reports; `id` or `meta.call_id` dedupes |
| `POST /v1/spend` | sealed-mpp-payer only (its fixed IP) | the payer's SpendReport; only the known counters (decimal strings, integers, booleans, `day` as YYYY-MM-DD) are kept, as `mpp_*` in health reports |
| `POST /v1/spend/reserve` | sealed-mpp-payer only | `{"amount":"<base units>","currency"?:"0x..."}` -> `{"ok":true,"reservationId":"0x<16 bytes>","remaining"}` or `{"ok":false,"remaining","reason":"budget"\|"too_many_reservations"}`; 422 when `currency` is not the config's `feeToken` |
| `POST /v1/spend/release` | sealed-mpp-payer only | `{"reservationId","used":"<base units>"}` -> `{"ok":true,"remaining"}`; 404 for an unknown or already released id |
| `GET /v1/gate?route=<route>` | caddy only (its fixed IP; 403 otherwise) | Caddy `forward_auth`, see below |
| `POST /v1/bootstrap/done` | the app's bootstrap service only | `{"app"}`, only for a job whose done file is not on the data disk (409 otherwise) |
| `GET /attest?nonce=0x...` | public via Caddy | 1/s, burst 5 per client (X-Forwarded-For only when Caddy relays), 10/s overall |

## Password gate (D-044)

Caddy asks `GET /v1/gate?route=<route>` (forward_auth) with the client's headers before it proxies a route whose auth is `gate` (and the non-bearer part of `bearer-passthrough`):

- `200` for a valid `sealed_gate` cookie, or for `Authorization: Basic` (the scheme followed by spaces, the only form Caddy strips) with user `sealed` (sealed-stack/v1 `gate.username`) whose password matches the released bcrypt hash `_gate/GATE_PASSWORD_BCRYPT`. A Basic success adds `Set-Cookie: sealed_gate=v1.<expiresAt>.<session id>.<HMAC-SHA256>; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax`. The HMAC key is drawn at every boot, so a restart signs everyone out. The cookie is not bound to a route. The answer carries `X-Sealed-Gate: cookie|basic` and, when the request's `Authorization` header holds the gate's own Basic credentials, `X-Sealed-Gate-Strip-Authorization: 1` (the composed Caddyfile removes the gate's own Basic credentials, matched as `Basic` plus spaces plus base64 of `sealed:`, before the app; with the cookie an app's own header, such as a Bearer token, passes untouched).
- `303` instead of `200` for a Basic success on a browser navigation (`X-Forwarded-Method: GET`, `Sec-Fetch-Mode: navigate`): `Location` is the same path and query (`X-Forwarded-Uri`, same-origin paths only) and the answer carries the `Set-Cookie`. forward_auth copies nothing from a 2xx answer onto the client's response but passes other answers through unchanged, so browsers get the cookie whether or not Caddy copies `Set-Cookie` from a 200.
- `401` with `WWW-Authenticate: Basic realm="sealed"` otherwise.
- `503 starting` until the gate hash is released and, for an app with a bootstrap job, until `bootstrap.donePath` exists as a regular file on the data disk (or the job reported done, see the local API). `503 gate not configured` when the released hash is not bcrypt or its cost is above 20.
- `429` with `Retry-After` when a client (X-Forwarded-For from Caddy) failed 10 times in a burst (refills one per 6 s) or all clients together 30 times (one per second). A failed attempt costs a token before bcrypt runs and a success returns it. Successful Basic checks are remembered for 5 minutes, so clients that keep sending Basic credentials do not pay bcrypt each time.

bcrypt (`$2a$`, `$2b$`, `$2y$`) is implemented in `src/gate/bcrypt.ts` and runs in a worker thread with at most 8 checks in flight. It is tested against golang.org/x/crypto/bcrypt and the OpenWall vectors. Passwords over 72 bytes never match.

## Settlement

Usage is priced as it arrives (`@sealed/core` pricing, remainders carried per app and unit). Reports are cut so no app's fee in a report exceeds `min(defaults cap, FeeSplitter perPaymentCap)`; the onchain cap is read before usage is accepted and again at every settlement. Each settlement closes the period, signs the EIP-712 `UsageReport`, posts it to `POST /v1/usage` and pays each app's unpaid legs in one Tempo transaction: `approve(FeeSplitter, exact total)` plus one `payFees` per leg.

A (report, app) leg is settled only when `usagePaid(deploymentId, usageHash, appId)` is at least the report's fee. FeeSplitter cannot see the report, so the customer can pay a leg first with any amount (contract review logic-F1 b / funds-F-02); a leg paid short stays unpaid and the batch carries `topUpFees(..., total = fee, usageHash)` for it, which pulls only the shortfall, and ends with `approve(FeeSplitter, 0)`. Budgets and the daily cap count the shortfall. A leg someone else paid in full is marked paid without a transaction. A leg opened in another token (`usageToken`) cannot be topped up and is a failure. The access key the customer authorizes must allow `payFees` and `topUpFees` on FeeSplitter and `approve` to FeeSplitter on the fee token.

Batches: the oldest legs that fit the daily cap and the payer's balance and access-key limit, at most 10 per transaction; the network fee is estimated for exactly that batch (gas = max(estimate x 1.5 + 50k, 600k + 1.3M per leg)), and the batch shrinks while the estimate reverts or the fee does not fit.

Billing fails closed. Failures: chain read errors (the customer controls the firewall and can block the RPC), a deployment still not registered (its failure clock starts at the oldest unpaid report, so blocking the platform API does not delay it), an app the registry does not list, reverted estimates or transactions, missing or revoked access keys, the spend limit, the balance. Failures that last `settlement.gracePeriodMinutes` switch Caddy to the measured `Caddyfile.payment-needed` (`POST /load`, `Content-Type: text/caddyfile`); it is re-applied every tick because Caddy restarts with the normal file. A Closed deployment (terminal) switches at once and stays switched. The next successful settlement loads the normal Caddyfile again. Deferrals, not failures: the FeeSplitter daily cap, and legs above a lowered per-payment cap (reported as `overCap`; they cannot be paid at that cap). The attest route and the data are never touched.

Caddy creates its admin socket with mode 0660 in the `sealed-caddy-admin` tmpfs (owner 10001:10001, setgid, so the socket's group is 10001; brief item 15), so the agent loads the two measured Caddyfiles over it directly after dropping to 10001:10001. There is no root helper.

Shared spend budget (D-048): fee settlement and sealed-mpp-payer draw on one daily limit, `settlement.spendLimitPerDay` (the access key's limit). The payer reserves through `/v1/spend/reserve` and gets at most `limit - fees spent - payer spent - open reservations - reserved_for_fees`, where `reserved_for_fees` is the next settlement's estimate: unpaid legs, the open period's fees, app-hours of heartbeat apps for one settlement interval, and 0.01 USD of network fees per app transaction. Each payment adds its fees plus the network fee it paid. The window is the access key's onchain period when the key has a periodic limit (`getRemainingLimit` `periodEnd`, read at boot and after every settlement), else the UTC day. A reservation not released within 15 minutes counts as spent until a late release corrects it. The budget lives in the state file on the encrypted disk.

- `access-key` mode signs with `Account.fromSecp256k1(enclaveKey, { access: customer })`, so FeeSplitter sees the customer as `msg.sender`.
- `enclave-account` mode pays from the enclave signer's own balance of the fee token.

Every payment, approval and network fee uses the config's `feeToken` (USDC.e on mainnet, D-035); nothing in the agent assumes pathUSD.

## Health report body

`POST /v1/health` `{"deploymentId","signature","body"}`, EIP-191 by the enclave signer over CJSON of:

```json
{"at":1800000000,
 "apps":{"crm":"healthy"},
 "egress":{"since":1799999000,"allowed":{"host:port":3},"blocked":{"host:port":1}},
 "payments":{"mode":"access-key","paymentNeeded":false,"failingSince":null,"lastPaidAt":null,"lastAttemptAt":null,"lastOutcome":"settled",
             "metered":"200833","unpaid":"0","overCap":0,
             "budget_limit":"2000000","budget_fees":"202833","budget_payer":"40000","budget_reserved":"0",
             "budget_reservedForFees":"10200","budget_payerAvailable":"1746967","budget_windowEnd":"1800014400",
             "mpp_debited":"1200","mpp_budget":"2000000","mpp_charges":3,"mpp_relayAttested":true}}
```

`mpp_*` are the payer's own counters from `POST /v1/spend` (its SpendReport as runtime/mpp-payer builds it, nested `counters` and `relay` flattened); `budget_*` is the shared budget above.

Egress keys must look like `host:port` (lowercase, optional `*.`), at most 50 per map, largest counts first.

## Environment

The composer sets these on the sealed-agent service (runtime/composer README, "Contract for the sidecars"):

| variable | default |
|---|---|
| `SEALED_CONFIG_FILE` | `/etc/sealed/config.json` |
| `SEALED_STACK_FILE`, `SEALED_CADDYFILE`, `SEALED_CADDYFILE_PAYMENT_NEEDED` | `/etc/sealed/stack.json`, `/etc/sealed/caddy/Caddyfile`, `/etc/sealed/caddy/Caddyfile.payment-needed` (cross-checked against app-compose) |
| `SEALED_CADDY_ADMIN_SOCKET` | `/run/sealed/caddy-admin/admin.sock` |
| `SEALED_SECRETS_DIR`, `SEALED_READY_DIR` | `/run/sealed/secrets`, `/run/sealed/ready` (the gate is `<dir>/ok`) |
| `SEALED_DATA_DIR`, `SEALED_DATA_DEVICE` | `/mnt/sealed-data`, `/dev/sealed-data` |
| `SEALED_EGRESS_STATS_URL` | `http://172.30.0.2:9100/v1/stats` |
| `DSTACK_SOCKET` | `/var/run/dstack.sock` |
| `PORT` | `7070` |

Agent-only settings: `SEALED_LISTEN_HOST` (`0.0.0.0`), `SEALED_LUKS_NAME` (`sealed-data`), `SEALED_STATE_DIR` (`<data>/.sealed-agent`), `SEALED_RUN_AS` (`10001:10001` in the image), `SEALED_DEFAULTS_PATH`, `SEALED_TEST_OVERRIDES=1`, `SEALED_APP_COMPOSE_PATH` (read app-compose from a file instead of `/Info`), `SEALED_REATTEST_HOURS` (24), `SEALED_HEALTH_INTERVAL_S` (60), `SEALED_POLL_INTERVAL_S` (30).

Development only, with `SEALED_DEV_SIM=1` (otherwise refused): `DSTACK_SIMULATOR_ENDPOINT` (socket path or `http://host:port`), `SEALED_DISK_MODE=dir` (a plain directory instead of LUKS), and secrets in plain directories instead of tmpfs mounts.

## Dev simulator

```
node dist/sim.js --app-compose app-compose.json --socket /tmp/dstack.sock   # or --port 8090
SEALED_DEV_SIM=1 DSTACK_SIMULATOR_ENDPOINT=/tmp/dstack.sock SEALED_DISK_MODE=dir node dist/main.js
```

Quotes are `SEALEDSIM1 || CJSON(...)` with the fixed sim measurements (INTERFACES 15) and an RTMR3 replayed from the exact dstack event sequence for the given compose. Production verifiers reject them.

## Tests

`pnpm --filter @sealed/agent test`. `test/catalog.e2e.test.ts` runs the real composer (`go run ./runtime/composer/cmd/sealed-compose compose --fill-release-ids --allow-missing-sbom`) on the catalog apps, boots the agent on that app-compose and verifies its evidence with the verifier library in simulator mode (`test/tools/verify-evidence.go`); it needs Go and is required when `CI` or `SEALED_REQUIRE_CHAIN_TESTS=1` is set. `test/golden.test.ts` boots the agent on the composer's golden app-compose (`test/fixtures/composer-golden`, copied from `runtime/composer/testdata/golden`). The chain tests start `anvil --network tempo --hardfork T4` and deploy the contracts from `contracts/out` (or `SEALED_CONTRACTS_DIR`); they are skipped when anvil or the contracts are missing, and fail instead with `SEALED_REQUIRE_CHAIN_TESTS=1` (CI), which also requires `pnpm -r build` for the simulator CLI test.
