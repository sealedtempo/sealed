# Devnet end to end (`make devnet-e2e`)

The whole Sealed trust and payment flow on one machine, with every component running as a process: no Docker, no
TDX, no Google Cloud. One command at the repo root:

```sh
make devnet-e2e                      # or scripts/devnet/run.sh [--keep] [--settle-seconds N]
make devnet-e2e DEVNET_ARGS=--keep   # keep tmp/devnet/runs/<run id> (logs, configs, evidence) after a pass
```

`run.sh` builds what the run needs (the sealed CLI, the key broker dev build with `-tags sealeddev`,
sealed-verifierd and sealed-compose into `tmp/devnet/bin`; `@sealed/core` and `@sealed/agent`; the platform api
from the private repo), then runs `src/main.ts`. It re-runs itself with a minimal environment, so nothing from the
caller (for example the workspace `.env` a Makefile includes) reaches forge, anvil or any component. Only anvil's
public dev keys sign, on chain 31337, so nothing signed here is valid on Tempo mainnet.

Prerequisites: Go 1.27, Node 22.18 or later (the orchestrator runs as TypeScript with Node's type stripping) and
pnpm, Foundry (anvil with `--network tempo`, forge) with `contracts/dependencies` installed, jq, openssl, PostgreSQL 17
binaries (`PG_BIN`, default `/opt/homebrew/opt/postgresql@17/bin`), and the private repo's `services/api`
(`SEALED_API_DIR`, else `../sealed-platform/services/api`, else the `../platform-integration` worktree).

## What runs

| component | how |
|---|---|
| Tempo node | `anvil --network tempo --hardfork T4 --gas-limit 500000000` on a free port |
| contracts | `contracts/script/Deploy.s.sol` broadcast with forge (oracle signer = a local test key, FEE_TOKEN = the local node's pathUSD), `record-deployment.sh` |
| release assets | a local HTTP server at `<base>/<appId>-v<version>/<appId>-<version>.bundle.tar` (D-046) |
| key broker | `key-broker` dev build, `SEALED_DEV_SIM=1`, `--dev-allow-simulated`, in-memory secret store (`--dev-secrets-file`), file-backed HMAC key, JSON-lines decision log |
| sealed-verifierd | `--dev-allow-simulated`, the run's deployments file, the local asset base |
| platform api | `services/api` `dist/main.js serve` as oracle and indexer, a throwaway PostgreSQL 17 cluster, ORACLE and OPS from anvil dev keys; its Google and Rekor endpoints point at a closed local port |
| dstack simulator | `runtime/agent` `dist/sim.js` serving the exact app-compose.json |
| sealed-agent | `src/agentHost.ts`: the real `Agent` class booted like `runtime/agent/src/main.ts` |
| attest host | `src/attestFront.ts`: HTTPS with a self-signed certificate for the stack's attest hostname, proxying `/attest` to the agent as Caddy does |

The agent host replaces only what a laptop has no equivalent for: the block-device tools behind `LuksDisk`
(`src/fakeLuks.ts`: the LUKS2 format, open, mkfs and mount steps run against a fake that keeps the header and
filesystem state across reboots and refuses another diskKey), Caddy's admin socket (switches are recorded), Caddy's
TLS listener (the attest front above), egress stats and container health probes, chown of volume directories, the caller address of
local API calls (taken from an `x-devnet-peer` header, standing in for the apps' fixed 172.30.x.y addresses), and
name resolution: the composer refuses loopback endpoints, so configs name `*.devnet.test` hosts (RFC 6761) and the
agent host resolves them to 127.0.0.1, as sealed-egress's DNS would inside a VM.

## Steps and assertions

1. anvil and the contracts: owner, registrar, oracle signer, verifier method 1, treasury, FEE_TOKEN allowlisted.
2. Images `sealed-sim` (INTERFACES 15 measurements, isDebug false) and `sealed-sim-debug` (isDebug true).
3. The five catalog apps plus inference-relay: `sealed release build --allow-missing-sbom --dev-allow-unbuilt`
   (all-zero digests are refused without the dev flag), served by the asset rule, `registerApp` (maintainer
   share 2000) and `publishRelease` from the registrar key; a non-registrar is refused.
4. The customer fetches each bundle by the asset rule (sha256 equals the onchain bundleHash), composes the
   five-app stack with sealed-compose and calls `approveStack`.
5. Key broker (seeded with every secret the manifests need, same_as resolved, gate bcrypt hash), verifierd,
   PostgreSQL and the api.
6. Agent boot: nonce, quote, release (16 broker checks, flagged simulated), LUKS format and mount, secrets
   per service (every read-only bind of the compose present with its value), payer key, volume directories,
   ready flag, the password gate, evidence; the oracle verifies with verifierd and registers onchain; the
   record, the api's evidence row, indexer row and a signed health report are checked.
7. `sealed verify --deployment <id> --evidence <file>` in an empty directory with an empty environment (only
   the evidence file, the RPC and the local chain's public description: deployments file and a defaults file
   naming chain 31337 and the asset base): every check passes, simulated flagged. Also `POST /v1/verify`, the
   `dep_` alias through `--api`, and `--live` against a local TLS front for the attest host (a self-signed
   certificate; the agent reads its key by a TLS handshake as it reads Caddy's): the quote binds that key, and a
   front with another certificate fails `tls_binding`.
8. Access-key mode: the customer authorizes the enclave signer on the AccountKeychain precompile; usage events
   from the apps' own addresses (wrong address and wrong unit refused); the agent settles every few seconds
   (`test_overrides.settlement_interval_seconds`), the api stores the signed report, FeesPaid legs, usagePaid,
   the indexer, the 80/20 split, the shared spend budget (D-048) and a maintainer withdrawal.
9. Enclave-account mode: a second deployment, funded enclave signer pays; then the customer closes it and the
   agent switches Caddy to the payment-needed page.
10. Reboot with the same data disk: same deploymentId and enclave signer, the volume is opened (not formatted),
    secrets again, a heartbeat lands onchain with a new quote.
11. Agent container restart inside one boot: the dm mapping and mount are found and checked, not redone; a
    heartbeat lands.
12. One changed byte in app-compose.json: denied `compose_mismatch`, no secrets, no ready flag, no record.
13. The debug image: `approveStack` reverts; the debug TD is denied `image_debug`.
14. A release request with no quote: 403 `quote_invalid`, and the nonce is burned.
15. `revokeStack`: the next boot is denied `stack_not_approved` and verify fails; re-approval restores it.
16. `revokeRelease`: approval cannot be restored, the next boot is denied, `sealed verify` and `POST /v1/verify`
    fail; the api's catalog shows the revocation.

The run prints each step with elapsed times and a summary with the assertion count and total time. Every process
logs to `tmp/devnet/runs/<run id>/logs/`; a failed run keeps that directory and prints the failing assertion with
the tail of the relevant log. Ports are chosen by the OS at start; every child process is stopped on success,
failure, SIGINT, SIGTERM and SIGHUP.

## Unit tests

```sh
pnpm --filter @sealed/devnet test        # asset rule and tar reader, fake LUKS runner with the real LuksDisk, secret plan, supervisor
pnpm --filter @sealed/devnet typecheck
```
