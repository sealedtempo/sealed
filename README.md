# Sealed

Every app is built from public source, pinned, scanned, signed and reviewed. You can verify that exactly that build is what runs.

Your data stays in your cloud account. Apps run in confidential VMs, we have no access path, and outbound traffic only reaches destinations you approve.

Your wallet approves exactly which builds can unlock your data.

Limits: confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access.

Sealed deploys a catalog of open-source apps into Intel TDX confidential VMs ([dstack](https://github.com/Dstack-TEE/dstack) on Google Cloud C3) inside the customer's own Google Cloud project. App releases, platform images, stack approvals, deployment records and fee payments live on Tempo mainnet (chain id 4217). Fees and maintainer payouts settle in USDC.e on Tempo, and inference through the platform relay is paid per token over MPP (Machine Payments Protocol).

This is the public repository: everything that runs in a customer's cloud is here, under Apache-2.0. The platform control plane (api, oracle, indexer, console) is in a separate private repository; nothing in this repository needs it to check a deployment.

## Documentation

| document | what it covers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, diagrams, networks inside a VM, the password gate, payments and the inference relay |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | what is and is not protected, trust anchors, the measurement chain on Google Cloud, attacks and the tests that cover them, residual risks |
| [docs/VERIFY.md](docs/VERIFY.md) | how anyone verifies a deployment with `sealed verify`, and how to do it with standard tools only |
| [docs/MAINTAINERS.md](docs/MAINTAINERS.md) | how to submit an app, the catalog rules, review, payouts and reproducible release bundles |
| [docs/ZK_UPGRADE.md](docs/ZK_UPGRADE.md) | how attestation method 2 (ZK proofs of TDX quote verification) plugs into the deployed contracts |
| [docs/INTERFACES.md](docs/INTERFACES.md) | formats, hashes and endpoints shared between components |
| [runtime/composer/README.md](runtime/composer/README.md) | the authoritative contract for app fragments and the composed stack |
| [contracts/README.md](contracts/README.md) | the five contracts, their rules and the contract review |

## Repository map

| path | what it is | language |
|---|---|---|
| `contracts/` | PlatformRegistry, AppRegistry, DeploymentRegistry, OracleSignatureVerifier, FeeSplitter; `deployments/tempo-mainnet.json` is the source of truth for addresses | Solidity, Foundry |
| `catalog/schema/` | manifest JSON schema (`sealed-manifest/v1`) | JSON Schema |
| `catalog/apps/<id>/` | one directory per app: `manifest.yaml`, `compose.fragment.yaml`, `egress.yaml`, `README.md`, `LICENSE-NOTICE`, `waivers.yaml` | YAML |
| `catalog/tools/` | shared catalog lint wrappers and the release tooling used by CI | Go, Node, Python |
| `runtime/composer/` | deterministic stack composer, canonical JSON, catalog lint, `sealed-compose` debug CLI | Go |
| `runtime/egress/` | sealed-egress: the HTTP(S) proxy and filtering DNS server of every VM | Go |
| `runtime/caddy/` | Caddyfile template (TLS, routes, forward_auth gate) and the payment-needed page | Caddyfile, Go |
| `runtime/envexec/` | static entrypoint wrapper: waits for secrets, exports only declared ones | Go |
| `runtime/agent/` | sealed-agent: key release, data disk, secrets, evidence, `/attest`, gate, metering, fee payments; dstack simulator | TypeScript |
| `runtime/mpp-payer/` | sealed-mpp-payer: verifies the relay and pays it per token over MPP | TypeScript |
| `runtime/relay/` | inference relay front (mppx server) and provider attestation sidecars | TypeScript |
| `runtime/images/local-model/` | Ollama image with the baked local model (Qwen3-4B-Instruct-2507, Apache-2.0) | Dockerfile, Go, Python |
| `packages/core/` | `@sealed/core`: chain, ABIs, EIP-712 types, CJSON twin, report_data builders, pricing | TypeScript |
| `verifier/` | verification library and `sealed-verifierd` (TDX quotes, RTMR3 replay, stack recomputation, chain checks) | Go |
| `key-broker/` | the customer's key broker (Cloud Run): releases secrets only to attested, approved stacks | Go |
| `cli/` | the `sealed` command line: bootstrap, secrets, deploy, verify, catalog, release build | Go |
| `infra/terraform/customer-bootstrap/` | what `sealed bootstrap` creates in the customer project | Terraform |
| `scripts/iam-checks/` | spec 8.6 IAM checks run as the platform's deployer identity | Bash, Go |
| `config/defaults.yaml` | public defaults every component reads (prices, caps, chain, networks, TCB policy, registry) | YAML |
| `.github/workflows/` | catalog checks, tests, release and runtime image builds | GitHub Actions |

The catalog holds six apps: `llm-gateway` (LiteLLM MIT core with a local Ollama model), `scraper` (first-party, Crawlee), `crm` (EspoCRM, D-049a), `coding-agent` (OpenHands agent-server), `internal-tools` (ToolJet CE, D-018a), and `inference-relay`, the platform's own relay stack, released and approved like any other app.

## Quick start for developers

Requirements: Go 1.26 or newer (the `go` directive in `go.mod`), Node 22 or newer with pnpm 10.33.2, Foundry 1.7.1 (`anvil --network tempo`), Python 3 with PyYAML, httpx and jsonschema for the catalog tests, Terraform for the bootstrap module tests, and the docker CLI (only `docker compose config` is used by the tests; no daemon is needed).

```sh
git clone https://github.com/sealedtempo/sealed && cd sealed
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 pnpm install --frozen-lockfile
make -C contracts deps          # forge soldeer install; contracts/dependencies is not committed
pnpm -r build                   # the agent simulator CLI test and the relay smoke test use dist/
go build ./... && go vet ./...
```

### Run the tests

```sh
make test                       # go test ./..., pnpm -r test, make -C contracts test
```

Per component, with the switches that turn silent skips into failures (CI sets them):

```sh
go test -count=1 ./...                                         # composer, egress, caddy, envexec, verifier, key broker, CLI
SEALED_REQUIRE_ANVIL=1 go test -race ./verifier/...            # verifier anvil suites must run
make -C key-broker test-ci                                     # production and dev builds, anvil and TypeScript interop
SEALED_REQUIRE_CHAIN_TESTS=1 pnpm -r --workspace-concurrency=1 test
make -C contracts test                                         # unit, fuzz, invariants, audit regressions
make -C contracts test-fork                                    # against Tempo mainnet over https://rpc.tempo.xyz, read only
for d in catalog/apps/llm-gateway catalog/apps/coding-agent runtime/images/local-model; do make -C "$d" test; done
for d in catalog/apps/crm catalog/apps/internal-tools; do (cd "$d" && pnpm install --ignore-workspace --frozen-lockfile && pnpm test); done
go run ./runtime/composer/cmd/sealed-compose lint --catalog catalog/apps
go test ./scripts/iam-checks/
```

The full suite is heavy (Postgres-backed scraper and relay tests, anvil chains, a real-composer catalog boot). On a shared machine run one area at a time.

### The local devnet end to end

Every end-to-end path runs on a local Tempo devnet, `anvil --network tempo`, with the real contracts built from `contracts/`. No mainnet transaction is sent and no cloud resource is touched. TDX quotes come from the dstack simulator (`runtime/agent/sim`), which production verifiers and key brokers refuse.

| command | what it runs |
|---|---|
| `make -C contracts local-e2e` | deploys the five contracts on anvil and drives registration, approval, records, heartbeats, fees, top-ups and withdrawals with `cast` |
| `SEALED_REQUIRE_ANVIL=1 go test -count=1 -v -run TestComposedStackEndToEnd ./verifier/cmd/sealed-verifierd/` | bundles served like a GitHub release, releases published onchain, `/v1/compose`, the customer's approval, a simulated quote, the oracle's registration, a passing evidence bundle, then evidence, asset, cache and chain tamper cases that each fail exactly the expected checks |
| `SEALED_REQUIRE_CHAIN_TESTS=1 pnpm --filter @sealed/agent test` | includes `test/catalog.e2e.test.ts`: the real composer composes the catalog apps, the agent boots on that app-compose against the simulator and a fake key broker, and the verifier library checks its evidence |
| `make -C key-broker test-ci` | key release against the real registries on anvil, 54 denial cases, and a boot written only with `@sealed/core` released by the Go broker |
| `go test -count=1 -run TestAnvilEndToEnd ./cli/internal/app/` | the `sealed` CLI against a local Tempo node with the real registries |
| `SEALED_REQUIRE_CHAIN_TESTS=1 pnpm --filter @sealed/mpp-payer test` | MPP charges and sessions from an access key over the emulated escrow, drawing on the shared spend budget |

To run the agent by hand against the simulator:

```sh
node runtime/agent/dist/sim.js --app-compose app-compose.json --socket /tmp/dstack.sock
SEALED_DEV_SIM=1 DSTACK_SIMULATOR_ENDPOINT=/tmp/dstack.sock SEALED_DISK_MODE=dir node runtime/agent/dist/main.js
```

Every development switch needs `SEALED_DEV_SIM=1`, and reports produced from simulated quotes say `simulated: true`.

## Quick start for customers

You need a Google Cloud project with C3 Intel TDX quota, a Tempo wallet holding USDC.e, and the `sealed` CLI (`go build -o sealed ./cli/cmd/sealed`).

1. Bootstrap your project with your own credentials (Cloud Shell works). This creates the VPC, firewall rules, a Cloud KMS HMAC key, the key broker on Cloud Run with its own service account, and a deployer service account that the platform may impersonate only to create, start, stop and delete `sealed-*` VMs, disks and addresses. It prints a connection token.

   ```sh
   sealed bootstrap --project <project> --region us-central1 --customer-address <your wallet> --platform-sa <platform service account> --plan
   sealed bootstrap --project <project> --region us-central1 --customer-address <your wallet> --platform-sa <platform service account>
   ```

   `sealed connect gcp --project <project> ...` is the same command.

2. Store the gate password and the app secrets in your own Secret Manager. Generated secrets never leave your project except to an attested VM.

   ```sh
   sealed secrets set gate --generate
   sealed secrets set --config stack.yaml --missing
   ```

3. Deploy from the console, or without it: `sealed deploy --config stack.yaml --plan` resolves the releases onchain, fetches their bundles by hash, composes the stack and prints the stackHash and the exact `approveStack` call for your wallet. Once your wallet approved it, `sealed deploy --config stack.yaml` creates the confidential VM.

4. Check it yourself when it has booted:

   ```sh
   sealed verify --deployment <0x deploymentId> --live https://attest.<ip-with-dashes>.sslip.io/attest
   ```

## Verify a deployment

Anyone with the evidence bundle and a Tempo RPC endpoint can check a deployment without trusting the platform:

```sh
sealed verify --deployment 0x<deploymentId> --evidence evidence.json --rpc https://rpc.tempo.xyz
```

The command checks the TDX quote against Intel's root of trust and the TCB policy, the image measurements against PlatformRegistry, the RTMR3 replay against the stackHash, recomputes the stack from the onchain releases and their public bundles, and checks the releases, the customer's approval and the onchain record on Tempo. It prints a report, can write JSON, and exits non-zero on any failure. [docs/VERIFY.md](docs/VERIFY.md) explains every check and how to repeat each one with standard tools.

## Contracts on Tempo mainnet

Deployed at block 46314877 and source-verified at https://contracts.tempo.xyz. Fee token: USDC.e `0x20c000000000000000000000b9537d11c60e8b50` (6 decimals).

| contract | address |
|---|---|
| PlatformRegistry | `0x18AB956ea44757587896dfD25632FB3e89F7002d` |
| AppRegistry | `0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43` |
| OracleSignatureVerifier (method 1) | `0xf680E602758222d5aE1CcD797a03022bCE2dd353` |
| DeploymentRegistry | `0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E` |
| FeeSplitter | `0x3D288c0756c3F26Da0f41257D688bAB3dB3d94AD` |

Attestation method 2 (`ZK_DCAP_V1`) is reserved and unset; see [docs/ZK_UPGRADE.md](docs/ZK_UPGRADE.md).

## Status (2026-10-28)

- Contracts: deployed on mainnet and source-verified after a three-lens security review (no critical or high findings; every medium finding fixed). See `contracts/README.md`.
- Runtime, catalog packages, verifier, key broker and CLI: built and tested locally and on the local devnet. The first boots on real TDX hardware are in progress, so the platform image measurements are not registered yet and will be recorded trust-on-first-use (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).
- The acceptance tests on mainnet and Google Cloud (bootstrap, deploy, verify, tamper, egress, fees, MPP, reboot, destroy) have not run yet. Until they do, every claim in these documents is backed by local tests only.
- The fresh security review of the key broker, egress and agent is pending.

## License

Apache-2.0. See [LICENSE](LICENSE). Each catalog app ships its upstream license and source link in `catalog/apps/<id>/LICENSE-NOTICE` and in its release bundle under `LICENSES/`.
