# sealed CLI

One Go binary (spec 8.4). Build it with `go build -o sealed ./cli/cmd/sealed`. It embeds `config/defaults.yaml`,
`contracts/deployments/tempo-mainnet.json`, the registry ABIs and `infra/terraform/customer-bootstrap`, so it works
outside a checkout (Cloud Shell included). `--defaults`, `--deployments` and `--rpc` (or `SEALED_DEFAULTS_FILE`,
`SEALED_DEPLOYMENTS_FILE`, `TEMPO_RPC_URL`) point it elsewhere.

Google Cloud calls use your own credentials: `SEALED_GCP_ACCESS_TOKEN` (or `GOOGLE_OAUTH_ACCESS_TOKEN`), else
`gcloud auth print-access-token`, else an `authorized_user` application default credentials file. Tokens are
never printed. The CLI only reads Tempo (eth_call); it holds no keys and sends no transactions.

## Commands

```sh
sealed bootstrap --project <id> --customer-address <0x...> --platform-sa <email> \
  --key-broker-image ghcr.io/sealedtempo/key-broker@sha256:<digest> [--region us-central1] [--plan] [--yes]
sealed connect gcp --project <id> ...                  # the same command (D-032)

sealed secrets set --config stack.yaml --missing       # generate or ask for every required secret, once
sealed secrets set <app> <NAME> --value-file <file>    # or --stdin, or --generate [--kind hex32]
sealed secrets set gate --generate                     # gate password, shown once, stored as its bcrypt hash
sealed secrets list --config stack.yaml                # set, missing, optional, same as
sealed secrets rm <app> <NAME> [--yes]

sealed deploy --config stack.yaml [--plan] [--wait-approval 10m] [--write-config config.json] [--replace]
sealed verify --deployment <0x id | dep_ alias> [--evidence file] [--live https://attest.<ip>.sslip.io/attest] [--json]
sealed catalog list | show <app> [--json]
sealed release build <app> [--out bundle.tar] [--check <version|latest>]
```

Exit codes: 0 success, 1 failure (any failed verification check included), 2 usage, 3 `deploy` stopped because the
wallet has not approved the stack.

### bootstrap

Writes the module to `<user config dir>/sealed/bootstrap/<project>` (or `--work-dir`), with the Terraform state
there or in `--state-bucket`, and runs `terraform init` and `apply` with your token. `--plan` only plans. It refuses
a key broker image that is not pinned by digest or still has the all-zero placeholder. The output is the `sct_`
token: `sct_` + base64url(JSON) with `v`, `project`, `region`, `deployerAccount`, `keyBrokerUrl`, `customer`,
`subnetwork` and `issuedAt`. It holds no secret.

### secrets

Secrets are Secret Manager entries `sealed-<app>-<NAME>` in your project; the key broker can read only `sealed-*`.
Manifests come from `--catalog <catalog/apps>` (default `./catalog/apps` when present) or from the release bundles
of `--config` (fetched by onchain bundleHash). Generators: `hex32` (64 hex), `base64-32` (44 base64), `sk-hex32`
(`sk-` + 64 hex), `password` (24 of [A-Za-z0-9]); `none` means you supply the value. A secret declared with
`same_as: <app>/<NAME>` is stored once, under the referenced app, and the key broker hands it to both apps, but
only when the referenced secret opts in: its own manifest entry must list the referencing app in
`share_with: [<appId>]` (D-059; llm-gateway's `APP_KEY_CODING_AGENT` declares `share_with: [coding-agent]`). The
CLI applies the composer's rules before it stores anything: the referenced app is in the stack and declares the
secret, which is not itself a reference, is shared with the referencing app, and is not optional when the
reference is required. `set --missing`, `list` and `deploy` refuse a stack that breaks them, and
`set <app> <NAME>` on an unshared reference says so. An existing secret is never overwritten without `--rotate`. Values are never taken from flags, printed or read back,
except a generated gate password, which is shown once. `sealed-gate-password` holds the bcrypt hash (cost 12) of
the gate password, so the VM never sees the password itself.

### deploy

Reads `stack.yaml` (`sealed-deploy/v1`, see `examples/stack.yaml`), resolves each app's release on AppRegistry
(`latest`, a version or a releaseId), fetches the bundles by onchain bundleHash, reserves the static IP (the
sslip hostnames are part of the config), composes the stack with `runtime/composer`, and checks: the image is
approved and not debug; `isStackApproved` and the approval's releases and image equal the stack's (D-014); every
required secret has a value. Until your wallet approved exactly that stackHash it prints the `approveStack`
arguments and stops (exit 3) without creating anything else. Then it builds the dstack shared disk (FAT volume
`DSTACKSHR` with `app-compose.json`, `.sys-config.json`, `.instance_info`) as an image through the boot bucket,
creates the `sealed-<name>-data` disk (kept across redeploys) and the VM: TDX, host maintenance TERMINATE, no
service account and so no scopes, `enable-oslogin=FALSE`, `serial-port-enable=FALSE`,
`serial-port-logging-enable=FALSE`, `block-project-ssh-keys=TRUE`, tag `sealed-vm`, NVMe pd-balanced disks, the
static IP. It reads the VM back and fails if the stored VM differs from spec 5.9. `--as-deployer` acts as the
bootstrap's deployer account (only the platform service account can impersonate it, so this is for the operator;
the deployer cannot create the shared disk image, see the build note).

#### Salt, data disk and upgrades (D-058)

The key broker derives the data disk key and the enclave signer seed from `(customer, salt)`, not from the
deploymentId. The salt is `salt:` in the stack file, or by default `sha256("sealed/deploy-salt/v1\0" || project ||
"\0" || name)`: it depends only on the project and the name, never on the apps, releases, image or config. So an
upgrade (new releases, another image, a changed config) gets a new stackHash and a new deploymentId, but keeps the
salt, and with it the disk key and the signer address. The broker still releases them only to a stack the wallet
approved.

A new salt means a fresh disk: the old disk cannot be opened with the new key. To start over, deploy under a new
`name` (new disk `sealed-<name>-data`), or set a new `salt:` after removing the old disk yourself. Deploy labels
the data disk with `sealed-disk-id` (the first 20 bytes of `sha256("sealed/data-disk/v1\0" || customer || "\0" ||
salt)`, nothing secret) and `sealed-variant`, and refuses to attach a disk created for another wallet or salt,
before it touches the running VM. A disk created before these labels gets a warning.

When the VM `sealed-<name>` already runs this deploymentId, deploy changes nothing. When it runs another one,
deploy stops and says so; `--replace` performs the upgrade: it checks that the old VM's `sealed-data` disk is the
stack's data disk and is not auto-deleted, deletes the old VM (its boot, system and shared disks go with it),
and creates the new VM on the same data disk and static IP. Approve the new stack first (exit 3 shows the
`approveStack` arguments).

#### Debug images (spec 5.8)

A debug image (PlatformRegistry `isDebug`) is for development only. PlatformRegistry never approves it, so
`approveStack` cannot name it and the key broker releases no secrets, disk key or signer seed to it. Deploy refuses
a debug image unless the stack file sets `image.debug: true`, and refuses `image.debug: true` on a production
image. For a debug image it skips the approval and secrets gates, sets `debug: true` in the config when the
composer has that switch (the local logging driver the image's exporter reads), labels the VM and its data disk
`sealed-variant=debug`, and attaches the bootstrap's `sealed-debug-logs` account (create it with
`sealed bootstrap --debug-logging`) with only the `logging.write` scope. That is the one exception to "no service
account"; a production VM never gets one, and the read-back check fails a production VM with any identity and a
debug VM with any other identity or scope. A debug VM never gets a production deployment's data disk (use another
name). Debug deploys run with your own credentials: the deployer cannot attach a service account (spec 8.6), so
`--as-deployer` is refused.

### verify

Runs the verifier library (`verifier/`): quote and TCB with Intel collateral (cached under the user cache dir),
image measurements against PlatformRegistry, RTMR3 replay, stack recomputation from the onchain releases (bundles
fetched by bundleHash), active releases, the customer's approval and its release set, the onchain record, the
enclave signer binding; with `--live`, a fresh nonce and the TLS key binding. Every chain read of one check runs
at one block. A `dep_` alias is resolved through `--api` (`POST /v1/verify`); without `--evidence` or `--live` the
evidence is downloaded from `--api` (`SEALED_API_KEY` as bearer). The platform is never trusted for a check: the
deployment id it resolves is required to match the evidence and the chain. Prints a readable report, or JSON
with `--json`; `--report <file>` writes the JSON too. `--dev-*` flags (simulated quotes, self-signed or private
attest hosts) need `SEALED_DEV_SIM=1` and reports then say simulated.

### catalog, release build

`catalog list` and `show` read AppRegistry (`appCount`, `appAt`, `getApp`, `latestRelease`, `releaseAt`,
`getRelease`); `show` downloads the latest bundle, checks it against bundleHash and prints its manifest.
`release build <app>` builds the deterministic bundle from `catalog/apps/<app>` and prints the publishRelease
arguments; `--check` rebuilds a published release with the SBOMs and scans of the published bundle (CI generates
them) and must match the onchain bundleHash byte for byte, or lists the files that differ.

## Release archives and licenses

```sh
go run ./cli/release --version 0.1.0 --out dist        # darwin, linux (amd64, arm64) and windows/amd64, plus SHA256SUMS
go run ./cli/release --version 0.1.0 --licenses-only dist/licenses   # only the license tree, for this host
```

The binary statically links go-ethereum (LGPL-3.0-or-later) and about 27 other modules (BSD, MIT, Apache-2.0,
ISC) and the Go standard library, so every release archive (`sealed_<version>_<os>_<arch>.tar.gz`, `.zip` for
Windows) carries, next to the binary, the repository `LICENSE` (Apache-2.0), this README and `licenses/`: the
license, notice, patents and authors files of every linked module (from the module root and from the linked
packages' own directories, so `go-ethereum/metrics/LICENSE` is there too), go-ethereum's `COPYING.LESSER`
(LGPL-3.0) and `COPYING` (GPL-3.0), the Go distribution's `LICENSE` and `PATENTS`, and `licenses/README`. That
README is the LGPL section 4 notice: which library, which license, where the texts are, and the corresponding
source (`https://github.com/sealedtempo/sealed/tree/cli-v<version>`, whose `go.mod` and `go.sum` pin the library,
with the `go mod edit -replace` step to relink against a modified copy). The module set is taken from
`go list -deps` for each target, exactly as the build links it. The tool refuses a linked module without any
license text, or one under the GPL or AGPL without the LGPL, and `--version` must equal the CLI's version. Builds
use `CGO_ENABLED=0 -trimpath -buildvcs=false` and an empty build id, and archives are reproducible (sorted
entries, owner 0, `SOURCE_DATE_EPOCH` or 1980-01-01 as the time). `sealed version` points at `licenses/`.

## Tests

```sh
go test ./cli/...
SEALED_REQUIRE_ANVIL=1 SEALED_CONTRACTS_DIR=$PWD/contracts go test ./cli/internal/app -run Anvil   # local Tempo node
SEALED_REQUIRE_TERRAFORM=1 go test ./cli/internal/bootstrap                                          # terraform validate
SEALED_REQUIRE_KEY_BROKER=1 go test -run TestKeyBrokerEnvContract ./cli/internal/bootstrap           # the broker's parser on the bootstrap env
go generate ./cli/internal/embedded    # after config/defaults.yaml, the deployments, ABIs or the module change
```

Unit and command tests run against fakes (Secret Manager, Compute Engine, Terraform, an in-memory registry, a
bundle server) with real bundles and the real composer. The anvil test deploys the real registries on
`anvil --network tempo` and runs catalog, release build, deploy and verify against them.
