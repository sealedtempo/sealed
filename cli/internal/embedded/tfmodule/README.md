# customer-bootstrap

Terraform for `sealed bootstrap` (alias `sealed connect gcp`, spec 8.4, D-032). The customer runs it with their own
credentials, in Cloud Shell or anywhere with gcloud. The `sealed` binary embeds this module, writes it to a work
directory together with `terraform.tfvars.json`, runs `terraform init` and `apply`, and turns the outputs into the
`sct_` connection token.

## What it creates

| resource | name | notes |
|---|---|---|
| APIs | compute, secretmanager, cloudkms, run, iam, iamcredentials, artifactregistry, logging, storage | never disabled on destroy |
| VPC and subnet | `sealed-vpc`, `sealed-subnet` (10.42.0.0/24) | no auto subnets, IPv4 only, no private Google access (VMs have no identity); the subnet's description is the connection binding (below) |
| firewall | `sealed-allow-web-ingress`, `sealed-deny-ingress`, `sealed-allow-egress`, `sealed-deny-egress` | ingress tcp 80 and 443 to VMs tagged `sealed-vm` only; egress tcp 443, tcp and udp 53 only; everything else denied, SSH included |
| KMS | key ring `sealed`, key `sealed-kb-hmac` (HMAC_SHA256) | `deletion_policy = PREVENT` and `prevent_destroy`: losing or rotating it makes every data disk unreadable, so the broker pins version 1; authoritative key policy, only the key broker may use it |
| key broker | Cloud Run `sealed-key-broker`, service account `sealed-key-broker` | image pinned by digest (ghcr.io pulled through the Artifact Registry remote repository `sealed-ghcr`, digest unchanged); `secretAccessor` with an IAM condition on `projects/<number>/secrets/sealed-*`; `logging.logWriter` for its decision log; no SSH; one instance by default (single-use nonces); 1 vCPU, 1 GiB with `GOMEMLIMIT=768MiB`; request timeout 120 s (above the broker's longest release request: 10 s body read, 90 s release deadline, 15 s decision log write); up to 80 concurrent requests per instance (the broker bounds its own work and answers 429 itself); invoker IAM off because VMs have no identity, every release is gated by the TDX quote and the onchain approval; authoritative empty policy on its service account |
| deployer | service account `sealed-deployer` | custom role `sealedDeployer` (create, start, stop, delete, get instances; create, delete, use disks; create, get, delete and use images) granted only with a condition on `sealed-*` instance and disk names in the region's zones and `sealed-*` images of the project; `sealedDeployerAddresses` (static IPs and zone, region and global operation polling, which IAM Conditions cannot scope by name); `sealedSubnetUser` on `sealed-subnet` only (use it, attach external IPs, read its binding); `roles/storage.objectAdmin` on the staging bucket only; authoritative policy: `serviceAccountTokenCreator` for the platform service account and nothing else |
| boot bucket | `<project>-sealed-boot` | private staging for the dstack shared disk image `sealed deploy` builds and for the OS release tarballs `sealed bootstrap` imports; objects expire after 7 days; the deployer has no access |
| staging bucket | `<project>-sealed-staging` | private staging for the shared disk images the platform publishes with the deployer's token (D-074); uniform access, public access prevention enforced, objects deleted after 1 day |
| debug log writer (optional) | service account `sealed-debug-logs` | only with `enable_debug_logging = true` (`sealed bootstrap --debug-logging`); `logging.logWriter` and nothing else; authoritative empty policy on the account, so the deployer can never attach it; see "Debug VMs" below |

The deployer cannot read secrets, change the key broker or its key, act as any service account, attach one to a VM,
use OS Login or IAP, or call `getSerialPortOutput` (P4). `scripts/iam-checks/check.sh` checks this against a live
project.

Known limits:

- Sealed needs a dedicated project. Static IPs and operations are not name-conditionable, so the deployer's address
  rights are project-wide: it can reserve, attach and release any regional static IP in the project, not only
  `sealed-*` ones.
- `compute.instances.setMetadata` is needed to create VMs with metadata, so the deployer can edit the metadata of
  `sealed-*` VMs at any time: it can set `serial-port-enable` to TRUE, which turns on the interactive serial
  console, and add `ssh-keys`. The production image has no SSH daemon, no getty and no login, and the firewall
  drops port 22, so this does not open a shell, but the serial console then shows the VM's console output.
  `check.sh` warns about it. The `compute.disableSerialPortAccess` organization policy blocks the serial console
  for the whole project.
- The deployer can create and delete `sealed-*` images (D-074), including the boot and system disk images
  `sealed bootstrap` creates. A replaced boot image measures differently, so the key broker refuses it. Running
  `sealed bootstrap` again restores a deleted image and refuses one that does not match the release.

### Connection binding

The description of `sealed-subnet` is exactly

```
sealed-binding/v1 customer=<customer_address, lowercase> key_broker=<the key broker's Cloud Run URL>
```

The platform reads it with the deployer's token (`compute.subnetworks.get`, granted on this subnet only) and refuses
a connection when the wallet or the key broker URL differ from the connecting wallet's session and its connection
token, so no other wallet can register this project. The deployer cannot change it, and Compute Engine sets a
subnet's description only when the subnet is created. The `connection_binding` output shows it.

### Boot and system disk images (D-075)

After the apply, `sealed bootstrap` creates the images every deployment in this project boots from, with the
customer's own credentials:

- `sealed-dstack-os-<version>` and `sealed-dstack-os-debug-<version>` (the version with dots as dashes, for example
  `sealed-dstack-os-0-6-1-s1`), imported from the OS image release assets
  `<release asset base>/os-image-v<version>/<name>-<version>-gce.tar.gz`. Each tarball's sha256 must match the
  release's `<name>-<version>-hashes.txt` before it is uploaded to the boot bucket and imported.
- `sealed-dstack-data-v1`, the dstack system disk: a 10 MiB GPT disk with one partition named `dstack-data`, the
  disk `sgdisk -o -n 1:0:0 -c 1:dstack-data` makes and `runtime/images/dstack-os/import-and-measure.sh` boots with.
  The CLI builds it itself.

It is idempotent: an image that exists and was made from the same tarball (its description carries the sha256) is
kept, and one made from different bytes stops the bootstrap. `--os-image-version` picks the release and
`--no-os-images` skips the step.

## Inputs

`project_id`, `region` (us-central1), `customer_address`, `platform_service_account`, `key_broker_image`
(registry/path@sha256:digest; the all-zero placeholder is refused), `tempo_rpc_url`, `chain_id`, the three registry
addresses, `release_asset_base`, and optional `fee_splitter` and `fee_token` (empty: mainnet's),
`key_broker_allowed_images` (empty: every image PlatformRegistry approves), `subnet_cidr`, `kms_protection_level` (SOFTWARE or HSM),
`key_broker_max_instances`, `key_broker_deletion_protection`, `enable_debug_logging` (false), `create_boot_bucket`,
`enable_apis`, `labels`.

### Key broker environment (the contract)

`modules/key-broker-env` (locals only, no providers) turns the inputs into exactly the variables
`key-broker/cmd/key-broker` reads (its README's configuration table), and `key_broker.tf` sets that map on the
Cloud Run service, one literal `env` block per name:

| variable | value | broker setting |
|---|---|---|
| `SEALED_CUSTOMER_ADDRESS` | `customer_address`, lowercase | `--customer` (required) |
| `TEMPO_RPC_URL` | `tempo_rpc_url` | `--tempo-rpc` |
| `TEMPO_CHAIN_ID` | `chain_id` | `--chain-id` |
| `SEALED_PLATFORM_REGISTRY`, `SEALED_APP_REGISTRY`, `SEALED_DEPLOYMENT_REGISTRY` | the registry addresses, lowercase | `--platform-registry`, `--app-registry`, `--deployment-registry` |
| `SEALED_RELEASE_ASSET_BASE` | `release_asset_base` | `--release-asset-base` |
| `SEALED_GCP_PROJECT` | `project_id` | `--project` (required) |
| `SEALED_GCP_PROJECT_NUMBER` | the project number | recorded |
| `SEALED_SECRET_PREFIX` | `sealed-` | must equal the prefix of the broker's IAM condition |
| `SEALED_KMS_KEY_VERSION` | `projects/<p>/locations/<region>/keyRings/sealed/cryptoKeys/sealed-kb-hmac/cryptoKeyVersions/1` | the HMAC key version (required, pinned to 1) |
| `GOMEMLIMIT` | `768MiB` | Go runtime, not broker configuration |

Set only when the customer chose a value (`optional_env` of the module, one `dynamic "env"` block per name in
`key_broker.tf`); without them the broker uses its mainnet defaults:

| variable | value | broker setting |
|---|---|---|
| `SEALED_FEE_SPLITTER` | `fee_splitter`, lowercase | `--fee-splitter`: config.contracts.feeSplitter must name it |
| `SEALED_FEE_TOKEN` | `fee_token`, lowercase | `--fee-token`: config.feeToken must name it |
| `SEALED_ALLOWED_IMAGES` | `key_broker_allowed_images`, lowercase, comma separated | `--allowed-images`: the customer's own imageIds on top of PlatformRegistry approval |

`sealed bootstrap` sets `fee_splitter` and `fee_token` from its deployments file (`--deployments`,
`SEALED_DEPLOYMENTS_FILE`) when they are not mainnet's, so a broker for other registries never checks fees against
mainnet's contracts; `--fee-splitter`, `--fee-token` and `--allowed-images` (or the same `SEALED_*` names in the
CLI's environment) set them explicitly.

Cloud Run sets `PORT` to the container port, 8080, and the broker takes its log resource region from the metadata
server. The broker's flag defaults are the mainnet values, so a variable it did not read would silently replace
the customer's choice, and it refuses any other `SEALED_*` or `TEMPO_*` variable. `cli/internal/bootstrap`
`TestKeyBrokerEnvContract` renders the module with Terraform and runs the broker's own `loadConfig` on the result
(this checkout's `key-broker/`, else the git ref `SEALED_KEY_BROKER_REF`, else `ws/integration` or
`ws/key-broker`): the broker must accept the environment, every variable but the recorded project number must
change its outcome when dropped or garbled, and every customer choice must reach its effective config (the
optional variables included). `tests/plan.tftest.hcl` checks that the Cloud Run env equals the module's map, and
the broker's own tests parse the `env` blocks of `key_broker.tf` (`TestBootstrapEnvContract`) and check its request
timeout and concurrency against the broker's limits (`TestBootstrapCloudRunLimits`). Add a variable in the module,
in `key_broker.tf` and in the broker together.

`sealed bootstrap` passes `--tempo-rpc`, or else the RPC the command itself was given (`--rpc` or `TEMPO_RPC_URL`),
or else the public RPC, and prints the RPC and chain the broker will use before it runs Terraform. The
`tempo_rpc_url` and `key_broker_env` outputs show them after the apply.

## Debug VMs

The debug OS image (`sealed-dstack-os-debug`, spec 5.8) sends container logs to Cloud Logging and needs a token for
that. It is the one exception to "no service account" (spec 5.9): with `enable_debug_logging = true` the bootstrap
creates `sealed-debug-logs`, which holds only `roles/logging.logWriter`, and `sealed deploy` attaches it with only the
`https://www.googleapis.com/auth/logging.write` scope to a VM whose stack file sets `image.debug: true` and whose
image PlatformRegistry marks as debug. A production image never gets it, and a debug image never gets production
secrets (PlatformRegistry never approves it, so the key broker refuses it). Nobody holds a role on the account
itself, the deployer included, so the platform cannot attach it (spec 8.6): debug VMs are created with the
customer's own credentials, and `scripts/iam-checks/check.sh` fails on any other VM identity.

## Outputs

`project_id`, `project_number`, `region`, `customer_address`, `network`, `subnetwork`, `subnetwork_self_link`,
`connection_binding`, `vm_tag`, `deployer_service_account`, `key_broker_service_account`, `key_broker_url`,
`tempo_rpc_url`, `chain_id`, `key_broker_env`, `key_broker_image`, `kms_key`, `kms_key_version`, `secret_prefix`,
`boot_bucket`, `staging_bucket`, `debug_log_service_account` (empty unless enabled).

## Tests

```sh
terraform init -backend=false && terraform validate && terraform fmt -check -recursive
terraform test     # tests/plan.tftest.hcl: plan-only with a mocked google provider, no credentials
go test ./scripts/iam-checks/   # renders modules/iam and checks the IAM documents
go test -run TestKeyBrokerEnvContract ./cli/internal/bootstrap/   # the broker's parser on modules/key-broker-env
```

`modules/iam` holds every permission list, IAM condition and policy document as plain locals (no providers), so
they can be rendered and tested without credentials. The provider is pinned to hashicorp/google 8.7.0
(`.terraform.lock.hcl` has the hashes for every platform).
