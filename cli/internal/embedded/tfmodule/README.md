# customer-bootstrap

Terraform for `sealed bootstrap` (alias `sealed connect gcp`, spec 8.4, D-032). The customer runs it with their own
credentials, in Cloud Shell or anywhere with gcloud. The `sealed` binary embeds this module, writes it to a work
directory together with `terraform.tfvars.json`, runs `terraform init` and `apply`, and turns the outputs into the
`sct_` connection token.

## What it creates

| resource | name | notes |
|---|---|---|
| APIs | compute, secretmanager, cloudkms, run, iam, iamcredentials, artifactregistry, logging, storage | never disabled on destroy |
| VPC and subnet | `sealed-vpc`, `sealed-subnet` (10.42.0.0/24) | no auto subnets, IPv4 only, no private Google access (VMs have no identity) |
| firewall | `sealed-allow-web-ingress`, `sealed-deny-ingress`, `sealed-allow-egress`, `sealed-deny-egress` | ingress tcp 80 and 443 to VMs tagged `sealed-vm` only; egress tcp 443, tcp and udp 53 only; everything else denied, SSH included |
| KMS | key ring `sealed`, key `sealed-kb-hmac` (HMAC_SHA256) | `deletion_policy = PREVENT` and `prevent_destroy`: losing or rotating it makes every data disk unreadable, so the broker pins version 1; authoritative key policy, only the key broker may use it |
| key broker | Cloud Run `sealed-key-broker`, service account `sealed-key-broker` | image pinned by digest (ghcr.io pulled through the Artifact Registry remote repository `sealed-ghcr`, digest unchanged); `secretAccessor` with an IAM condition on `projects/<number>/secrets/sealed-*`; `logging.logWriter` for its decision log; no SSH; one instance by default (single-use nonces); 1 vCPU, 1 GiB with `GOMEMLIMIT=768MiB`; request timeout 120 s (above the broker's 90 s release deadline); invoker IAM off because VMs have no identity, every release is gated by the TDX quote and the onchain approval; authoritative empty policy on its service account |
| deployer | service account `sealed-deployer` | custom role `sealedDeployer` (create, start, stop, delete, get instances; create, delete, use disks; use images) granted only with a condition on `sealed-*` instance and disk names in the region's zones and `sealed-*` images of the project; `sealedDeployerAddresses` (static IPs and operation polling, which IAM Conditions cannot scope by name); `sealedSubnetUser` on `sealed-subnet` only; authoritative policy: `serviceAccountTokenCreator` for the platform service account and nothing else |
| boot bucket | `<project>-sealed-boot` | private staging for the dstack shared disk image `sealed deploy` builds; objects expire after 7 days |
| debug log writer (optional) | service account `sealed-debug-logs` | only with `enable_debug_logging = true` (`sealed bootstrap --debug-logging`); `logging.logWriter` and nothing else; authoritative empty policy on the account, so the deployer can never attach it; see "Debug VMs" below |

The deployer cannot read secrets, change the key broker or its key, act as any service account, attach one to a VM,
use OS Login or IAP, or read the serial port (P4). `scripts/iam-checks/check.sh` checks this against a live project.

Known limits:

- Static IPs are not name-conditionable, so the deployer can create and release any regional static IP in the
  project. Use a dedicated project.
- `compute.instances.setMetadata` is needed to create VMs with metadata, so the deployer can edit metadata of
  `sealed-*` VMs (for example add `ssh-keys`). The production image has no SSH daemon, no getty and the firewall
  drops port 22, so this does not open a shell.

## Inputs

`project_id`, `region` (us-central1), `customer_address`, `platform_service_account`, `key_broker_image`
(registry/path@sha256:digest; the all-zero placeholder is refused), `tempo_rpc_url`, `chain_id`, the three registry
addresses, `release_asset_base`, and optional `subnet_cidr`, `kms_protection_level` (SOFTWARE or HSM),
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

Cloud Run sets `PORT` to the container port, 8080, and the broker takes its log resource region from the metadata
server. The broker's flag defaults are the mainnet values, so a variable it did not read would silently replace
the customer's choice, and it refuses any other `SEALED_*` or `TEMPO_*` variable. `cli/internal/bootstrap`
`TestKeyBrokerEnvContract` renders the module with Terraform and runs the broker's own `loadConfig` on the result
(this checkout's `key-broker/`, else the git ref `SEALED_KEY_BROKER_REF`, else `ws/integration` or
`ws/key-broker`): the broker must accept the environment, every variable but the recorded project number must
change its outcome when dropped or garbled, and every customer choice must reach its effective config.
`tests/plan.tftest.hcl` checks that the Cloud Run env equals the module's map, and the broker's own test parses
the `env` blocks of `key_broker.tf`. Add a variable in the module, in `key_broker.tf` and in the broker together.

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
`vm_tag`, `deployer_service_account`, `key_broker_service_account`, `key_broker_url`, `tempo_rpc_url`, `chain_id`,
`key_broker_env`, `key_broker_image`, `kms_key`, `kms_key_version`, `secret_prefix`, `boot_bucket`,
`debug_log_service_account` (empty unless enabled).

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
