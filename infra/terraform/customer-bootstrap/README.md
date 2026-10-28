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
| key broker | Cloud Run `sealed-key-broker`, service account `sealed-key-broker` | image pinned by digest (ghcr.io pulled through the Artifact Registry remote repository `sealed-ghcr`, digest unchanged); `secretAccessor` with an IAM condition on `projects/<number>/secrets/sealed-*`; no SSH; one instance by default (single-use nonces); invoker IAM off because VMs have no identity, every release is gated by the TDX quote and the onchain approval; authoritative empty policy on its service account |
| deployer | service account `sealed-deployer` | custom role `sealedDeployer` (create, start, stop, delete, get instances; create, delete, use disks; use images) granted only with a condition on `sealed-*` instance and disk names in the region's zones and `sealed-*` images of the project; `sealedDeployerAddresses` (static IPs and operation polling, which IAM Conditions cannot scope by name); `sealedSubnetUser` on `sealed-subnet` only; authoritative policy: `serviceAccountTokenCreator` for the platform service account and nothing else |
| boot bucket | `<project>-sealed-boot` | private staging for the dstack shared disk image `sealed deploy` builds; objects expire after 7 days |

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
`key_broker_max_instances`, `key_broker_deletion_protection`, `create_boot_bucket`, `enable_apis`, `labels`.

The key broker reads its settings from the environment: `SEALED_CUSTOMER_ADDRESS`, `SEALED_GCP_PROJECT`,
`SEALED_GCP_PROJECT_NUMBER`, `SEALED_SECRET_PREFIX` (`sealed-`), `SEALED_KMS_KEY_VERSION`, `TEMPO_RPC_URL`,
`TEMPO_CHAIN_ID`, `SEALED_PLATFORM_REGISTRY`, `SEALED_APP_REGISTRY`, `SEALED_DEPLOYMENT_REGISTRY`,
`SEALED_RELEASE_ASSET_BASE`.

## Outputs

`project_id`, `project_number`, `region`, `customer_address`, `network`, `subnetwork`, `subnetwork_self_link`,
`vm_tag`, `deployer_service_account`, `key_broker_service_account`, `key_broker_url`, `key_broker_image`,
`kms_key`, `kms_key_version`, `secret_prefix`, `boot_bucket`.

## Tests

```sh
terraform init -backend=false && terraform validate && terraform fmt -check -recursive
terraform test     # tests/plan.tftest.hcl: plan-only with a mocked google provider, no credentials
go test ./scripts/iam-checks/   # renders modules/iam and checks the IAM documents
```

`modules/iam` holds every permission list, IAM condition and policy document as plain locals (no providers), so
they can be rendered and tested without credentials. The provider is pinned to hashicorp/google 8.7.0
(`.terraform.lock.hcl` has the hashes for every platform).
