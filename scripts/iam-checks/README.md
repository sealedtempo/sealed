# IAM checks (spec 8.6)

`check.sh` checks a project bootstrapped with `sealed bootstrap` (`infra/terraform/customer-bootstrap`). It
impersonates the deployer service account and expects every path to secrets, the key broker, service account
identities and a shell to be denied, and it reads (as you) the policies that make it so.

```sh
# As the platform operator (gcloud uses the chain you -> platform SA -> deployer):
scripts/iam-checks/check.sh --project <customer project> --platform-sa <platform SA email>
# Also try real changes as the deployer (they must be refused):
scripts/iam-checks/check.sh --project <id> --platform-sa <email> --attempt-mutations
# Also require the connection binding to name this wallet:
scripts/iam-checks/check.sh --project <id> --platform-sa <email> --customer-address 0x...
```

Only the platform service account holds `serviceAccountTokenCreator` on the deployer, so run it as the platform
operator (or as that service account). The checks that read the customer's IAM policies need a project owner or
viewer; without that access they are skipped, not passed. Needs bash, gcloud, curl and jq (Cloud Shell has them).
Exit status is non-zero when any check fails.

| check | how | passes when |
|---|---|---|
| deployer identity | getIamPolicy on the deployer SA | only `roles/iam.serviceAccountTokenCreator` for the platform SA |
| deployer roles | project, subnet and staging bucket getIamPolicy; custom roles | only `sealedDeployer` (condition on `sealed-*` instance, disk and image names), `sealedDeployerAddresses`, `sealedSubnetUser` on `sealed-subnet` and `roles/storage.objectAdmin` on `<project>-sealed-staging`, each with exactly its permissions |
| connection binding | GET `sealed-subnet` as the deployer | its description is `sealed-binding/v1 customer=<wallet> key_broker=<url>`, the URL is the key broker service's, and the wallet is `--customer-address` when given |
| boot bucket | testIamPermissions on `<project>-sealed-boot` as the deployer | nothing granted (the customer's own credentials stage the OS images there) |
| key broker identity | project and KMS key policies, Cloud Run service | `secretAccessor` with the `sealed-*` condition plus `logging.logWriter` for its decision log and nothing else, `cloudkms.signer` on the HMAC key only, runs as its own SA from a digest-pinned image |
| debug log writer (when present) | project policy | `sealed-debug-logs` holds `logging.logWriter` only |
| firewall | firewall rules of `sealed-vpc` | ingress tcp 80/443 to `sealed-vm` only, egress 443 and 53 only, deny-all egress |
| cannot read a secret | testIamPermissions and `versions/latest:access` on every `sealed-*` secret as the deployer | nothing granted; access is 403 (the response is discarded, never printed) |
| cannot change the key broker | testIamPermissions on the service (and a label update with `--attempt-mutations`) | nothing granted; the update is 403 |
| cannot attach a service account | testIamPermissions on the project, every SA and every sealed VM (and `setServiceAccount` with `--attempt-mutations`) | no `actAs`, `getAccessToken`, `setServiceAccount`; 403 |
| no shell | testIamPermissions (OS Login, IAP, `getSerialPortOutput`), VM metadata, TCP to port 22 | nothing granted; serial port and OS Login off, project SSH keys blocked, no `ssh-keys`; port 22 closed |
| VM identity | every sealed VM | no service account; the one exception (spec 5.8) is a VM labeled `sealed-variant=debug` with exactly `sealed-debug-logs` and only the `logging.write` scope |
| positive controls | testIamPermissions as the deployer | it does hold its own permissions (the probes really ran as the deployer) |
| non-confidential VM (D-036) | `POST /v1/release` with a simulated (non-TDX) quote | 403 `quote_invalid` |

By default nothing is changed: denials are probed with `testIamPermissions` and read-only calls.

Two WARN lines name what IAM cannot prevent; they never fail the run:

- `compute.instances.setMetadata` (needed to create VMs with metadata) lets the deployer set `serial-port-enable`
  and add `ssh-keys` on a `sealed-*` VM at any time. The VM check above only sees the metadata at the moment it
  runs. The image has no getty, login or SSH daemon and the firewall drops port 22, so this opens no shell, but the
  interactive serial console then shows console output. The `compute.disableSerialPortAccess` organization policy
  blocks it.
- Static IP and operation permissions cannot be scoped by name, so the deployer's address rights are project-wide:
  it can reserve, attach and release any regional static IP in the project. Sealed needs a dedicated project.

## Tests

```sh
go test ./scripts/iam-checks/
```

- `check_test.go` runs `check.sh` against a fake Google Cloud (stub `gcloud` and `curl` on PATH, real bash and
  jq): a compliant project passes, with and without a debug VM; each of 21 misconfigurations (a debug VM with
  a broad scope, the log writer on an unlabeled VM or with an extra role, a key broker without its log writer role,
  a missing or foreign connection binding, an extra role on the staging bucket and a deployer that can write the
  boot bucket among them) fails with the right line; a binding for another wallet fails with `--customer-address`;
  no secret value is printed; no mutating request goes out without `--attempt-mutations`.
- `policy_test.go` renders `modules/iam` with `terraform plan` (no providers, no credentials, nothing applied),
  checks the permission lists against forbidden sets, evaluates the IAM conditions on sample resource names with a
  small evaluator that fails on any clause it does not understand, and checks that `check.sh` expects exactly the
  module's lists, roles and the debug VM scope. Needs terraform (skipped without it; `SEALED_REQUIRE_TERRAFORM=1` makes it fail instead).
