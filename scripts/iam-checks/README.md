# IAM checks (spec 8.6)

`check.sh` checks a project bootstrapped with `sealed bootstrap` (`infra/terraform/customer-bootstrap`). It
impersonates the deployer service account and expects every path to secrets, the key broker, service account
identities and a shell to be denied, and it reads (as you) the policies that make it so.

```sh
# As the platform operator (gcloud uses the chain you -> platform SA -> deployer):
scripts/iam-checks/check.sh --project <customer project> --platform-sa <platform SA email>
# Also try real changes as the deployer (they must be refused):
scripts/iam-checks/check.sh --project <id> --platform-sa <email> --attempt-mutations
```

Only the platform service account holds `serviceAccountTokenCreator` on the deployer, so run it as the platform
operator (or as that service account). The checks that read the customer's IAM policies need a project owner or
viewer; without that access they are skipped, not passed. Needs bash, gcloud, curl and jq (Cloud Shell has them).
Exit status is non-zero when any check fails.

| check | how | passes when |
|---|---|---|
| deployer identity | getIamPolicy on the deployer SA | only `roles/iam.serviceAccountTokenCreator` for the platform SA |
| deployer roles | project, subnet getIamPolicy; custom roles | only `sealedDeployer` (condition on `sealed-*` instance, disk and image names), `sealedDeployerAddresses` and `sealedSubnetUser` on `sealed-subnet`, each with exactly its permissions |
| key broker identity | project and KMS key policies, Cloud Run service | `secretAccessor` with the `sealed-*` condition, `cloudkms.signer` on the HMAC key only, runs as its own SA from a digest-pinned image |
| firewall | firewall rules of `sealed-vpc` | ingress tcp 80/443 to `sealed-vm` only, egress 443 and 53 only, deny-all egress |
| cannot read a secret | testIamPermissions and `versions/latest:access` on every `sealed-*` secret as the deployer | nothing granted; access is 403 (the response is discarded, never printed) |
| cannot change the key broker | testIamPermissions on the service (and a label update with `--attempt-mutations`) | nothing granted; the update is 403 |
| cannot attach a service account | testIamPermissions on the project, every SA and every sealed VM (and `setServiceAccount` with `--attempt-mutations`) | no `actAs`, `getAccessToken`, `setServiceAccount`; 403 |
| no shell | testIamPermissions (OS Login, IAP, serial port), VM metadata, TCP to port 22 | nothing granted; serial port and OS Login off, project SSH keys blocked, no `ssh-keys`; port 22 closed |
| positive controls | testIamPermissions as the deployer | it does hold its own permissions (the probes really ran as the deployer) |
| non-confidential VM (D-036) | `POST /v1/release` with a simulated (non-TDX) quote | 403 `quote_invalid` |

By default nothing is changed: denials are probed with `testIamPermissions` and read-only calls.

## Tests

```sh
go test ./scripts/iam-checks/
```

- `check_test.go` runs `check.sh` against a fake Google Cloud (stub `gcloud` and `curl` on PATH, real bash and
  jq): a compliant project passes; each of eleven misconfigurations fails with the right line; no secret value is
  printed; no mutating request goes out without `--attempt-mutations`.
- `policy_test.go` renders `modules/iam` with `terraform plan` (no providers, no credentials, nothing applied),
  checks the permission lists against forbidden sets, evaluates the IAM conditions on sample resource names with a
  small evaluator that fails on any clause it does not understand, and checks that `check.sh` expects exactly the
  module's lists. Needs terraform (skipped without it; `SEALED_REQUIRE_TERRAFORM=1` makes it fail instead).
