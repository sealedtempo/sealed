# Sealed threat model

Status: first version, written before the runtime spike. Sections marked TOFU are updated once real measurements are captured on Google Cloud.

## What Sealed protects

Your data stays in your cloud account. Apps run in confidential VMs, we have no access path, and outbound traffic only reaches destinations you approve. Your wallet approves exactly which builds can unlock your data.

Concretely:

1. Customer secrets (app secrets, the data-disk key, the gate password, provider keys) are released only to a VM that proves, with an Intel TDX quote, that it runs an approved non-debug image and exactly the stack the customer's wallet approved onchain, built only from active releases (P1).
2. The operator cannot read customer data: the platform's deployer account can create, stop and delete `sealed-*` VMs, disks and IPs, but cannot read Secret Manager, change the key broker, attach a service account to a VM, or open a shell (P2, P4).
3. App containers cannot exfiltrate data to destinations the customer did not approve: they have no route to the internet, and the only proxy and DNS server enforces a measured allowlist (P3).
4. Data leaving the VM toward the platform is content-free: health, counts, signed usage totals and attestation evidence (P5). Onchain records hold only hashes and addresses (P6).
5. Anyone holding an evidence bundle can re-verify a deployment against Tempo without trusting the platform (P7).

## What Sealed does not protect

Confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access. In addition:

- A malicious or buggy app that the customer approved can misuse the data it is given, within its egress allowlist.
- Destinations the customer adds to the allowlist are trusted with whatever apps send them.
- TDX side channels and microcode or firmware bugs are out of scope beyond Intel's TCB status reporting (the key broker rejects quotes whose TCB status is not allowed by policy).
- Availability: the operator or the cloud provider can stop or delete VMs. Data on the persistent disk stays encrypted with a key only an attested VM can obtain.
- Supply chain before the catalog: an upstream project that ships malicious code in a pinned version. Mitigations are review, SBOMs, scans and the ability to revoke a release onchain, not prevention.

## Trust anchors

| anchor | why it is trusted | how to rotate or revoke |
|---|---|---|
| Intel TDX root of trust and PCS collateral | hardware attestation; quotes chain to Intel's root CA | TCB recovery by Intel; policy in key broker config |
| dstack OS image (MRTD, RTMR0 to RTMR2) | open source, reproducible build or TOFU measurement, registered in PlatformRegistry | `revokeImage`, register a new image |
| Release bundles | public source, digest-pinned images, cosign keyless signature in Rekor, SLSA provenance | `revokeRelease` |
| Customer wallet | sole signer of `approveStack` and `revokeStack` for that customer | customer moves to a new wallet and re-bootstraps |
| Customer key broker | runs in the customer's project from a pinned public image with its own service account; config (customer address, Tempo RPC) set by the customer | customer redeploys it |
| Tempo RPC | read-only source of onchain state; customer chooses the endpoint | change endpoint at bootstrap |
| Oracle key (method 1 records) | operator key, attests that the platform verified evidence; not needed for secret release | remove signer onchain; method 2 (ZK) removes this anchor |

The oracle is not in the secret-release path. A compromised oracle can write misleading deployment records, but cannot make the customer's key broker release secrets, and `sealed verify` re-checks the evidence itself.

## Measurement chain

Primary runtime: dstack on Google Cloud C3 Intel TDX.

1. MRTD measures the TD firmware (on Google Cloud, Google's TDVF build).
2. RTMR0 measures firmware configuration and ACPI tables. It can vary with machine type; images are registered per machine type if so (TOFU until computed).
3. RTMR1 measures the kernel and initrd (unified image), RTMR2 the kernel command line, which carries the dm-verity root hash of the read-only root filesystem.
4. RTMR3 is extended at runtime by dstack with app events. The `compose-hash` event carries `sha256(app-compose.json)`, which is the stackHash. Replaying the event log reproduces RTMR3 exactly; any changed byte in the stack changes RTMR3.
5. `measurementsHash = keccak256(mrtd || rtmr0 || rtmr1 || rtmr2)` is registered in PlatformRegistry with `isDebug`.

Fallback runtime (only if the dstack spike fails): a plain C3 TDX VM booting a mkosi-built unified kernel image with a dm-verity root. The agent binds stackHash into report_data, and trust flows through MRTD and RTMR0 to RTMR2 only.

TOFU: until measurements are computed from the image build with dstack's tooling, they are recorded from a first boot and marked trust-on-first-use in this section.

## Attacks considered

| attack | defense | test |
|---|---|---|
| Operator boots a modified stack to get secrets | RTMR3 compose hash differs, stack recomputation fails, approval missing | A7 one changed byte |
| Operator boots a debug image | `isDebug` images are never approved; key broker rejects | A7 debug image |
| Use of a revoked release | `isStackApproved` requires all releases active; broker checks the approval's release set | A7 revoked release |
| Customer revokes approval | broker checks approval at every boot | A7 revoked approval |
| Replay of an old quote to the broker | single-use nonce with 5 minute lifetime bound in report_data | key broker unit tests |
| Quote produced for one purpose reused for another | domain-separated report_data tags | verifier unit tests |
| Network attacker intercepts released secrets | HPKE to an ephemeral key bound in the quote | key broker unit tests |
| App exfiltrates to an unapproved host, raw IP, metadata server or via DNS | internal network, egress allowlist, DNS filtering, IP range blocks, DOCKER-USER rules | A8 |
| Platform deployer account escalates | custom role with name conditions; no secret, KMS, Cloud Run or SA permissions | A3 IAM checks |
| Non-confidential VM requests secrets | no valid TDX quote | A3 |
| Shell access to a production VM | no SSH daemon, no getty, serial port off, no service account | A3 |
| Enclave signer key overspends | access-key daily limit, FeeSplitter per-payment and daily caps | A9 |
| Malicious relay provider | provider attestation verified per request; relay attestation verified by the payer every 15 minutes | A10 |
